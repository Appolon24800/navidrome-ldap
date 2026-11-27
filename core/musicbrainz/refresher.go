package musicbrainz

import (
	"context"
	"errors"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/navidrome/navidrome/log"
	"github.com/navidrome/navidrome/model"
	"github.com/navidrome/navidrome/model/request"
	"github.com/navidrome/navidrome/server/filter"
	"github.com/navidrome/navidrome/utils/httpclient"
	"github.com/navidrome/navidrome/utils/singleton"
	"golang.org/x/time/rate"
)

type refreshKey struct {
	albumID string
	force   bool
}

type refreshRequest struct {
	key  refreshKey
	user model.User
}

type Refresher struct {
	ds      model.DataStore
	scanner model.Scanner
	fetch   func(context.Context, string) (ReleaseCredits, error)
	queue   chan refreshRequest
	pending sync.Map
}

// GetRefresher shares one queue and MusicBrainz rate limit across all API routers.
func GetRefresher(ctx context.Context, ds model.DataStore, scanner model.Scanner) *Refresher {
	return singleton.GetInstance(func() *Refresher {
		client := httpclient.New(8 * time.Second)
		limiter := rate.NewLimiter(rate.Every(time.Second), 1)
		fetch := func(ctx context.Context, releaseID string) (ReleaseCredits, error) {
			return fetchWithRetry(ctx, func() (ReleaseCredits, error) {
				if err := limiter.Wait(ctx); err != nil {
					return nil, err
				}
				return fetchRelease(ctx, client, releaseURL, releaseID)
			})
		}
		r := &Refresher{ds: ds, scanner: scanner, fetch: fetch, queue: make(chan refreshRequest, 256)}
		go r.run(ctx)
		return r
	})
}

func fetchWithRetry(ctx context.Context, fetch func() (ReleaseCredits, error)) (ReleaseCredits, error) {
	credits, err := fetch()
	var limited throttledError
	if !errors.As(err, &limited) {
		return credits, err
	}
	delay := time.Until(limited.retryAt)
	if delay > 10*time.Second {
		return nil, err
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-timer.C:
		return fetch()
	}
}

// Queue requests a refresh without delaying the track response.
func (r *Refresher) Queue(ctx context.Context, albumID string, force bool) {
	user, ok := request.UserFrom(ctx)
	if !ok || albumID == "" {
		return
	}
	key := refreshKey{albumID: albumID, force: force}
	if _, pending := r.pending.LoadOrStore(key, struct{}{}); pending {
		return
	}
	select {
	case r.queue <- refreshRequest{key, user}:
	default:
		r.pending.Delete(key)
	}
}

func (r *Refresher) run(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case item := <-r.queue:
			work := request.WithUser(ctx, item.user)
			if err := r.refresh(work, item.key); err != nil {
				log.Warn(work, "MusicBrainz: Could not refresh track credits", "albumId", item.key.albumID, err)
			}
			r.pending.Delete(item.key)
		}
	}
}

func (r *Refresher) refresh(ctx context.Context, key refreshKey) error {
	tracks, err := r.ds.MediaFile().GetAll(ctx, filter.SongsByAlbum(key.albumID))
	if err != nil {
		return err
	}
	releases := make(map[string]ReleaseCredits)
	folders := make(map[model.ScanTarget]struct{})
	for _, track := range tracks {
		if track.Missing || (!key.force && !eligible(track)) || track.MbzReleaseTrackID == "" {
			continue
		}
		releaseID := strings.ToLower(track.MbzAlbumID)
		credits, seen := releases[releaseID]
		if !seen {
			credits, err = r.getRelease(ctx, releaseID, key.force)
			if err != nil {
				return err
			}
			releases[releaseID] = credits
		}
		if credits != nil && (key.force || apply(&track, credits)) {
			folders[model.ScanTarget{LibraryID: track.LibraryID, FolderPath: path.Dir(track.Path)}] = struct{}{}
		}
	}
	if len(folders) == 0 {
		return nil
	}
	targets := make([]model.ScanTarget, 0, len(folders))
	for folder := range folders {
		targets = append(targets, folder)
	}
	return r.scanWhenReady(ctx, targets)
}

func (r *Refresher) getRelease(ctx context.Context, releaseID string, force bool) (ReleaseCredits, error) {
	if !validReleaseID(releaseID) {
		return nil, nil
	}
	repo := r.ds.Property()
	release, err := loadRelease(ctx, repo, releaseID)
	if err != nil {
		return nil, err
	}
	if !force && (release.Credits != nil || time.Now().Before(release.RetryAt)) {
		return release.Credits, nil
	}
	credits, err := r.fetch(ctx, releaseID)
	if err != nil {
		release.RetryAt = time.Now().Add(5 * time.Minute)
		var limited throttledError
		if errors.As(err, &limited) && limited.retryAt.After(release.RetryAt) {
			release.RetryAt = limited.retryAt
		}
		return nil, errors.Join(err, saveRelease(ctx, repo, releaseID, release))
	}
	return credits, saveRelease(ctx, repo, releaseID, cachedRelease{Credits: credits})
}

func (r *Refresher) scanWhenReady(ctx context.Context, targets []model.ScanTarget) error {
	timeout := time.NewTimer(time.Minute)
	defer timeout.Stop()
	retry := time.NewTicker(2 * time.Second)
	defer retry.Stop()
	for {
		_, err := r.scanner.ScanFolders(ctx, true, targets)
		if !errors.Is(err, model.ErrAlreadyScanning) {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timeout.C:
			return err
		case <-retry.C:
		}
	}
}
