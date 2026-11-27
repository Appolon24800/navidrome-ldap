package musicbrainz

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/navidrome/navidrome/conf"
	"github.com/navidrome/navidrome/model"
	"github.com/navidrome/navidrome/model/metadata"
)

const (
	releaseURL = "https://musicbrainz.org/ws/2/release/"
	userAgent  = "NavidromeLDAP/1.0 ( https://github.com/Appolon24800/navidrome-ldap )"
)

// ReleaseCredits contains the ordered artist credits for each release track ID.
type ReleaseCredits map[string][]artistCredit

type artistCredit struct {
	Name       string `json:"name"`
	JoinPhrase string `json:"joinphrase"`
	Artist     struct {
		ID       string `json:"id"`
		Name     string `json:"name"`
		SortName string `json:"sort-name"`
	} `json:"artist"`
}

type throttledError struct {
	statusCode int
	retryAt    time.Time
}

func (e throttledError) Error() string {
	return fmt.Sprintf("MusicBrainz release lookup returned HTTP %d", e.statusCode)
}

func throttleDelay(value string, now time.Time) time.Time {
	if seconds, err := strconv.ParseUint(value, 10, 32); err == nil {
		return now.Add(time.Duration(seconds) * time.Second)
	}
	if date, err := http.ParseTime(value); err == nil {
		return date
	}
	return now.Add(2 * time.Second)
}

func fetchRelease(ctx context.Context, client *http.Client, baseURL, releaseID string) (ReleaseCredits, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL+releaseID+"?inc=recordings+artist-credits&fmt=json", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", userAgent)
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	credits := make(ReleaseCredits)
	if resp.StatusCode == http.StatusNotFound {
		return credits, nil
	}
	if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode == http.StatusServiceUnavailable {
		return nil, throttledError{resp.StatusCode, throttleDelay(resp.Header.Get("Retry-After"), time.Now())}
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("MusicBrainz release lookup returned HTTP %d", resp.StatusCode)
	}
	var release struct {
		ID    string
		Media []struct {
			Tracks []struct {
				ID           string
				ArtistCredit []artistCredit `json:"artist-credit"`
			}
		}
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 16<<20)).Decode(&release); err != nil {
		return nil, err
	}
	if !strings.EqualFold(releaseID, release.ID) {
		return nil, fmt.Errorf("MusicBrainz returned release %q for %q", release.ID, releaseID)
	}
	for _, medium := range release.Media {
		for _, track := range medium.Tracks {
			if len(track.ArtistCredit) > 1 {
				credits[strings.ToLower(track.ID)] = track.ArtistCredit
			}
		}
	}
	return credits, nil
}

type cachedRelease struct {
	Credits ReleaseCredits
	RetryAt time.Time
}

func validReleaseID(value string) bool {
	return len(value) == 36 && uuid.Validate(value) == nil
}

func cacheKey(releaseID string) string {
	return "musicbrainz-track-credits:" + strings.ToLower(releaseID)
}

func loadRelease(ctx context.Context, repo model.PropertyRepository, releaseID string) (cachedRelease, error) {
	var release cachedRelease
	data, err := repo.Get(ctx, cacheKey(releaseID))
	if errors.Is(err, model.ErrNotFound) {
		return release, nil
	}
	if err != nil {
		return release, err
	}
	err = json.Unmarshal([]byte(data), &release)
	return release, err
}

func saveRelease(ctx context.Context, repo model.PropertyRepository, releaseID string, release cachedRelease) error {
	data, err := json.Marshal(release)
	if err != nil {
		return err
	}
	return repo.Put(ctx, cacheKey(releaseID), string(data))
}

// ApplyCached adds credits to newly scanned tracks before the scanner indexes their artists.
func ApplyCached(ctx context.Context, repo model.PropertyRepository, tracks model.MediaFiles) error {
	if !conf.Server().EnableMusicBrainzTrackCredits {
		return nil
	}
	releases := make(map[string]ReleaseCredits)
	for i := range tracks {
		track := &tracks[i]
		if !eligible(*track) {
			continue
		}
		releaseID := strings.ToLower(track.MbzAlbumID)
		credits, ok := releases[releaseID]
		if !ok {
			release, err := loadRelease(ctx, repo, releaseID)
			if err != nil {
				return fmt.Errorf("loading cached MusicBrainz release %s: %w", releaseID, err)
			}
			credits = release.Credits
			releases[releaseID] = credits
		}
		apply(track, credits)
	}
	return nil
}

func eligible(track model.MediaFile) bool {
	return !track.Missing && validReleaseID(track.MbzAlbumID) && uuid.Validate(track.MbzReleaseTrackID) == nil &&
		len(track.Participants[model.RoleArtist]) == 1
}

func apply(track *model.MediaFile, credits ReleaseCredits) bool {
	if len(track.Participants[model.RoleArtist]) != 1 {
		return false
	}
	credit := credits[strings.ToLower(track.MbzReleaseTrackID)]
	if len(credit) < 2 {
		return false
	}
	primary := track.Participants.First(model.RoleArtist)
	first := credit[0]
	if primary.MbzArtistID != "" {
		if !strings.EqualFold(primary.MbzArtistID, first.Artist.ID) {
			return false
		}
	} else if !strings.EqualFold(primary.Name, first.Name) && !strings.EqualFold(primary.Name, first.Artist.Name) {
		return false
	}

	var display strings.Builder
	display.WriteString(primary.Name)
	participants := model.Participants{}
	participants.Add(model.RoleArtist, primary)
	for i, guest := range credit[1:] {
		name := strings.TrimSpace(cmp.Or(guest.Name, guest.Artist.Name))
		if name == "" || uuid.Validate(guest.Artist.ID) != nil {
			return false
		}
		participants.Add(model.RoleArtist, metadata.NewArtist(name, guest.Artist.SortName, guest.Artist.ID))
		display.WriteString(cmp.Or(credit[i].JoinPhrase, " & "))
		display.WriteString(name)
	}
	if len(participants[model.RoleArtist]) != len(credit) {
		return false
	}
	track.Participants[model.RoleArtist] = participants[model.RoleArtist]
	track.Artist = display.String()
	return true
}
