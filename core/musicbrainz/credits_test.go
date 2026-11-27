package musicbrainz

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/navidrome/navidrome/model"
	"github.com/navidrome/navidrome/model/metadata"
)

const (
	clipseRelease = "5601fd90-0a57-47df-842e-2449ae1cebf3"
	chainsTrack   = "0dc5ed34-dcc5-405a-9538-a15d5ec08de8"
	clipseID      = "e6424fa5-08d3-41c6-96f3-8549f733708c"
	kendrickID    = "381086ea-f511-4aba-bdf9-71c753dc5077"
)

func TestReleaseCreditsKeepTrackArtistOrder(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/"+clipseRelease || r.URL.Query().Get("inc") != "recordings artist-credits" || r.UserAgent() != userAgent {
			t.Errorf("unexpected MusicBrainz request: %s, agent %q", r.URL, r.UserAgent())
		}
		fmt.Fprintf(w, `{"id": %q, "media": [{"tracks": [
			{"id": %q, "artist-credit": [
				{"name": "Clipse", "joinphrase": " & ", "artist": {"id": %q}},
				{"name": "Kendrick Lamar", "artist": {"id": %q, "sort-name": "Lamar, Kendrick"}}
			]}
		]}]}`, clipseRelease, chainsTrack, clipseID, kendrickID)
	}))
	t.Cleanup(server.Close)

	credits, err := fetchRelease(t.Context(), server.Client(), server.URL+"/", clipseRelease)
	if err != nil {
		t.Fatal(err)
	}
	primary := metadata.NewArtist("Clipse", "", clipseID)
	track := model.MediaFile{
		ID: "song", PID: "persistent-song", AlbumID: "album", ArtistID: primary.ID,
		MbzAlbumID: clipseRelease, MbzReleaseTrackID: chainsTrack,
		Artist: "Clipse", AlbumArtist: "Clipse", Participants: model.Participants{},
	}
	track.Participants.Add(model.RoleArtist, primary)
	track.Participants.Add(model.RoleAlbumArtist, primary)
	if !apply(&track, credits) {
		t.Fatal("expected credits from the exact release track")
	}
	artists := track.Participants[model.RoleArtist]
	if len(artists) != 2 || artists[0].ID != primary.ID || artists[1].MbzArtistID != kendrickID {
		t.Fatalf("wrong ordered artist credits: %+v", artists)
	}
	if track.Artist != "Clipse & Kendrick Lamar" || track.AlbumArtist != "Clipse" ||
		track.ID != "song" || track.PID != "persistent-song" || track.AlbumID != "album" || track.ArtistID != primary.ID {
		t.Fatalf("wrong display artist or changed track identity: %+v", track)
	}
	if apply(&track, credits) {
		t.Fatal("existing multi-artist credits must take precedence")
	}

	track.Participants[model.RoleArtist] = track.Participants[model.RoleAlbumArtist]
	track.MbzReleaseTrackID = "other-track"
	if apply(&track, credits) {
		t.Fatal("a credit must not be used for another track")
	}
	track.MbzReleaseTrackID = chainsTrack
	track.Participants[model.RoleArtist] = model.ParticipantList{{Artist: metadata.NewArtist("Other artist", "", "")}}
	if apply(&track, credits) {
		t.Fatal("a credit must not replace a different local artist")
	}
}

func TestReleaseCreditsRetryAfterServiceUnavailable(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if requests.Add(1) == 1 {
			w.Header().Set("Retry-After", "0")
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		fmt.Fprintf(w, `{"id": %q, "media": []}`, clipseRelease)
	}))
	t.Cleanup(server.Close)

	credits, err := fetchWithRetry(t.Context(), func() (ReleaseCredits, error) {
		return fetchRelease(t.Context(), server.Client(), server.URL+"/", clipseRelease)
	})
	if err != nil || credits == nil || requests.Load() != 2 {
		t.Fatalf("the second request should have succeeded: credits=%#v requests=%d err=%v", credits, requests.Load(), err)
	}
}
