package usps

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestIsUSPSCarrier(t *testing.T) {
	cases := map[string]bool{
		"USPS":              true,
		"usps":              true,
		"USPSPriority":      true,
		"US Postal Service": true,
		"UPS":               false,
		"FedEx":             false,
		"":                  false,
	}
	for in, want := range cases {
		if got := IsUSPSCarrier(in); got != want {
			t.Fatalf("IsUSPSCarrier(%q)=%v, want %v", in, got, want)
		}
	}
}

func TestDestinationZIP(t *testing.T) {
	if got := DestinationZIP("78704-1234"); got != "78704" {
		t.Fatalf("got %q", got)
	}
	if got := DestinationZIP(" 77007 "); got != "77007" {
		t.Fatalf("got %q", got)
	}
	if got := DestinationZIP(""); got != "" {
		t.Fatalf("got %q", got)
	}
}

func TestMailingDate(t *testing.T) {
	if got := MailingDate("2026-06-23T16:00:00.000Z"); got != "2026-06-23" {
		t.Fatalf("got %q", got)
	}
	if got := MailingDate("", "2026-07-10"); got != "2026-07-10" {
		t.Fatalf("got %q", got)
	}
	if got := MailingDate(""); got != "" {
		t.Fatalf("got %q", got)
	}
}

func TestStringListUnmarshal(t *testing.T) {
	var fromString Tracking
	if err := json.Unmarshal([]byte(`{"services":"USPS Tracking"}`), &fromString); err != nil {
		t.Fatal(err)
	}
	if len(fromString.Services) != 1 || fromString.Services[0] != "USPS Tracking" {
		t.Fatalf("string services: %#v", fromString.Services)
	}

	var fromArray Tracking
	if err := json.Unmarshal([]byte(`{"services":["USPS Tracking","Insurance"]}`), &fromArray); err != nil {
		t.Fatal(err)
	}
	if len(fromArray.Services) != 2 {
		t.Fatalf("array services: %#v", fromArray.Services)
	}
}

func TestDecodeTrackingObjectAndArray(t *testing.T) {
	obj, err := decodeTracking([]byte(`{"trackingNumber":"1","status":"Delivered"}`))
	if err != nil || obj.TrackingNumber != "1" || obj.Status != "Delivered" {
		t.Fatalf("object: %+v err=%v", obj, err)
	}
	list, err := decodeTracking([]byte(`[{"trackingNumber":"2","status":"In Transit"}]`))
	if err != nil || list.TrackingNumber != "2" {
		t.Fatalf("array: %+v err=%v", list, err)
	}
}

func TestTrackUsesV3DetailPath(t *testing.T) {
	var tokenHits, trackHits int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/oauth2/v3/token":
			tokenHits++
			json.NewEncoder(w).Encode(map[string]any{
				"access_token": "tok-1",
				"expires_in":   "3600",
			})
		case strings.HasPrefix(r.URL.Path, "/tracking/v3/tracking/"):
			trackHits++
			if got := r.Header.Get("Authorization"); got != "Bearer tok-1" {
				t.Errorf("auth header %q", got)
			}
			if r.URL.Query().Get("expand") != "DETAIL" {
				t.Errorf("expand %q", r.URL.Query().Get("expand"))
			}
			if got := r.URL.Path; got != "/tracking/v3/tracking/9400111899562537875111" {
				t.Errorf("path %q", got)
			}
			if r.ContentLength > 0 {
				t.Error("v3 request should not send a body")
			}
			json.NewEncoder(w).Encode(Tracking{
				TrackingNumber: "9400111899562537875111",
				Status:         "Delivered",
				StatusCategory: "Delivered",
			})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)

	c := New(server.Client(), "id", "secret", false)
	c.BaseURL = server.URL

	first, err := c.Track(context.Background(), TrackRequest{
		TrackingNumber:     "9400111899562537875111",
		MailingDate:        "2026-06-23",
		DestinationZIPCode: "78704",
	})
	if err != nil {
		t.Fatal(err)
	}
	if first.Status != "Delivered" {
		t.Fatalf("status %q", first.Status)
	}
	if _, err := c.Track(context.Background(), TrackRequest{TrackingNumber: "9400111899562537875111"}); err != nil {
		t.Fatal(err)
	}
	if tokenHits != 1 {
		t.Fatalf("token hits %d, want 1", tokenHits)
	}
	if trackHits != 2 {
		t.Fatalf("track hits %d, want 2", trackHits)
	}
}

func TestTrackFallsBackToV3r2(t *testing.T) {
	var v3, v3r2 int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/oauth2/v3/token":
			json.NewEncoder(w).Encode(map[string]any{"access_token": "tok-1", "expires_in": 3600})
		case strings.HasPrefix(r.URL.Path, "/tracking/v3/tracking/"):
			v3++
			w.WriteHeader(http.StatusNotFound)
		case r.URL.Path == "/tracking/v3r2/tracking" || r.URL.Path == "/tracking/v3r2/tracking/":
			v3r2++
			if r.Method != http.MethodPost {
				t.Errorf("v3r2 method %s, want POST", r.Method)
			}
			json.NewEncoder(w).Encode(Tracking{Status: "In Transit"})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)

	c := New(server.Client(), "id", "secret", false)
	c.BaseURL = server.URL
	got, err := c.Track(context.Background(), TrackRequest{TrackingNumber: "1"})
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != "In Transit" {
		t.Fatalf("status %q", got.Status)
	}
	if v3 != 1 || v3r2 != 1 {
		t.Fatalf("v3=%d v3r2=%d", v3, v3r2)
	}
}
