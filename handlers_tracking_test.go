package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.tesla.com/chrzhang/sealift/usps"
)

func TestHandleUSPSTrackingReturnsDetail(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/oauth2/v3/token":
			json.NewEncoder(w).Encode(map[string]any{"access_token": "tok", "expires_in": 3600})
		case strings.HasPrefix(r.URL.Path, "/tracking/v3/tracking/"):
			json.NewEncoder(w).Encode(usps.Tracking{
				TrackingNumber: "9400111899562537875111",
				Status:         "Delivered",
				StatusCategory: "Delivered",
			})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(upstream.Close)

	c := usps.New(upstream.Client(), "id", "secret", false)
	c.BaseURL = upstream.URL
	s := &Server{usps: c}

	req := httptest.NewRequest(http.MethodGet, "/api/tracking/9400111899562537875111?mailingDate=2026-06-23T16:00:00.000Z&destinationZIPCode=78704-1234", nil)
	req.SetPathValue("trackingNumber", "9400111899562537875111")
	rec := httptest.NewRecorder()
	s.handleUSPSTracking(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status %d body %s", rec.Code, rec.Body.String())
	}
	var got usps.Tracking
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Status != "Delivered" {
		t.Fatalf("status %q", got.Status)
	}
}

func TestHandleUSPSTrackingUnavailableWithoutClient(t *testing.T) {
	s := &Server{}
	req := httptest.NewRequest(http.MethodGet, "/api/tracking/9400111899562537875111", nil)
	req.SetPathValue("trackingNumber", "9400111899562537875111")
	rec := httptest.NewRecorder()
	s.handleUSPSTracking(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status %d", rec.Code)
	}
}

func TestHandleUSPSTrackingRequiresNumber(t *testing.T) {
	s := &Server{usps: usps.New(http.DefaultClient, "id", "secret", false)}
	req := httptest.NewRequest(http.MethodGet, "/api/tracking/", nil)
	req.SetPathValue("trackingNumber", "  ")
	rec := httptest.NewRecorder()
	s.handleUSPSTracking(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status %d", rec.Code)
	}
}

func TestHandleUSPSTrackingMapsUnknownNumberTo404(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/oauth2/v3/token":
			json.NewEncoder(w).Encode(map[string]any{"access_token": "tok", "expires_in": 3600})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(upstream.Close)

	c := usps.New(upstream.Client(), "id", "secret", false)
	c.BaseURL = upstream.URL
	s := &Server{usps: c}

	req := httptest.NewRequest(http.MethodGet, "/api/tracking/1", nil)
	req.SetPathValue("trackingNumber", "1")
	rec := httptest.NewRecorder()
	s.handleUSPSTracking(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status %d body %s", rec.Code, rec.Body.String())
	}
}
