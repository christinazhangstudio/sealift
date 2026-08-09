package ebay

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestIsAPIError(t *testing.T) {
	err := fmt.Errorf("get subscriptions: %w", &APIError{
		StatusCode: http.StatusConflict,
		Body:       []byte(`{"errors":[{"errorId":195003}]}`),
	})

	if !IsAPIError(err, http.StatusConflict, NotificationConfigRequiredError) {
		t.Fatal("expected wrapped notification config error to be recognized")
	}
	if IsAPIError(err, http.StatusForbidden, NotificationConfigRequiredError) {
		t.Fatal("matched the wrong HTTP status")
	}
	if IsAPIError(err, http.StatusConflict, 195000) {
		t.Fatal("matched the wrong eBay error ID")
	}
}

func TestIsAPIErrorRejectsMalformedPayload(t *testing.T) {
	err := &APIError{StatusCode: http.StatusConflict, Body: []byte(`not json`)}
	if IsAPIError(err, http.StatusConflict, NotificationConfigRequiredError) {
		t.Fatal("malformed error payload should not match")
	}
}

func TestDoJSONAcceptsEmptySuccessfulResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()

	client := &Client{Client: server.Client()}
	var response struct {
		NotificationID string `json:"notificationId"`
	}
	if err := client.doJSON(context.Background(), http.MethodPost, server.URL, "token", nil, &response); err != nil {
		t.Fatalf("expected an empty 202 response to succeed, got %v", err)
	}
}

func TestDoJSONDecodesAcceptedResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusAccepted)
		json.NewEncoder(w).Encode(map[string]string{"notificationId": "test-notification-id"})
	}))
	defer server.Close()

	client := &Client{Client: server.Client()}
	var response struct {
		NotificationID string `json:"notificationId"`
	}
	if err := client.doJSON(context.Background(), http.MethodPost, server.URL, "token", nil, &response); err != nil {
		t.Fatalf("expected a JSON 202 response to succeed, got %v", err)
	}
	if response.NotificationID != "test-notification-id" {
		t.Fatalf("expected notification ID to be decoded, got %q", response.NotificationID)
	}
}
