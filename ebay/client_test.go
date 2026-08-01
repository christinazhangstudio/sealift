package ebay

import (
	"fmt"
	"net/http"
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
