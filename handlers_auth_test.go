package main

import (
	"bytes"
	"context"
	"log/slog"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo/integration/mtest"
)

func TestAuthCallbackRequiresUnexpiredState(t *testing.T) {
	mt := mtest.New(t, mtest.NewOptions().ClientType(mtest.Mock))
	for _, tc := range []struct {
		name      string
		createdAt time.Time
		want      string
	}{
		{"current state", time.Now(), "missing auth code"},
		{"expired state awaiting TTL cleanup", time.Now().Add(-oauthStateTTL - time.Minute), "authorization link has expired"},
		{"state without creation time", time.Time{}, "authorization link has expired"},
	} {
		mt.Run(tc.name, func(mt *mtest.T) {
			mt.AddMockResponses(mtest.CreateSuccessResponse(bson.E{Key: "value", Value: bson.M{
				"tenantId": "tenant-id", "createdAt": tc.createdAt,
			}}))
			s := &Server{oauthStatesCol: mt.Coll}
			r := httptest.NewRequest("GET", "/api/auth-callback?state=single-use-state", nil)
			// A session cannot replace the required OAuth state, even if the
			// callback is later used behind an authenticated route.
			r = r.WithContext(context.WithValue(r.Context(), "userId", "session-tenant"))
			w := httptest.NewRecorder()
			s.handleAuthCallback(w, r)
			if !strings.Contains(w.Body.String(), tc.want) {
				mt.Fatalf("callback body = %q, want %q", w.Body.String(), tc.want)
			}
			command := mt.GetStartedEvent()
			if command == nil || command.CommandName != "findAndModify" {
				mt.Fatal("callback did not atomically consume state")
			}
			if !command.Command.Lookup("remove").Boolean() ||
				command.Command.Lookup("query", "state").StringValue() != "single-use-state" {
				mt.Fatalf("unexpected state consumption command: %s", command.Command)
			}
		})
	}
}

func TestAuthCallbackRejectsMissingOrReplayedState(t *testing.T) {
	mt := mtest.New(t, mtest.NewOptions().ClientType(mtest.Mock))
	for _, state := range []string{"", "already-consumed"} {
		mt.Run("state="+state, func(mt *mtest.T) {
			if state != "" {
				mt.AddMockResponses(mtest.CreateSuccessResponse(bson.E{Key: "value", Value: nil}))
			}
			s := &Server{oauthStatesCol: mt.Coll}
			r := httptest.NewRequest("GET", "/api/auth-callback?code=code&state="+state, nil)
			r = r.WithContext(context.WithValue(r.Context(), "userId", "session-tenant"))
			w := httptest.NewRecorder()
			s.handleAuthCallback(w, r)
			if !strings.Contains(w.Body.String(), "authorization link has expired") {
				mt.Fatalf("callback accepted missing or consumed state: %s", w.Body.String())
			}
		})
	}
}

func TestAuthCallbackDoesNotLogOAuthSecrets(t *testing.T) {
	var logs bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	t.Cleanup(func() { slog.SetDefault(previous) })

	mt := mtest.New(t, mtest.NewOptions().ClientType(mtest.Mock))
	for _, query := range []string{
		"state=private-state&code=private-code",
		"state=private-state&error_description=private-error",
	} {
		mt.Run(query, func(mt *mtest.T) {
			mt.AddMockResponses(mtest.CreateSuccessResponse(bson.E{Key: "value", Value: bson.M{
				"tenantId": "tenant-id", "createdAt": time.Now(),
			}}))
			s := &Server{oauthStatesCol: mt.Coll}
			w := httptest.NewRecorder()
			s.handleAuthCallback(w, httptest.NewRequest("GET", "/api/auth-callback?"+query, nil))
		})
	}
	for _, secret := range []string{"private-state", "private-code", "private-error"} {
		if strings.Contains(logs.String(), secret) {
			t.Errorf("callback logged OAuth secret %q: %s", secret, logs.String())
		}
	}
}
