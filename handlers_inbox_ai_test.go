package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
)

func TestParseInboxRuleSuggestionsFiltersUnknownAndDuplicateMatches(t *testing.T) {
	knownIDs := map[string]struct{}{"offer-1": {}, "offer-2": {}, "security-1": {}}
	answer := "```json\n" + `{
		"suggestions": [{
			"title": "Group offers",
			"description": "Recurring promotions can be reviewed together.",
			"destination": "Offers",
			"conditions": ["Sender is eBay", "Message is promotional"],
			"matchingIds": ["offer-2", "made-up", "offer-1", "offer-1"]
		}]
	}` + "\n```"

	suggestions, err := parseInboxRuleSuggestions(answer, knownIDs)
	if err != nil {
		t.Fatalf("parseInboxRuleSuggestions returned error: %v", err)
	}
	if len(suggestions) != 1 {
		t.Fatalf("got %d suggestions, want 1", len(suggestions))
	}
	got := suggestions[0]
	if got.ID != "offers" {
		t.Fatalf("rule ID = %q, want offers", got.ID)
	}
	if !reflect.DeepEqual(got.MatchingIDs, []string{"offer-1", "offer-2"}) {
		t.Fatalf("matching IDs = %#v", got.MatchingIDs)
	}
}

func TestParseInboxRuleSuggestionsRejectsRulesWithoutRecurringMatches(t *testing.T) {
	knownIDs := map[string]struct{}{"offer-1": {}, "security-1": {}}
	answer := `{"suggestions":[{
		"title":"One message",
		"description":"Not a recurring pattern.",
		"destination":"Misc",
		"conditions":["Message is unique"],
		"matchingIds":["offer-1","invented"]
	}]}`

	if _, err := parseInboxRuleSuggestions(answer, knownIDs); err == nil {
		t.Fatal("parseInboxRuleSuggestions accepted a rule with fewer than two known matches")
	}
}

func TestTruncateRunesDoesNotSplitUTF8(t *testing.T) {
	if got := truncateRunes("offer 🚀 ending", 8); got != "offer 🚀 " {
		t.Fatalf("truncateRunes = %q", got)
	}
}

func TestStoredInboxAnalysisBSONRoundTrip(t *testing.T) {
	want := storedInboxAnalysis{
		TenantID: "tenant-1",
		Model:    "qwen",
		Suggestions: []inboxRuleSuggestion{{
			ID: "offers", Title: "Offers", Description: "Recurring offers.",
			Destination: "Promotions", Conditions: []string{"Sender is eBay"},
			MatchingIDs: []string{"offer-1", "offer-2"},
		}},
		ActiveRuleIDs: []string{"offers"},
	}
	encoded, err := bson.Marshal(want)
	if err != nil {
		t.Fatal(err)
	}
	var got storedInboxAnalysis
	if err := bson.Unmarshal(encoded, &got); err != nil {
		t.Fatal(err)
	}
	if got.TenantID != want.TenantID || got.Model != want.Model ||
		!reflect.DeepEqual(got.Suggestions, want.Suggestions) ||
		!reflect.DeepEqual(got.ActiveRuleIDs, want.ActiveRuleIDs) {
		t.Fatalf("BSON round trip = %#v, want %#v", got, want)
	}
}

type fakeInboxAnalysisStore struct {
	saved            storedInboxAnalysis
	loaded           storedInboxAnalysis
	loadErr          error
	setAppliedResult storedInboxAnalysis
	setAppliedErr    error
	setTenantID      string
	setRuleID        string
	setApplied       bool
}

func (store *fakeInboxAnalysisStore) Save(_ context.Context, analysis storedInboxAnalysis) error {
	store.saved = analysis
	return nil
}

func (store *fakeInboxAnalysisStore) Load(_ context.Context, _ string) (storedInboxAnalysis, error) {
	return store.loaded, store.loadErr
}

func (store *fakeInboxAnalysisStore) SetRuleApplied(_ context.Context, tenantID, ruleID string, applied bool) (storedInboxAnalysis, error) {
	store.setTenantID = tenantID
	store.setRuleID = ruleID
	store.setApplied = applied
	return store.setAppliedResult, store.setAppliedErr
}

func TestHandleAIInboxRulesAcceptsHundredMessagesAndPersistsSuggestions(t *testing.T) {
	modelServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"choices": []any{map[string]any{
				"message": map[string]string{
					"content": `{"suggestions":[{"title":"Offers","description":"Group recurring offers.","destination":"Promotions","conditions":["Sender is eBay"],"matchingIds":["offer-1","offer-2"]}]}`,
				},
			}},
		})
	}))
	defer modelServer.Close()

	originalUseSelfHosted := useSelfHostedAI
	originalURL := selfHostedAIChatCompletionsURL
	originalModel := selfHostedAIChatCompletionsModel
	useSelfHostedAI = "true"
	selfHostedAIChatCompletionsURL = modelServer.URL
	selfHostedAIChatCompletionsModel = "qwen-test"
	t.Cleanup(func() {
		useSelfHostedAI = originalUseSelfHosted
		selfHostedAIChatCompletionsURL = originalURL
		selfHostedAIChatCompletionsModel = originalModel
	})

	messages := make([]inboxAnalysisMessage, 100)
	for index := range messages {
		messages[index] = inboxAnalysisMessage{
			ID:      fmt.Sprintf("message-%d", index),
			Sender:  "eBay",
			Subject: "Offer",
			Body:    "Save now",
		}
	}
	messages[0].ID = "offer-1"
	messages[1].ID = "offer-2"
	requestBody, err := json.Marshal(map[string]any{"messages": messages})
	if err != nil {
		t.Fatal(err)
	}
	store := &fakeInboxAnalysisStore{}
	server := &Server{inboxAnalysisStore: store}
	request := httptest.NewRequest(http.MethodPost, "/api/ai/inbox-rules", bytes.NewReader(requestBody))
	request = request.WithContext(context.WithValue(request.Context(), "userId", "tenant-1"))
	response := httptest.NewRecorder()

	server.handleAIInboxRules(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	if store.saved.TenantID != "tenant-1" {
		t.Fatalf("saved tenant = %q", store.saved.TenantID)
	}
	if store.saved.Model != "qwen-test" || len(store.saved.Suggestions) != 1 {
		t.Fatalf("unexpected saved analysis: %#v", store.saved)
	}
	if store.saved.UpdatedAt.IsZero() {
		t.Fatal("saved analysis has no update timestamp")
	}
	if store.saved.ActiveRuleIDs == nil || len(store.saved.ActiveRuleIDs) != 0 {
		t.Fatalf("new analysis retained applied rules: %#v", store.saved.ActiveRuleIDs)
	}
}

func TestHandleGetAIInboxRulesReturnsSavedTenantSuggestions(t *testing.T) {
	store := &fakeInboxAnalysisStore{
		loaded: storedInboxAnalysis{
			TenantID: "tenant-1",
			Model:    "qwen",
			Suggestions: []inboxRuleSuggestion{{
				ID: "promotions", Title: "Offers", Description: "Recurring offers.",
				Destination: "Promotions", Conditions: []string{"Sender is eBay"},
				MatchingIDs: []string{"offer-1", "offer-2"},
			}},
			ActiveRuleIDs: []string{"promotions"},
		},
	}
	server := &Server{inboxAnalysisStore: store}
	request := httptest.NewRequest(http.MethodGet, "/api/ai/inbox-rules", nil)
	request = request.WithContext(context.WithValue(request.Context(), "userId", "tenant-1"))
	response := httptest.NewRecorder()

	server.handleGetAIInboxRules(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	var analysis inboxAnalysisResponse
	if err := json.NewDecoder(response.Body).Decode(&analysis); err != nil {
		t.Fatal(err)
	}
	if analysis.Model != "qwen" || len(analysis.Suggestions) != 1 ||
		!reflect.DeepEqual(analysis.ActiveRuleIDs, []string{"promotions"}) {
		t.Fatalf("unexpected response: %#v", analysis)
	}
}

func TestHandleSetAIInboxRuleAppliedPersistsTenantPreference(t *testing.T) {
	store := &fakeInboxAnalysisStore{
		setAppliedResult: storedInboxAnalysis{
			TenantID:      "tenant-1",
			Model:         "qwen",
			Suggestions:   []inboxRuleSuggestion{{ID: "promotions"}},
			ActiveRuleIDs: []string{"promotions"},
		},
	}
	server := &Server{inboxAnalysisStore: store}
	request := httptest.NewRequest(http.MethodPut, "/api/ai/inbox-rules", strings.NewReader(
		`{"ruleId":"promotions","applied":true}`,
	))
	request = request.WithContext(context.WithValue(request.Context(), "userId", "tenant-1"))
	response := httptest.NewRecorder()

	server.handleSetAIInboxRuleApplied(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	if store.setTenantID != "tenant-1" || store.setRuleID != "promotions" || !store.setApplied {
		t.Fatalf("saved preference = tenant %q, rule %q, applied %t", store.setTenantID, store.setRuleID, store.setApplied)
	}
	var analysis inboxAnalysisResponse
	if err := json.NewDecoder(response.Body).Decode(&analysis); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(analysis.ActiveRuleIDs, []string{"promotions"}) {
		t.Fatalf("active rule IDs = %#v", analysis.ActiveRuleIDs)
	}
}

func TestHandleGetAIInboxRulesReturnsEmptyAnalysisWhenNoneSaved(t *testing.T) {
	server := &Server{inboxAnalysisStore: &fakeInboxAnalysisStore{loadErr: mongo.ErrNoDocuments}}
	request := httptest.NewRequest(http.MethodGet, "/api/ai/inbox-rules", nil)
	request = request.WithContext(context.WithValue(request.Context(), "userId", "tenant-1"))
	response := httptest.NewRecorder()

	server.handleGetAIInboxRules(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), `"suggestions":[]`) {
		t.Fatalf("expected empty suggestions, body = %s", response.Body.String())
	}
}

func TestHandleGetAIInboxRulesRejectsMissingTenant(t *testing.T) {
	server := &Server{inboxAnalysisStore: &fakeInboxAnalysisStore{loadErr: errors.New("must not load")}}
	response := httptest.NewRecorder()
	server.handleGetAIInboxRules(response, httptest.NewRequest(http.MethodGet, "/api/ai/inbox-rules", nil))
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusUnauthorized)
	}
}
