package main

import (
	"testing"

	"github.tesla.com/chrzhang/sealift/ebay"
)

func TestTopicAvailability(t *testing.T) {
	const granted = "base-scope message-scope"
	topics := []ebay.TopicResponse{
		{TopicID: "user-ready", Scope: "USER", Status: "ENABLED", AuthorizationScopes: []string{"message-scope"}},
		{TopicID: "application", Scope: "APPLICATION", Status: "ENABLED"},
		{TopicID: "disabled", Scope: "USER", Status: "DISABLED"},
		{TopicID: "missing-scope", Scope: "USER", Status: "ENABLED", AuthorizationScopes: []string{"partner-scope"}},
	}

	got := topicAvailability(topics, granted)
	if len(got) != len(topics) {
		t.Fatalf("expected every topic to remain visible: %#v", got)
	}
	want := []struct {
		canSubscribe bool
		availability string
	}{
		{true, "available"},
		{false, "application"},
		{false, "unavailable"},
		{false, "not_authorized"},
	}
	for i, expected := range want {
		if got[i].CanSubscribe != expected.canSubscribe || got[i].Availability != expected.availability {
			t.Fatalf("topic %s: got canSubscribe=%v availability=%q", got[i].TopicID, got[i].CanSubscribe, got[i].Availability)
		}
	}
}

func TestTopicAvailabilityWithoutConfiguredScopes(t *testing.T) {
	topics := []ebay.TopicResponse{
		{TopicID: "user", Scope: "user", Status: "enabled", AuthorizationScopes: []string{"unknown"}},
	}

	got := topicAvailability(topics, "")
	if len(got) != 1 || got[0].TopicID != "user" || !got[0].CanSubscribe {
		t.Fatalf("expected eBay to decide authorization when scopes are undeclared: %#v", got)
	}
}
