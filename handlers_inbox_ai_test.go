package main

import (
	"reflect"
	"testing"
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
