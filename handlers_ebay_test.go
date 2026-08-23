package main

import (
	"strings"
	"testing"
	"time"
)

func TestParseSellerListRangePreservesLocalDayBoundaries(t *testing.T) {
	start, end, err := parseSellerListRange(
		"2026-08-23T05:00:00.000Z",
		"2026-08-24T04:59:59.999Z",
	)
	if err != nil {
		t.Fatal(err)
	}
	if got := start.Format(time.RFC3339Nano); got != "2026-08-23T05:00:00Z" {
		t.Fatalf("start %q", got)
	}
	if got := end.Format(time.RFC3339Nano); got != "2026-08-24T04:59:59.999Z" {
		t.Fatalf("end %q", got)
	}
}

func TestParseSellerListRangeRejectsDateOnlyCutoff(t *testing.T) {
	_, _, err := parseSellerListRange("2026-08-23", "2026-08-24")
	if err == nil || !strings.Contains(err.Error(), "RFC3339") {
		t.Fatalf("expected RFC3339 error, got %v", err)
	}
}

func TestParseSellerListRangeRejectsMoreThan120Days(t *testing.T) {
	_, _, err := parseSellerListRange(
		"2026-01-01T00:00:00Z",
		"2026-05-01T00:00:00.001Z",
	)
	if err == nil || !strings.Contains(err.Error(), "120 days") {
		t.Fatalf("expected range error, got %v", err)
	}
}
