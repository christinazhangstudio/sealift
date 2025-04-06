package api

import "github.tesla.com/chrzhang/sealift/ebay"

// JSON responses sealift provides.
type Error struct {
	Message string `json:"message"`
}

type UserSummary struct {
	User    string                           `json:"user"`
	Summary *ebay.TransactionSummaryResponse `json:"summary"`
}
