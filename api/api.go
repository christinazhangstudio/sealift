package api

import "github.tesla.com/chrzhang/sealift/ebay"

// JSON responses sealift provides.
type Error struct {
	Message string `json:"message"`
}

type Users struct {
	Users []string `json:"users"`
}

type UserSummary struct {
	User    string                           `json:"user"`
	Summary *ebay.TransactionSummaryResponse `json:"summary"`
}

type UserPayouts struct {
	User    string                `json:"user"`
	Payouts *ebay.PayoutsResponse `json:"payouts"`
}

type UserListings struct {
	User     string                   `json:"user"`
	Listings *ebay.SellerListResponse `json:"listings"`
}

type UserAccount struct {
	User    string                `json:"user"`
	Account *ebay.AccountResponse `json:"account"`
}
