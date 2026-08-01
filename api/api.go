package api

import (
	"github.tesla.com/chrzhang/sealift/auth"

	"github.tesla.com/chrzhang/sealift/ebay"
)

// JSON responses sealift provides.
type Error struct {
	Message string `json:"message"`
}

type Users struct {
	Users []string `json:"users"`
	// Sellers carries the same sellers with their connection health. Users is
	// kept for existing callers that only need the names.
	Sellers []auth.SellerStatus `json:"sellers"`
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

// Notification API responses
type NotificationTopic struct {
	Topic *ebay.TopicResponse `json:"topic"`
}

type NotificationTopicSummary struct {
	ebay.TopicResponse
	CanSubscribe bool   `json:"canSubscribe"`
	Availability string `json:"availability"`
}

type NotificationTopics struct {
	Topics []NotificationTopicSummary `json:"topics"`
}

// ebay.DestinationsResponse is App-level, but we want
// user-ordered destinations, so we'll transform (and basically invert)
// the response since this suits our app.
// This breaks for user-level-pagination,
// but this is ok enough given the way this eBay API is set up,
// and this endpoint is largely for debugging.
type NotificationDestinations struct {
	UserDestinations []UserDestination `json:"userDestinations"`
	Next             string            `json:"next"`
	Total            int               `json:"total"`
}

type UserDestination struct {
	User         string             `json:"user"`
	Destinations []ebay.Destination `json:"destinations"`
}

type CreateUserSubscription struct {
	SubscriptionID string `json:"subscriptionID"`
}

type NotificationSubscriptions struct {
	Subscriptions []ebay.SubscriptionResponse `json:"subscriptions"`
}
