package ebay

import (
	"context"
	"fmt"
	"net/http"

	"github.tesla.com/chrzhang/sealift/auth"
	"go.mongodb.org/mongo-driver/mongo"
)

// Client interacts with eBay APIs.
type Client struct {
	// Client is the HTTP client that makes requests to eBay APIs.
	*http.Client

	// DB client
	// would be a singleton (only bc there are no tests and this is thread safe :9)
	// but cyclic dependency (and db pkg not needed)
	DB *mongo.Collection

	// URL specifies the APIz endpoint.
	// https://apiz.ebay.com for prod
	// https://api.sandbox.ebay.com for sandbox
	URL string

	// TradURL specifies the legacy API endpoint that some APIs are on.
	// https://api.ebay.com/ws/api.dll for prod
	// https://api.sandbox.ebay.com/ws/api.dll for sandbox
	TradURL string

	// Notification specifies the URL that hosts the notification API.
	// apiz.ebay.com doesn't work here!
	// https://api.ebay.com for production
	// https://api.sandbox.ebay.com for sandbox
	NotificationURL string

	// Auth contains auth-related functions.
	// Used for loading in the respective user
	// token at API request time.
	Auth *auth.Client
}

// Takes an operation e.g. transaction_summary
// as well as optional params e.g. filter=transactionStatus:{PAYOUT}
// A list of APIs and their rate limits:
// https://developer.ebay.com/develop/get-started/api-call-limits
func (c *Client) request(
	ctx context.Context,
	api string,
	op string,
	params map[string]string,
) (*http.Request, error) {
	token, err := c.Auth.GetToken(ctx, ctx.Value(auth.USER).(string))
	if err != nil {
		return nil, fmt.Errorf("failed to get or refresh user token; %w", err)
	}

	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodGet,
		c.URL+api+op,
		nil,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to make new request; %w", err)
	}

	q := req.URL.Query()

	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	for k, v := range params {
		if v != "" {
			q.Set(k, v)
		}
	}

	req.URL.RawQuery = q.Encode()

	return req, nil
}
