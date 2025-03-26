package ebay

import (
	"context"
	"fmt"
	"net/http"

	"github.tesla.com/chrzhang/sealift/auth"
)

// Client interacts with eBay APIs.
type Client struct {
	// Client is the HTTP client that makes requests to eBay APIs.
	*http.Client

	// URL specifies the API endpoint.
	// https://apiz.ebay.com for prod
	// https://api.sandbox.ebay.com for sandbox
	URL string

	// Auth contains auth-related functions.
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
	token, err := c.Auth.GetToken(ctx.Value(auth.USER).(string))
	if err != nil {
		return nil, fmt.Errorf("failed to get or refresh user token; %w", err)
	}

	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodGet,
		c.URL+api,
		nil,
	)

	if err != nil {
		return nil, fmt.Errorf("failed to make new request; %w", err)
	}

	q := req.URL.Query()
	q.Set("Operation-Name", op)
	// q.Set("Service-Version", "1.0.0")
	// q.Set("Security-AppName", c.AppID)
	// q.Set("Response-Data-Format", "JSON")
	// q.Set("REST-Payload", "")

	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	for k, v := range params {
		if v != "" {
			q.Set(k, v)
		}
	}

	return req, err
}
