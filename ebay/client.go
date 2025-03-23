package ebay

import (
	"context"
	"fmt"
	"net/http"
)

// EbayClient interacts with eBay APIs.
type Client struct {
	// Client is the HTTP client used to make requests to the eBay Finding API.
	*http.Client

	// AppID is the eBay application ID.
	// https://developer.ebay.com/api-docs/static/gs_create-the-ebay-api-keysets.html.
	AppID string

	// URL specifies the API endpoint.
	//
	// URL defaults to the eBay Production API Gateway URI, but can be changed to
	// the eBay Sandbox endpoint or localhost for testing purposes.
	//URL string
}

// Takes an operation e.g. transaction_summary
// as well as optional params e.g. filter=transactionStatus:{PAYOUT}
// A list of APIs and their rate limits:
// https://developer.ebay.com/develop/get-started/api-call-limits
func (c *Client) get(
	ctx context.Context,
	url string, // embed struct?
	op string,
	params map[string]string,
) error {
	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodGet,
		url,
		nil,
	)

	if err != nil {
		return fmt.Errorf("failed to make new request; %w", err)
	}

	q := req.URL.Query()
	q.Set("Operation-Name", op)
}
