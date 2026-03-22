package ebay

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"

	"github.tesla.com/chrzhang/sealift/auth"
)

// Client interacts with eBay APIs.
type Client struct {
	// Client is the HTTP client that makes requests to eBay APIs.
	*http.Client

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

// doJSON handles the full lifecycle of a REST JSON API request.
// It creates the request, sets common headers, executes it, checks for errors, and unmarshals the response.
func (c *Client) doJSON(
	ctx context.Context,
	method string,
	url string,
	token string,
	reqBody interface{},
	respBody interface{},
) error {
	var bodyReader io.Reader
	if reqBody != nil {
		bodyBytes, err := json.Marshal(reqBody)
		if err != nil {
			return fmt.Errorf("failed to marshal request body; %w", err)
		}
		bodyReader = bytes.NewReader(bodyBytes)
	}

	req, err := http.NewRequestWithContext(ctx, method, url, bodyReader)
	if err != nil {
		return fmt.Errorf("failed to create request; %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	if method == http.MethodGet {
		req.Header.Set("Accept", "application/json")
	}

	resp, err := c.Do(req)
	if err != nil {
		return fmt.Errorf("failed to execute request; %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("API failed with status %d: %s", resp.StatusCode, string(b))
	}

	if respBody != nil && resp.StatusCode != http.StatusNoContent {
		if err := json.NewDecoder(resp.Body).Decode(respBody); err != nil {
			return fmt.Errorf("failed to parse response; %w", err)
		}
	}

	return nil
}

// doXML handles the full lifecycle of a legacy XML Trading API request.
// It marshals the XML, sets required Trading API headers, executes it, and unmarshals the response.
// Caller is responsible for verifying the Ack status in the response struct.
func (c *Client) doXML(
	ctx context.Context,
	callName string,
	compatLevel string,
	token string,
	reqBody interface{},
	respBody interface{},
) error {
	xmlData, err := xml.MarshalIndent(reqBody, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal request XML; %w", err)
	}
	xmlPayload := []byte(`<?xml version="1.0" encoding="utf-8"?>` + string(xmlData))

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.TradURL, bytes.NewBuffer(xmlPayload))
	if err != nil {
		return fmt.Errorf("failed to create request; %w", err)
	}

	req.Header.Set("Content-Type", "text/xml")
	req.Header.Set("X-EBAY-API-COMPATIBILITY-LEVEL", compatLevel)
	req.Header.Set("X-EBAY-API-CALL-NAME", callName)
	req.Header.Set("X-EBAY-API-SITEID", "0") // US site
	req.Header.Set("X-EBAY-API-DEV-NAME", c.Auth.DevID)
	req.Header.Set("X-EBAY-API-APP-NAME", c.Auth.ClientID)
	req.Header.Set("X-EBAY-API-CERT-NAME", c.Auth.ClientSecret)

	resp, err := c.Do(req)
	if err != nil {
		return fmt.Errorf("failed to execute request; %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response body; %w", err)
	}

	if err := xml.Unmarshal(body, respBody); err != nil {
		return fmt.Errorf("failed to unmarshal response XML (status %d): %w; body: %s", resp.StatusCode, err, string(body))
	}

	return nil
}
