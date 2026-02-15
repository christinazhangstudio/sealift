package ebay

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.tesla.com/chrzhang/sealift/auth"
)

const (
	notificationAPI = "/commerce/notification/v1/"
)

type TopicResponse struct {
	TopicID             string          `json:"topicId"`
	Description         string          `json:"description"`
	Status              string          `json:"status"`
	Context             string          `json:"context"`
	Scope               string          `json:"scope"`
	AuthorizationScopes []string        `json:"authorizationScopes,omitempty"`
	SupportedPayloads   []PayloadDetail `json:"supportedPayloads,omitempty"`
	Filterable          bool            `json:"filterable"`
}

type PayloadDetail struct {
	Format           []string `json:"format"`
	SchemaVersion    string   `json:"schemaVersion"`
	DeliveryProtocol string   `json:"deliveryProtocol"`
	Deprecated       bool     `json:"deprecated"`
}

// DestinationResponse represents a notification destination endpoint.
type DestinationResponse struct {
	DestinationID string `json:"destinationId"`
	URL           string `json:"url"`
	Status        string `json:"status"`
	CreatedDate   string `json:"createdDate,omitempty"`
	UpdatedDate   string `json:"updatedDate,omitempty"`
}

// SubscriptionResponse represents a notification subscription.
type SubscriptionResponse struct {
	SubscriptionID string `json:"subscriptionId"`
	TopicID        string `json:"topicId"`
	DestinationID  string `json:"destinationId"`
	Status         string `json:"status"` // ENABLED, DISABLED
	CreatedDate    string `json:"createdDate,omitempty"`
	UpdatedDate    string `json:"updatedDate,omitempty"`
	FilterID       string `json:"filterId,omitempty"`
}

// GetTopic retrieves details for a specified notification topic.
// topicID is the unique identifier of the notification topic (e.g., "MARKETPLACE_ACCOUNT_DELETION")
// API docs: https://developer.ebay.com/api-docs/commerce/notification/resources/topic/methods/getTopic
func (c *Client) GetTopic(ctx context.Context, topicID string) (*TopicResponse, error) {
	token, err := c.Auth.GetApplicationToken(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get or refresh user token; %w", err)
	}

	req, err := http.NewRequestWithContext(
		ctx, http.MethodGet,
		c.NotificationURL+notificationAPI+"topic/"+topicID,
		nil,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to execute request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		var errResp map[string]interface{}
		if err := json.NewDecoder(resp.Body).Decode(&errResp); err != nil {
			return nil, fmt.Errorf("notification API returned status %d: %w", resp.StatusCode, err)
		}
		return nil, fmt.Errorf("notification API returned status %d: %v", resp.StatusCode, errResp)
	}

	var topic TopicResponse
	if err := json.NewDecoder(resp.Body).Decode(&topic); err != nil {
		return nil, fmt.Errorf("failed to parse topic response: %w", err)
	}

	return &topic, nil
}

// GetTopics retrieves details for all available notification topics.
// API docs: https://developer.ebay.com/api-docs/commerce/notification/resources/topic/methods/getTopics
func (c *Client) GetTopics(ctx context.Context) ([]TopicResponse, error) {
	token, err := c.Auth.GetApplicationToken(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get or refresh user token; %w", err)
	}

	req, err := http.NewRequestWithContext(
		ctx, http.MethodGet,
		c.NotificationURL+notificationAPI+"topic",
		nil,
	)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to execute request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		var errResp map[string]interface{}
		if err := json.NewDecoder(resp.Body).Decode(&errResp); err != nil {
			return nil, fmt.Errorf("notification API returned status %d: %w", resp.StatusCode, err)
		}
		return nil, fmt.Errorf("notification API returned status %d: %v", resp.StatusCode, errResp)
	}

	var topicsResp struct {
		Topics []TopicResponse `json:"topics"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&topicsResp); err != nil {
		return nil, fmt.Errorf("failed to parse topics response: %w", err)
	}

	return topicsResp.Topics, nil
}

// CreateDestination creates a new notification destination endpoint.
// This endpoint will receive a challenge code from eBay that must be respond to
// with a hashed value to verify ownership (see /sealift-webhook).
// https://developer.ebay.com/api-docs/commerce/notification/resources/destination/methods/createDestination
func (c *Client) CreateDestination(
	ctx context.Context,
	endpoint string,
	verificationToken string,
) error {
	token, err := c.Auth.GetApplicationToken(ctx)
	if err != nil {
		return fmt.Errorf("failed to get or refresh user token; %w", err)
	}

	reqBody := map[string]interface{}{
		"name":   ctx.Value(auth.USER).(string), // may not be necessary
		"status": "ENABLED",
		"deliveryConfig": map[string]interface{}{
			"endpoint":          endpoint,
			"verificationToken": verificationToken,
		},
	}

	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return fmt.Errorf("failed to marshal request body: %w", err)
	}

	req, err := http.NewRequestWithContext(
		ctx, http.MethodPost,
		c.NotificationURL+notificationAPI+"destination",
		bytes.NewReader(bodyBytes),
	)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.Do(req)
	if err != nil {
		return fmt.Errorf("failed to execute request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("notification API returned status %d: %s", resp.StatusCode, string(body))
	}

	// only Location header is returned, no body
	if loc := resp.Header.Get("Location"); loc != "" {
		fmt.Println("CreateDestination returned location header:", loc)
	}

	return nil
}

// GetDestinations retrieves all notification destinations.
func (c *Client) GetDestinations(ctx context.Context) ([]DestinationResponse, error) {
	token, err := c.Auth.GetApplicationToken(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get or refresh user token; %w", err)
	}

	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodGet,
		c.NotificationURL+notificationAPI+"destination",
		nil,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to execute request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("notification API returned status %d: %s", resp.StatusCode, string(body))
	}

	var destResp struct {
		Destinations []DestinationResponse `json:"destinations"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&destResp); err != nil {
		return nil, fmt.Errorf("failed to parse destinations response: %w", err)
	}

	return destResp.Destinations, nil
}

// CreateUserSubscription creates a subscription to a topic.
// topicID must be from an available topic (e.g., "MARKETPLACE_ACCOUNT_DELETION").
// https://developer.ebay.com/api-docs/commerce/notification/resources/subscription/methods/createSubscription
func (c *Client) CreateUserSubscription(
	ctx context.Context,
	topicID string,
	destinationID string,
) (*SubscriptionResponse, error) {
	// Use Application token for Application-level notifications,
	// and User token for User-level notifications.
	token, err := c.Auth.GetToken(ctx, ctx.Value(auth.USER).(string))
	if err != nil {
		return nil, fmt.Errorf("failed to get or refresh user token; %w", err)
	}

	type payload struct {
		DeliveryProtocol string `json:"deliveryProtocol"`
		Format           string `json:"format"`
		SchemaVersion    string `json:"schemaVersion"`
	}

	reqBody := struct {
		DestinationID string  `json:"destinationId"`
		TopicID       string  `json:"topicId"`
		Status        string  `json:"status"`
		Payload       payload `json:"payload"`
	}{
		DestinationID: destinationID,
		TopicID:       topicID,
		Status:        "ENABLED",
		Payload: payload{
			// Looks like all topics follow these specs,
			// so just hardcode.
			DeliveryProtocol: "HTTPS",
			Format:           "JSON",
			SchemaVersion:    "1.0",
		},
	}

	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request body: %w", err)
	}

	req, err := http.NewRequestWithContext(
		ctx, http.MethodPost,
		c.NotificationURL+notificationAPI+"subscription",
		bytes.NewReader(bodyBytes),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to execute request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("notification API returned status %d: %s", resp.StatusCode, string(body))
	}

	var sub SubscriptionResponse
	if err := json.NewDecoder(resp.Body).Decode(&sub); err != nil {
		return nil, fmt.Errorf("failed to parse subscription response: %w", err)
	}

	return &sub, nil
}

// GetSubscriptions retrieves all subscriptions for a user.
// API docs: https://developer.ebay.com/api-docs/commerce/notification/resources/subscription/methods/getSubscriptions
func (c *Client) GetUserSubscriptions(ctx context.Context) ([]SubscriptionResponse, error) {
	// Use Application token for Application-level notifications,
	// and User token for User-level notifications.
	token, err := c.Auth.GetToken(ctx, ctx.Value(auth.USER).(string))
	if err != nil {
		return nil, fmt.Errorf("failed to get or refresh user token; %w", err)
	}

	req, err := http.NewRequestWithContext(
		ctx, http.MethodGet,
		c.NotificationURL+notificationAPI+"subscription",
		nil,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Set required headers
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	// Execute the request
	resp, err := c.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to execute request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("notification API returned status %d: %s", resp.StatusCode, string(body))
	}

	var subsResp struct {
		Subscriptions []SubscriptionResponse `json:"subscriptions"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&subsResp); err != nil {
		return nil, fmt.Errorf("failed to parse subscriptions response: %w", err)
	}

	return subsResp.Subscriptions, nil
}

// EnableUserSubscriptions enables all subscriptions for a user.
// It retrieves all subscriptions and calls the /enable endpoint for each.
// Returns the list of enabled subscriptions.
func (c *Client) EnableUserSubscriptions(ctx context.Context) ([]SubscriptionResponse, error) {
	// 1. Get all subscriptions
	subs, err := c.GetUserSubscriptions(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get user subscriptions: %w", err)
	}

	// 2. Get User-level auth token for the enable calls
	token, err := c.Auth.GetToken(ctx, ctx.Value(auth.USER).(string))
	if err != nil {
		return nil, fmt.Errorf("failed to get user token: %w", err)
	}

	// 3. Enable each subscription
	for _, sub := range subs {
		url := fmt.Sprintf("%s%ssubscription/%s/enable", c.NotificationURL, notificationAPI, sub.SubscriptionID)
		req, err := http.NewRequestWithContext(
			ctx,
			http.MethodPost,
			url,
			nil,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to create enable request for subscription %s: %w", sub.SubscriptionID, err)
		}

		req.Header.Set("Authorization", "Bearer "+token)

		resp, err := c.Do(req)
		if err != nil {
			return nil, fmt.Errorf("failed to enable subscription %s: %w", sub.SubscriptionID, err)
		}

		if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			return nil, fmt.Errorf("failed to enable subscription %s (status %d): %s", sub.SubscriptionID, resp.StatusCode, string(body))
		}
		resp.Body.Close()
	}

	return subs, nil
}

// // DisableSubscription disables a subscription to stop receiving notifications.
// // API docs: https://developer.ebay.com/api-docs/commerce/notification/resources/subscription/methods/disableSubscription
// func (c *Client) DisableSubscription(ctx context.Context, subscriptionID string) error {
// 	if subscriptionID == "" {
// 		return fmt.Errorf("subscription ID cannot be empty")
// 	}

// 	// Build the request URL
// 	endpoint := c.buildEndpoint("subscription", subscriptionID, "disable")

// 	// Create the request
// 	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, nil)
// 	if err != nil {
// 		return fmt.Errorf("failed to create request: %w", err)
// 	}

// 	// Set required headers
// 	req.Header.Set("Authorization", "Bearer "+c.AccessToken)
// 	req.Header.Set("Content-Type", "application/json")

// 	// Execute the request
// 	resp, err := c.Do(req)
// 	if err != nil {
// 		return fmt.Errorf("failed to execute request: %w", err)
// 	}
// 	defer resp.Body.Close()

// 	// Handle error responses
// 	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
// 		body, _ := io.ReadAll(resp.Body)
// 		return fmt.Errorf("notification API returned status %d: %s", resp.StatusCode, string(body))
// 	}

// 	return nil
// }
