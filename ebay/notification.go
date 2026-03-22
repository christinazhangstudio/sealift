package ebay

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"path"

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

type Destination struct {
	DestinationID  string `json:"destinationId"`
	DeliveryConfig struct {
		Endpoint string `json:"endpoint"`
		// omit verificationToken
		// VerificationToken string `json:"verificationToken"`
	} `json:"deliveryConfig"`
	Name   string `json:"name"`   // created to match the "user"
	Status string `json:"status"` // ENABLED, DISABLED, MARKED_DOWN
}

type SubscriptionResponse struct {
	SubscriptionID string `json:"subscriptionId"`
	TopicID        string `json:"topicId"`
	DestinationID  string `json:"destinationId"`
	Status         string `json:"status"` // ENABLED, DISABLED
	CreatedDate    string `json:"createdDate,omitempty"`
	UpdatedDate    string `json:"updatedDate,omitempty"`
	FilterID       string `json:"filterId,omitempty"`
}

type NotificationPayload struct {
	Metadata struct {
		Topic         string `json:"topic"`
		SchemaVersion string `json:"schemaVersion"`
		Deprecated    bool   `json:"deprecated"`
	} `json:"metadata"`
	Notification struct {
		NotificationID string `json:"notificationId"`
		EventDate      string `json:"eventDate"`
		PublishDate    string `json:"publishDate"`
		PublishAttempt int    `json:"publishAttempt"`
		Data           struct {
			SenderUserName string `json:"senderUserName"`
			MessageBody    string `json:"messageBody"`
			Subject        string `json:"subject"`
		} `json:"data"`
	} `json:"notification"`
}

type PublicKeyResponse struct {
	Algorithm string `json:"algorithm"`
	Digest    string `json:"digest"`
	Key       string `json:"key"`
}

// GetTopic retrieves details for a specified notification topic.
// topicID is the unique identifier of the notification topic (e.g., "MARKETPLACE_ACCOUNT_DELETION")
// API docs: https://developer.ebay.com/api-docs/commerce/notification/resources/topic/methods/getTopic
func (c *Client) GetTopic(ctx context.Context, topicID string) (*TopicResponse, error) {
	token, err := c.Auth.GetApplicationToken(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get or refresh user token; %w", err)
	}

	url := c.NotificationURL + notificationAPI + "topic/" + topicID
	var topic TopicResponse
	if err := c.doJSON(ctx, http.MethodGet, url, token, nil, &topic); err != nil {
		return nil, err
	}

	return &topic, nil
}

// GetPublicKey retrieves the public key associated with a given public_key_id.
// It is used to verify the signature of incoming webhook notifications.
// API docs: https://developer.ebay.com/api-docs/commerce/notification/resources/public_key/methods/getPublicKey
func (c *Client) GetPublicKey(ctx context.Context, publicKeyID string) (*PublicKeyResponse, error) {
	token, err := c.Auth.GetApplicationToken(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get or refresh application token; %w", err)
	}

	url := c.NotificationURL + notificationAPI + "public_key/" + publicKeyID
	var pubKeyResp PublicKeyResponse
	if err := c.doJSON(ctx, http.MethodGet, url, token, nil, &pubKeyResp); err != nil {
		return nil, err
	}

	return &pubKeyResp, nil
}

// GetTopics retrieves details for all available notification topics.
// API docs: https://developer.ebay.com/api-docs/commerce/notification/resources/topic/methods/getTopics
func (c *Client) GetTopics(ctx context.Context) ([]TopicResponse, error) {
	token, err := c.Auth.GetApplicationToken(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get or refresh user token; %w", err)
	}

	url := c.NotificationURL + notificationAPI + "topic"
	var topicsResp struct {
		Topics []TopicResponse `json:"topics"`
	}
	if err := c.doJSON(ctx, http.MethodGet, url, token, nil, &topicsResp); err != nil {
		return nil, err
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
) (string, error) {
	token, err := c.Auth.GetApplicationToken(ctx)
	if err != nil {
		return "", fmt.Errorf("failed to get application token; %w", err)
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
		return "", fmt.Errorf("failed to marshal request body; %w", err)
	}

	req, err := http.NewRequestWithContext(
		ctx, http.MethodPost,
		c.NotificationURL+notificationAPI+"destination",
		bytes.NewReader(bodyBytes),
	)
	if err != nil {
		return "", fmt.Errorf("failed to create request; %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to execute request; %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("notification API returned status %d: %s", resp.StatusCode, string(body))
	}

	// only Location header is returned, no body
	loc := resp.Header.Get("Location")
	if loc == "" {
		return "", fmt.Errorf("notification API returned no location header")
	}

	slog.Info("created notification destination", "loc", loc)

	// loc returned in the format:
	// https://api.ebay.com/commerce/notification/v1/destination/{destinationId}
	destinationID := path.Base(loc)

	return destinationID, nil
}

// DisableDestination disables a notification destination endpoint by updating its status to DISABLED.
// https://developer.ebay.com/api-docs/commerce/notification/resources/destination/methods/updateDestination
func (c *Client) DisableDestination(
	ctx context.Context,
	destinationID string,
	endpoint string,
	verificationToken string,
) error {
	token, err := c.Auth.GetApplicationToken(ctx)
	if err != nil {
		return fmt.Errorf("failed to get application token; %w", err)
	}

	reqBody := map[string]interface{}{
		"status": "DISABLED",
		"deliveryConfig": map[string]interface{}{
			"endpoint":          endpoint,
			"verificationToken": verificationToken,
		},
	}

	url := c.NotificationURL + notificationAPI + "destination/" + destinationID
	if err := c.doJSON(ctx, http.MethodPut, url, token, reqBody, nil); err != nil {
		return err
	}

	slog.Info("disabled notification destination", "destinationId", destinationID)
	return nil
}

// DeleteDestination deletes a notification destination.
// https://developer.ebay.com/api-docs/commerce/notification/resources/destination/methods/deleteDestination
func (c *Client) DeleteDestination(ctx context.Context, destinationID string) error {
	token, err := c.Auth.GetApplicationToken(ctx)
	if err != nil {
		return fmt.Errorf("failed to get application token; %w", err)
	}

	url := c.NotificationURL + notificationAPI + "destination/" + destinationID
	return c.doJSON(ctx, http.MethodDelete, url, token, nil, nil)
}

type DestinationsResponse struct {
	Destinations []Destination `json:"destinations"`
	Href         string        `json:"href"`
	Limit        int           `json:"limit"`
	Next         string        `json:"next"`
	Total        int           `json:"total"`
}

// GetDestinations retrieves all notification destinations.
func (c *Client) GetDestinations(ctx context.Context, pageSize int) (*DestinationsResponse, error) {
	token, err := c.Auth.GetApplicationToken(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get or refresh user token; %w", err)
	}

	url := fmt.Sprintf("%s%sdestination?limit=%d", c.NotificationURL, notificationAPI, pageSize)
	var destResp DestinationsResponse
	
	if err := c.doJSON(ctx, http.MethodGet, url, token, nil, &destResp); err != nil {
		return nil, err
	}

	return &destResp, nil
}

// CreateUserSubscription creates a subscription to a topic.
// topicID must be from an available topic (e.g., "MARKETPLACE_ACCOUNT_DELETION").
// https://developer.ebay.com/api-docs/commerce/notification/resources/subscription/methods/createSubscription
func (c *Client) CreateUserSubscription(
	ctx context.Context,
	topicID string,
	destinationID string,
) (string, error) {
	// Use Application token for Application-level notifications,
	// and User token for User-level notifications.
	user := ctx.Value(auth.USER).(string)
	if destinationID == "" {
		return "", fmt.Errorf("destination ID is required for user subscription")
	}

	token, err := c.Auth.GetToken(ctx, user)
	if err != nil {
		return "", fmt.Errorf("failed to get or refresh user token; %w", err)
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
		return "", fmt.Errorf("failed to marshal request body; %w", err)
	}

	req, err := http.NewRequestWithContext(
		ctx, http.MethodPost,
		c.NotificationURL+notificationAPI+"subscription",
		bytes.NewReader(bodyBytes),
	)
	if err != nil {
		return "", fmt.Errorf("failed to create request; %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to execute request; %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("notification API returned status %d: %s", resp.StatusCode, string(body))
	}

	// only Location header is returned, no body
	loc := resp.Header.Get("Location")
	if loc == "" {
		return "", fmt.Errorf("notification API returned no location header")
	}

	slog.Info("created notification subscription", "loc", loc)

	// loc returned in the format:
	// https://api.ebay.com/commerce/notification/v1/subscription/{subscriptionId}
	subscriptionID := path.Base(loc)
	return subscriptionID, nil
}

// GetSubscriptions retrieves all subscriptions for a user.
// API docs: https://developer.ebay.com/api-docs/commerce/notification/resources/subscription/methods/getSubscriptions
func (c *Client) GetUserSubscriptions(ctx context.Context) ([]SubscriptionResponse, error) {
	token, err := c.Auth.GetToken(ctx, ctx.Value(auth.USER).(string))
	if err != nil {
		return nil, fmt.Errorf("failed to get or refresh user token; %w", err)
	}

	url := c.NotificationURL + notificationAPI + "subscription"
	var subsResp struct {
		Subscriptions []SubscriptionResponse `json:"subscriptions"`
	}

	if err := c.doJSON(ctx, http.MethodGet, url, token, nil, &subsResp); err != nil {
		return nil, err
	}

	return subsResp.Subscriptions, nil
}

// DeleteUserSubscription deletes a user subscription.
func (c *Client) DeleteUserSubscription(ctx context.Context, subscriptionID string) error {
	user := ctx.Value(auth.USER).(string)
	token, err := c.Auth.GetToken(ctx, user)
	if err != nil {
		return fmt.Errorf("failed to get or refresh user token; %w", err)
	}

	url := c.NotificationURL + notificationAPI + "subscription/" + subscriptionID
	return c.doJSON(ctx, http.MethodDelete, url, token, nil, nil)
}

// DeleteAllUserSubscriptions deletes all subscriptions for a user.
func (c *Client) DeleteAllUserSubscriptions(ctx context.Context) error {
	subs, err := c.GetUserSubscriptions(ctx)
	if err != nil {
		return fmt.Errorf("failed to get user subscriptions; %w", err)
	}

	for _, sub := range subs {
		if err := c.DeleteUserSubscription(ctx, sub.SubscriptionID); err != nil {
			return fmt.Errorf("failed to delete subscription; %w", err)
		}
	}
	return nil
}

// EnableUserSubscriptions enables all subscriptions for a user.
// It retrieves all subscriptions and calls the /enable endpoint for each.
// Returns the list of enabled subscriptions.
func (c *Client) EnableUserSubscriptions(ctx context.Context) ([]SubscriptionResponse, error) {
	subs, err := c.GetUserSubscriptions(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get user subscriptions; %w", err)
	}

	token, err := c.Auth.GetToken(ctx, ctx.Value(auth.USER).(string))
	if err != nil {
		return nil, fmt.Errorf("failed to get user token; %w", err)
	}

	for _, sub := range subs {
		url := fmt.Sprintf("%s%ssubscription/%s/enable", c.NotificationURL, notificationAPI, sub.SubscriptionID)
		if err := c.doJSON(ctx, http.MethodPost, url, token, nil, nil); err != nil {
			return nil, fmt.Errorf("failed to enable subscription %s; %w", sub.SubscriptionID, err)
		}
	}

	return subs, nil
}

// TestUserSubscription triggers a test notification payload for a given subscription.
// https://developer.ebay.com/api-docs/commerce/notification/resources/subscription/methods/testSubscription
func (c *Client) TestUserSubscription(ctx context.Context, subscriptionID string) error {
	user := ctx.Value(auth.USER).(string)
	token, err := c.Auth.GetToken(ctx, user)
	if err != nil {
		return fmt.Errorf("failed to get or refresh user token: %w", err)
	}

	url := c.NotificationURL + notificationAPI + "subscription/" + subscriptionID + "/test"
	return c.doJSON(ctx, http.MethodPost, url, token, nil, nil)
}
