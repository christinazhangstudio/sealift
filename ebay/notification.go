package ebay

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"path"
	"strconv"
	"time"

	"github.tesla.com/chrzhang/sealift/auth"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
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
		return nil, fmt.Errorf("failed to create request; %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to execute request; %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		var errResp map[string]interface{}
		if err := json.NewDecoder(resp.Body).Decode(&errResp); err != nil {
			return nil, fmt.Errorf("notification API returned status %d; %w", resp.StatusCode, err)
		}
		return nil, fmt.Errorf("notification API returned status %d: %v", resp.StatusCode, errResp)
	}

	var topic TopicResponse
	if err := json.NewDecoder(resp.Body).Decode(&topic); err != nil {
		return nil, fmt.Errorf("failed to parse topic response; %w", err)
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
		return nil, fmt.Errorf("failed to execute request; %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		var errResp map[string]interface{}
		if err := json.NewDecoder(resp.Body).Decode(&errResp); err != nil {
			return nil, fmt.Errorf("notification API returned status %d; %w", resp.StatusCode, err)
		}
		return nil, fmt.Errorf("notification API returned status %d: %v", resp.StatusCode, errResp)
	}

	var topicsResp struct {
		Topics []TopicResponse `json:"topics"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&topicsResp); err != nil {
		return nil, fmt.Errorf("failed to parse topics response; %w", err)
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
		return fmt.Errorf("failed to get application token; %w", err)
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
		return fmt.Errorf("failed to marshal request body; %w", err)
	}

	req, err := http.NewRequestWithContext(
		ctx, http.MethodPost,
		c.NotificationURL+notificationAPI+"destination",
		bytes.NewReader(bodyBytes),
	)
	if err != nil {
		return fmt.Errorf("failed to create request; %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.Do(req)
	if err != nil {
		return fmt.Errorf("failed to execute request; %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("notification API returned status %d: %s", resp.StatusCode, string(body))
	}

	// only Location header is returned, no body
	loc := resp.Header.Get("Location")
	if loc == "" {
		return fmt.Errorf("notification API returned no location header")
	}

	slog.Info("created notification destination", "loc", loc)

	user := ctx.Value(auth.USER).(string)
	// loc returned in the format:
	// https://api.ebay.com/commerce/notification/v1/destination/{destinationId}
	destinationID := path.Base(loc)
	if err := c.updateUserDestination(ctx, user, destinationID); err != nil {
		return fmt.Errorf("failed to update user destination in DB; %w", err)
	}

	return nil
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

	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return fmt.Errorf("failed to marshal request body; %w", err)
	}

	req, err := http.NewRequestWithContext(
		ctx, http.MethodPut,
		c.NotificationURL+notificationAPI+"destination/"+destinationID,
		bytes.NewReader(bodyBytes),
	)
	if err != nil {
		return fmt.Errorf("failed to create request; %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.Do(req)
	if err != nil {
		return fmt.Errorf("failed to execute request; %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("notification API returned status %d: %s", resp.StatusCode, string(body))
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

	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodDelete,
		c.NotificationURL+notificationAPI+"destination/"+destinationID,
		nil,
	)
	if err != nil {
		return fmt.Errorf("failed to create request; %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := c.Do(req)
	if err != nil {
		return fmt.Errorf("failed to execute request; %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("notification API returned status %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

func (c *Client) updateUserDestination(
	ctx context.Context,
	user string,
	destinationID string,
) error {
	filter := bson.D{{Key: "user", Value: user}}
	update := bson.M{
		"$set": bson.M{
			"destination_id": destinationID,
		},
	}

	dbCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	result, err := c.DB.UpdateOne(dbCtx, filter, update)
	if err != nil {
		return fmt.Errorf("failed to update user destination; %w", err)
	}

	if result.MatchedCount == 0 {
		return errors.New("user somehow does not exist after auth flow")
	}

	return nil
}

func (c *Client) GetUserDestinationID(ctx context.Context, user string) (string, error) {
	filter := bson.D{{Key: "user", Value: user}}
	var result struct {
		DestinationID string `bson:"destination_id"`
	}

	dbCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	err := c.DB.FindOne(dbCtx, filter).Decode(&result)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return "", nil
		}
		return "", fmt.Errorf("failed to get user destination; %w", err)
	}

	return result.DestinationID, nil
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

	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodGet,
		c.NotificationURL+notificationAPI+"destination",
		nil,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create request; %w", err)
	}

	q := req.URL.Query()
	q.Set("limit", strconv.Itoa(pageSize))
	req.URL.RawQuery = q.Encode()

	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to execute request; %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("notification API returned status %d: %s", resp.StatusCode, string(body))
	}

	var destResp DestinationsResponse
	if err := json.NewDecoder(resp.Body).Decode(&destResp); err != nil {
		return nil, fmt.Errorf("failed to parse destinations response; %w", err)
	}

	return &destResp, nil
}

// CreateUserSubscription creates a subscription to a topic.
// topicID must be from an available topic (e.g., "MARKETPLACE_ACCOUNT_DELETION").
// https://developer.ebay.com/api-docs/commerce/notification/resources/subscription/methods/createSubscription
func (c *Client) CreateUserSubscription(
	ctx context.Context,
	topicID string,
) (string, error) {
	// Use Application token for Application-level notifications,
	// and User token for User-level notifications.
	user := ctx.Value(auth.USER).(string)
	token, err := c.Auth.GetToken(ctx, user)
	if err != nil {
		return "", fmt.Errorf("failed to get or refresh user token; %w", err)
	}

	destinationID, err := c.GetUserDestinationID(ctx, user)
	if err != nil || destinationID == "" {
		return "", fmt.Errorf("failed to get destination ID for user %s; %w", user, err)
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

	slog.Info("created notification destination", "loc", loc)

	// loc returned in the format:
	// https://api.ebay.com/commerce/notification/v1/subscription/{subscriptionId}
	subscriptionID := path.Base(loc)
	return subscriptionID, nil
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
		return nil, fmt.Errorf("failed to create request; %w", err)
	}

	// Set required headers
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	// Execute the request
	resp, err := c.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to execute request; %w", err)
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
		return nil, fmt.Errorf("failed to parse subscriptions response; %w", err)
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

	req, err := http.NewRequestWithContext(
		ctx, http.MethodDelete,
		c.NotificationURL+notificationAPI+"subscription/"+subscriptionID,
		nil,
	)
	if err != nil {
		return fmt.Errorf("failed to create request; %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := c.Do(req)
	if err != nil {
		return fmt.Errorf("failed to execute request; %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("notification API returned status %d: %s", resp.StatusCode, string(body))
	}

	return nil
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
	// 1. Get all subscriptions
	subs, err := c.GetUserSubscriptions(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get user subscriptions; %w", err)
	}

	// 2. Get User-level auth token for the enable calls
	token, err := c.Auth.GetToken(ctx, ctx.Value(auth.USER).(string))
	if err != nil {
		return nil, fmt.Errorf("failed to get user token; %w", err)
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
			return nil, fmt.Errorf("failed to create enable request for subscription %s; %w", sub.SubscriptionID, err)
		}

		req.Header.Set("Authorization", "Bearer "+token)

		resp, err := c.Do(req)
		if err != nil {
			return nil, fmt.Errorf("failed to enable subscription %s; %w", sub.SubscriptionID, err)
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

// TestUserSubscription triggers a test notification payload for a given subscription.
// https://developer.ebay.com/api-docs/commerce/notification/resources/subscription/methods/testSubscription
func (c *Client) TestUserSubscription(ctx context.Context, subscriptionID string) error {
	user := ctx.Value(auth.USER).(string)
	token, err := c.Auth.GetToken(ctx, user)
	if err != nil {
		return fmt.Errorf("failed to get or refresh user token: %w", err)
	}

	req, err := http.NewRequestWithContext(
		ctx, http.MethodPost,
		c.NotificationURL+notificationAPI+"subscription/"+subscriptionID+"/test",
		nil,
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

	if resp.StatusCode != http.StatusAccepted && resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("notification API returned status %d: %s", resp.StatusCode, string(body))
	}

	return nil
}
