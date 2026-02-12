package auth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"

	"go.mongodb.org/mongo-driver/mongo/options"
)

const (
	USER = "user"

	timezone = "America/Chicago"
)

const (
	userAPI = "https://apiz.ebay.com/commerce/identity/v1/user/"
)

type Client struct {
	// HTTP client for making auth related API calls.
	*http.Client

	// DB client
	// would be a singleton (only bc there are no tests and this is thread safe :9)
	// but cyclic dependency
	DB *mongo.Collection

	// AuthURL specifies the OAuth token request endpoints.
	// Note that the prod URL is not quite the same as the API endpoint.
	// https://api.ebay.com/identity/v1/oauth2/token for prod
	// https://api.sandbox.ebay.com/identity/v1/oauth2/token for sandbox
	AuthURL string

	// RedirectURI specifies the "RuName".
	RedirectURI string

	// ClientID is the eBay application ID.
	// https://developer.ebay.com/api-docs/static/gs_create-the-ebay-api-keysets.html.
	ClientID string

	// ClientSecret is the eBay application secret.
	ClientSecret string

	// DevID used for specific APIs, such as GetAccount.
	DevID string
}

// UserDocument represents a document associating user with their OAuth token.
// if bson tag is not specified, mongo driver uses lowercase of the field name,
// but bson tags are useful if struct fields are renamed and thereby save some
// inconsistency issues at no functional cost.
type UserTokenDocument struct {
	User         string    `bson:"user"`
	AccessToken  string    `bson:"access_token"`
	RefreshToken string    `bson:"refresh_token"`
	ExpiresAt    time.Time `bson:"expires_at,omitempty"`
}

// GetUsers returns all the users this app has registered.
func (c *Client) GetUsers(ctx context.Context) ([]string, error) {
	dbCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	var users []string
	undec, err := c.DB.Distinct(dbCtx, "user", bson.D{})
	if err != nil {
		return nil, fmt.Errorf("failed to get users; %w", err)
	}

	for _, u := range undec {
		if user, ok := u.(string); ok {
			users = append(users, user)
		} else {
			return nil, fmt.Errorf("unexpected type for name: %T", u)
		}
	}

	// sorted for UI purposes
	slices.Sort(users)
	return users, nil
}

// AuthUser is the initial flow when a user consents through auth-callback.
func (c *Client) AuthUser(ctx context.Context, authCode string) error {
	tokenResp, err := c.getUserToken(authCode)
	if err != nil {
		return fmt.Errorf("failed to get user token; %w", err)
	}

	user, err := c.getUser(tokenResp.AccessToken)
	if err != nil {
		return fmt.Errorf("failed to get user; %w", err)
	}

	// c.Sellers.Lock()
	// defer c.Sellers.Unlock()
	// c.Sellers.tokens[user] = &token{
	// 	accessToken:  tokenResp.AccessToken,
	// 	refreshToken: tokenResp.RefreshToken,
	// 	expiresAt:    time.Now().In(loc).Add(time.Duration(tokenResp.ExpiresIn) * time.Second),
	// }

	loc, err := time.LoadLocation(timezone)
	if err != nil {
		return fmt.Errorf("failed to load timezone: %w", err)
	}

	expiresAt := time.Now().In(loc).Add(time.Duration(tokenResp.ExpiresIn) * time.Second)

	filter := bson.D{{Key: "user", Value: user}}
	update := bson.M{
		"$set": UserTokenDocument{
			User:         user,
			AccessToken:  tokenResp.AccessToken,
			RefreshToken: tokenResp.RefreshToken,
			ExpiresAt:    expiresAt,
		},
	}

	dbCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	// upsert allows insert if not exist
	opts := options.Update().SetUpsert(true)
	result, err := c.DB.UpdateOne(dbCtx, filter, update, opts)
	if err != nil {
		return fmt.Errorf("failed to insert user; %w", err)
	}
	slog.Info(
		"upserted user token document",
		"matched", result.MatchedCount,
		"modified", result.ModifiedCount,
		"upserted_id", result.UpsertedID,
	)

	slog.Info("authorized new user", "user", user)

	return nil
}

// TokenResponse represents the eBay OAuth token response.
type TokenResponse struct {
	AccessToken           string `json:"access_token"`
	TokenType             string `json:"token_type"`
	ExpiresIn             int    `json:"expires_in"`
	RefreshToken          string `json:"refresh_token,omitempty"`
	RefreshTokenExpiresIn int    `json:"refresh_token_expires_in,omitempty"`
	Error                 string `json:"error,omitempty"`
	ErrorDescription      string `json:"error_description,omitempty"`
}

// getUserToken exchanges an auth code for a user token.
// Used for initial auth flow through the redirect URI.
func (c *Client) getUserToken(authCode string) (*TokenResponse, error) {
	// base64 encode client_id:client_secret for Authorization header
	auth := base64.StdEncoding.EncodeToString([]byte(c.ClientID + ":" + c.ClientSecret))

	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("code", authCode)
	data.Set("redirect_uri", c.RedirectURI)

	req, err := http.NewRequest(
		"POST",
		c.AuthURL,
		strings.NewReader(data.Encode()),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to make token request; %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Basic "+auth)

	resp, err := c.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to request token endpoint; %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read resp; %w", err)
	}

	var tokenResp TokenResponse
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return nil, fmt.Errorf("failed to unmarshal resp; %w", err)
	}

	if tokenResp.Error != "" {
		return nil, fmt.Errorf(
			"token request failed - %s; %s",
			tokenResp.Error,
			tokenResp.ErrorDescription,
		)
	}

	if tokenResp.AccessToken == "" {
		return nil, errors.New("empty access token")
	}

	htos := int(time.Hour / time.Second)
	slog.Info(
		"generated access token",
		"expires_in_hrs", (tokenResp.ExpiresIn / htos),
		"refresh_token_expires_in_hrs", (tokenResp.RefreshTokenExpiresIn / htos))

	return &tokenResp, nil
}

type UserResponse struct {
	Username string `json:"username"`
}

// getUser gets the identity associated with an access token.
// This allows multiple users to use the app under their context.
// https://developer.ebay.com/api-docs/commerce/identity/overview.html
// Used for initial auth flow through the redirect URI.
func (c *Client) getUser(accessToken string) (string, error) {
	req, err := http.NewRequest(
		http.MethodGet,
		userAPI,
		nil,
	)
	if err != nil {
		return "", fmt.Errorf("failed to make request for user; %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := c.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to do request for user; %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read user resp body; %w", err)
	}

	var userResp UserResponse
	if err := json.Unmarshal(body, &userResp); err != nil {
		return "", fmt.Errorf("failed to unmarshal user resp body; %w", err)
	}
	return userResp.Username, nil
}

// getToken gets or refreshes a OAuth user token associated with a particular user.
// func (c *Client) GetToken(user string) (string, error) {
// 	c.Sellers.Lock()
// 	defer c.Sellers.Unlock()

// 	token, exists := c.Sellers.tokens[user]
// 	if !exists {
// 		return "", fmt.Errorf("no token for seller %s", user)
// 	}

// 	if time.Until(token.expiresAt) < 5*time.Minute {
// 		slog.Info("found expired/expiring token; refreshing", "user", user)
// 		newToken, err := c.refreshToken(token.refreshToken)
// 		if err != nil {
// 			return "", fmt.Errorf("failed to refresh token; %w", err)
// 		}
// 		token.accessToken = newToken.AccessToken
// 		token.refreshToken = newToken.RefreshToken
// 		token.expiresAt = time.Now().Add(time.Duration(newToken.ExpiresIn) * time.Second)
// 	}

// 	return token.accessToken, nil
// }

// GetToken gets or refreshes a OAuth user token associated with a particular user.
// A token has to be initialized for a user i.e. after AuthUser().
// Otherwise, an error needs to be returned.
// After, it can be and is usually made right before a request.
func (c *Client) GetToken(ctx context.Context, user string) (string, error) {
	dbCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	filter := bson.D{{Key: "user", Value: user}}
	var token UserTokenDocument
	err := c.DB.FindOne(dbCtx, filter).Decode(&token)
	if err != nil {
		return "", fmt.Errorf("failed to find token for user; %w", err)
	}

	loc, err := time.LoadLocation(timezone)
	if err != nil {
		return "", fmt.Errorf("failed to load timezone: %w", err)
	}

	expiresAt := token.ExpiresAt.In(loc)

	now := time.Now().In(loc)
	if expiresAt.Sub(now) < 5*time.Minute {
		slog.Info(
			"found expired/expiring token; refreshing",
			"user", user,
			"time_left_or_already_elapsed_if_neg", expiresAt.Sub(now),
		)
		newToken, err := c.refreshToken(token.RefreshToken)
		if err != nil {
			return "", fmt.Errorf("failed to refresh token; %w", err)
		}

		// update document, refresh token remains the same
		newExpiresAt := time.Now().In(loc).Add(time.Duration(newToken.ExpiresIn) * time.Second)
		filter := bson.D{{Key: "user", Value: user}}
		update := bson.M{
			"$set": UserTokenDocument{
				User:         user,
				AccessToken:  newToken.AccessToken,
				ExpiresAt:    newExpiresAt,
				RefreshToken: token.RefreshToken,
			},
		}

		result := c.DB.FindOneAndUpdate(dbCtx, filter, update)
		if result.Err() != nil {
			return "", fmt.Errorf("failed to update user token document; %w", err)
		}

		return newToken.AccessToken, nil
	}

	// return already valid access token
	return token.AccessToken, nil
}

// refreshToken refreshes an expired token.
// Uses the long-lived refresh_token from the last access_token.
func (c *Client) refreshToken(refreshToken string) (*TokenResponse, error) {
	auth := base64.StdEncoding.EncodeToString([]byte(c.ClientID + ":" + c.ClientSecret))
	data := url.Values{}
	data.Set("grant_type", "refresh_token")
	data.Set("refresh_token", refreshToken)

	req, err := http.NewRequest(
		"POST",
		c.AuthURL,
		strings.NewReader(data.Encode()),
	)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Basic "+auth)

	resp, err := c.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to request token endpoint; %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read resp; %w", err)
	}

	var tokenResp TokenResponse
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return nil, fmt.Errorf("failed to unmarshal resp; %w", err)
	}

	if tokenResp.Error != "" {
		return nil, fmt.Errorf(
			"token request failed - %s; %s",
			tokenResp.Error,
			tokenResp.ErrorDescription,
		)
	}
	// TODO: if refresh token failed with:
	// "token request failed - invalid_grant; the provided authorization refresh token is invalid or was issued to another client"
	// should redirect user back to oauth consent/login

	if tokenResp.AccessToken == "" {
		return nil, errors.New("empty access token")
	}

	htos := int(time.Hour / time.Second)
	slog.Info(
		"refreshed access token",
		"expires_in_hrs", (tokenResp.ExpiresIn / htos),
	)

	return &tokenResp, nil
}

// GetApplicationToken gets an OAuth application token using the client credentials grant flow.
// This is used for application-level operations like accessing the Notification API.
// https://developer.ebay.com/api-docs/static/oauth-client-credentials-grant.html
func (c *Client) GetApplicationToken(ctx context.Context) (string, error) {
	// base64 encode client_id:client_secret for Authorization header
	auth := base64.StdEncoding.EncodeToString([]byte(c.ClientID + ":" + c.ClientSecret))

	data := url.Values{}
	data.Set("grant_type", "client_credentials")
	data.Set("scope", "https://api.ebay.com/oauth/api_scope")

	// TODO: CACHE THIS APPLICATION TOKEN

	req, err := http.NewRequestWithContext(
		ctx,
		"POST",
		c.AuthURL,
		strings.NewReader(data.Encode()),
	)
	if err != nil {
		return "", fmt.Errorf("failed to create token request; %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Basic "+auth)

	resp, err := c.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to request token endpoint; %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response; %w", err)
	}

	var tokenResp TokenResponse
	err = json.Unmarshal(body, &tokenResp)
	if err != nil {
		return "", fmt.Errorf("failed to parse token response; %w", err)
	}

	if tokenResp.Error != "" {
		return "", fmt.Errorf("eBay auth error: %s - %s", tokenResp.Error, tokenResp.ErrorDescription)
	}

	if tokenResp.AccessToken == "" {
		return "", errors.New("empty access token in response")
	}

	htos := int(time.Hour / time.Second)
	slog.Info(
		"obtained application token",
		"expires_in_hrs", (tokenResp.ExpiresIn / htos),
	)

	return tokenResp.AccessToken, nil
}
