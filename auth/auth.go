package auth

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"
)

const USER = "user"

const (
	userAPI = "https://apiz.ebay.com/commerce/identity/v1/user/"
)

type Client struct {
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

	// ClientSecret
	ClientSecret string

	Sellers *Sellers
}

// Sellers manages tokens for multiple sellers.
type Sellers struct {
	sync.Mutex
	tokens map[string]*token
}

// token represents an OAuth token.
type token struct {
	accessToken  string
	refreshToken string
	expiresAt    time.Time
}

func MakeSellersMap() *Sellers {
	return &Sellers{sync.Mutex{}, make(map[string]*token, 0)}
}

// GetUsers returns all the users this app has registered.
func (c *Client) GetUsers() []string {
	return slices.Sorted(maps.Keys(c.Sellers.tokens))
}

// AuthUser is the initial flow when a user consents through auth-callback.
func (c *Client) AuthUser(authCode string) error {
	tokenResp, err := c.getUserToken(authCode)
	if err != nil {
		return fmt.Errorf("failed to get user token; %w", err)
	}

	user, err := getUser(tokenResp.AccessToken)
	if err != nil {
		return fmt.Errorf("failed to get user; %w", err)
	}

	c.Sellers.Lock()
	defer c.Sellers.Unlock()
	c.Sellers.tokens[user] = &token{
		accessToken:  tokenResp.AccessToken,
		refreshToken: tokenResp.RefreshToken,
		expiresAt:    time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second),
	}

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

	client := &http.Client{}
	resp, err := client.Do(req)
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
func getUser(accessToken string) (string, error) {
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

	client := &http.Client{}
	resp, err := client.Do(req)
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
func (c *Client) GetToken(user string) (string, error) {
	c.Sellers.Lock()
	defer c.Sellers.Unlock()

	token, exists := c.Sellers.tokens[user]
	if !exists {
		return "", fmt.Errorf("no token for seller %s", user)
	}

	if time.Until(token.expiresAt) < 5*time.Minute {
		slog.Info("found expired/expiring token; refreshing", "user", user)
		newToken, err := c.refreshToken(token.refreshToken)
		if err != nil {
			return "", fmt.Errorf("failed to refresh token; %w", err)
		}
		token.accessToken = newToken.AccessToken
		token.refreshToken = newToken.RefreshToken
		token.expiresAt = time.Now().Add(time.Duration(newToken.ExpiresIn) * time.Second)
	}

	return token.accessToken, nil
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

	client := &http.Client{}
	resp, err := client.Do(req)
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
		"refreshed access token",
		"expires_in_hrs", (tokenResp.ExpiresIn / htos),
		"refresh_token_expires_in_hrs", (tokenResp.RefreshTokenExpiresIn / htos))

	return &tokenResp, nil
}
