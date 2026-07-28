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

	// defaultRefreshTokenLifetime is eBay's documented refresh-token validity,
	// used when a grant response omits refresh_token_expires_in.
	defaultRefreshTokenLifetime = 18 * 30 * 24 * time.Hour
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

	// UserAPI specifies the Identity API endpoint.
	UserAPI string
}

type UserTokenDocument struct {
	User          string    `bson:"user"`
	SealiftUserId string    `bson:"sealift_user_id"`
	AccessToken   string    `bson:"access_token"`
	RefreshToken  string    `bson:"refresh_token"`
	ExpiresAt     time.Time `bson:"expires_at,omitempty"`
	// RefreshTokenExpiresAt is when the seller must re-consent. eBay returns
	// this (~18 months out) on every grant; it used to be logged and discarded,
	// so nothing could warn before a seller silently stopped working.
	RefreshTokenExpiresAt time.Time `bson:"refresh_token_expires_at,omitempty"`
	// ReauthRequired is set when eBay rejects the refresh token outright, so the
	// UI can prompt for reconnection instead of showing an empty page.
	ReauthRequired       bool   `bson:"reauth_required,omitempty"`
	NotificationEndpoint string `bson:"notification_endpoint,omitempty"`
}

// ErrSellerReauthRequired means the seller's refresh token is no longer valid
// and only the eBay consent flow can restore access — retrying won't help.
var ErrSellerReauthRequired = errors.New("seller must re-authorize with eBay")

// GetUsers returns the users registered for a specific Sealift client.
// Seller connection states surfaced to the UI.
const (
	SellerConnected = "connected"
	SellerExpiring  = "expiring"
	SellerExpired   = "expired"
)

// expiringWindow is how far ahead of re-consent we start warning.
const expiringWindow = 30 * 24 * time.Hour

// SellerStatus describes the health of one seller's eBay connection.
type SellerStatus struct {
	User      string     `json:"user"`
	Status    string     `json:"status"`
	ExpiresAt *time.Time `json:"expiresAt,omitempty"`
}

// GetSellers returns each registered seller with the state of its eBay
// authorization, so the UI can warn before a connection lapses instead of
// silently returning nothing once it has.
func (c *Client) GetSellers(ctx context.Context, sealiftUserId string) ([]SellerStatus, error) {
	if sealiftUserId == "" {
		return nil, errors.New("tenant id is required")
	}

	dbCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	cursor, err := c.DB.Find(dbCtx, bson.M{"sealift_user_id": sealiftUserId})
	if err != nil {
		return nil, fmt.Errorf("failed to list sellers; %w", err)
	}
	defer cursor.Close(dbCtx)

	var docs []UserTokenDocument
	if err := cursor.All(dbCtx, &docs); err != nil {
		return nil, fmt.Errorf("failed to decode sellers; %w", err)
	}

	sellers := make([]SellerStatus, 0, len(docs))
	for _, doc := range docs {
		status := SellerConnected
		switch {
		case doc.ReauthRequired:
			status = SellerExpired
		case !doc.RefreshTokenExpiresAt.IsZero():
			remaining := time.Until(doc.RefreshTokenExpiresAt)
			if remaining <= 0 {
				status = SellerExpired
			} else if remaining <= expiringWindow {
				status = SellerExpiring
			}
		}

		seller := SellerStatus{User: doc.User, Status: status}
		if !doc.RefreshTokenExpiresAt.IsZero() {
			expiry := doc.RefreshTokenExpiresAt
			seller.ExpiresAt = &expiry
		}
		sellers = append(sellers, seller)
	}

	slices.SortFunc(sellers, func(a, b SellerStatus) int {
		return strings.Compare(a.User, b.User)
	})
	return sellers, nil
}

func (c *Client) GetUsers(ctx context.Context, sealiftUserId string) ([]string, error) {
	dbCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	if sealiftUserId == "" {
		return nil, errors.New("tenant id is required")
	}
	filter := bson.D{{Key: "sealift_user_id", Value: sealiftUserId}}

	var users []string
	undec, err := c.DB.Distinct(dbCtx, "user", filter)
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
// Returns the authenticated user ID.
func (c *Client) AuthUser(ctx context.Context, authCode string, sealiftUserId string) (string, error) {
	slog.Info("AuthUser started", "sealiftUserId", sealiftUserId)
	tokenResp, err := c.getUserToken(authCode)
	if err != nil {
		return "", fmt.Errorf("failed to get user token; %w", err)
	}

	user, err := c.getUser(tokenResp.AccessToken)
	if err != nil {
		return "", fmt.Errorf("failed to get user; %w", err)
	}

	if user == "" {
		return "", errors.New("retrieved empty username from eBay identity API")
	}

	slog.Info("Successfully identified eBay user", "username", user, "sealiftUserId", sealiftUserId)

	loc, err := time.LoadLocation(timezone)
	if err != nil {
		return "", fmt.Errorf("failed to load timezone; %w", err)
	}

	expiresAt := time.Now().In(loc).Add(time.Duration(tokenResp.ExpiresIn) * time.Second)

	// eBay omits refresh_token_expires_in on some grants; fall back to its
	// documented lifetime so the field is never silently zero.
	refreshLifetime := time.Duration(tokenResp.RefreshTokenExpiresIn) * time.Second
	if refreshLifetime <= 0 {
		refreshLifetime = defaultRefreshTokenLifetime
	}

	filter := bson.M{
		"user":            user,
		"sealift_user_id": sealiftUserId,
	}
	update := bson.M{
		"$set": UserTokenDocument{
			User:                  user,
			SealiftUserId:         sealiftUserId,
			AccessToken:           tokenResp.AccessToken,
			RefreshToken:          tokenResp.RefreshToken,
			ExpiresAt:             expiresAt,
			RefreshTokenExpiresAt: time.Now().In(loc).Add(refreshLifetime),
		},
	}

	dbCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	// upsert allows insert if not exist
	opts := options.Update().SetUpsert(true)
	result, err := c.DB.UpdateOne(dbCtx, filter, update, opts)
	if err != nil {
		return "", fmt.Errorf("failed to insert user; %w", err)
	}
	slog.Info(
		"upserted user token document",
		"matched", result.MatchedCount,
		"modified", result.ModifiedCount,
		"upserted_id", result.UpsertedID,
	)

	slog.Info("authorized new user", "user", user)

	return user, nil
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
		c.UserAPI,
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

	if resp.StatusCode != http.StatusOK {
		slog.Error("eBay Identity API returned error status", "status", resp.Status, "body", string(body))
		return "", fmt.Errorf("identity API failed with status: %s", resp.Status)
	}

	var userResp UserResponse
	if err := json.Unmarshal(body, &userResp); err != nil {
		slog.Error("Failed to unmarshal user identity response", "body", string(body), "err", err)
		return "", fmt.Errorf("failed to unmarshal user resp body; %w", err)
	}

	slog.Debug("Identity API response parsed", "username", userResp.Username)
	return userResp.Username, nil
}

// GetToken gets or refreshes a OAuth user token associated with a particular user.
// A token has to be initialized for a user i.e. after AuthUser().
// Otherwise, an error needs to be returned.
// After, it can be and is usually made right before a request.
func (c *Client) GetToken(ctx context.Context, user string) (string, error) {
	dbCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	filter := bson.M{"user": user}
	// Tenant scoping is mandatory: without it this can return another tenant's
	// OAuth token for a seller both tenants have registered.
	userID, ok := ctx.Value("userId").(string)
	if !ok || userID == "" {
		return "", errors.New("tenant id is required to resolve a seller token")
	}
	filter["sealift_user_id"] = userID

	var token UserTokenDocument
	err := c.DB.FindOne(dbCtx, filter).Decode(&token)
	if err != nil {
		return "", fmt.Errorf("failed to find token for user; %w", err)
	}

	loc, err := time.LoadLocation(timezone)
	if err != nil {
		return "", fmt.Errorf("failed to load timezone; %w", err)
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
			if errors.Is(err, ErrSellerReauthRequired) {
				// Flag the seller so the UI can offer a Reconnect button rather
				// than rendering an empty page forever.
				if _, markErr := c.DB.UpdateOne(dbCtx, filter,
					bson.M{"$set": bson.M{"reauth_required": true}}); markErr != nil {
					slog.Error("failed to flag seller for reauth", "err", markErr, "user", user)
				}
				return "", err
			}
			return "", fmt.Errorf("failed to refresh token; %w", err)
		}

		// The refresh call is a network round trip; dbCtx's short deadline was
		// budgeted for the read above and may already be spent.
		writeCtx, writeCancel := context.WithTimeout(ctx, 5*time.Second)
		defer writeCancel()

		// update document, refresh token remains the same
		newExpiresAt := time.Now().In(loc).Add(time.Duration(newToken.ExpiresIn) * time.Second)
		set := bson.M{
			"access_token":    newToken.AccessToken,
			"expires_at":      newExpiresAt,
			"reauth_required": false,
		}
		// eBay reissues the refresh token on some grants; keep the expiry current.
		if newToken.RefreshTokenExpiresIn > 0 {
			set["refresh_token_expires_at"] = time.Now().In(loc).
				Add(time.Duration(newToken.RefreshTokenExpiresIn) * time.Second)
		}
		if err := c.DB.FindOneAndUpdate(writeCtx, filter, bson.M{"$set": set}).Err(); err != nil {
			// The token itself is valid — returning it beats failing the request
			// because a database write didn't land.
			slog.Error("failed to persist refreshed token", "err", err, "user", user)
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
		// invalid_grant means the refresh token is dead (expired, revoked by the
		// seller, or issued to different credentials). No amount of retrying
		// fixes it — the seller has to go through eBay consent again.
		if tokenResp.Error == "invalid_grant" {
			slog.Warn("refresh token rejected by eBay; re-consent required",
				"err", tokenResp.ErrorDescription)
			return nil, ErrSellerReauthRequired
		}
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
