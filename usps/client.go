// Package usps calls the USPS REST APIs (OAuth + Tracking v3r2).
package usps

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	ProdBaseURL = "https://apis.usps.com"
	TEMBaseURL  = "https://apis-tem.usps.com"

	tokenPath      = "/oauth2/v3/token"
	trackingV3Path = "/tracking/v3/tracking/"
	trackingV3r2   = "/tracking/v3r2/tracking"

	tokenSkew = time.Minute
)

// Client talks to USPS with a cached client-credentials token.
type Client struct {
	*http.Client

	BaseURL      string
	ClientID     string
	ClientSecret string

	mu       sync.Mutex
	token    string
	tokenExp time.Time
}

// Tracking is the v3 / v3r2 detail payload.
type Tracking struct {
	TrackingNumber        string           `json:"trackingNumber,omitempty"`
	Status                string           `json:"status,omitempty"`
	StatusCategory        string           `json:"statusCategory,omitempty"`
	StatusSummary         string           `json:"statusSummary,omitempty"`
	MailClass             string           `json:"mailClass,omitempty"`
	MailType              string           `json:"mailType,omitempty"`
	Services              StringList       `json:"services,omitempty"`
	ServiceTypeCode       string           `json:"serviceTypeCode,omitempty"`
	OriginCity            string           `json:"originCity,omitempty"`
	OriginState           string           `json:"originState,omitempty"`
	OriginZIP             string           `json:"originZIP,omitempty"`
	DestinationCity       string           `json:"destinationCity,omitempty"`
	DestinationState      string           `json:"destinationState,omitempty"`
	DestinationZIP        string           `json:"destinationZIP,omitempty"`
	ExpectedDeliveryDate  string           `json:"expectedDeliveryDate,omitempty"`
	ProofOfDeliveryEnabled string          `json:"proofOfDeliveryEnabled,omitempty"`
	TrackingEvents        []TrackingEvent  `json:"trackingEvents,omitempty"`
}

// TrackingEvent is one scan on the package.
type TrackingEvent struct {
	EventType      string `json:"eventType,omitempty"`
	EventTimestamp string `json:"eventTimestamp,omitempty"`
	EventCountry   string `json:"eventCountry,omitempty"`
	EventCity      string `json:"eventCity,omitempty"`
	EventState     string `json:"eventState,omitempty"`
	EventZIP       string `json:"eventZIP,omitempty"`
	EventCode      string `json:"eventCode,omitempty"`
	Firm           string `json:"firm,omitempty"`
	Name           string `json:"name,omitempty"`
}

// TrackRequest is one item in the v3r2 request body.
type TrackRequest struct {
	TrackingNumber     string `json:"trackingNumber"`
	MailingDate        string `json:"mailingDate,omitempty"`
	DestinationZIPCode string `json:"destinationZIPCode,omitempty"`
}

// APIError is a non-2xx USPS response.
type APIError struct {
	StatusCode int
	Body       []byte
}

func (e *APIError) Error() string {
	return fmt.Sprintf("USPS API failed with status %d: %s", e.StatusCode, string(e.Body))
}

// StringList accepts either a JSON string or array of strings.
type StringList []string

func (s *StringList) UnmarshalJSON(b []byte) error {
	b = bytes.TrimSpace(b)
	if len(b) == 0 || string(b) == "null" {
		return nil
	}
	if b[0] == '[' {
		var arr []string
		if err := json.Unmarshal(b, &arr); err != nil {
			return err
		}
		*s = arr
		return nil
	}
	var str string
	if err := json.Unmarshal(b, &str); err != nil {
		return err
	}
	if str != "" {
		*s = []string{str}
	}
	return nil
}

type flexibleInt int

func (n *flexibleInt) UnmarshalJSON(b []byte) error {
	var i int
	if err := json.Unmarshal(b, &i); err == nil {
		*n = flexibleInt(i)
		return nil
	}
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	if s == "" {
		*n = 0
		return nil
	}
	v, err := strconv.Atoi(s)
	if err != nil {
		return err
	}
	*n = flexibleInt(v)
	return nil
}

type tokenResponse struct {
	AccessToken string      `json:"access_token"`
	ExpiresIn   flexibleInt `json:"expires_in"`
}

// New builds a client. tem selects apis-tem.usps.com.
func New(httpClient *http.Client, clientID, clientSecret string, tem bool) *Client {
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	base := ProdBaseURL
	if tem {
		base = TEMBaseURL
	}
	return &Client{
		Client:       httpClient,
		BaseURL:      base,
		ClientID:     clientID,
		ClientSecret: clientSecret,
	}
}

// IsUSPSCarrier reports whether an eBay carrier code is USPS.
func IsUSPSCarrier(code string) bool {
	c := strings.ToUpper(strings.TrimSpace(code))
	if c == "" {
		return false
	}
	if c == "USPS" || strings.HasPrefix(c, "USPS") {
		return true
	}
	return strings.Contains(c, "US POSTAL")
}

// DestinationZIP keeps the first five digits of a postal code.
func DestinationZIP(raw string) string {
	var b strings.Builder
	for _, r := range raw {
		if r >= '0' && r <= '9' {
			b.WriteRune(r)
			if b.Len() == 5 {
				break
			}
		}
	}
	return b.String()
}

// MailingDate returns YYYY-MM-DD from an RFC3339 or date-prefixed timestamp.
func MailingDate(values ...string) string {
	for _, v := range values {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			return t.Format("2006-01-02")
		}
		if len(v) >= 10 && v[4] == '-' && v[7] == '-' {
			return v[:10]
		}
	}
	return ""
}

func (c *Client) Track(ctx context.Context, req TrackRequest) (*Tracking, error) {
	if strings.TrimSpace(req.TrackingNumber) == "" {
		return nil, errors.New("missing tracking number")
	}

	track, err := c.trackOnce(ctx, req, false)
	if err == nil {
		return track, nil
	}
	if isUnauthorized(err) {
		c.invalidateToken()
		track, err = c.trackOnce(ctx, req, false)
		if err == nil {
			return track, nil
		}
	}
	if !shouldFallbackV3r2(err) {
		return nil, err
	}

	track, err = c.trackOnce(ctx, req, true)
	if err == nil {
		return track, nil
	}
	if isUnauthorized(err) {
		c.invalidateToken()
		return c.trackOnce(ctx, req, true)
	}
	return nil, err
}

func (c *Client) trackOnce(ctx context.Context, req TrackRequest, v3r2 bool) (*Tracking, error) {
	token, err := c.accessToken(ctx)
	if err != nil {
		return nil, err
	}

	var (
		method   = http.MethodGet
		endpoint string
		body     io.Reader
	)
	if v3r2 {
		raw, err := json.Marshal([]TrackRequest{req})
		if err != nil {
			return nil, fmt.Errorf("failed to marshal tracking request: %w", err)
		}
		method = http.MethodPost
		endpoint = strings.TrimRight(c.BaseURL, "/") + trackingV3r2
		body = bytes.NewReader(raw)
	} else {
		endpoint = strings.TrimRight(c.BaseURL, "/") + trackingV3Path + url.PathEscape(req.TrackingNumber) + "?expand=DETAIL"
	}

	httpReq, err := http.NewRequestWithContext(ctx, method, endpoint, body)
	if err != nil {
		return nil, fmt.Errorf("failed to create tracking request: %w", err)
	}
	httpReq.Header.Set("Authorization", "Bearer "+token)
	httpReq.Header.Set("Accept", "application/json")
	if v3r2 {
		httpReq.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("failed to execute tracking request: %w", err)
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read tracking response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, &APIError{StatusCode: resp.StatusCode, Body: respBody}
	}
	return decodeTracking(respBody)
}

func isUnauthorized(err error) bool {
	var apiErr *APIError
	return errors.As(err, &apiErr) && apiErr.StatusCode == http.StatusUnauthorized
}

func shouldFallbackV3r2(err error) bool {
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		return false
	}
	switch apiErr.StatusCode {
	case http.StatusBadRequest, http.StatusNotFound, http.StatusMethodNotAllowed,
		http.StatusUnsupportedMediaType, http.StatusNotImplemented:
		return true
	default:
		return false
	}
}

func decodeTracking(body []byte) (*Tracking, error) {
	body = bytes.TrimSpace(body)
	if len(body) == 0 {
		return nil, errors.New("empty tracking response")
	}
	if body[0] == '[' {
		var list []Tracking
		if err := json.Unmarshal(body, &list); err != nil {
			return nil, fmt.Errorf("failed to parse tracking list: %w", err)
		}
		if len(list) == 0 {
			return nil, errors.New("empty tracking list")
		}
		return &list[0], nil
	}
	var t Tracking
	if err := json.Unmarshal(body, &t); err != nil {
		return nil, fmt.Errorf("failed to parse tracking response: %w", err)
	}
	return &t, nil
}

func (c *Client) accessToken(ctx context.Context) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.token != "" && time.Now().Before(c.tokenExp) {
		return c.token, nil
	}

	payload, err := json.Marshal(map[string]string{
		"client_id":     c.ClientID,
		"client_secret": c.ClientSecret,
		"grant_type":    "client_credentials",
	})
	if err != nil {
		return "", fmt.Errorf("failed to marshal token request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+tokenPath, bytes.NewReader(payload))
	if err != nil {
		return "", fmt.Errorf("failed to create token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := c.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to execute token request: %w", err)
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read token response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", &APIError{StatusCode: resp.StatusCode, Body: respBody}
	}

	var tok tokenResponse
	if err := json.Unmarshal(respBody, &tok); err != nil {
		return "", fmt.Errorf("failed to parse token response: %w", err)
	}
	if tok.AccessToken == "" {
		return "", errors.New("USPS token response missing access_token")
	}
	ttl := time.Duration(tok.ExpiresIn) * time.Second
	if ttl <= tokenSkew {
		ttl = time.Hour
	}
	c.token = tok.AccessToken
	c.tokenExp = time.Now().Add(ttl - tokenSkew)
	return c.token, nil
}

func (c *Client) invalidateToken() {
	c.mu.Lock()
	c.token = ""
	c.tokenExp = time.Time{}
	c.mu.Unlock()
}
