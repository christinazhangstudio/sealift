package ebay

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

// "Important! You should not use any API response or notification,
// other than the Notification API, as a source to query the Finances API,
// as this may result in immutable response and system errors
// due to lack of payment data availability."

// Due to this lag, the successfully execution of a transaction
// will be signaled by the Notifications API.
// It does not reflect the precise time it might have been made.

// "Note: Charges and credits for shipping labels purchased
// with methods other than eBay funds, such as PayPal,
// are not supported in the Finances API."

// https://apiz.ebay.com/sell/finances/v1/transaction_summary?filter=transactionStatus:{PAYOUT}

const (
	financesAPI = "/sell/finances/v1/"
)

type TransactionSummaryResponse struct {
	CreditCount      int    `json:"creditCount"`
	CreditAmount     Amount `json:"creditAmount"`
	DebitCount       int    `json:"debitCount"`
	DebitAmount      Amount `json:"debitAmount"`
	OnHoldCount      int    `json:"onHoldCount"`
	OnHoldAmount     Amount `json:"onHoldAmount"`
	TotalCount       int    `json:"totalCount"`
	TotalAmount      Amount `json:"totalAmount"`
	ProcessingCount  int    `json:"processingCount"`
	ProcessingAmount Amount `json:"processingAmount"`
}

type Amount struct {
	Value    string `json:"value"`
	Currency string `json:"currency"`
}

// ErrorResponse represents a standard eBay API error response.
type ErrorResponse struct {
	Errors []ErrorDetail `json:"errors"`
}

// ErrorDetail represents individual error information.
type ErrorDetail struct {
	ErrorID     int64            `json:"errorId"`              // numeric error identifier
	Domain      string           `json:"domain"`               // error domain (e.g., "API")
	Category    string           `json:"category"`             // error category (e.g., "REQUEST")
	Message     string           `json:"message"`              // human-readable error message
	LongMessage string           `json:"longMessage"`          // detailed error description
	Parameters  []ErrorParameter `json:"parameters,omitempty"` // optional parameters for the error
}

// ErrorParameter provides additional context for the error.
type ErrorParameter struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

func (c *Client) GetTransactionSummary(
	ctx context.Context,
) (*TransactionSummaryResponse, error) {
	//https://developer.ebay.com/api-docs/sell/finances/types/pay:TransactionStatusEnum
	params := map[string]string{
		"filter": "transactionStatus:{PAYOUT}",
	}
	req, err := c.request(
		ctx,
		financesAPI,
		"transaction_summary",
		params,
	)

	resp, err := c.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to do request; %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		var errResp ErrorResponse
		if err := json.Unmarshal(body, &errResp); err != nil {
			return nil, fmt.Errorf("failed to unmarshal error response: %w", err)
		}
		if len(errResp.Errors) > 0 {
			return nil, fmt.Errorf("API failed with status %d with error %d: %s",
				resp.StatusCode,
				errResp.Errors[0].ErrorID,
				errResp.Errors[0].LongMessage,
			)
		}

		return nil, fmt.Errorf("API failed with status %d with unknown error: %s",
			resp.StatusCode,
			string(body),
		)
	}

	var summary TransactionSummaryResponse
	if err := json.Unmarshal(body, &summary); err != nil {
		return nil, fmt.Errorf("failed to unmarshal success response: %w", err)
	}

	return &summary, nil
}
