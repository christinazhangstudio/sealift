package ebay

import (
	"context"
	"fmt"
	"log/slog"
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
	financesUrl = "https://apiz.ebay.com/sell/finances/v1"
)

// type Storefront struct {
// 	StoreName []string `json:"storeName"`
// 	StoreURL  []string `json:"storeURL"`
// }

func (c *Client) GetTransactionSummary(
	ctx context.Context,
) error {
	//https://developer.ebay.com/api-docs/sell/finances/types/pay:TransactionStatusEnum
	params := map[string]string{
		"filter": "transactionStatus:{PAYOUT}",
	}
	req, err := c.request(ctx, financesUrl, "transaction_summary", params)

	resp, err := c.Do(req)
	if err != nil {
		return fmt.Errorf("failed to do request; %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("status not OK; got %d", resp.StatusCode)
	}

	slog.Info("got resp", "body", resp.Body)
	return nil
}
