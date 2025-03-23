package ebay

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
