package ebay

import (
	"fmt"
	"strings"
)

// TradingAPIError represents an unsuccessful Trading API acknowledgement.
// Trading failures can arrive with HTTP 200, and Errors can also contain
// non-fatal warnings, so the Ack determines whether a response succeeded.
type TradingAPIError struct {
	Call   string
	Ack    string
	Errors []ErrorType
}

func (e *TradingAPIError) Error() string {
	var details []string
	for _, detail := range e.Errors {
		message := detail.LongMessage
		if message == "" {
			message = detail.ShortMessage
		}
		if detail.ErrorCode != "" {
			message = detail.ErrorCode + ": " + message
		}
		if message != "" {
			details = append(details, message)
		}
	}
	message := fmt.Sprintf("%s failed with acknowledgement %q", e.Call, e.Ack)
	if len(details) > 0 {
		message += "; " + strings.Join(details, "; ")
	}
	return message
}

func checkTradingResponse(call, ack string, details []ErrorType) error {
	// https://developer.ebay.com/devzone/xml/docs/Reference/eBay/types/AckCodeType.html
	if ack == "Success" || ack == "Warning" {
		return nil
	}
	return &TradingAPIError{Call: call, Ack: ack, Errors: details}
}
