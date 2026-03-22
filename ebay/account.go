package ebay

import (
	"context"
	"encoding/xml"
	"fmt"

	"github.tesla.com/chrzhang/sealift/auth"
)

// https://developer.ebay.com/Devzone/XML/docs/Reference/eBay/GetAccount.html

// "GetAccount returns account data in one of three report formats, depending on the inputs used for the call.
// Specify the type of report to generate with AccountHistorySelection.
// The types of reports you can request are
// (1) LastInvoice (returns entries since last invoice sent),
// (2) BetweenSpecifiedDates (returns entries posted between specific dates),
// or (3) OrderId (returns entries related to a specific order)."

type AccountRequest struct {
	XMLName                 xml.Name `xml:"GetAccountRequest"`
	XMLNS                   string   `xml:"xmlns,attr"`
	AccountEntrySortType    string   `xml:"AccountEntrySortType"`
	AccountHistorySelection string   `xml:"AccountHistorySelection"`
	RequesterCredentials    struct {
		EBayAuthToken string `xml:"eBayAuthToken"`
	} `xml:"RequesterCredentials"`
	// BeginDate/EndDate only applicable if the AccountHistorySelection value is set to 'BetweenSpecifiedDates'
	// otherwise, this field will be ignored
	BeginDate      string `xml:"BeginDate,omitempty"`
	Currency       string `xml:"Currency,omitempty"`
	EndDate        string `xml:"EndDate,omitempty"`
	ExcludeBalance bool   `xml:"ExcludeBalance"`
	ExcludeSummary bool   `xml:"ExcludeSummary"`
	ItemID         string `xml:"ItemID,omitempty"`
	OrderID        string `xml:"OrderID,omitempty"`
	Pagination     struct {
		EntriesPerPage int `xml:"EntriesPerPage"`
		PageNumber     int `xml:"PageNumber"`
	} `xml:"Pagination"`
	ErrorLanguage string `xml:"ErrorLanguage"`
	WarningLevel  string `xml:"WarningLevel"`
}

type AccountResponse struct {
	XMLName              xml.Name            `xml:"GetAccountResponse"`
	XMLNS                string              `xml:"xmlns,attr"`
	AccountEntries       *AccountEntriesType `xml:"AccountEntries,omitempty"`
	AccountID            string              `xml:"AccountID"`
	AccountSummaryUPPORT *AccountSummaryType `xml:"AccountSummary,omitempty"`
	Currency             string              `xml:"Currency"`
	EntriesPerPage       *int                `xml:"EntriesPerPage,omitempty"`
	FeeNettingStatus     *string             `xml:"FeeNettingStatus,omitempty"`
	HasMoreEntries       *bool               `xml:"HasMoreEntries,omitempty"`
	PageNumber           *int                `xml:"PageNumber,omitempty"`
	PaginationResult     *struct {
		TotalNumberOfEntries *int `xml:"TotalNumberOfEntries,omitempty"`
		TotalNumberOfPages   *int `xml:"TotalNumberOfPages,omitempty"`
	} `xml:"PaginationResult,omitempty"`
	Ack                   string      `xml:"Ack"`
	Build                 string      `xml:"Build"`
	CorrelationID         *string     `xml:"CorrelationID,omitempty"`
	Errors                []ErrorType `xml:"Errors,omitempty"`
	HardExpirationWarning *string     `xml:"HardExpirationWarning,omitempty"`
	Timestamp             string      `xml:"Timestamp"`
	Version               string      `xml:"Version"`
}

type AmountType struct {
	Value      float64 `xml:",chardata"`
	CurrencyID string  `xml:"currencyID,attr"`
}

type DiscountType struct {
	Amount       AmountType `xml:"Amount"`
	DiscountType *string    `xml:"DiscountType,omitempty"`
}

type DiscountDetailType struct {
	Discount []DiscountType `xml:"Discount,omitempty"`
}

type AccountEntryType struct {
	AccountDetailsEntryType  *string             `xml:"AccountDetailsEntryType,omitempty"`
	Balance                  AmountType          `xml:"Balance"`
	ConversionRate           *AmountType         `xml:"ConversionRate,omitempty"`
	Date                     *string             `xml:"Date,omitempty"`
	Description              *string             `xml:"Description,omitempty"`
	DiscountDetail           *DiscountDetailType `xml:"DiscountDetail,omitempty"`
	GrossDetailAmount        *AmountType         `xml:"GrossDetailAmount,omitempty"`
	ItemID                   *string             `xml:"ItemID,omitempty"`
	Memo                     *string             `xml:"Memo,omitempty"`
	NetDetailAmount          *AmountType         `xml:"NetDetailAmount,omitempty"`
	Netted                   *bool               `xml:"Netted,omitempty"`
	OrderID                  *string             `xml:"OrderId,omitempty"`
	OrderLineItemID          *string             `xml:"OrderLineItemID,omitempty"`
	ReceivedTopRatedDiscount *bool               `xml:"ReceivedTopRatedDiscount,omitempty"`
	RefNumber                *string             `xml:"RefNumber,omitempty"`
	Title                    *string             `xml:"Title,omitempty"`
	TransactionID            *string             `xml:"TransactionID,omitempty"`
	VATPercent               *float64            `xml:"VATPercent,omitempty"`
}

type AccountEntriesType struct {
	AccountEntry []AccountEntryType `xml:"AccountEntry,omitempty"`
}

type AdditionalAccountType struct {
	AccountCode *string    `xml:"AccountCode,omitempty"`
	Balance     AmountType `xml:"Balance"`
	Currency    *string    `xml:"Currency,omitempty"`
}

type NettedTransactionSummaryType struct {
	TotalNettedChargeAmount *AmountType `xml:"TotalNettedChargeAmount,omitempty"`
	TotalNettedCreditAmount *AmountType `xml:"TotalNettedCreditAmount,omitempty"`
}

type AccountSummaryType struct {
	AccountState             *string                       `xml:"AccountState,omitempty"`
	AdditionalAccount        []AdditionalAccountType       `xml:"AdditionalAccount,omitempty"`
	AmountPastDue            *AmountType                   `xml:"AmountPastDue,omitempty"`
	BankAccountInfo          *string                       `xml:"BankAccountInfo,omitempty"`
	BankModifyDate           *string                       `xml:"BankModifyDate,omitempty"`
	BillingCycleDate         *int                          `xml:"BillingCycleDate,omitempty"`
	CreditCardExpiration     *string                       `xml:"CreditCardExpiration,omitempty"`
	CreditCardInfo           *string                       `xml:"Creditbanana"`
	CreditCardModifyDate     *string                       `xml:"CreditCardModifyDate,omitempty"`
	CurrentBalance           *AmountType                   `xml:"CurrentBalance,omitempty"`
	InvoiceBalance           *AmountType                   `xml:"InvoiceBalance,omitempty"`
	InvoiceCredit            *AmountType                   `xml:"InvoiceCredit,omitempty"`
	InvoiceDate              *string                       `xml:"InvoiceDate,omitempty"`
	InvoiceNewFee            *AmountType                   `xml:"InvoiceNewFee,omitempty"`
	InvoicePayment           *AmountType                   `xml:"InvoicePayment,omitempty"`
	LastAmountPaid           *AmountType                   `xml:"LastAmountPaid,omitempty"`
	LastPaymentDate          *string                       `xml:"LastPaymentDate,omitempty"`
	NettedTransactionSummary *NettedTransactionSummaryType `xml:"NettedTransactionSummary,omitempty"`
	PastDue                  *bool                         `xml:"PastDue,omitempty"`
	PaymentMethod            *string                       `xml:"PaymentMethod,omitempty"`
}

type ErrorParameterType struct {
	Value   string `xml:"Value"`
	ParamID string `xml:"ParamID,attr"`
}

type ErrorType struct {
	ErrorClassification string               `xml:"ErrorClassification"`
	ErrorCode           string               `xml:"ErrorCode"`
	ErrorParameters     []ErrorParameterType `xml:"ErrorParameters"`
	LongMessage         string               `xml:"LongMessage"`
	SeverityCode        string               `xml:"SeverityCode"`
	ShortMessage        string               `xml:"ShortMessage"`
}

func (c *Client) GetAccount(
	ctx context.Context,
	pageSize int,
	pageIdx int, // 1 indexed
) (*AccountResponse, error) {
	token, err := c.Auth.GetToken(ctx, ctx.Value(auth.USER).(string))
	if err != nil {
		return nil, fmt.Errorf("failed to get or refresh user token; %w", err)
	}

	request := AccountRequest{
		XMLNS:                   "urn:ebay:apis:eBLBaseComponents",
		ErrorLanguage:           "en_US",
		WarningLevel:            "High",
		AccountEntrySortType:    "AccountEntryFeeTypeAscending",
		AccountHistorySelection: "LastInvoice",
		ExcludeBalance:          false,
		ExcludeSummary:          false,
	}
	request.RequesterCredentials.EBayAuthToken = token
	request.Pagination.EntriesPerPage = pageSize
	request.Pagination.PageNumber = pageIdx

	var accountResp AccountResponse
	if err := c.doXML(ctx, "GetAccount", "1207", token, request, &accountResp); err != nil {
		return nil, err
	}

	for _, err := range accountResp.Errors {
		if err.LongMessage != "" {
			return nil, fmt.Errorf("API failed with error; %s", err.LongMessage)
		}
	}

	if accountResp.Ack != "Success" {
		return nil, fmt.Errorf("API failed with status %s", accountResp.Ack)
	}

	return &accountResp, nil
}
