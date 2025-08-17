package ebay

import (
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.tesla.com/chrzhang/sealift/auth"
)

var ErrHasNoMoreItems = errors.New("seller has no more items to display")

// The Inventory API is not used since only items created through the Inventory API are supported through it.
// The traditional "Trading API" has to be used, which uses XML.
// https://developer.ebay.com/api-docs/user-guides/static/make-a-call/using-xml.html

type SellerListRequest struct {
	XMLName              xml.Name `xml:"GetSellerListRequest"`
	XMLNS                string   `xml:"xmlns,attr"`
	RequesterCredentials struct {
		EBayAuthToken string `xml:"eBayAuthToken"`
	} `xml:"RequesterCredentials"`
	ErrorLanguage string `xml:"ErrorLanguage"`
	WarningLevel  string `xml:"WarningLevel"`
	StartTimeFrom string `xml:"StartTimeFrom"`
	StartTimeTo   string `xml:"StartTimeTo"`
	Pagination    struct {
		EntriesPerPage int `xml:"EntriesPerPage"`
		PageNumber     int `xml:"PageNumber"`
	} `xml:"Pagination"`
	GranularityLevel string `xml:"GranularityLevel"`
}

type SellerListResponse struct {
	XMLName          xml.Name `xml:"GetSellerListResponse"`
	Timestamp        string   `xml:"Timestamp"`
	Ack              string   `xml:"Ack"`
	Version          string   `xml:"Version"`
	Build            string   `xml:"Build"`
	PaginationResult struct {
		TotalNumberOfPages   int `xml:"TotalNumberOfPages"`
		TotalNumberOfEntries int `xml:"TotalNumberOfEntries"`
	} `xml:"PaginationResult"`
	HasMoreItems bool `xml:"HasMoreItems"`
	ItemArray    struct {
		Items []Item `xml:"Item"`
	} `xml:"ItemArray"`
	ItemsPerPage            int `xml:"ItemsPerPage"`
	PageNumber              int `xml:"PageNumber"`
	ReturnedItemCountActual int `xml:"ReturnedItemCountActual"`
}

type Item struct {
	AutoPay                       bool                    `xml:"AutoPay"`
	BuyerProtection               string                  `xml:"BuyerProtection"`
	Country                       string                  `xml:"Country"`
	Currency                      string                  `xml:"Currency"`
	HitCounter                    string                  `xml:"HitCounter"`
	ItemID                        string                  `xml:"ItemID"`
	ListingDetails                ListingDetails          `xml:"ListingDetails"`
	ListingDuration               string                  `xml:"ListingDuration"`
	Location                      string                  `xml:"Location"`
	PrimaryCategory               Category                `xml:"PrimaryCategory"`
	Quantity                      int                     `xml:"Quantity"`
	ReviseStatus                  ReviseStatus            `xml:"ReviseStatus"`
	SellingStatus                 SellingStatus           `xml:"SellingStatus"`
	ShippingDetails               ShippingDetails         `xml:"ShippingDetails"`
	ShipToLocations               string                  `xml:"ShipToLocations"`
	Site                          string                  `xml:"Site"`
	Storefront                    Storefront              `xml:"Storefront"`
	TimeLeft                      string                  `xml:"TimeLeft"`
	Title                         string                  `xml:"Title"`
	WatchCount                    int                     `xml:"WatchCount"`
	BestOfferDetails              BestOfferDetails        `xml:"BestOfferDetails"`
	LocationDefaulted             bool                    `xml:"LocationDefaulted"`
	BuyerResponsibleForShipping   bool                    `xml:"BuyerResponsibleForShipping"`
	PostalCode                    string                  `xml:"PostalCode"`
	PictureDetails                PictureDetails          `xml:"PictureDetails"`
	ProxyItem                     bool                    `xml:"ProxyItem"`
	BuyerGuaranteePrice           CurrencyValue           `xml:"BuyerGuaranteePrice"`
	BuyerRequirementDetails       BuyerRequirementDetails `xml:"BuyerRequirementDetails"`
	ReturnPolicy                  ReturnPolicy            `xml:"ReturnPolicy"`
	ConditionID                   string                  `xml:"ConditionID"`
	ConditionDisplayName          string                  `xml:"ConditionDisplayName"`
	PostCheckoutExperienceEnabled bool                    `xml:"PostCheckoutExperienceEnabled"`
	SellerProfiles                SellerProfiles          `xml:"SellerProfiles"`
	RelistParentID                string                  `xml:"RelistParentID"`
	HideFromSearch                bool                    `xml:"HideFromSearch"`
	EBayPlus                      bool                    `xml:"eBayPlus"`
	EBayPlusEligible              bool                    `xml:"eBayPlusEligible"`
	IsSecureDescription           bool                    `xml:"IsSecureDescription"`
}

type ListingDetails struct {
	RelistedItemID              string `xml:"RelistedItemID"`
	StartTime                   string `xml:"StartTime"`
	EndTime                     string `xml:"EndTime"`
	ViewItemURL                 string `xml:"ViewItemURL"`
	HasUnansweredQuestions      bool   `xml:"HasUnansweredQuestions"`
	HasPublicMessages           bool   `xml:"HasPublicMessages"`
	ViewItemURLForNaturalSearch string `xml:"ViewItemURLForNaturalSearch"`
}

type Category struct {
	CategoryID   string `xml:"CategoryID"`
	CategoryName string `xml:"CategoryName"`
}

type ReviseStatus struct {
	ItemRevised bool `xml:"ItemRevised"`
}

type SellingStatus struct {
	BidCount              int           `xml:"BidCount"`
	BidIncrement          CurrencyValue `xml:"BidIncrement"`
	ConvertedCurrentPrice CurrencyValue `xml:"ConvertedCurrentPrice"`
	CurrentPrice          CurrencyValue `xml:"CurrentPrice"`
	MinimumToBid          CurrencyValue `xml:"MinimumToBid"`
	QuantitySold          int           `xml:"QuantitySold"`
	SecondChanceEligible  bool          `xml:"SecondChanceEligible"`
	ListingStatus         string        `xml:"ListingStatus"`
}

type CurrencyValue struct {
	Value      float64 `xml:",chardata"`
	CurrencyID string  `xml:"currencyID,attr"`
}

type ShippingDetails struct {
	ShippingDiscountProfileID              string `xml:"ShippingDiscountProfileID"`
	InternationalShippingDiscountProfileID string `xml:"InternationalShippingDiscountProfileID"`
}

type Storefront struct {
	StoreCategoryID  int64  `xml:"StoreCategoryID"`
	StoreCategory2ID int64  `xml:"StoreCategory2ID"`
	StoreURL         string `xml:"StoreURL"`
}

type BestOfferDetails struct {
	BestOfferCount   int  `xml:"BestOfferCount"`
	BestOfferEnabled bool `xml:"BestOfferEnabled"`
	NewBestOffer     bool `xml:"NewBestOffer"`
}

type PictureDetails struct {
	GalleryURL   string   `xml:"GalleryURL"`
	PhotoDisplay string   `xml:"PhotoDisplay"`
	PictureURLs  []string `xml:"PictureURL"`
}

type BuyerRequirementDetails struct {
	ShipToRegistrationCountry bool `xml:"ShipToRegistrationCountry"`
}

type ReturnPolicy struct {
	RefundOption             string `xml:"RefundOption"`
	Refund                   string `xml:"Refund"`
	ReturnsWithinOption      string `xml:"ReturnsWithinOption"`
	ReturnsWithin            string `xml:"ReturnsWithin"`
	ReturnsAcceptedOption    string `xml:"ReturnsAcceptedOption"`
	ReturnsAccepted          string `xml:"ReturnsAccepted"`
	ShippingCostPaidByOption string `xml:"ShippingCostPaidByOption"`
	ShippingCostPaidBy       string `xml:"ShippingCostPaidBy"`
}

type SellerProfiles struct {
	SellerShippingProfile struct {
		ShippingProfileID   string `xml:"ShippingProfileID"`
		ShippingProfileName string `xml:"ShippingProfileName"`
	} `xml:"SellerShippingProfile"`
	SellerReturnProfile struct {
		ReturnProfileID   string `xml:"ReturnProfileID"`
		ReturnProfileName string `xml:"ReturnProfileName"`
	} `xml:"SellerReturnProfile"`
	SellerPaymentProfile struct {
		PaymentProfileID   string `xml:"PaymentProfileID"`
		PaymentProfileName string `xml:"PaymentProfileName"`
	} `xml:"SellerPaymentProfile"`
}

func (c *Client) GetSellerList(
	ctx context.Context,
	pageSize int,
	pageIdx int, // 1 indexed
	startFrom time.Time,
	startTo time.Time,
) (*SellerListResponse, error) {
	token, err := c.Auth.GetToken(ctx, ctx.Value(auth.USER).(string))
	if err != nil {
		return nil, fmt.Errorf("failed to get or refresh user token; %w", err)
	}

	request := SellerListRequest{
		XMLNS:            "urn:ebay:apis:eBLBaseComponents",
		ErrorLanguage:    "en_US",
		WarningLevel:     "High",
		GranularityLevel: "Coarse",
	}
	request.RequesterCredentials.EBayAuthToken = token
	// maximum time range must be a value less than 120 days
	request.StartTimeFrom = startFrom.Format(time.RFC3339)
	request.StartTimeTo = startTo.Format(time.RFC3339)
	request.Pagination.EntriesPerPage = pageSize
	request.Pagination.PageNumber = pageIdx // API is 1 indexed

	xmlData, err := xml.MarshalIndent(request, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to marshal XML: %w", err)
	}
	xmlBody := []byte(`<?xml version="1.0" encoding="utf-8"?>` + string(xmlData))

	req, err := http.NewRequestWithContext(
		ctx,
		"POST",
		c.TradURL,
		bytes.NewBuffer(xmlBody),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to make request; %w", err)
	}

	req.Header.Set("Content-Type", "text/xml")
	req.Header.Set("X-EBAY-API-COMPATIBILITY-LEVEL", "967")
	req.Header.Set("X-EBAY-API-CALL-NAME", "GetSellerList")
	req.Header.Set("X-EBAY-API-SITEID", "0") // US site

	resp, err := c.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to do request; %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	var sellerList SellerListResponse
	if err := xml.Unmarshal(body, &sellerList); err != nil {
		return nil, fmt.Errorf(
			"failed to unmarshal error response with status %d: %w; body %s",
			resp.StatusCode,
			err,
			string(body),
		)
	}

	// check if the call was successful
	if sellerList.Ack != "Success" {
		return nil, ErrHasNoMoreItems
		//return nil, fmt.Errorf("API failed with status %s", sellerList.Ack)
	}

	if sellerList.HasMoreItems {
		slog.Info("more items available; increase PageNumber or EntriesPerPage")
	}

	return &sellerList, nil
}
