package ebay

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"

	"golang.org/x/sync/errgroup"

	"github.tesla.com/chrzhang/sealift/auth"
)


const (
	fulfillmentAPI = "/sell/fulfillment/v1/"
)

type Address struct {
	FullName       string `json:"fullName,omitempty"`
	City           string `json:"city,omitempty"`
	StateOrProvince string `json:"stateOrProvince,omitempty"`
	PostalCode     string `json:"postalCode,omitempty"`
	CountryCode    string `json:"countryCode,omitempty"`
}

type ShippingStep struct {
	ShipTo              Address `json:"shipTo"`
	ShippingCarrierCode string  `json:"shippingCarrierCode,omitempty"`
	ShippingServiceCode string  `json:"shippingServiceCode,omitempty"`
}

type FulfillmentStartInstruction struct {
	FulfillmentInstructionsType string       `json:"fulfillmentInstructionsType,omitempty"`
	MinEstimatedDeliveryDate    string       `json:"minEstimatedDeliveryDate,omitempty"`
	MaxEstimatedDeliveryDate    string       `json:"maxEstimatedDeliveryDate,omitempty"`
	ShippingStep                ShippingStep `json:"shippingStep"`
}

type Buyer struct {
	Username string `json:"username,omitempty"`
}

type PricingSummary struct {
	Total        Amount `json:"total"`
	DeliveryCost Amount `json:"deliveryCost"`
}

type CancelStatus struct {
	CancelState        string `json:"cancelState,omitempty"`
	CancelledDate      string `json:"cancelledDate,omitempty"`
}

type Order struct {
	OrderID                      string                        `json:"orderId"`
	LegacyOrderId                string                        `json:"legacyOrderId"`
	CreationDate                 string                        `json:"creationDate"`
	LastModifiedDate             string                        `json:"lastModifiedDate,omitempty"`
	FulfillmentStatus            string                        `json:"orderFulfillmentStatus"`
	PaymentStatus                string                        `json:"orderPaymentStatus"`
	Buyer                        Buyer                         `json:"buyer"`
	PricingSummary               PricingSummary                `json:"pricingSummary"`
	CancelStatus                 CancelStatus                  `json:"cancelStatus"`
	SalesRecordReference         string                        `json:"salesRecordReference,omitempty"`
	LineItems                    []LineItem                    `json:"lineItems"`
	FulfillmentStartInstructions []FulfillmentStartInstruction `json:"fulfillmentStartInstructions,omitempty"`
	FulfillmentHrefs             []string                      `json:"fulfillmentHrefs,omitempty"`
	ShippingFulfillments         []ShippingFulfillment         `json:"shippingFulfillments,omitempty"`
}

type LineItem struct {
	LineItemID                 string `json:"lineItemId"`
	LegacyItemID               string `json:"legacyItemId"`
	Title                      string `json:"title"`
	Sku                        string `json:"sku"`
	Quantity                   int    `json:"quantity"`
	LineItemFulfillmentStatus  string `json:"lineItemFulfillmentStatus,omitempty"`
	Total                      Amount `json:"total"`
	LineItemCost               Amount `json:"lineItemCost"`
}

type FulfillmentLineItem struct {
	LineItemID string `json:"lineItemId"`
	Quantity   int    `json:"quantity"`
}

type ShippingFulfillment struct {
	FulfillmentID          string                `json:"fulfillmentId"`
	ShipmentTrackingNumber string                `json:"shipmentTrackingNumber"`
	ShippingCarrierCode    string                `json:"shippingCarrierCode"`
	ShippedDate            string                `json:"shippedDate"`
	LineItems              []FulfillmentLineItem `json:"lineItems,omitempty"`
	USPSTracking           any                   `json:"uspsTracking,omitempty"`
}

type shippingFulfillmentsResponse struct {
	Fulfillments []ShippingFulfillment `json:"fulfillments"`
}



type GetOrdersResponse struct {
	Href   string  `json:"href"`
	Next   string  `json:"next"`
	Limit  int     `json:"limit"`
	Offset int     `json:"offset"`
	Total  int     `json:"total"`
	Orders []Order `json:"orders"`
}

const getOrdersPageLimit = 200
const getOrdersMaxPages = 100

func (c *Client) GetOrders(
	ctx context.Context,
) (*GetOrdersResponse, error) {
	token, err := c.Auth.GetToken(ctx, ctx.Value(auth.USER).(string))
	if err != nil {
		return nil, fmt.Errorf("failed to get or refresh user token; %w", err)
	}

	url := fmt.Sprintf("%s%sorder?limit=%d&offset=0", c.SellURL, fulfillmentAPI, getOrdersPageLimit)
	var all []Order
	total := 0

	for page := 0; page < getOrdersMaxPages; page++ {
		var resp GetOrdersResponse
		if err := c.doJSON(ctx, http.MethodGet, url, token, nil, &resp); err != nil {
			return nil, err
		}
		if resp.Total > total {
			total = resp.Total
		}
		all = append(all, resp.Orders...)

		if resp.Next == "" || len(resp.Orders) == 0 || (total > 0 && len(all) >= total) {
			break
		}
		url = resp.Next
	}

	g, gCtx := errgroup.WithContext(ctx)
	g.SetLimit(8)
	for i := range all {
		i := i
		status := all[i].FulfillmentStatus
		if status != "IN_PROGRESS" && status != "FULFILLED" {
			continue
		}
		g.Go(func() error {
			fulfillments, err := c.GetShippingFulfillments(gCtx, all[i].OrderID)
			if err != nil {
				slog.Warn("failed to get shipping fulfillments", "orderId", all[i].OrderID, "err", err)
				return nil
			}
			all[i].ShippingFulfillments = fulfillments
			return nil
		})
	}
	_ = g.Wait()

	return &GetOrdersResponse{
		Total:  total,
		Orders: all,
	}, nil
}

func (c *Client) GetShippingFulfillments(ctx context.Context, orderID string) ([]ShippingFulfillment, error) {
	token, err := c.Auth.GetToken(ctx, ctx.Value(auth.USER).(string))
	if err != nil {
		return nil, fmt.Errorf("failed to get or refresh user token; %w", err)
	}

	endpoint := fmt.Sprintf("%s%sorder/%s/shipping_fulfillment", c.SellURL, fulfillmentAPI, url.PathEscape(orderID))
	var resp shippingFulfillmentsResponse
	if err := c.doJSON(ctx, http.MethodGet, endpoint, token, nil, &resp); err != nil {
		return nil, err
	}
	return resp.Fulfillments, nil
}

