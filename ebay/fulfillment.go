package ebay

import (
	"context"
	"fmt"
	"net/http"

	"github.tesla.com/chrzhang/sealift/auth"
)

const (
	fulfillmentAPI = "/sell/fulfillment/v1/"
)

type Order struct {
	OrderID           string `json:"orderId"`
	CreationDate      string `json:"creationDate"`
	FulfillmentStatus string `json:"fulfillmentStatus"`
	OrderStatus       string `json:"orderStatus"`
	// add other fields if needed, but keeping it simple
}

type GetOrdersResponse struct {
	Href   string  `json:"href"`
	Total  int     `json:"total"`
	Orders []Order `json:"orders"`
}

func (c *Client) GetOrders(
	ctx context.Context,
) (*GetOrdersResponse, error) {
	token, err := c.Auth.GetToken(ctx, ctx.Value(auth.USER).(string))
	if err != nil {
		return nil, fmt.Errorf("failed to get or refresh user token; %w", err)
	}

	url := fmt.Sprintf("%s%sorder", c.URL, fulfillmentAPI)
	var resp GetOrdersResponse
	
	err = c.doJSON(ctx, http.MethodGet, url, token, nil, &resp)
	if err != nil {
		return nil, err
	}

	return &resp, nil
}
