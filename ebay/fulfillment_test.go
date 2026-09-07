package ebay

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.tesla.com/chrzhang/sealift/auth"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo/integration/mtest"
)

func TestGetOrdersResolvesTokenOnceForPagesAndFulfillments(t *testing.T) {
	mt := mtest.New(t, mtest.NewOptions().ClientType(mtest.Mock))
	mt.Run("one seller token for the complete request", func(mt *mtest.T) {
		// Only one token lookup response is available. Re-reading credentials
		// during fulfillment enrichment would fail and lose tracking details.
		mt.AddMockResponses(mtest.CreateCursorResponse(0, mt.DB.Name()+"."+mt.Coll.Name(), mtest.FirstBatch, bson.D{
			{Key: "access_token", Value: "seller-token"},
			{Key: "expires_at", Value: time.Now().Add(time.Hour)},
		}))
		var mu sync.Mutex
		requests := make(map[string]int)
		var server *httptest.Server
		server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			mu.Lock()
			requests[r.URL.RequestURI()]++
			mu.Unlock()
			if got := r.Header.Get("Authorization"); got != "Bearer seller-token" {
				mt.Errorf("authorization = %q", got)
			}
			switch r.URL.Path {
			case fulfillmentAPI + "order":
				if r.URL.Query().Get("offset") == "0" {
					json.NewEncoder(w).Encode(GetOrdersResponse{
						Next:  server.URL + fulfillmentAPI + "order?limit=200&offset=2",
						Total: 3,
						Orders: []Order{
							{OrderID: "shipped", FulfillmentStatus: "FULFILLED"},
							{OrderID: "unshipped", FulfillmentStatus: "NOT_STARTED"},
						},
					})
				} else {
					json.NewEncoder(w).Encode(GetOrdersResponse{
						Total:  3,
						Orders: []Order{{OrderID: "partially-shipped", FulfillmentStatus: "IN_PROGRESS"}},
					})
				}
			case fulfillmentAPI + "order/shipped/shipping_fulfillment", fulfillmentAPI + "order/partially-shipped/shipping_fulfillment":
				orderID := strings.Split(r.URL.Path, "/")[5]
				json.NewEncoder(w).Encode(shippingFulfillmentsResponse{
					Fulfillments: []ShippingFulfillment{{FulfillmentID: "shipment-" + orderID, ShipmentTrackingNumber: "tracking-" + orderID}},
				})
			default:
				mt.Errorf("unexpected fulfillment request: %s", r.URL)
				http.NotFound(w, r)
			}
		}))
		defer server.Close()
		client := &Client{Client: server.Client(), SellURL: server.URL, Auth: &auth.Client{DB: mt.Coll}}
		ctx := context.WithValue(context.Background(), "userId", "tenant-1")
		ctx = context.WithValue(ctx, auth.USER, "seller-1")
		got, err := client.GetOrders(ctx)
		if err != nil {
			mt.Fatal(err)
		}
		if got.Total != 3 || len(got.Orders) != 3 {
			mt.Fatalf("lost order pages: %#v", got)
		}
		for _, order := range got.Orders {
			if order.OrderID == "unshipped" {
				if len(order.ShippingFulfillments) != 0 {
					mt.Fatal("unshipped order unexpectedly has tracking details")
				}
				continue
			}
			if len(order.ShippingFulfillments) != 1 || order.ShippingFulfillments[0].ShipmentTrackingNumber != "tracking-"+order.OrderID {
				mt.Fatalf("lost tracking details for %s: %#v", order.OrderID, order.ShippingFulfillments)
			}
		}
		if events := mt.GetAllStartedEvents(); len(events) != 1 || events[0].CommandName != "find" {
			mt.Fatalf("expected one seller token lookup, got %d database commands", len(events))
		}
		mu.Lock()
		defer mu.Unlock()
		if len(requests) != 4 {
			mt.Fatalf("expected two pages and two shipping lookups: %#v", requests)
		}
		for path, count := range requests {
			if count != 1 {
				mt.Errorf("%s requested %d times", path, count)
			}
		}
	})
}

func TestGetShippingFulfillmentsResolvesTokenForStandaloneCall(t *testing.T) {
	mt := mtest.New(t, mtest.NewOptions().ClientType(mtest.Mock))
	mt.Run("standalone shipping lookup", func(mt *mtest.T) {
		mt.AddMockResponses(mtest.CreateCursorResponse(0, mt.DB.Name()+"."+mt.Coll.Name(), mtest.FirstBatch, bson.D{
			{Key: "access_token", Value: "standalone-token"},
			{Key: "expires_at", Value: time.Now().Add(time.Hour)},
		}))
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if got := r.Header.Get("Authorization"); got != "Bearer standalone-token" {
				mt.Errorf("authorization = %q", got)
			}
			if r.URL.EscapedPath() != fulfillmentAPI+"order/order%2Fid/shipping_fulfillment" {
				mt.Errorf("order ID not escaped: %s", r.URL.EscapedPath())
			}
			json.NewEncoder(w).Encode(shippingFulfillmentsResponse{Fulfillments: []ShippingFulfillment{{FulfillmentID: "shipment-1"}}})
		}))
		defer server.Close()
		client := &Client{Client: server.Client(), SellURL: server.URL, Auth: &auth.Client{DB: mt.Coll}}
		ctx := context.WithValue(context.Background(), "userId", "tenant-1")
		ctx = context.WithValue(ctx, auth.USER, "seller-1")
		got, err := client.GetShippingFulfillments(ctx, "order/id")
		if err != nil || len(got) != 1 || got[0].FulfillmentID != "shipment-1" {
			mt.Fatalf("standalone lookup: got=%#v err=%v", got, err)
		}
	})
}
