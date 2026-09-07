package ebay

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
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

func TestGetOrdersRefreshesExpiredTokenForFulfillment(t *testing.T) {
	mt := mtest.New(t, mtest.NewOptions().ClientType(mtest.Mock))
	mt.Run("token expires after order crawl", func(mt *mtest.T) {
		namespace := mt.DB.Name() + "." + mt.Coll.Name()
		mt.AddMockResponses(
			mtest.CreateCursorResponse(0, namespace, mtest.FirstBatch, bson.D{
				{Key: "access_token", Value: "old-token"},
				{Key: "expires_at", Value: time.Now().Add(6 * time.Minute)},
			}),
			// Model the same credential after the crawl has outlived its expiry.
			mtest.CreateCursorResponse(0, namespace, mtest.FirstBatch, bson.D{
				{Key: "access_token", Value: "old-token"},
				{Key: "refresh_token", Value: "refresh-token"},
				{Key: "expires_at", Value: time.Now().Add(-time.Minute)},
			}),
			mtest.CreateSuccessResponse(bson.E{Key: "value", Value: bson.D{}}),
		)
		var oldRequests, freshRequests, refreshRequests atomic.Int32
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case fulfillmentAPI + "order":
				if r.Header.Get("Authorization") != "Bearer old-token" {
					mt.Error("order crawl did not use the initial token")
				}
				json.NewEncoder(w).Encode(GetOrdersResponse{
					Total: 1, Orders: []Order{{OrderID: "shipped", FulfillmentStatus: "FULFILLED"}},
				})
			case fulfillmentAPI + "order/shipped/shipping_fulfillment":
				if r.Header.Get("Authorization") == "Bearer old-token" {
					oldRequests.Add(1)
					w.WriteHeader(http.StatusUnauthorized)
					return
				}
				if r.Header.Get("Authorization") != "Bearer fresh-token" {
					mt.Errorf("unexpected retry authorization: %q", r.Header.Get("Authorization"))
				}
				freshRequests.Add(1)
				json.NewEncoder(w).Encode(shippingFulfillmentsResponse{
					Fulfillments: []ShippingFulfillment{{ShipmentTrackingNumber: "tracking-1"}},
				})
			case "/token":
				refreshRequests.Add(1)
				if err := r.ParseForm(); err != nil || r.Form.Get("grant_type") != "refresh_token" || r.Form.Get("refresh_token") != "refresh-token" {
					mt.Errorf("unexpected token refresh request: %v, %v", r.Form, err)
				}
				json.NewEncoder(w).Encode(map[string]any{"access_token": "fresh-token", "expires_in": 3600})
			default:
				mt.Errorf("unexpected request: %s", r.URL)
				http.NotFound(w, r)
			}
		}))
		defer server.Close()
		client := &Client{Client: server.Client(), SellURL: server.URL, Auth: &auth.Client{
			Client: server.Client(), DB: mt.Coll, AuthURL: server.URL + "/token",
		}}
		ctx := context.WithValue(context.Background(), "userId", "tenant-1")
		ctx = context.WithValue(ctx, auth.USER, "seller-1")
		got, err := client.GetOrders(ctx)
		if err != nil || len(got.Orders) != 1 || len(got.Orders[0].ShippingFulfillments) != 1 || got.Orders[0].ShippingFulfillments[0].ShipmentTrackingNumber != "tracking-1" {
			mt.Fatalf("expired token lost tracking details: got=%#v err=%v", got, err)
		}
		if oldRequests.Load() != 1 || freshRequests.Load() != 1 || refreshRequests.Load() != 1 {
			mt.Fatalf("expected one failed lookup, one refresh, and one retry: old=%d refresh=%d fresh=%d", oldRequests.Load(), refreshRequests.Load(), freshRequests.Load())
		}
	})
}

func TestGetOrdersBoundsFulfillmentRetries(t *testing.T) {
	mt := mtest.New(t, mtest.NewOptions().ClientType(mtest.Mock))
	for _, status := range []int{http.StatusUnauthorized, http.StatusServiceUnavailable} {
		mt.Run(http.StatusText(status), func(mt *mtest.T) {
			wantAttempts := int32(1)
			if status == http.StatusUnauthorized {
				wantAttempts = 2
			}
			for i := int32(0); i < wantAttempts; i++ {
				mt.AddMockResponses(mtest.CreateCursorResponse(0, mt.DB.Name()+"."+mt.Coll.Name(), mtest.FirstBatch, bson.D{
					{Key: "access_token", Value: "token"},
					{Key: "expires_at", Value: time.Now().Add(time.Hour)},
				}))
			}
			var attempts atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == fulfillmentAPI+"order" {
					json.NewEncoder(w).Encode(GetOrdersResponse{
						Total: 1, Orders: []Order{{OrderID: "shipped", FulfillmentStatus: "FULFILLED"}},
					})
					return
				}
				attempts.Add(1)
				w.WriteHeader(status)
			}))
			defer server.Close()
			client := &Client{Client: server.Client(), SellURL: server.URL, Auth: &auth.Client{DB: mt.Coll}}
			ctx := context.WithValue(context.Background(), "userId", "tenant-1")
			ctx = context.WithValue(ctx, auth.USER, "seller-1")
			got, err := client.GetOrders(ctx)
			if err != nil || len(got.Orders) != 1 {
				mt.Fatalf("shipping error should preserve the order: got=%#v err=%v", got, err)
			}
			if attempts.Load() != wantAttempts || len(mt.GetAllStartedEvents()) != int(wantAttempts) {
				mt.Fatalf("status %d: attempts=%d database reads=%d, want %d", status, attempts.Load(), len(mt.GetAllStartedEvents()), wantAttempts)
			}
		})
	}
}
