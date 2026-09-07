package ebay

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.tesla.com/chrzhang/sealift/auth"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo/integration/mtest"
)

func TestTradingAcknowledgements(t *testing.T) {
	mt := mtest.New(t, mtest.NewOptions().ClientType(mtest.Mock))
	operations := []struct {
		name    string
		payload string
		call    func(*Client, context.Context) (any, error)
		check   func(*testing.T, any)
	}{
		{
			name:    "GetSellerList",
			payload: `<HasMoreItems>true</HasMoreItems><ItemArray><Item><ItemID>listing-1</ItemID></Item></ItemArray>`,
			call: func(c *Client, ctx context.Context) (any, error) {
				return c.GetSellerList(ctx, 200, 1, time.Now().Add(-time.Hour), time.Now())
			},
			check: func(t *testing.T, response any) {
				got := response.(*SellerListResponse)
				if !got.HasMoreItems || len(got.ItemArray.Items) != 1 || got.ItemArray.Items[0].ItemID != "listing-1" {
					t.Fatalf("lost listing data: %#v", got)
				}
			},
		},
		{
			name:    "GetAccount",
			payload: `<AccountID>account-1</AccountID>`,
			call: func(c *Client, ctx context.Context) (any, error) {
				return c.GetAccount(ctx, 200, 1)
			},
			check: func(t *testing.T, response any) {
				if got := response.(*AccountResponse); got.AccountID != "account-1" {
					t.Fatalf("lost account data: %#v", got)
				}
			},
		},
		{
			name:    "GetItem",
			payload: `<Item><ItemID>listing-1</ItemID></Item>`,
			call: func(c *Client, ctx context.Context) (any, error) {
				return c.GetItem(ctx, "listing-1")
			},
			check: func(t *testing.T, response any) {
				if got := response.(*Item); got.ItemID != "listing-1" {
					t.Fatalf("lost item data: %#v", got)
				}
			},
		},
	}
	for _, operation := range operations {
		for _, ack := range []string{"Success", "Warning", "Failure", "PartialFailure", ""} {
			mt.Run(operation.name+"/"+ack, func(mt *mtest.T) {
				mt.AddMockResponses(mtest.CreateCursorResponse(0, mt.DB.Name()+"."+mt.Coll.Name(), mtest.FirstBatch, bson.D{
					{Key: "access_token", Value: "test-token"},
					{Key: "expires_at", Value: time.Now().Add(time.Hour)},
				}))
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if got := r.Header.Get("X-EBAY-API-CALL-NAME"); got != operation.name {
						mt.Errorf("call name = %q, want %q", got, operation.name)
					}
					details := ""
					if ack != "Success" && ack != "" {
						details = `<Errors><ErrorCode>123</ErrorCode><ShortMessage>Short detail</ShortMessage><LongMessage>Upstream detail</LongMessage><SeverityCode>`
						if ack == "Warning" {
							details += "Warning"
						} else {
							details += "Error"
						}
						details += `</SeverityCode></Errors>`
					}
					fmt.Fprintf(w, `<%sResponse xmlns="urn:ebay:apis:eBLBaseComponents"><Ack>%s</Ack>%s%s</%sResponse>`,
						operation.name, ack, details, operation.payload, operation.name)
				}))
				defer server.Close()
				client := &Client{Client: server.Client(), TradURL: server.URL, Auth: &auth.Client{DB: mt.Coll}}
				ctx := context.WithValue(context.Background(), "userId", "tenant-1")
				ctx = context.WithValue(ctx, auth.USER, "seller-1")
				got, err := operation.call(client, ctx)
				if ack == "Success" || ack == "Warning" {
					if err != nil {
						mt.Fatalf("successful response rejected: %v", err)
					}
					operation.check(mt.T, got)
					return
				}
				var apiErr *TradingAPIError
				if !errors.As(err, &apiErr) || apiErr.Ack != ack || apiErr.Call != operation.name {
					mt.Fatalf("expected TradingAPIError for %q, got %v", ack, err)
				}
				if ack != "" && (!strings.Contains(err.Error(), "123") || !strings.Contains(err.Error(), "Upstream detail")) {
					mt.Fatalf("lost upstream error detail: %v", err)
				}
			})
		}
	}
}

func TestGetSellerListEmptySuccess(t *testing.T) {
	mt := mtest.New(t, mtest.NewOptions().ClientType(mtest.Mock))
	mt.Run("empty item array", func(mt *mtest.T) {
		mt.AddMockResponses(mtest.CreateCursorResponse(0, mt.DB.Name()+"."+mt.Coll.Name(), mtest.FirstBatch, bson.D{
			{Key: "access_token", Value: "test-token"},
			{Key: "expires_at", Value: time.Now().Add(time.Hour)},
		}))
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprint(w, `<GetSellerListResponse><Ack>Success</Ack><HasMoreItems>false</HasMoreItems><ItemArray/></GetSellerListResponse>`)
		}))
		defer server.Close()
		client := &Client{Client: server.Client(), TradURL: server.URL, Auth: &auth.Client{DB: mt.Coll}}
		ctx := context.WithValue(context.Background(), "userId", "tenant-1")
		ctx = context.WithValue(ctx, auth.USER, "seller-1")
		got, err := client.GetSellerList(ctx, 200, 1, time.Now().Add(-time.Hour), time.Now())
		if err != nil || got == nil || got.HasMoreItems || len(got.ItemArray.Items) != 0 {
			mt.Fatalf("empty seller list must remain successful: got=%#v err=%v", got, err)
		}
	})
}

func TestDoXMLRejectsHTTPFailure(t *testing.T) {
	for _, body := range []string{
		`<GetSellerListResponse><Ack>Success</Ack></GetSellerListResponse>`,
		`upstream unavailable`,
	} {
		t.Run(body, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusServiceUnavailable)
				fmt.Fprint(w, body)
			}))
			defer server.Close()
			client := &Client{Client: server.Client(), TradURL: server.URL, Auth: &auth.Client{}}
			var response SellerListResponse
			err := client.doXML(context.Background(), "GetSellerList", "967", SellerListRequest{}, &response)
			var apiErr *APIError
			if !errors.As(err, &apiErr) || apiErr.StatusCode != http.StatusServiceUnavailable || string(apiErr.Body) != body {
				t.Fatalf("expected original HTTP failure, got %v", err)
			}
		})
	}
}
