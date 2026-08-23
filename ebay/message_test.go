package ebay

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"
)

func TestGetAllConversationsPaginatesAndAppliesWindow(t *testing.T) {
	start := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)
	end := time.Date(2026, 8, 9, 0, 0, 0, 0, time.UTC)
	requests := 0

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if r.URL.Query().Get("start_time") != start.Format(time.RFC3339Nano) ||
			r.URL.Query().Get("end_time") != end.Format(time.RFC3339Nano) {
			t.Errorf("missing history window: %s", r.URL.RawQuery)
		}
		if r.URL.Query().Get("conversation_type") != memberConversationType {
			t.Errorf("missing member conversation type: %s", r.URL.RawQuery)
		}
		offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
		conversations := make([]ConversationDetail, 0, messagePageSize)
		if offset == 0 {
			for i := 0; i < messagePageSize; i++ {
				conversations = append(conversations, ConversationDetail{ConversationID: strconv.Itoa(i)})
			}
		} else {
			conversations = append(conversations, ConversationDetail{ConversationID: "last"})
		}
		_ = json.NewEncoder(w).Encode(conversationsPage{
			Conversations: conversations,
			Limit:         messagePageSize,
			Offset:        offset,
			Total:         messagePageSize + 1,
		})
	}))
	defer server.Close()

	client := &Client{Client: server.Client(), NotificationURL: server.URL}
	got, err := client.getAllConversations(context.Background(), "token", &start, end)
	if err != nil {
		t.Fatal(err)
	}
	if requests != 2 || len(got) != messagePageSize+1 {
		t.Fatalf("requests=%d conversations=%d", requests, len(got))
	}
}

func TestGetAllConversationMessagesReturnsBothParticipants(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != messageAPI+"conversation/conversation-1" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		if r.URL.Query().Get("conversation_type") != memberConversationType {
			t.Errorf("missing conversation type: %s", r.URL.RawQuery)
		}
		_ = json.NewEncoder(w).Encode(messagesPage{
			Messages: []MessageDetail{
				{MessageID: "message-1", SenderUsername: "buyer-1", RecipientUsername: "seller-1"},
				{MessageID: "message-2", SenderUsername: "seller-1", RecipientUsername: "buyer-1"},
			},
			Total: 2,
		})
	}))
	defer server.Close()

	client := &Client{Client: server.Client(), NotificationURL: server.URL}
	got, err := client.getAllConversationMessages(
		context.Background(), "token", "conversation-1", memberConversationType,
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 ||
		got[0].SenderUsername != "buyer-1" ||
		got[1].SenderUsername != "seller-1" {
		t.Fatalf("conversation did not preserve both participants: %#v", got)
	}
}
