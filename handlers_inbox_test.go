package main

import (
	"testing"
	"time"

	"github.tesla.com/chrzhang/sealift/ebay"
)

func TestHistoricalNotificationMatchesWebhookContract(t *testing.T) {
	item := ebay.MessageHistoryItem{
		ConversationID:   "conversation-1",
		ConversationType: "FROM_MEMBERS",
		ReferenceID:      "listing-1",
		ReferenceType:    "LISTING",
		Message: ebay.MessageDetail{
			CreatedDate:       "2026-08-01T12:34:56Z",
			MessageBody:       "Is this still available?",
			MessageID:         "message-1",
			ReadStatus:        false,
			RecipientUsername: "seller-1",
			SenderUsername:    "buyer-1",
			Subject:           "Question",
		},
	}

	notification, ok := historicalNotification("seller-1", item, time.Now())
	if !ok {
		t.Fatal("expected history item to be normalized")
	}
	if notification.MessageID != "message-1" || notification.Read {
		t.Fatalf("unexpected normalized metadata: %#v", notification)
	}

	metadata := notification.Payload["metadata"].(map[string]interface{})
	if metadata["topic"] != "NEW_MESSAGE" || metadata["source"] != "MESSAGE_API" {
		t.Fatalf("unexpected metadata: %#v", metadata)
	}
	notif := notification.Payload["notification"].(map[string]interface{})
	if notif["notificationId"] != "ebay-message-message-1" {
		t.Fatalf("unexpected notification id: %v", notif["notificationId"])
	}
	data := notif["data"].(map[string]interface{})
	if data["senderUserName"] != "buyer-1" || data["recipientUserName"] != "seller-1" {
		t.Fatalf("unexpected message participants: %#v", data)
	}
}

func TestHistoricalOutboundMessageIsAlreadyRead(t *testing.T) {
	item := ebay.MessageHistoryItem{
		ConversationID:   "conversation-1",
		ConversationType: "FROM_MEMBERS",
		Message: ebay.MessageDetail{
			CreatedDate:    "2026-08-01T12:34:56Z",
			MessageID:      "message-2",
			SenderUsername: "seller-1",
		},
	}

	notification, ok := historicalNotification("seller-1", item, time.Now())
	if !ok || !notification.Read {
		t.Fatalf("seller-authored history should not become unread: %#v", notification)
	}
}
