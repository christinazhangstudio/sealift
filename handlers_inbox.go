package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.tesla.com/chrzhang/sealift/ebay"
	"github.tesla.com/chrzhang/sealift/inbox"
	"go.mongodb.org/mongo-driver/bson"
)

// assertSellerOwnedByTenant confirms the eBay seller in the path belongs to the
// authenticated tenant. Inbox documents are keyed by eBay username with no
// tenant field, so without this any signed-in user could read or destroy
// another tenant's notifications by guessing a (public) seller name.
func (s *Server) assertSellerOwnedByTenant(w http.ResponseWriter, r *http.Request, ebayUser string) bool {
	userID, ok := r.Context().Value("userId").(string)
	if !ok || userID == "" {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return false
	}

	var check bson.M
	if err := s.ebayAccountsCol.FindOne(r.Context(), bson.M{
		"user":            ebayUser,
		"sealift_user_id": userID,
	}).Decode(&check); err != nil {
		slog.Warn("rejected inbox access for unowned seller", "user", ebayUser, "userId", userID)
		http.Error(w, "Access Denied", http.StatusForbidden)
		return false
	}
	return true
}

// handleTrashNotification trashes a specific notification.
func (s *Server) handleTrashNotification(w http.ResponseWriter, r *http.Request) {
	user := r.PathValue("user")
	notificationID := r.PathValue("notificationId")
	if user == "" || notificationID == "" {
		http.Error(w, "missing user or notification id", http.StatusBadRequest)
		return
	}

	if !s.assertSellerOwnedByTenant(w, r, user) {
		return
	}

	slog.Info("trashing notification", "user", user, "notificationId", notificationID)
	if err := s.inboxReceiver.TrashNotification(r.Context(), user, notificationID); err != nil {
		slog.Error("failed to trash notification", "err", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "OK")
}

// handleMarkRead marks a specific notification as read in the inbox.
func (s *Server) handleMarkRead(w http.ResponseWriter, r *http.Request) {
	user := r.PathValue("user")
	notificationID := r.PathValue("notificationId")
	if user == "" || notificationID == "" {
		http.Error(w, "missing user or notification id", http.StatusBadRequest)
		return
	}

	if !s.assertSellerOwnedByTenant(w, r, user) {
		return
	}

	slog.Info("marking notification as read", "user", user, "notificationId", notificationID)
	if err := s.inboxReceiver.ReadNotification(r.Context(), user, notificationID); err != nil {
		slog.Error("failed to mark notification as read", "err", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "OK")
}

// handleDeletePermanent permanently deletes a specific notification from trash.
func (s *Server) handleDeletePermanent(w http.ResponseWriter, r *http.Request) {
	user := r.PathValue("user")
	notificationID := r.PathValue("notificationId")
	if user == "" || notificationID == "" {
		http.Error(w, "missing user or notification id", http.StatusBadRequest)
		return
	}

	if !s.assertSellerOwnedByTenant(w, r, user) {
		return
	}

	slog.Info("permanently deleting notification", "user", user, "notificationId", notificationID)
	if err := s.inboxReceiver.DeletePermanent(r.Context(), user, notificationID); err != nil {
		slog.Error("failed to permanently delete notification", "err", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "OK")
}

// handleSSEStream provides a Server-Sent Events stream for frontend updates.
func (s *Server) handleSSEStream(w http.ResponseWriter, r *http.Request) {
	ebayUser := r.PathValue("user")
	userID, ok := r.Context().Value("userId").(string)
	if !ok || userID == "" {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// Verify store ownership
	var check bson.M
	err := s.ebayAccountsCol.FindOne(r.Context(), bson.M{"user": ebayUser, "sealift_user_id": userID}).Decode(&check)
	if err != nil {
		slog.Error("Unauthorized SSE attempt", "user", ebayUser, "userId", userID, "err", err)
		http.Error(w, "Access Denied", http.StatusForbidden)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	// Disable proxy buffering (nginx) so pushes aren't held back.
	w.Header().Set("X-Accel-Buffering", "no")

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming unsupported", http.StatusInternalServerError)
		return
	}

	connChan := make(chan map[string]interface{}, 100)
	s.inboxReceiver.AddClient(ebayUser, connChan)
	defer func() {
		s.inboxReceiver.RemoveClient(ebayUser, connChan)
		close(connChan)
	}()

	// Establish the stream immediately. Without this the response headers are
	// withheld until the first notification arrives, which browsers and proxies
	// treat as a hung request and retry.
	fmt.Fprint(w, "retry: 5000\n: connected\n\n")
	flusher.Flush()

	userWebhooks, err := s.inboxReceiver.GetPastNotifications(r.Context(), ebayUser)
	if err != nil {
		slog.Error("failed to load past notifications", "err", err, "user", ebayUser)
		userWebhooks = []map[string]interface{}{}
	}
	// Always send initial (even empty) so the client knows the backlog is loaded.
	data, _ := json.Marshal(userWebhooks)
	fmt.Fprintf(w, "event: initial\ndata: %s\n\n", data)
	flusher.Flush()

	// Reconcile eBay's Message API in the background so historical retrieval
	// never delays or breaks the existing stream. Newly discovered messages are
	// emitted as one batch after they have been persisted in MongoDB.
	type historyResult struct {
		payloads []map[string]interface{}
		err      error
	}
	historyChan := make(chan historyResult, 1)
	go func() {
		payloads, err := s.syncEbayMessageHistory(r.Context(), userID, ebayUser)
		historyChan <- historyResult{payloads: payloads, err: err}
	}()

	// Cloudflare drops idle connections after ~100s; heartbeat well inside that
	// so the stream survives quiet periods instead of reconnect-looping.
	heartbeat := time.NewTicker(25 * time.Second)
	defer heartbeat.Stop()

	for {
		select {
		case msg := <-connChan:
			data, _ := json.Marshal(msg)
			fmt.Fprintf(w, "event: message\ndata: %s\n\n", data)
			flusher.Flush()
		case result := <-historyChan:
			if result.err != nil {
				slog.Warn("eBay message history reconciliation failed", "err", result.err, "user", ebayUser)
			} else if len(result.payloads) > 0 {
				data, _ := json.Marshal(result.payloads)
				fmt.Fprintf(w, "event: history\ndata: %s\n\n", data)
				flusher.Flush()
				slog.Info("reconciled eBay message history", "user", ebayUser, "inserted", len(result.payloads))
			}
			// A nil channel disables this select case after the one sync result.
			historyChan = nil
		case <-heartbeat.C:
			fmt.Fprint(w, ": keepalive\n\n")
			flusher.Flush()
		case <-r.Context().Done():
			return
		}
	}
}

// syncEbayMessageHistory imports messages eBay still exposes into the same
// collection and payload contract used by NEW_MESSAGE webhooks. The first run
// is a full backfill; later runs overlap by a day to cover delayed updates.
func (s *Server) syncEbayMessageHistory(
	ctx context.Context,
	tenantID string,
	ebayUser string,
) ([]map[string]interface{}, error) {
	client, _, err := s.getEbayClientForUser(ctx, tenantID)
	if err != nil {
		return nil, err
	}

	var account struct {
		MessageHistorySyncedAt time.Time `bson:"message_history_synced_at"`
	}
	if err := s.ebayAccountsCol.FindOne(ctx, bson.M{
		"user": ebayUser, "sealift_user_id": tenantID,
	}).Decode(&account); err != nil {
		return nil, fmt.Errorf("load message sync state: %w", err)
	}

	syncStartedAt := time.Now().UTC()
	var start *time.Time
	if !account.MessageHistorySyncedAt.IsZero() {
		overlapStart := account.MessageHistorySyncedAt.Add(-24 * time.Hour)
		start = &overlapStart
	}

	history, err := client.GetMessageHistory(ctx, ebayUser, start, syncStartedAt)
	if err != nil {
		return nil, err
	}

	notifications := make([]inbox.HistoricalNotification, 0, len(history))
	for _, item := range history {
		notification, ok := historicalNotification(ebayUser, item, syncStartedAt)
		if ok {
			notifications = append(notifications, notification)
		}
	}

	inserted, err := s.inboxReceiver.UpsertHistoricalNotifications(ctx, ebayUser, notifications)
	if err != nil {
		return nil, err
	}
	if _, err := s.ebayAccountsCol.UpdateOne(ctx, bson.M{
		"user": ebayUser, "sealift_user_id": tenantID,
	}, bson.M{"$set": bson.M{"message_history_synced_at": syncStartedAt}}); err != nil {
		return nil, fmt.Errorf("save message sync state: %w", err)
	}
	return inserted, nil
}

func historicalNotification(
	ebayUser string,
	item ebay.MessageHistoryItem,
	fallbackDate time.Time,
) (inbox.HistoricalNotification, bool) {
	message := item.Message
	if strings.TrimSpace(message.MessageID) == "" {
		return inbox.HistoricalNotification{}, false
	}

	createdAt, err := time.Parse(time.RFC3339, message.CreatedDate)
	if err != nil {
		createdAt = fallbackDate
	}
	read := message.ReadStatus || strings.EqualFold(message.SenderUsername, ebayUser)

	data := map[string]interface{}{
		"conversationId":    item.ConversationID,
		"conversationType":  item.ConversationType,
		"createdDate":       message.CreatedDate,
		"messageBody":       message.MessageBody,
		"messageId":         message.MessageID,
		"messageMedia":      message.MessageMedia,
		"readStatus":        message.ReadStatus,
		"recipientUserName": message.RecipientUsername,
		"senderUserName":    message.SenderUsername,
		"subject":           message.Subject,
	}
	if item.ReferenceID != "" {
		data["referenceId"] = item.ReferenceID
		data["referenceType"] = item.ReferenceType
	}

	payload := map[string]interface{}{
		"metadata": map[string]interface{}{
			"deprecated":    false,
			"schemaVersion": "1.0",
			"source":        "MESSAGE_API",
			"topic":         "NEW_MESSAGE",
		},
		"notification": map[string]interface{}{
			"data":                data,
			"eventDate":           createdAt.UTC().Format(time.RFC3339Nano),
			"notificationId":      "ebay-message-" + message.MessageID,
			"publishAttemptCount": 1,
			"publishDate":         createdAt.UTC().Format(time.RFC3339Nano),
		},
	}

	return inbox.HistoricalNotification{
		MessageID: message.MessageID,
		Payload:   payload,
		CreatedAt: createdAt,
		Read:      read,
	}, true
}
