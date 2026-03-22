package main

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"

	"go.mongodb.org/mongo-driver/bson"
)

// handleTrashNotification trashes a specific notification.
func (s *Server) handleTrashNotification(w http.ResponseWriter, r *http.Request) {
	user := r.PathValue("user")
	notificationID := r.PathValue("notificationId")
	if user == "" || notificationID == "" {
		http.Error(w, "missing user or notification id", http.StatusBadRequest)
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

	connChan := make(chan map[string]interface{}, 100)
	s.inboxReceiver.AddClient(ebayUser, connChan)
	defer func() {
		s.inboxReceiver.RemoveClient(ebayUser, connChan)
		close(connChan)
	}()

	userWebhooks, _ := s.inboxReceiver.GetPastNotifications(r.Context(), ebayUser)
	if len(userWebhooks) > 0 {
		data, _ := json.Marshal(userWebhooks)
		fmt.Fprintf(w, "event: initial\ndata: %s\n\n", data)
		w.(http.Flusher).Flush()
	}

	for {
		select {
		case msg := <-connChan:
			data, _ := json.Marshal(msg)
			fmt.Fprintf(w, "event: message\ndata: %s\n\n", data)
			w.(http.Flusher).Flush()
		case <-r.Context().Done():
			return
		}
	}
}
