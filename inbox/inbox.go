package inbox

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// Example eBay Notification Payload (NEW_MESSAGE):
// {
// 	"metadata": {
// 		"deprecated": false,
// 		"schemaVersion": "1.0",
// 		"topic": "NEW_MESSAGE"
// 	},
// 	"notification": {
// 		"data": {
// 			"conversationId": "<conversationId>",
// 			"conversationType": "FROM_MEMBERS",
// 			"createdDate": "2025-04-21T08:16:20.000Z",
// 			"messageBody": "Is there a size standard?",
// 			"messageId": "<messageId>",
// 			"messageMedia": [
// 				{
// 					"mediaName": "",
// 					"mediaType": "",
// 					"mediaUrl": ""
// 				}
// 			],
// 			"readStatus": false,
// 			"recipientUserName": "skyhome-de",
// 			"senderUserName": "pwz796",
// 			"subject": ""
// 		},
// 		"eventDate": "2026-02-28T21:02:25.657Z",
// 		"notificationId": "<notificationId>",
// 		"publishAttemptCount": 1,
// 		"publishDate": "2026-02-28T21:02:25.849Z"
// 	}
// }

// inbox Receiver that receives notifications from platform POSTs to destination webhooks.
type Receiver struct {
	DB *mongo.Collection
	streamer
}

type streamer struct {
	conns     map[string][]chan map[string]interface{}
	connMutex sync.Mutex
}

// Init sets up the internal channel mapping so it's ready for broadcast routing.
func (s *streamer) Init() {
	s.conns = make(map[string][]chan map[string]interface{})
}

// PushNotification saves the notification to MongoDB according to the user
// and broadcasts it to all active SSE browser connections for that user.
func (r *Receiver) PushNotification(
	ctx context.Context,
	user string,
	notif map[string]interface{},
) error {
	var createdAt time.Time
	if notifInfo, ok := notif["notification"].(map[string]interface{}); ok {
		if eventDateStr, ok := notifInfo["eventDate"].(string); ok {
			parsedTime, err := time.Parse(time.RFC3339, eventDateStr)
			if err != nil {
				return fmt.Errorf("failed to parse eventDate from notification payload: %w", err)
			}

			createdAt = parsedTime
		}
	}

	doc := map[string]interface{}{
		"user":      user,
		"payload":   notif,
		"createdAt": createdAt,
	}

	_, err := r.DB.InsertOne(ctx, doc)
	if err != nil {
		return fmt.Errorf("failed to insert notification to mongo: %w", err)
	}

	// SSE broadcast
	if err := r.broadcast(user, notif); err != nil {
		return fmt.Errorf("failed to broadcast notification: %w", err)
	}

	return nil
}

func (s *streamer) broadcast(user string, notif map[string]interface{}) error {
	s.connMutex.Lock()
	defer s.connMutex.Unlock()
	if s.conns == nil {
		return errors.New("no active SSE connections; not initialized?")
	}

	if clients, ok := s.conns[user]; ok {
		for _, ch := range clients {
			select {
			case ch <- notif:
			default:
				// if channel is full, drop to prevent blocking
				// (the browser isn't reading SSE events fast enough)
				// (though, for fallback, at this point, mongoDB has already stored the notification)
			}
		}
	}

	return nil
}

// GetPastNotifications returns the recent notifications (max 50) for a user from MongoDB.
func (r *Receiver) GetPastNotifications(
	ctx context.Context,
	user string,
) ([]map[string]interface{}, error) {
	opts := options.Find().SetSort(bson.D{{Key: "createdAt", Value: -1}}).SetLimit(50)
	filter := bson.D{{Key: "user", Value: user}}

	result, err := r.DB.Find(ctx, filter, opts)
	if err != nil {
		return nil, err
	}
	defer result.Close(ctx)

	var results []map[string]interface{}
	if err = result.All(ctx, &results); err != nil {
		return nil, err
	}

	// Unpack the payload back to raw webhooks
	var notifs []map[string]interface{}
	for _, res := range results {
		if payload, ok := res["payload"].(map[string]interface{}); ok {
			trashed := false
			if resTrashed, ok := res["trashed"].(bool); ok {
				trashed = resTrashed
			}
			payload["sealift_trashed"] = trashed

			read := false
			if resRead, ok := res["read"].(bool); ok {
				read = resRead
			}
			payload["sealift_read"] = read

			notifs = append(notifs, payload)
		}
	}

	if notifs == nil {
		notifs = []map[string]interface{}{}
	}

	return notifs, nil
}

// TrashNotification marks a notification as trashed in MongoDB.
func (r *Receiver) TrashNotification(
	ctx context.Context,
	user string,
	notificationID string,
) error {
	filter := bson.M{
		"user":                                user,
		"payload.notification.notificationId": notificationID,
	}
	update := bson.M{
		"$set": bson.M{"trashed": true},
	}
	res, err := r.DB.UpdateMany(ctx, filter, update)
	if err != nil {
		return err
	}
	if res.MatchedCount == 0 {
		return errors.New("notification not found")
	}
	return nil
}

// ReadNotification marks a notification as read in MongoDB.
func (r *Receiver) ReadNotification(
	ctx context.Context,
	user string,
	notificationID string,
) error {
	filter := bson.M{
		"user":                                user,
		"payload.notification.notificationId": notificationID,
	}
	update := bson.M{
		"$set": bson.M{"read": true},
	}
	res, err := r.DB.UpdateMany(ctx, filter, update)
	if err != nil {
		return err
	}
	if res.MatchedCount == 0 {
		return errors.New("notification not found")
	}
	return nil
}

// DeletePermanent physically deletes a trashed notification from MongoDB.
func (r *Receiver) DeletePermanent(
	ctx context.Context,
	user string,
	notificationID string,
) error {
	filter := bson.M{
		"user":                                user,
		"payload.notification.notificationId": notificationID,
		"trashed":                             true,
	}
	res, err := r.DB.DeleteMany(ctx, filter)
	if err != nil {
		return err
	}
	if res.DeletedCount == 0 {
		return errors.New("trashed notification not found")
	}
	return nil
}

// AddClient adds a new SSE connection channel for a user's browser tab.
func (s *streamer) AddClient(
	user string,
	connChan chan map[string]interface{},
) {
	s.connMutex.Lock()
	defer s.connMutex.Unlock()

	s.conns[user] = append(s.conns[user], connChan)
}

// RemoveClient removes a specific SSE connection channel when the browser tab closes.
func (s *streamer) RemoveClient(
	user string,
	connChan chan map[string]interface{},
) {
	s.connMutex.Lock()
	defer s.connMutex.Unlock()

	if s.conns == nil {
		return
	}

	conns := s.conns[user]
	for i, ch := range conns {
		if ch == connChan {
			s.conns[user] = append(conns[:i], conns[i+1:]...)
			break
		}
	}
}
