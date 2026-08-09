package ebay

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	messageAPI      = "/commerce/message/v1/"
	messagePageSize = 10 // eBay's documented maximum for conversation searches.
)

// MessageDetail is the common message representation returned by both
// getConversations (as latestMessage) and getConversation.
type MessageDetail struct {
	CreatedDate       string                   `json:"createdDate"`
	MessageBody       string                   `json:"messageBody"`
	MessageID         string                   `json:"messageId"`
	MessageMedia      []map[string]interface{} `json:"messageMedia,omitempty"`
	ReadStatus        bool                     `json:"readStatus"`
	RecipientUsername string                   `json:"recipientUsername"`
	SenderUsername    string                   `json:"senderUsername"`
	Subject           string                   `json:"subject"`
}

type ConversationDetail struct {
	ConversationID     string        `json:"conversationId"`
	ConversationStatus string        `json:"conversationStatus"`
	ConversationTitle  string        `json:"conversationTitle"`
	ConversationType   string        `json:"conversationType"`
	CreatedDate        string        `json:"createdDate"`
	LatestMessage      MessageDetail `json:"latestMessage"`
	ReferenceID        string        `json:"referenceId,omitempty"`
	ReferenceType      string        `json:"referenceType,omitempty"`
	UnreadCount        int           `json:"unreadCount"`
}

type MessageHistoryItem struct {
	ConversationID    string
	ConversationType  string
	ConversationTitle string
	ReferenceID       string
	ReferenceType     string
	Message           MessageDetail
}

type conversationsPage struct {
	Conversations []ConversationDetail `json:"conversations"`
	Limit         int                  `json:"limit"`
	Offset        int                  `json:"offset"`
	Total         int                  `json:"total"`
	Next          string               `json:"next"`
}

type messagesPage struct {
	Messages []MessageDetail `json:"messages"`
	Limit    int             `json:"limit"`
	Offset   int             `json:"offset"`
	Total    int             `json:"total"`
	Next     string          `json:"next"`
}

// GetMessageHistory retrieves every message in each conversation visible in
// the requested time window. A nil start performs the first full backfill;
// later reconciliations can use a bounded overlap window.
func (c *Client) GetMessageHistory(
	ctx context.Context,
	user string,
	start *time.Time,
	end time.Time,
) ([]MessageHistoryItem, error) {
	token, err := c.Auth.GetToken(ctx, user)
	if err != nil {
		return nil, fmt.Errorf("failed to get user token for message history: %w", err)
	}

	conversations, err := c.getAllConversations(ctx, token, start, end)
	if err != nil {
		return nil, err
	}

	history := make([]MessageHistoryItem, 0)
	for _, conversation := range conversations {
		if strings.TrimSpace(conversation.ConversationID) == "" ||
			strings.TrimSpace(conversation.ConversationType) == "" {
			continue
		}

		messages, err := c.getAllConversationMessages(
			ctx, token, conversation.ConversationID, conversation.ConversationType,
		)
		if err != nil {
			return nil, fmt.Errorf("get conversation %s: %w", conversation.ConversationID, err)
		}
		for _, message := range messages {
			if strings.TrimSpace(message.MessageID) == "" {
				continue
			}
			history = append(history, MessageHistoryItem{
				ConversationID:    conversation.ConversationID,
				ConversationType:  conversation.ConversationType,
				ConversationTitle: conversation.ConversationTitle,
				ReferenceID:       conversation.ReferenceID,
				ReferenceType:     conversation.ReferenceType,
				Message:           message,
			})
		}
	}

	return history, nil
}

func (c *Client) getAllConversations(
	ctx context.Context,
	token string,
	start *time.Time,
	end time.Time,
) ([]ConversationDetail, error) {
	all := make([]ConversationDetail, 0)
	for offset := 0; ; offset += messagePageSize {
		query := url.Values{}
		query.Set("limit", strconv.Itoa(messagePageSize))
		query.Set("offset", strconv.Itoa(offset))
		if start != nil {
			query.Set("start_time", start.UTC().Format(time.RFC3339Nano))
			query.Set("end_time", end.UTC().Format(time.RFC3339Nano))
		}

		var page conversationsPage
		requestURL := c.NotificationURL + messageAPI + "conversation?" + query.Encode()
		if err := c.doJSON(ctx, http.MethodGet, requestURL, token, nil, &page); err != nil {
			return nil, fmt.Errorf("get conversations: %w", err)
		}
		all = append(all, page.Conversations...)
		if len(page.Conversations) < messagePageSize ||
			(page.Total > 0 && offset+len(page.Conversations) >= page.Total) {
			break
		}
	}
	return all, nil
}

func (c *Client) getAllConversationMessages(
	ctx context.Context,
	token string,
	conversationID string,
	conversationType string,
) ([]MessageDetail, error) {
	all := make([]MessageDetail, 0)
	for offset := 0; ; offset += messagePageSize {
		query := url.Values{}
		query.Set("conversation_type", conversationType)
		query.Set("limit", strconv.Itoa(messagePageSize))
		query.Set("offset", strconv.Itoa(offset))

		var page messagesPage
		requestURL := c.NotificationURL + messageAPI + "conversation/" +
			url.PathEscape(conversationID) + "?" + query.Encode()
		if err := c.doJSON(ctx, http.MethodGet, requestURL, token, nil, &page); err != nil {
			return nil, err
		}
		all = append(all, page.Messages...)
		if len(page.Messages) < messagePageSize ||
			(page.Total > 0 && offset+len(page.Messages) >= page.Total) {
			break
		}
	}
	return all, nil
}
