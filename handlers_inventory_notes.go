package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

const inventoryNoteMaxLength = 4000

var errInventorySellerNotOwned = errors.New("inventory seller not owned by tenant")

type inventoryNote struct {
	ID        primitive.ObjectID `bson:"_id,omitempty" json:"-"`
	TenantID  primitive.ObjectID `bson:"tenantId" json:"-"`
	Seller    string             `bson:"seller" json:"seller"`
	ItemID    string             `bson:"itemId" json:"itemId"`
	Body      string             `bson:"body" json:"body"`
	CreatedAt time.Time          `bson:"createdAt" json:"createdAt"`
	UpdatedAt time.Time          `bson:"updatedAt" json:"updatedAt"`
}

type inventoryNoteStore interface {
	List(context.Context, string, string) ([]inventoryNote, error)
	Upsert(context.Context, string, string, string, string) (inventoryNote, error)
	Delete(context.Context, string, string, string) error
	DeleteTenant(context.Context, string) error
}

type mongoInventoryNoteStore struct {
	notes        *mongo.Collection
	ebayAccounts *mongo.Collection
}

func (store *mongoInventoryNoteStore) tenantObjectID(tenantID string) (primitive.ObjectID, error) {
	return primitive.ObjectIDFromHex(tenantID)
}

func (store *mongoInventoryNoteStore) assertSellerOwned(ctx context.Context, tenantID, seller string) error {
	var account bson.M
	err := store.ebayAccounts.FindOne(ctx, bson.M{
		"sealift_user_id": tenantID,
		"user":            seller,
	}).Decode(&account)
	if errors.Is(err, mongo.ErrNoDocuments) {
		return errInventorySellerNotOwned
	}
	return err
}

func (store *mongoInventoryNoteStore) List(ctx context.Context, tenantID, seller string) ([]inventoryNote, error) {
	if err := store.assertSellerOwned(ctx, tenantID, seller); err != nil {
		return nil, err
	}
	tenantObjectID, err := store.tenantObjectID(tenantID)
	if err != nil {
		return nil, err
	}

	cursor, err := store.notes.Find(ctx, bson.M{
		"tenantId": tenantObjectID,
		"seller":   seller,
	}, options.Find().SetSort(bson.D{{Key: "updatedAt", Value: -1}}))
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	notes := make([]inventoryNote, 0)
	if err := cursor.All(ctx, &notes); err != nil {
		return nil, err
	}
	return notes, nil
}

func (store *mongoInventoryNoteStore) Upsert(
	ctx context.Context,
	tenantID, seller, itemID, body string,
) (inventoryNote, error) {
	if err := store.assertSellerOwned(ctx, tenantID, seller); err != nil {
		return inventoryNote{}, err
	}
	tenantObjectID, err := store.tenantObjectID(tenantID)
	if err != nil {
		return inventoryNote{}, err
	}

	now := time.Now().UTC()
	filter := bson.M{"tenantId": tenantObjectID, "seller": seller, "itemId": itemID}
	update := bson.M{
		"$set": bson.M{
			"body":      body,
			"updatedAt": now,
		},
		"$setOnInsert": bson.M{
			"tenantId":  tenantObjectID,
			"seller":    seller,
			"itemId":    itemID,
			"createdAt": now,
		},
	}

	var note inventoryNote
	err = store.notes.FindOneAndUpdate(
		ctx,
		filter,
		update,
		options.FindOneAndUpdate().SetUpsert(true).SetReturnDocument(options.After),
	).Decode(&note)
	return note, err
}

func (store *mongoInventoryNoteStore) Delete(ctx context.Context, tenantID, seller, itemID string) error {
	if err := store.assertSellerOwned(ctx, tenantID, seller); err != nil {
		return err
	}
	tenantObjectID, err := store.tenantObjectID(tenantID)
	if err != nil {
		return err
	}
	_, err = store.notes.DeleteOne(ctx, bson.M{
		"tenantId": tenantObjectID,
		"seller":   seller,
		"itemId":   itemID,
	})
	return err
}

func (store *mongoInventoryNoteStore) DeleteTenant(ctx context.Context, tenantID string) error {
	tenantObjectID, err := store.tenantObjectID(tenantID)
	if err != nil {
		return err
	}
	_, err = store.notes.DeleteMany(ctx, bson.M{"tenantId": tenantObjectID})
	return err
}

func inventoryNoteRequestValues(r *http.Request) (tenantID, seller, itemID string, ok bool) {
	tenantID, ok = r.Context().Value("userId").(string)
	if !ok || strings.TrimSpace(tenantID) == "" {
		return "", "", "", false
	}
	return tenantID, strings.TrimSpace(r.PathValue("user")), strings.TrimSpace(r.PathValue("itemId")), true
}

func writeInventoryNoteError(w http.ResponseWriter, err error) {
	if errors.Is(err, errInventorySellerNotOwned) {
		http.Error(w, "Access Denied", http.StatusForbidden)
		return
	}
	http.Error(w, "Failed to persist inventory note", http.StatusInternalServerError)
}

func (s *Server) handleListInventoryNotes(w http.ResponseWriter, r *http.Request) {
	tenantID, seller, _, ok := inventoryNoteRequestValues(r)
	if !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	if seller == "" {
		http.Error(w, "missing seller", http.StatusBadRequest)
		return
	}

	notes, err := s.inventoryNotes.List(r.Context(), tenantID, seller)
	if err != nil {
		writeInventoryNoteError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(struct {
		Notes []inventoryNote `json:"notes"`
	}{Notes: notes})
}

func (s *Server) handleUpsertInventoryNote(w http.ResponseWriter, r *http.Request) {
	tenantID, seller, itemID, ok := inventoryNoteRequestValues(r)
	if !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	if seller == "" || itemID == "" {
		http.Error(w, "missing seller or item id", http.StatusBadRequest)
		return
	}

	var input struct {
		Body string `json:"body"`
	}
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16*1024))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&input); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	input.Body = strings.TrimSpace(input.Body)
	if input.Body == "" {
		http.Error(w, "note cannot be empty", http.StatusBadRequest)
		return
	}
	if utf8.RuneCountInString(input.Body) > inventoryNoteMaxLength {
		http.Error(w, "note exceeds 4000 characters", http.StatusBadRequest)
		return
	}

	note, err := s.inventoryNotes.Upsert(r.Context(), tenantID, seller, itemID, input.Body)
	if err != nil {
		writeInventoryNoteError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(note)
}

func (s *Server) handleDeleteInventoryNote(w http.ResponseWriter, r *http.Request) {
	tenantID, seller, itemID, ok := inventoryNoteRequestValues(r)
	if !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	if seller == "" || itemID == "" {
		http.Error(w, "missing seller or item id", http.StatusBadRequest)
		return
	}

	if err := s.inventoryNotes.Delete(r.Context(), tenantID, seller, itemID); err != nil {
		writeInventoryNoteError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
