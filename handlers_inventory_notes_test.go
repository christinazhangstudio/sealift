package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type fakeInventoryNoteStore struct {
	notes          []inventoryNote
	err            error
	upsertTenant   string
	upsertSeller   string
	upsertItemID   string
	upsertBody     string
	deleteTenant   string
	deleteSeller   string
	deleteItemID   string
	deletedAccount string
}

func (store *fakeInventoryNoteStore) List(_ context.Context, _, _ string) ([]inventoryNote, error) {
	return store.notes, store.err
}

func (store *fakeInventoryNoteStore) Upsert(
	_ context.Context,
	tenantID, seller, itemID, body string,
) (inventoryNote, error) {
	store.upsertTenant = tenantID
	store.upsertSeller = seller
	store.upsertItemID = itemID
	store.upsertBody = body
	if store.err != nil {
		return inventoryNote{}, store.err
	}
	return inventoryNote{
		Seller:    seller,
		ItemID:    itemID,
		Body:      body,
		CreatedAt: time.Date(2026, time.August, 23, 12, 0, 0, 0, time.UTC),
		UpdatedAt: time.Date(2026, time.August, 23, 12, 0, 0, 0, time.UTC),
	}, nil
}

func (store *fakeInventoryNoteStore) Delete(_ context.Context, tenantID, seller, itemID string) error {
	store.deleteTenant = tenantID
	store.deleteSeller = seller
	store.deleteItemID = itemID
	return store.err
}

func (store *fakeInventoryNoteStore) DeleteTenant(_ context.Context, tenantID string) error {
	store.deletedAccount = tenantID
	return store.err
}

func inventoryNoteRequest(method, target, body, seller, itemID string) *http.Request {
	request := httptest.NewRequest(method, target, strings.NewReader(body))
	request = request.WithContext(context.WithValue(request.Context(), "userId", "tenant-1"))
	request.SetPathValue("user", seller)
	request.SetPathValue("itemId", itemID)
	return request
}

func TestHandleListInventoryNotesReturnsSellerNotes(t *testing.T) {
	store := &fakeInventoryNoteStore{notes: []inventoryNote{{
		Seller: "seller-1",
		ItemID: "item-1",
		Body:   "Photograph the serial number.",
	}}}
	server := &Server{inventoryNotes: store}
	response := httptest.NewRecorder()

	server.handleListInventoryNotes(response, inventoryNoteRequest(http.MethodGet, "/api/inventory-notes/seller-1", "", "seller-1", ""))

	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	var payload struct {
		Notes []inventoryNote `json:"notes"`
	}
	if err := json.NewDecoder(response.Body).Decode(&payload); err != nil {
		t.Fatal(err)
	}
	if len(payload.Notes) != 1 || payload.Notes[0].Body != "Photograph the serial number." {
		t.Fatalf("unexpected notes: %#v", payload.Notes)
	}
}

func TestHandleUpsertInventoryNoteTrimsAndPersistsBody(t *testing.T) {
	store := &fakeInventoryNoteStore{}
	server := &Server{inventoryNotes: store}
	response := httptest.NewRecorder()
	body := `{"body":"  Keep the original packaging.  "}`

	server.handleUpsertInventoryNote(response, inventoryNoteRequest(
		http.MethodPut,
		"/api/inventory-notes/seller-1/item-1",
		body,
		"seller-1",
		"item-1",
	))

	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	if store.upsertTenant != "tenant-1" || store.upsertSeller != "seller-1" || store.upsertItemID != "item-1" {
		t.Fatalf("unexpected key: tenant=%q seller=%q item=%q", store.upsertTenant, store.upsertSeller, store.upsertItemID)
	}
	if store.upsertBody != "Keep the original packaging." {
		t.Fatalf("body was not normalized: %q", store.upsertBody)
	}
}

func TestHandleUpsertInventoryNoteRejectsInvalidBodies(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{name: "empty", body: `{"body":"   "}`},
		{name: "too long", body: `{"body":"` + strings.Repeat("é", inventoryNoteMaxLength+1) + `"}`},
		{name: "unknown field", body: `{"body":"valid","tenantId":"other"}`},
		{name: "trailing JSON", body: `{"body":"valid"}{}`},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			store := &fakeInventoryNoteStore{}
			server := &Server{inventoryNotes: store}
			response := httptest.NewRecorder()
			server.handleUpsertInventoryNote(response, inventoryNoteRequest(
				http.MethodPut,
				"/api/inventory-notes/seller-1/item-1",
				test.body,
				"seller-1",
				"item-1",
			))
			if response.Code != http.StatusBadRequest {
				t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
			}
			if store.upsertItemID != "" {
				t.Fatal("invalid note reached persistence")
			}
		})
	}
}

func TestInventoryNoteHandlersEnforceTenantAndOwnership(t *testing.T) {
	server := &Server{inventoryNotes: &fakeInventoryNoteStore{err: errInventorySellerNotOwned}}

	for _, method := range []string{http.MethodGet, http.MethodPut, http.MethodDelete} {
		response := httptest.NewRecorder()
		body := ""
		if method == http.MethodPut {
			body = `{"body":"valid"}`
		}
		request := inventoryNoteRequest(method, "/api/inventory-notes/seller-1/item-1", body, "seller-1", "item-1")
		switch method {
		case http.MethodGet:
			server.handleListInventoryNotes(response, request)
		case http.MethodPut:
			server.handleUpsertInventoryNote(response, request)
		case http.MethodDelete:
			server.handleDeleteInventoryNote(response, request)
		}
		if response.Code != http.StatusForbidden {
			t.Fatalf("method=%s status=%d body=%s", method, response.Code, response.Body.String())
		}
	}

	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/api/inventory-notes/seller-1", nil)
	server.handleListInventoryNotes(response, request)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("missing tenant status=%d", response.Code)
	}
}

func TestHandleDeleteInventoryNoteIsIdempotent(t *testing.T) {
	store := &fakeInventoryNoteStore{}
	server := &Server{inventoryNotes: store}
	response := httptest.NewRecorder()

	server.handleDeleteInventoryNote(response, inventoryNoteRequest(
		http.MethodDelete,
		"/api/inventory-notes/seller-1/item-1",
		"",
		"seller-1",
		"item-1",
	))

	if response.Code != http.StatusNoContent {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	if store.deleteTenant != "tenant-1" || store.deleteSeller != "seller-1" || store.deleteItemID != "item-1" {
		t.Fatalf("unexpected delete key: %#v", store)
	}
}

func TestWriteInventoryNoteErrorDoesNotExposeDatabaseFailure(t *testing.T) {
	response := httptest.NewRecorder()
	writeInventoryNoteError(response, errors.New("mongodb connection string secret"))
	if response.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d", response.Code)
	}
	if bytes.Contains(response.Body.Bytes(), []byte("connection string")) {
		t.Fatalf("internal error leaked: %s", response.Body.String())
	}
}
