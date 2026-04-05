package main

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"

	"github.tesla.com/chrzhang/sealift/notes"
)

func (s *Server) handleGetNotes(w http.ResponseWriter, r *http.Request) {
	userID, _ := r.Context().Value("userId").(string)
	notesDB := s.notesCol
	allNotes, err := notes.GetNotes(r.Context(), notesDB, userID)
	if err != nil {
		slog.Error("failed to get notes", "err", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(allNotes)
}

func (s *Server) handleCreateNote(w http.ResponseWriter, r *http.Request) {
	userID, _ := r.Context().Value("userId").(string)
	var req struct {
		Content string `json:"content"`
		Color   string `json:"color"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		slog.Error("invalid json", "err", err)
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}

	notesDB := s.notesCol
	err := notes.CreateNote(r.Context(), notesDB, userID, req.Content, req.Color)
	if err != nil {
		slog.Error("failed to create note", "err", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "OK")
}

func (s *Server) handleUpdateNote(w http.ResponseWriter, r *http.Request) {
	userID, _ := r.Context().Value("userId").(string)
	id := r.PathValue("id")
	if id == "" {
		slog.Error("id not specified")
		http.Error(w, "id not specified.", http.StatusBadRequest)
		return
	}

	var req struct {
		Content string `json:"content"`
		Color   string `json:"color"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		slog.Error("invalid json", "err", err)
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}

	notesDB := s.notesCol
	err := notes.UpdateNote(r.Context(), notesDB, userID, id, req.Content, req.Color)
	if err != nil {
		slog.Error("failed to update note", "err", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "OK")
}

func (s *Server) handleDeleteNote(w http.ResponseWriter, r *http.Request) {
	userID, _ := r.Context().Value("userId").(string)
	id := r.PathValue("id")
	if id == "" {
		slog.Error("id not specified")
		http.Error(w, "id not specified.", http.StatusBadRequest)
		return
	}

	notesDB := s.notesCol
	err := notes.DeleteNote(r.Context(), notesDB, userID, id)
	if err != nil {
		slog.Error("failed to delete notes", "err", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "OK")
}
