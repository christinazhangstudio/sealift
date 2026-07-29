package main

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"time"
)

// handleLiveness answers "is this process functioning?" and deliberately checks
// nothing external.
//
// Liveness failures get the container killed. Tying that to MongoDB would mean a
// database blip restarts every backend pod — turning a recoverable dependency
// outage into a crash loop that makes it worse. Dependency health belongs in
// readiness, which only removes the pod from load balancing.
func (s *Server) handleLiveness(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

// handleReadiness answers "can this process serve traffic right now?" — which
// means the database it needs for nearly every request is reachable.
func (s *Server) handleReadiness(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()

	if err := s.db.Client().Ping(ctx, nil); err != nil {
		slog.Warn("readiness check failed", "err", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		json.NewEncoder(w).Encode(map[string]string{
			"status": "unavailable",
			"reason": "database unreachable",
		})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ready"})
}
