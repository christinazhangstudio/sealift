package main

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/alexedwards/argon2id"
	"github.tesla.com/chrzhang/sealift/secrets"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
)

// passwordResetTTL bounds how long a reset link stays usable. Short enough to
// limit exposure if the email is read by someone else, long enough to be
// practical.
const passwordResetTTL = time.Hour

// minPasswordLength is deliberately modest — length is the only rule, since
// composition rules push people toward predictable substitutions.
const minPasswordLength = 8

// handleGetSettings returns the tenant's own account settings. It never
// includes the password hash, and returns the eBay Cert ID only as a masked
// hint so the page can show which value is stored without disclosing it.
func (s *Server) handleGetSettings(w http.ResponseWriter, r *http.Request) {
	userID, _ := r.Context().Value("userId").(string)
	objID, err := primitive.ObjectIDFromHex(userID)
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	var user SealiftUser
	if err := s.sealiftUsersCol.FindOne(r.Context(), bson.M{"_id": objID}).Decode(&user); err != nil {
		http.Error(w, "Account not found", http.StatusNotFound)
		return
	}

	cfg := user.EbayDeveloperConfig
	// Decrypt only to derive the masked hint; the value itself is never sent.
	if plain, err := secrets.Decrypt(cfg.CertID); err == nil {
		cfg.CertID = plain
	} else {
		slog.Warn("could not decrypt cert id for masking", "err", err, "userID", userID)
		cfg.CertID = ""
	}


	json.NewEncoder(w).Encode(map[string]any{
		"email":     user.Email,
		"createdAt": user.CreatedAt,
		"ebayDeveloperConfig": map[string]any{
			"appId":       cfg.AppID,
			"devId":       cfg.DevID,
			"certIdHint":  maskSecret(cfg.CertID),
			"redirectUri": cfg.RedirectURI,
			"isSandbox":   cfg.IsSandbox,
		},
	})
}

// maskSecret renders a stored secret as a recognizable hint (last four
// characters) so a user can tell which value is saved without exposing it.
func maskSecret(secret string) string {
	if secret == "" {
		return ""
	}
	if len(secret) <= 4 {
		return "••••"
	}
	return "••••" + secret[len(secret)-4:]
}

// handleChangePassword updates the tenant's password after re-verifying the
// current one.
func (s *Server) handleChangePassword(w http.ResponseWriter, r *http.Request) {
	userID, _ := r.Context().Value("userId").(string)
	objID, err := primitive.ObjectIDFromHex(userID)
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	var req struct {
		CurrentPassword string `json:"currentPassword"`
		NewPassword     string `json:"newPassword"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}
	if len(req.NewPassword) < minPasswordLength {
		http.Error(w, "New password must be at least 8 characters", http.StatusBadRequest)
		return
	}

	var user SealiftUser
	if err := s.sealiftUsersCol.FindOne(r.Context(), bson.M{"_id": objID}).Decode(&user); err != nil {
		http.Error(w, "Account not found", http.StatusNotFound)
		return
	}

	ok, err := verifyPassword(req.CurrentPassword, user.PasswordHash)
	if err != nil || !ok {
		http.Error(w, "Current password is incorrect", http.StatusUnauthorized)
		return
	}

	if err := s.setPassword(r, objID, req.NewPassword); err != nil {
		slog.Error("failed to change password", "err", err, "userID", userID)
		http.Error(w, "Could not update password", http.StatusInternalServerError)
		return
	}

	slog.Info("password changed", "userID", userID)
	w.WriteHeader(http.StatusNoContent)
}

// setPassword hashes and stores a new password for a tenant.
func (s *Server) setPassword(r *http.Request, userID primitive.ObjectID, password string) error {
	hash, err := argon2id.CreateHash(password, argon2id.DefaultParams)
	if err != nil {
		return err
	}
	_, err = s.sealiftUsersCol.UpdateOne(r.Context(),
		bson.M{"_id": userID},
		bson.M{"$set": bson.M{"passwordHash": hash}},
	)
	return err
}

// handleUpdateEbayConfig replaces the tenant's eBay developer keyset. This is
// the recovery path for a rotated Cert ID or a value mistyped at registration —
// without it the account is stuck with whatever it was created with.
func (s *Server) handleUpdateEbayConfig(w http.ResponseWriter, r *http.Request) {
	userID, _ := r.Context().Value("userId").(string)
	objID, err := primitive.ObjectIDFromHex(userID)
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	var req struct {
		AppID       string `json:"appId"`
		DevID       string `json:"devId"`
		CertID      string `json:"certId"`
		RedirectURI string `json:"redirectUri"`
		IsSandbox   bool   `json:"isSandbox"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	req.AppID = strings.TrimSpace(req.AppID)
	req.DevID = strings.TrimSpace(req.DevID)
	req.CertID = strings.TrimSpace(req.CertID)
	req.RedirectURI = strings.TrimSpace(req.RedirectURI)

	if req.AppID == "" || req.DevID == "" || req.RedirectURI == "" {
		http.Error(w, "App ID, Dev ID and RuName are required", http.StatusBadRequest)
		return
	}

	// A blank Cert ID means "keep the stored one" — validate with that value so
	// saving unrelated changes doesn't require retyping a secret we never show.
	certForCheck := req.CertID
	if certForCheck == "" {
		var current SealiftUser
		if err := s.sealiftUsersCol.FindOne(r.Context(), bson.M{"_id": objID}).Decode(&current); err != nil {
			http.Error(w, "Account not found", http.StatusNotFound)
			return
		}
		if certForCheck, err = secrets.Decrypt(current.EbayDeveloperConfig.CertID); err != nil {
			slog.Error("failed to decrypt stored cert id", "err", err, "userID", userID)
			http.Error(w, "Could not read stored eBay settings", http.StatusInternalServerError)
			return
		}
	}

	// Same check as registration: don't let Settings brick an account.
	if err := s.validateEbayKeyset(r.Context(), EbayDeveloperConfig{
		AppID:       req.AppID,
		DevID:       req.DevID,
		CertID:      certForCheck,
		RedirectURI: req.RedirectURI,
		IsSandbox:   req.IsSandbox,
	}); err != nil {
		slog.Warn("rejected eBay config update", "err", err, "userID", userID)
		http.Error(w,
			"eBay rejected these developer keys. Check the App ID and Cert ID (and the Sandbox setting) and try again.",
			http.StatusBadRequest)
		return
	}

	update := bson.M{
		"ebayDeveloperConfig.appId":       req.AppID,
		"ebayDeveloperConfig.devId":       req.DevID,
		"ebayDeveloperConfig.redirectUri": req.RedirectURI,
		"ebayDeveloperConfig.isSandbox":   req.IsSandbox,
	}
	// An empty Cert ID means "leave it alone" — the settings page shows only a
	// masked hint, so the user can't retype a value they can't see.
	if req.CertID != "" {
		encrypted, err := secrets.Encrypt(req.CertID)
		if err != nil {
			slog.Error("failed to encrypt eBay credentials", "err", err, "userID", userID)
			http.Error(w, "Could not save eBay settings", http.StatusInternalServerError)
			return
		}
		update["ebayDeveloperConfig.certId"] = encrypted
	}

	if _, err := s.sealiftUsersCol.UpdateOne(r.Context(), bson.M{"_id": objID}, bson.M{"$set": update}); err != nil {
		slog.Error("failed to update ebay config", "err", err, "userID", userID)
		http.Error(w, "Could not save eBay settings", http.StatusInternalServerError)
		return
	}

	slog.Info("ebay developer config updated", "userID", userID, "isSandbox", req.IsSandbox)
	w.WriteHeader(http.StatusNoContent)
}

// handleRequestPasswordReset issues a single-use reset token. The response is
// identical whether or not the address is registered, so this can't be used to
// discover which emails have accounts.
func (s *Server) handleRequestPasswordReset(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email string `json:"email"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Email == "" {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	respondAccepted := func() {
		w.WriteHeader(http.StatusAccepted)
		json.NewEncoder(w).Encode(map[string]string{
			"status": "If an account exists for that address, a reset link has been sent.",
		})
	}

	user, err := s.findUserByEmail(r.Context(), req.Email)
	if err != nil {
		if err != mongo.ErrNoDocuments {
			slog.Error("password reset lookup failed", "err", err)
		}
		respondAccepted()
		return
	}

	token, err := newStateToken()
	if err != nil {
		slog.Error("failed to generate reset token", "err", err)
		respondAccepted()
		return
	}

	// Store a hash of the token: a leaked database row shouldn't be usable to
	// reset anyone's password.
	if _, err := s.passwordResetsCol.InsertOne(r.Context(), bson.M{
		"tokenHash": hashToken(token),
		"userId":    user.ID,
		"createdAt": time.Now(),
	}); err != nil {
		slog.Error("failed to store reset token", "err", err)
		respondAccepted()
		return
	}

	resetURL := strings.TrimRight(frontendURL, "/") + "/reset-password?token=" + token
	if err := sendPasswordResetEmail(user.Email, resetURL); err != nil {
		// Delivery isn't configured or failed. Log the link so the operator can
		// still hand it to the user rather than leaving them locked out.
		slog.Warn("could not email password reset link", "err", err, "email", user.Email, "resetURL", resetURL)
	}

	respondAccepted()
}

// handleResetPassword consumes a reset token and sets a new password.
func (s *Server) handleResetPassword(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Token       string `json:"token"`
		NewPassword string `json:"newPassword"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Token == "" {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}
	if len(req.NewPassword) < minPasswordLength {
		http.Error(w, "New password must be at least 8 characters", http.StatusBadRequest)
		return
	}

	// Deleting as we read makes the token single-use even if two requests race.
	var reset struct {
		UserID    primitive.ObjectID `bson:"userId"`
		CreatedAt time.Time          `bson:"createdAt"`
	}
	err := s.passwordResetsCol.FindOneAndDelete(r.Context(),
		bson.M{"tokenHash": hashToken(req.Token)}).Decode(&reset)
	if err != nil {
		http.Error(w, "This reset link is invalid or has already been used", http.StatusBadRequest)
		return
	}
	if time.Since(reset.CreatedAt) > passwordResetTTL {
		http.Error(w, "This reset link has expired. Please request a new one.", http.StatusBadRequest)
		return
	}

	if err := s.setPassword(r, reset.UserID, req.NewPassword); err != nil {
		slog.Error("failed to reset password", "err", err, "userID", reset.UserID.Hex())
		http.Error(w, "Could not update password", http.StatusInternalServerError)
		return
	}

	slog.Info("password reset completed", "userID", reset.UserID.Hex())
	w.WriteHeader(http.StatusNoContent)
}

// sendPasswordResetEmail delivers the reset link. Delivery is configured with
// SMTP_* environment variables; when they're absent the caller logs the link
// instead so accounts are still recoverable by hand.
func sendPasswordResetEmail(to, resetURL string) error {
	if smtpHost == "" {
		return errors.New("no SMTP host configured")
	}
	return sendMail(to,
		"Reset your Sealift password",
		"Someone asked to reset the password for your Sealift account.\r\n\r\n"+
			"Open this link to choose a new one:\r\n"+resetURL+"\r\n\r\n"+
			"The link works once and expires in an hour. If this wasn't you, you can ignore this email.\r\n",
	)
}
