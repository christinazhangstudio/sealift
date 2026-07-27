package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/smtp"
	"os"
	"strings"
)

// Outbound mail is optional: Sealift works without it, but password reset links
// can only be delivered (rather than logged for the operator) when it's set.
var (
	smtpHost = os.Getenv("SMTP_HOST")
	smtpPort = os.Getenv("SMTP_PORT")
	smtpUser = os.Getenv("SMTP_USERNAME")
	smtpPass = os.Getenv("SMTP_PASSWORD")
	smtpFrom = os.Getenv("SMTP_FROM")
)

// hashToken hashes a single-use token before it is stored, so a leaked database
// row can't be replayed as a valid link.
func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// sendMail sends a plaintext message over SMTP.
func sendMail(to, subject, body string) error {
	if smtpHost == "" {
		return fmt.Errorf("SMTP_HOST is not configured")
	}

	port := smtpPort
	if port == "" {
		port = "587"
	}
	from := smtpFrom
	if from == "" {
		from = smtpUser
	}
	if from == "" {
		return fmt.Errorf("SMTP_FROM or SMTP_USERNAME must be set")
	}

	msg := strings.Join([]string{
		"From: " + from,
		"To: " + to,
		"Subject: " + subject,
		"MIME-Version: 1.0",
		"Content-Type: text/plain; charset=UTF-8",
		"",
		body,
	}, "\r\n")

	addr := smtpHost + ":" + port
	var auth smtp.Auth
	if smtpUser != "" {
		auth = smtp.PlainAuth("", smtpUser, smtpPass, smtpHost)
	}

	return smtp.SendMail(addr, auth, from, []string{to}, []byte(msg))
}
