package main

import (
	"crypto/rand"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"time"
)

const emailOTPLength = 6
const emailOTPExpiry = 10 * time.Minute
const maxOTPAttempts = 5

// generateOTP returns a cryptographically random N-digit string.
func generateOTP(n int) string {
	code := make([]byte, n)
	for i := range code {
		d, _ := rand.Int(rand.Reader, big.NewInt(10))
		code[i] = byte('0') + byte(d.Int64())
	}
	return string(code)
}

// handleEmailOTPSend generates a new OTP and "sends" it (logs it to stdout in this demo).
func handleEmailOTPSend(w http.ResponseWriter, r *http.Request) {
	sess, user, ok := requireAuth(w, r, 1)
	if !ok {
		return
	}
	if sess.Step == 2 {
		jsonError(w, http.StatusBadRequest, "already fully authenticated")
		return
	}

	code := generateOTP(emailOTPLength)
	store.SetEmailOTP(user.Username, &EmailOTP{
		Code:      code,
		ExpiresAt: time.Now().Add(emailOTPExpiry),
	})

	// Production: send via email (SendGrid, SES, …).
	// Demo: print to server stdout so you can copy it without a real mail server.
	log.Printf("[EMAIL OTP] To: %s  Code: %s  (expires in %v)", user.Email, code, emailOTPExpiry)

	jsonOK(w, map[string]any{
		"message":    fmt.Sprintf("OTP sent to %s — check server console for the demo code", user.Email),
		"debug_code": code, // remove in production
	})
}

// handleLoginEmailOTP verifies the submitted OTP and advances the session to step 2.
func handleLoginEmailOTP(w http.ResponseWriter, r *http.Request) {
	sess, user, ok := requireAuth(w, r, 1)
	if !ok {
		return
	}
	if sess.Step == 2 {
		jsonError(w, http.StatusBadRequest, "already fully authenticated")
		return
	}

	var req struct {
		Code string `json:"code"`
	}
	if err := decodeJSON(r, &req); err != nil || req.Code == "" {
		jsonError(w, http.StatusBadRequest, "code is required")
		return
	}

	otp, ok := store.GetEmailOTP(user.Username)
	if !ok {
		jsonError(w, http.StatusBadRequest, "no OTP found; request a new one first")
		return
	}

	if otp.Attempts >= maxOTPAttempts {
		store.DeleteEmailOTP(user.Username)
		jsonError(w, http.StatusTooManyRequests, "too many failed attempts; request a new OTP")
		return
	}
	if time.Now().After(otp.ExpiresAt) {
		store.DeleteEmailOTP(user.Username)
		jsonError(w, http.StatusBadRequest, "OTP expired; request a new one")
		return
	}

	otp.Attempts++
	if otp.Code != req.Code {
		store.SetEmailOTP(user.Username, otp)
		remaining := maxOTPAttempts - otp.Attempts
		jsonError(w, http.StatusUnauthorized, fmt.Sprintf("invalid code; %d attempts remaining", remaining))
		return
	}

	store.DeleteEmailOTP(user.Username)
	sess.Step = 2
	store.SaveSession(sess)
	jsonOK(w, map[string]int{"step": 2})
}
