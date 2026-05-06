package main

import (
	"bytes"
	"encoding/base64"
	"image/png"
	"net/http"

	"github.com/pquerna/otp/totp"
)

// handleTOTPSetup generates a new TOTP secret + QR code for the logged-in user.
// The secret is held as "pending" until the user activates it with a valid code.
func handleTOTPSetup(w http.ResponseWriter, r *http.Request) {
	_, user, ok := requireAuth(w, r, 2)
	if !ok {
		return
	}

	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "OT Demo",
		AccountName: user.Email,
	})
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "failed to generate TOTP key")
		return
	}

	store.SetTOTPPending(user.Username, key.Secret())

	img, err := key.Image(200, 200)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "failed to render QR code")
		return
	}
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		jsonError(w, http.StatusInternalServerError, "failed to encode QR code")
		return
	}

	jsonOK(w, map[string]string{
		"secret":  key.Secret(),
		"qrCode":  "data:image/png;base64," + base64.StdEncoding.EncodeToString(buf.Bytes()),
		"otpauth": key.URL(),
	})
}

// handleTOTPActivate verifies a code against the pending secret and, if valid,
// saves it to the user record and marks TOTP as enabled.
func handleTOTPActivate(w http.ResponseWriter, r *http.Request) {
	_, user, ok := requireAuth(w, r, 2)
	if !ok {
		return
	}

	var req struct {
		Code string `json:"code"`
	}
	if err := decodeJSON(r, &req); err != nil || req.Code == "" {
		jsonError(w, http.StatusBadRequest, "code is required")
		return
	}

	secret, ok := store.GetTOTPPending(user.Username)
	if !ok {
		jsonError(w, http.StatusBadRequest, "no pending TOTP setup; call /api/2fa/totp/setup first")
		return
	}

	if !totp.Validate(req.Code, secret) {
		jsonError(w, http.StatusBadRequest, "invalid code")
		return
	}

	store.DeleteTOTPPending(user.Username)
	user.TOTPSecret = secret
	user.TOTPEnabled = true
	store.UpdateUser(user)

	jsonOK(w, map[string]bool{"totpEnabled": true})
}

func handleTOTPDisable(w http.ResponseWriter, r *http.Request) {
	_, user, ok := requireAuth(w, r, 2)
	if !ok {
		return
	}
	user.TOTPSecret = ""
	user.TOTPEnabled = false
	store.UpdateUser(user)
	jsonOK(w, map[string]bool{"totpEnabled": false})
}

// handleLoginTOTP is the 2FA verification step for TOTP (session step 1 → 2).
func handleLoginTOTP(w http.ResponseWriter, r *http.Request) {
	sess, user, ok := requireAuth(w, r, 1)
	if !ok {
		return
	}
	if sess.Step == 2 {
		jsonError(w, http.StatusBadRequest, "already fully authenticated")
		return
	}
	if !user.TOTPEnabled {
		jsonError(w, http.StatusBadRequest, "TOTP not configured for this account")
		return
	}

	var req struct {
		Code string `json:"code"`
	}
	if err := decodeJSON(r, &req); err != nil || req.Code == "" {
		jsonError(w, http.StatusBadRequest, "code is required")
		return
	}

	if !totp.Validate(req.Code, user.TOTPSecret) {
		jsonError(w, http.StatusUnauthorized, "invalid code")
		return
	}

	sess.Step = 2
	store.SaveSession(sess)
	jsonOK(w, map[string]int{"step": 2})
}
