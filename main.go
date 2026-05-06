package main

import (
	"log"
	"net/http"

	"github.com/go-webauthn/webauthn/webauthn"
)

var (
	store  *Store
	wauthn *webauthn.WebAuthn
)

func main() {
	store = NewStore()

	var err error
	wauthn, err = webauthn.New(&webauthn.Config{
		RPDisplayName: "OT Demo",
		RPID:          "localhost",
		RPOrigins:     []string{"http://localhost:8080"},
	})
	if err != nil {
		log.Fatalf("webauthn init: %v", err)
	}

	mux := http.NewServeMux()

	// Static assets
	mux.Handle("/", http.FileServer(http.Dir("static")))

	// ── Auth ──────────────────────────────────────────────────────────────────
	mux.HandleFunc("POST /api/register", handleRegister)
	mux.HandleFunc("POST /api/login", handleLogin)
	mux.HandleFunc("POST /api/logout", handleLogout)
	mux.HandleFunc("GET /api/me", handleMe)
	mux.HandleFunc("POST /api/2fa/toggle", handleToggle2FA)

	// ── TOTP setup (requires full login, step=2) ──────────────────────────────
	mux.HandleFunc("POST /api/2fa/totp/setup", handleTOTPSetup)
	mux.HandleFunc("POST /api/2fa/totp/activate", handleTOTPActivate)
	mux.HandleFunc("POST /api/2fa/totp/disable", handleTOTPDisable)

	// ── Passkey setup (requires full login, step=2) ───────────────────────────
	mux.HandleFunc("POST /api/2fa/passkey/register/begin", handlePasskeyRegisterBegin)
	mux.HandleFunc("POST /api/2fa/passkey/register/finish", handlePasskeyRegisterFinish)

	// ── 2FA login verification (requires step=1) ──────────────────────────────
	mux.HandleFunc("POST /api/login/2fa/totp", handleLoginTOTP)
	mux.HandleFunc("POST /api/login/2fa/passkey/begin", handleLoginPasskeyBegin)
	mux.HandleFunc("POST /api/login/2fa/passkey/finish", handleLoginPasskeyFinish)
	mux.HandleFunc("POST /api/login/2fa/email/send", handleEmailOTPSend)
	mux.HandleFunc("POST /api/login/2fa/email/verify", handleLoginEmailOTP)

	log.Println("Server running at http://localhost:8080")
	log.Fatal(http.ListenAndServe(":8080", mux))
}
