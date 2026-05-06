package main

import (
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
)

// User represents an account in the system.
type User struct {
	ID           string
	Username     string
	Email        string
	PasswordHash string

	// TOTP
	TOTPSecret  string
	TOTPEnabled bool

	// Passkey (WebAuthn / FIDO2)
	Credentials    []webauthn.Credential
	PasskeyEnabled bool

	// Global 2FA switch
	TwoFAEnabled bool
}

// The four methods below implement webauthn.User so *User can be passed directly
// to the go-webauthn library.
func (u *User) WebAuthnID() []byte                         { return []byte(u.ID) }
func (u *User) WebAuthnName() string                       { return u.Username }
func (u *User) WebAuthnDisplayName() string                { return u.Username }
func (u *User) WebAuthnIcon() string                       { return "" }
func (u *User) WebAuthnCredentials() []webauthn.Credential { return u.Credentials }

// Session tracks a logged-in user. Step 1 means the password was accepted;
// step 2 means 2FA was also accepted (fully authenticated).
type Session struct {
	ID        string
	Username  string
	Step      int // 1 = password verified, 2 = fully authenticated
	ExpiresAt time.Time
}

// EmailOTP holds a pending one-time password for the email-based 2FA method.
type EmailOTP struct {
	Code      string
	ExpiresAt time.Time
	Attempts  int
}
