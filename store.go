package main

import (
	"fmt"
	"sync"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
)

// Store is a thread-safe in-memory database.
// Replace with a real DB (Postgres, Redis, …) in production.
type Store struct {
	mu sync.RWMutex

	users            map[string]*User                 // key: username
	sessions         map[string]*Session              // key: sessionID
	emailOTPs        map[string]*EmailOTP             // key: username
	webAuthnSessions map[string]*webauthn.SessionData // key: "passkey_reg_<sid>" or "passkey_auth_<sid>"
	totpPending      map[string]string                // key: username → unactivated TOTP secret
}

func NewStore() *Store {
	return &Store{
		users:            make(map[string]*User),
		sessions:         make(map[string]*Session),
		emailOTPs:        make(map[string]*EmailOTP),
		webAuthnSessions: make(map[string]*webauthn.SessionData),
		totpPending:      make(map[string]string),
	}
}

// ── User ──────────────────────────────────────────────────────────────────────

func (s *Store) CreateUser(u *User) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.users[u.Username]; ok {
		return fmt.Errorf("username already taken")
	}
	s.users[u.Username] = u
	return nil
}

func (s *Store) GetUser(username string) (*User, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	u, ok := s.users[username]
	return u, ok
}

func (s *Store) UpdateUser(u *User) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.users[u.Username] = u
}

// ── Session ───────────────────────────────────────────────────────────────────

func (s *Store) SaveSession(sess *Session) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[sess.ID] = sess
}

func (s *Store) GetSession(id string) (*Session, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	sess, ok := s.sessions[id]
	if !ok || time.Now().After(sess.ExpiresAt) {
		return nil, false
	}
	return sess, true
}

func (s *Store) DeleteSession(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, id)
}

// ── Email OTP ─────────────────────────────────────────────────────────────────

func (s *Store) SetEmailOTP(username string, otp *EmailOTP) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.emailOTPs[username] = otp
}

func (s *Store) GetEmailOTP(username string) (*EmailOTP, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	otp, ok := s.emailOTPs[username]
	return otp, ok
}

func (s *Store) DeleteEmailOTP(username string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.emailOTPs, username)
}

// ── WebAuthn session data ─────────────────────────────────────────────────────

func (s *Store) SaveWebAuthnSession(key string, data *webauthn.SessionData) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.webAuthnSessions[key] = data
}

func (s *Store) GetWebAuthnSession(key string) (*webauthn.SessionData, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	data, ok := s.webAuthnSessions[key]
	return data, ok
}

func (s *Store) DeleteWebAuthnSession(key string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.webAuthnSessions, key)
}

// ── TOTP pending ──────────────────────────────────────────────────────────────

func (s *Store) SetTOTPPending(username, secret string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.totpPending[username] = secret
}

func (s *Store) GetTOTPPending(username string) (string, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	secret, ok := s.totpPending[username]
	return secret, ok
}

func (s *Store) DeleteTOTPPending(username string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.totpPending, username)
}
