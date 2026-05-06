package main

import (
	"net/http"
	"time"

	"golang.org/x/crypto/bcrypt"
)

type registerRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Email    string `json:"email"`
}

func handleRegister(w http.ResponseWriter, r *http.Request) {
	var req registerRequest
	if err := decodeJSON(r, &req); err != nil || req.Username == "" || req.Password == "" || req.Email == "" {
		jsonError(w, http.StatusBadRequest, "username, password and email are required")
		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "failed to hash password")
		return
	}

	user := &User{
		ID:           newUUID(),
		Username:     req.Username,
		Email:        req.Email,
		PasswordHash: string(hash),
	}
	if err := store.CreateUser(user); err != nil {
		jsonError(w, http.StatusConflict, err.Error())
		return
	}
	jsonOK(w, map[string]string{"message": "registered successfully"})
}

type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
	var req loginRequest
	if err := decodeJSON(r, &req); err != nil {
		jsonError(w, http.StatusBadRequest, "invalid request")
		return
	}

	user, ok := store.GetUser(req.Username)
	if !ok {
		jsonError(w, http.StatusUnauthorized, "invalid credentials")
		return
	}
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.Password)); err != nil {
		jsonError(w, http.StatusUnauthorized, "invalid credentials")
		return
	}

	// If 2FA is disabled, grant full access immediately.
	step := 2
	if user.TwoFAEnabled {
		step = 1
	}

	sess := &Session{
		ID:        newUUID(),
		Username:  user.Username,
		Step:      step,
		ExpiresAt: time.Now().Add(sessionDuration),
	}
	store.SaveSession(sess)
	setSessionCookie(w, sess.ID)

	jsonOK(w, map[string]any{
		"step":           step,
		"twoFAEnabled":   user.TwoFAEnabled,
		"totpEnabled":    user.TOTPEnabled,
		"passkeyEnabled": user.PasskeyEnabled,
		"email":          user.Email,
	})
}

func handleLogout(w http.ResponseWriter, r *http.Request) {
	if cookie, err := r.Cookie(sessionCookieName); err == nil {
		store.DeleteSession(cookie.Value)
	}
	clearSessionCookie(w)
	jsonOK(w, map[string]string{"message": "logged out"})
}

func handleMe(w http.ResponseWriter, r *http.Request) {
	_, user, ok := requireAuth(w, r, 2)
	if !ok {
		return
	}
	jsonOK(w, map[string]any{
		"username":       user.Username,
		"email":          user.Email,
		"twoFAEnabled":   user.TwoFAEnabled,
		"totpEnabled":    user.TOTPEnabled,
		"passkeyEnabled": user.PasskeyEnabled,
		"passkeyCount":   len(user.Credentials),
	})
}

func handleToggle2FA(w http.ResponseWriter, r *http.Request) {
	_, user, ok := requireAuth(w, r, 2)
	if !ok {
		return
	}
	var req struct {
		Enabled bool `json:"enabled"`
	}
	if err := decodeJSON(r, &req); err != nil {
		jsonError(w, http.StatusBadRequest, "invalid request")
		return
	}
	user.TwoFAEnabled = req.Enabled
	store.UpdateUser(user)
	jsonOK(w, map[string]bool{"twoFAEnabled": user.TwoFAEnabled})
}
