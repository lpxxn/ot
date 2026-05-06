package main

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/google/uuid"
)

const sessionCookieName = "session_id"
const sessionDuration = 24 * time.Hour

func jsonOK(w http.ResponseWriter, data any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(data)
}

func jsonError(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

func newUUID() string {
	return uuid.New().String()
}

func setSessionCookie(w http.ResponseWriter, sessionID string) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    sessionID,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Expires:  time.Now().Add(sessionDuration),
	})
}

func clearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:    sessionCookieName,
		Value:   "",
		Path:    "/",
		MaxAge:  -1,
		Expires: time.Unix(0, 0),
	})
}

func getSessionFromRequest(r *http.Request) (*Session, bool) {
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil {
		return nil, false
	}
	return store.GetSession(cookie.Value)
}

// requireAuth validates the session cookie and ensures Step >= minStep.
// On failure it writes the error response and returns (nil, nil, false).
func requireAuth(w http.ResponseWriter, r *http.Request, minStep int) (*Session, *User, bool) {
	sess, ok := getSessionFromRequest(r)
	if !ok {
		jsonError(w, http.StatusUnauthorized, "not logged in")
		return nil, nil, false
	}
	if sess.Step < minStep {
		jsonError(w, http.StatusForbidden, "2FA verification required")
		return nil, nil, false
	}
	user, ok := store.GetUser(sess.Username)
	if !ok {
		jsonError(w, http.StatusUnauthorized, "user not found")
		return nil, nil, false
	}
	return sess, user, true
}

func decodeJSON(r *http.Request, dst any) error {
	return json.NewDecoder(r.Body).Decode(dst)
}
