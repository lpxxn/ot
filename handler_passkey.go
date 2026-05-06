package main

import (
	"bytes"
	"net/http"
)

// handlePasskeyRegisterBegin starts WebAuthn credential registration.
// Returns the PublicKeyCredentialCreationOptions challenge to the browser.
func handlePasskeyRegisterBegin(w http.ResponseWriter, r *http.Request) {
	sess, user, ok := requireAuth(w, r, 2)
	if !ok {
		return
	}

	options, sessionData, err := wauthn.BeginRegistration(user)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "begin registration failed: "+err.Error())
		return
	}

	store.SaveWebAuthnSession("passkey_reg_"+sess.ID, sessionData)
	jsonOK(w, options)
}

// handlePasskeyRegisterFinish receives the browser credential and stores it.
// The request body must be the raw PublicKeyCredential JSON from the browser.
func handlePasskeyRegisterFinish(w http.ResponseWriter, r *http.Request) {
	sess, user, ok := requireAuth(w, r, 2)
	if !ok {
		return
	}

	sessionData, ok := store.GetWebAuthnSession("passkey_reg_" + sess.ID)
	if !ok {
		jsonError(w, http.StatusBadRequest, "no pending registration; call begin first")
		return
	}
	store.DeleteWebAuthnSession("passkey_reg_" + sess.ID)

	// wauthn.FinishRegistration reads and parses r.Body directly.
	credential, err := wauthn.FinishRegistration(user, *sessionData, r)
	if err != nil {
		jsonError(w, http.StatusBadRequest, "registration failed: "+err.Error())
		return
	}

	user.Credentials = append(user.Credentials, *credential)
	user.PasskeyEnabled = true
	store.UpdateUser(user)

	jsonOK(w, map[string]any{
		"passkeyEnabled": true,
		"passkeyCount":   len(user.Credentials),
	})
}

// handleLoginPasskeyBegin starts WebAuthn assertion (login step 1 → 2).
// Returns the PublicKeyCredentialRequestOptions challenge to the browser.
func handleLoginPasskeyBegin(w http.ResponseWriter, r *http.Request) {
	sess, user, ok := requireAuth(w, r, 1)
	if !ok {
		return
	}
	if sess.Step == 2 {
		jsonError(w, http.StatusBadRequest, "already fully authenticated")
		return
	}
	if !user.PasskeyEnabled || len(user.Credentials) == 0 {
		jsonError(w, http.StatusBadRequest, "passkey not configured for this account")
		return
	}

	options, sessionData, err := wauthn.BeginLogin(user)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "begin login failed: "+err.Error())
		return
	}

	store.SaveWebAuthnSession("passkey_auth_"+sess.ID, sessionData)
	jsonOK(w, options)
}

// handleLoginPasskeyFinish verifies the signed assertion and advances the session to step 2.
func handleLoginPasskeyFinish(w http.ResponseWriter, r *http.Request) {
	sess, user, ok := requireAuth(w, r, 1)
	if !ok {
		return
	}
	if sess.Step == 2 {
		jsonError(w, http.StatusBadRequest, "already fully authenticated")
		return
	}

	sessionData, ok := store.GetWebAuthnSession("passkey_auth_" + sess.ID)
	if !ok {
		jsonError(w, http.StatusBadRequest, "no pending passkey login; call begin first")
		return
	}
	store.DeleteWebAuthnSession("passkey_auth_" + sess.ID)

	// wauthn.FinishLogin reads and parses r.Body directly.
	credential, err := wauthn.FinishLogin(user, *sessionData, r)
	if err != nil {
		jsonError(w, http.StatusUnauthorized, "passkey authentication failed: "+err.Error())
		return
	}

	// Update the sign counter to prevent credential-cloning attacks.
	for i, c := range user.Credentials {
		if bytes.Equal(c.ID, credential.ID) {
			user.Credentials[i].Authenticator.SignCount = credential.Authenticator.SignCount
			break
		}
	}
	store.UpdateUser(user)

	sess.Step = 2
	store.SaveSession(sess)
	jsonOK(w, map[string]int{"step": 2})
}
