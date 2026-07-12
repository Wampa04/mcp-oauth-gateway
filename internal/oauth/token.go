package oauth

import (
	"net/http"
	"strconv"
)

type tokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
	Scope       string `json:"scope,omitempty"`
}

// Token handles POST /token (authorization_code grant with PKCE).
func (h *Handlers) Token(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "invalid_request", "POST required")
		return
	}
	if err := r.ParseForm(); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "malformed form body")
		return
	}
	if r.Form.Get("grant_type") != "authorization_code" {
		writeError(w, http.StatusBadRequest, "unsupported_grant_type", "only authorization_code is supported")
		return
	}

	ac, ok := h.Store.TakeCode(r.Form.Get("code"))
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid_grant", "unknown, expired or already-used code")
		return
	}
	if r.Form.Get("client_id") != ac.ClientID {
		writeError(w, http.StatusBadRequest, "invalid_grant", "client_id mismatch")
		return
	}
	if r.Form.Get("redirect_uri") != ac.RedirectURI {
		writeError(w, http.StatusBadRequest, "invalid_grant", "redirect_uri mismatch")
		return
	}
	if res := r.Form.Get("resource"); res != "" && !sameOrigin(res, ac.Resource) {
		writeError(w, http.StatusBadRequest, "invalid_target", "resource is not served by this gateway")
		return
	}
	if !VerifyS256(r.Form.Get("code_verifier"), ac.CodeChallenge) {
		writeError(w, http.StatusBadRequest, "invalid_grant", "PKCE verification failed")
		return
	}
	// Re-check the allowlist at issuance time (fail-closed).
	if !h.Allow.IsAllowed(ac.GitHubUserID) {
		writeError(w, http.StatusForbidden, "access_denied", "this GitHub account is not permitted")
		return
	}

	sub := strconv.FormatInt(ac.GitHubUserID, 10)
	access, err := h.Tokens.Issue(sub, ac.Resource, h.TokenTTL)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", "could not issue token")
		return
	}
	writeJSON(w, http.StatusOK, tokenResponse{
		AccessToken: access,
		TokenType:   "Bearer",
		ExpiresIn:   int(h.TokenTTL.Seconds()),
		Scope:       ac.Scope,
	})
}
