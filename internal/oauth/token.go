package oauth

import (
	"net/http"
	"strconv"
	"time"
)

type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	Scope        string `json:"scope,omitempty"`
}

// Token handles POST /token: the authorization_code grant (with PKCE) and the
// refresh_token grant used to renew an access token without repeating the
// GitHub login.
func (h *Handlers) Token(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "invalid_request", "POST required")
		return
	}
	if err := r.ParseForm(); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "malformed form body")
		return
	}
	switch r.Form.Get("grant_type") {
	case "authorization_code":
		h.tokenFromCode(w, r)
	case "refresh_token":
		h.tokenFromRefreshToken(w, r)
	default:
		writeError(w, http.StatusBadRequest, "unsupported_grant_type", "only authorization_code and refresh_token are supported")
	}
}

func (h *Handlers) tokenFromCode(w http.ResponseWriter, r *http.Request) {
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
	if res := r.Form.Get("resource"); res != "" && !h.acceptsResource(res) {
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
	h.issueTokens(w, ac.ClientID, ac.GitHubUserID, ac.Resource, ac.Scope)
}

// tokenFromRefreshToken validates against a non-destructive peek and only
// consumes the presented refresh token once its replacement is safely
// persisted, so a client_id mismatch, a de-allowlisted user, or the refresh
// store being briefly at capacity leaves the still-valid token usable for a
// retry instead of permanently stranding the client (forcing a full GitHub
// re-login even though the session was otherwise fine).
func (h *Handlers) tokenFromRefreshToken(w http.ResponseWriter, r *http.Request) {
	old := r.Form.Get("refresh_token")
	rt, ok := h.Store.PeekRefreshToken(old)
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid_grant", "unknown, expired or already-used refresh token")
		return
	}
	if r.Form.Get("client_id") != rt.ClientID {
		writeError(w, http.StatusBadRequest, "invalid_grant", "client_id mismatch")
		return
	}
	// Re-check the allowlist at refresh time (fail-closed): a user removed from
	// the allowlist loses access even with a still-valid refresh token.
	if !h.Allow.IsAllowed(rt.GitHubUserID) {
		writeError(w, http.StatusForbidden, "access_denied", "this GitHub account is not permitted")
		return
	}

	sub := strconv.FormatInt(rt.GitHubUserID, 10)
	access, err := h.Tokens.Issue(sub, rt.Resource, h.TokenTTL)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", "could not issue token")
		return
	}
	newRefresh := randomToken()
	if !h.Store.SaveRefreshToken(newRefresh, &RefreshToken{
		ClientID:     rt.ClientID,
		GitHubUserID: rt.GitHubUserID,
		Resource:     rt.Resource,
		Scope:        rt.Scope,
		Expiry:       time.Now().Add(h.RefreshTokenTTL),
	}) {
		writeError(w, http.StatusServiceUnavailable, "temporarily_unavailable", "too many refresh tokens outstanding, try again later")
		return
	}
	// Rotation is complete and a usable replacement exists: only now retire the
	// presented token. If a concurrent request already consumed it first, that
	// request completed a valid rotation, so give up the just-minted duplicate
	// rather than hand out two live refresh tokens for one.
	if _, ok := h.Store.TakeRefreshToken(old); !ok {
		h.Store.TakeRefreshToken(newRefresh)
		writeError(w, http.StatusBadRequest, "invalid_grant", "unknown, expired or already-used refresh token")
		return
	}

	writeJSON(w, http.StatusOK, tokenResponse{
		AccessToken:  access,
		TokenType:    "Bearer",
		ExpiresIn:    int(h.TokenTTL.Seconds()),
		RefreshToken: newRefresh,
		Scope:        rt.Scope,
	})
}

// issueTokens signs a new access token and rotates the refresh token.
func (h *Handlers) issueTokens(w http.ResponseWriter, clientID string, githubUserID int64, resource, scope string) {
	sub := strconv.FormatInt(githubUserID, 10)
	access, err := h.Tokens.Issue(sub, resource, h.TokenTTL)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", "could not issue token")
		return
	}
	refresh := randomToken()
	if !h.Store.SaveRefreshToken(refresh, &RefreshToken{
		ClientID:     clientID,
		GitHubUserID: githubUserID,
		Resource:     resource,
		Scope:        scope,
		Expiry:       time.Now().Add(h.RefreshTokenTTL),
	}) {
		writeError(w, http.StatusServiceUnavailable, "temporarily_unavailable", "too many refresh tokens outstanding, try again later")
		return
	}
	writeJSON(w, http.StatusOK, tokenResponse{
		AccessToken:  access,
		TokenType:    "Bearer",
		ExpiresIn:    int(h.TokenTTL.Seconds()),
		RefreshToken: refresh,
		Scope:        scope,
	})
}
