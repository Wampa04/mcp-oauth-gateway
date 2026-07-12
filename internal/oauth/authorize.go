package oauth

import (
	"html"
	"net/http"
	"net/url"
	"slices"
	"time"

	"mcp-oauth-gateway/internal/routes"
)

// Authorize handles GET /authorize: validate the client request, optionally show
// a consent screen, then redirect the user to GitHub to authenticate.
func (h *Handlers) Authorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	clientID := q.Get("client_id")
	redirectURI := q.Get("redirect_uri")

	client, ok := h.Store.GetClient(clientID)
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid_client", "unknown client_id")
		return
	}
	// Exact redirect_uri match against registration; never redirect to an
	// unregistered URI.
	if !slices.Contains(client.RedirectURIs, redirectURI) {
		writeError(w, http.StatusBadRequest, "invalid_request", "redirect_uri not registered for this client")
		return
	}

	// From here the redirect_uri is trusted, so request errors go back to it.
	if q.Get("response_type") != "code" {
		redirectErr(w, r, redirectURI, q.Get("state"), "unsupported_response_type", "only response_type=code is supported")
		return
	}
	challenge := q.Get("code_challenge")
	if challenge == "" || q.Get("code_challenge_method") != "S256" {
		redirectErr(w, r, redirectURI, q.Get("state"), "invalid_request", "PKCE with code_challenge_method=S256 is required")
		return
	}
	resource := q.Get("resource")
	if resource == "" {
		resource = h.Resource
	}
	if resource != h.Resource {
		redirectErr(w, r, redirectURI, q.Get("state"), "invalid_target", "resource does not match this MCP server")
		return
	}

	// Consent is proven by a one-time server-issued token from renderConsent,
	// not a client-supplied flag, so a client cannot skip the screen.
	if h.Consent {
		cid, ok := h.Store.TakeConsent(q.Get("consent_token"))
		if !ok || cid != clientID {
			h.renderConsent(w, r, client)
			return
		}
	}

	state := randomToken()
	h.Store.SavePending(state, &PendingFlow{
		ClientID:      clientID,
		RedirectURI:   redirectURI,
		ClientState:   q.Get("state"),
		CodeChallenge: challenge,
		Resource:      resource,
		Scope:         q.Get("scope"),
		Expiry:        time.Now().Add(pendingTTL),
	})
	http.Redirect(w, r, h.GitHub.AuthURL(state, h.CallbackURL), http.StatusFound)
}

// Callback handles GET /callback: GitHub's redirect target. It resolves the
// GitHub identity, enforces the allowlist, and issues our own authorization code.
func (h *Handlers) Callback(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	if e := q.Get("error"); e != "" {
		http.Error(w, "github authorization failed: "+e, http.StatusBadRequest)
		return
	}
	pending, ok := h.Store.TakePending(q.Get("state"))
	if !ok {
		http.Error(w, "invalid or expired state", http.StatusBadRequest)
		return
	}
	userID, _, err := h.GitHub.Exchange(r.Context(), q.Get("code"), h.CallbackURL)
	if err != nil {
		http.Error(w, "github token exchange failed", http.StatusBadGateway)
		return
	}
	if !h.Allow.IsAllowed(userID) {
		redirectErr(w, r, pending.RedirectURI, pending.ClientState, "access_denied", "this GitHub account is not permitted")
		return
	}

	code := randomToken()
	h.Store.SaveCode(code, &AuthCode{
		ClientID:      pending.ClientID,
		RedirectURI:   pending.RedirectURI,
		CodeChallenge: pending.CodeChallenge,
		Resource:      pending.Resource,
		GitHubUserID:  userID,
		Scope:         pending.Scope,
		Expiry:        time.Now().Add(codeTTL),
	})

	u, _ := url.Parse(pending.RedirectURI)
	rq := u.Query()
	rq.Set("code", code)
	if pending.ClientState != "" {
		rq.Set("state", pending.ClientState)
	}
	u.RawQuery = rq.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound)
}

func redirectErr(w http.ResponseWriter, r *http.Request, redirectURI, state, code, desc string) {
	u, err := url.Parse(redirectURI)
	if err != nil {
		writeError(w, http.StatusBadRequest, code, desc)
		return
	}
	q := u.Query()
	q.Set("error", code)
	q.Set("error_description", desc)
	if state != "" {
		q.Set("state", state)
	}
	u.RawQuery = q.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound)
}

// renderConsent shows a minimal per-client consent page (confused-deputy
// mitigation) that re-issues the same request with consent granted.
func (h *Handlers) renderConsent(w http.ResponseWriter, r *http.Request, client *Client) {
	ct := randomToken()
	h.Store.SaveConsent(ct, client.ID, consentTTL)
	q := r.URL.Query()
	q.Set("consent_token", ct)
	proceed := routes.Authorize + "?" + q.Encode()

	name := client.Name
	if name == "" {
		name = client.ID
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write([]byte(`<!doctype html><meta charset="utf-8">` +
		`<title>Authorize access</title>` +
		`<div style="font-family:system-ui;max-width:32rem;margin:4rem auto;line-height:1.5">` +
		`<h1>Authorize access</h1>` +
		`<p><strong>` + html.EscapeString(name) + `</strong> is requesting access to this MCP server on your behalf. ` +
		`You will sign in with GitHub.</p>` +
		`<p><a href="` + html.EscapeString(proceed) + `" style="display:inline-block;padding:.6rem 1.2rem;background:#1f883d;color:#fff;border-radius:.4rem;text-decoration:none">Continue to GitHub</a></p>` +
		`</div>`))
}
