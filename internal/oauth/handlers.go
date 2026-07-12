// Package oauth implements the gateway's OAuth 2.1 authorization server:
// dynamic client registration (RFC 7591), the PKCE authorization-code flow, and
// token issuance, bridging user identity to GitHub.
package oauth

import (
	"context"
	"net/http"
	"net/url"
	"time"

	"mcp-oauth-gateway/internal/allowlist"
	"mcp-oauth-gateway/internal/httputils"
	"mcp-oauth-gateway/internal/token"
)

// GitHubBridge abstracts the GitHub OAuth exchange so the flow is testable.
type GitHubBridge interface {
	AuthURL(state, redirectURI string) string
	Exchange(ctx context.Context, code, redirectURI string) (userID int64, login string, err error)
}

type Handlers struct {
	Issuer      string
	Resource    string
	CallbackURL string
	TokenTTL    time.Duration
	Consent     bool

	Store  *Store
	Allow  *allowlist.Allowlist
	Tokens *token.Issuer
	GitHub GitHubBridge
}

const (
	pendingTTL = 10 * time.Minute
	codeTTL    = time.Minute
	consentTTL = 10 * time.Minute
)

func writeError(w http.ResponseWriter, status int, code, desc string) {
	httputils.WriteJSON(w, status, "no-store", map[string]string{
		"error":             code,
		"error_description": desc,
	})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	httputils.WriteJSON(w, status, "no-store", v)
}

// validRedirectURI enforces the spec: redirect URIs must be https, or http on
// loopback only.
func validRedirectURI(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Fragment != "" || u.Host == "" {
		return false
	}
	switch u.Scheme {
	case "https":
		return true
	case "http":
		return httputils.IsLoopbackHost(u.Hostname())
	default:
		return false
	}
}
