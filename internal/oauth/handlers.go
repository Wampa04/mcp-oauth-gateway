// Package oauth implements the gateway's OAuth 2.1 authorization server:
// dynamic client registration (RFC 7591), the PKCE authorization-code flow, and
// token issuance, bridging user identity to GitHub.
package oauth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"time"

	"mcp-oauth-gateway/internal/allowlist"
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
)

func writeError(w http.ResponseWriter, status int, code, desc string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error":             code,
		"error_description": desc,
	})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
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
		h := u.Hostname()
		return h == "localhost" || h == "127.0.0.1" || h == "::1"
	default:
		return false
	}
}

func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}
