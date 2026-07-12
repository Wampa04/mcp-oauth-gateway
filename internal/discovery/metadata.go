// Package discovery serves the OAuth metadata documents (RFC 9728 / RFC 8414)
// and the JWKS that MCP clients use to discover and trust the gateway.
package discovery

import (
	"encoding/json"
	"net/http"

	"mcp-oauth-gateway/internal/keys"
)

type Handlers struct {
	Issuer   string
	Resource string
	Signer   *keys.Signer
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	_ = json.NewEncoder(w).Encode(v)
}

// ProtectedResource serves /.well-known/oauth-protected-resource (RFC 9728).
func (h *Handlers) ProtectedResource(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, map[string]any{
		"resource":                 h.Resource,
		"authorization_servers":    []string{h.Issuer},
		"scopes_supported":         []string{},
		"bearer_methods_supported": []string{"header"},
	})
}

// AuthorizationServer serves /.well-known/oauth-authorization-server (RFC 8414).
func (h *Handlers) AuthorizationServer(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, map[string]any{
		"issuer":                                h.Issuer,
		"authorization_endpoint":                h.Issuer + "/authorize",
		"token_endpoint":                        h.Issuer + "/token",
		"registration_endpoint":                 h.Issuer + "/register",
		"jwks_uri":                              h.Issuer + "/.well-known/jwks.json",
		"response_types_supported":              []string{"code"},
		"grant_types_supported":                 []string{"authorization_code"},
		"code_challenge_methods_supported":      []string{"S256"},
		"token_endpoint_auth_methods_supported": []string{"none"},
	})
}

// JWKS serves /.well-known/jwks.json with the public signing key.
func (h *Handlers) JWKS(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, h.Signer.JWKS())
}
