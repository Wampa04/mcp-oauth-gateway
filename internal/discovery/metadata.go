// Package discovery serves the OAuth metadata documents (RFC 9728 / RFC 8414)
// and the JWKS that MCP clients use to discover and trust the gateway.
package discovery

import (
	"net/http"

	"mcp-oauth-gateway/internal/httputils"
	"mcp-oauth-gateway/internal/keys"
	"mcp-oauth-gateway/internal/routes"
)

// jwksMaxAge is kept short so a signing-key change is picked up quickly instead
// of clients rejecting freshly issued tokens against a stale cached key.
const jwksMaxAge = "public, max-age=300"

const metadataMaxAge = "public, max-age=3600"

type Handlers struct {
	Issuer   string
	Resource string
	Signer   *keys.Signer
}

// ProtectedResource serves /.well-known/oauth-protected-resource (RFC 9728).
func (h *Handlers) ProtectedResource(w http.ResponseWriter, _ *http.Request) {
	httputils.WriteJSON(w, http.StatusOK, metadataMaxAge, map[string]any{
		"resource":                 h.Resource,
		"authorization_servers":    []string{h.Issuer},
		"scopes_supported":         []string{},
		"bearer_methods_supported": []string{"header"},
	})
}

// AuthorizationServer serves /.well-known/oauth-authorization-server (RFC 8414).
func (h *Handlers) AuthorizationServer(w http.ResponseWriter, _ *http.Request) {
	httputils.WriteJSON(w, http.StatusOK, metadataMaxAge, map[string]any{
		"issuer":                                h.Issuer,
		"authorization_endpoint":                h.Issuer + routes.Authorize,
		"token_endpoint":                        h.Issuer + routes.Token,
		"registration_endpoint":                 h.Issuer + routes.Register,
		"jwks_uri":                              h.Issuer + routes.JWKS,
		"response_types_supported":              []string{"code"},
		"grant_types_supported":                 []string{"authorization_code"},
		"code_challenge_methods_supported":      []string{"S256"},
		"token_endpoint_auth_methods_supported": []string{"none"},
	})
}

// JWKS serves /.well-known/jwks.json with the public signing key.
func (h *Handlers) JWKS(w http.ResponseWriter, _ *http.Request) {
	httputils.WriteJSON(w, http.StatusOK, jwksMaxAge, h.Signer.JWKS())
}
