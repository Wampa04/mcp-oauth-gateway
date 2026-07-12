package server

import (
	"net/http"

	"mcp-oauth-gateway/internal/discovery"
	"mcp-oauth-gateway/internal/oauth"
)

// New wires the public OAuth/metadata endpoints and puts everything else behind
// the auth middleware, forwarding to the upstream proxy.
func New(disc *discovery.Handlers, oa *oauth.Handlers, mw *Middleware, upstream http.Handler) http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("/.well-known/oauth-protected-resource", disc.ProtectedResource)
	mux.HandleFunc("/.well-known/oauth-authorization-server", disc.AuthorizationServer)
	mux.HandleFunc("/.well-known/openid-configuration", disc.AuthorizationServer)
	mux.HandleFunc("/.well-known/jwks.json", disc.JWKS)

	mux.HandleFunc("/authorize", oa.Authorize)
	mux.HandleFunc("/callback", oa.Callback)
	mux.HandleFunc("/token", oa.Token)
	mux.HandleFunc("/register", oa.Register)

	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	mux.Handle("/", mw.Auth(upstream))

	return Logging(mux)
}
