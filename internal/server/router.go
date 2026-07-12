package server

import (
	"net/http"

	"mcp-oauth-gateway/internal/discovery"
	"mcp-oauth-gateway/internal/oauth"
	"mcp-oauth-gateway/internal/routes"
)

// New wires the public OAuth/metadata endpoints and puts everything else behind
// the auth middleware, forwarding to the upstream proxy.
func New(disc *discovery.Handlers, oa *oauth.Handlers, mw *Middleware, upstream http.Handler) http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc(routes.ProtectedResource, disc.ProtectedResource)
	mux.HandleFunc(routes.AuthorizationServer, disc.AuthorizationServer)
	mux.HandleFunc(routes.OpenIDConfiguration, disc.AuthorizationServer)
	mux.HandleFunc(routes.JWKS, disc.JWKS)

	mux.HandleFunc(routes.Authorize, oa.Authorize)
	mux.HandleFunc(routes.Callback, oa.Callback)
	mux.HandleFunc(routes.Token, oa.Token)
	mux.HandleFunc(routes.Register, oa.Register)

	mux.HandleFunc(routes.Healthz, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	mux.Handle("/", mw.Auth(upstream))

	return Logging(mux)
}
