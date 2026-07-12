// Package routes holds the gateway's HTTP path constants so the router, the
// discovery metadata and the entrypoint share one source of truth.
package routes

const (
	Authorize           = "/authorize"
	Token               = "/token"
	Register            = "/register"
	Callback            = "/callback"
	Healthz             = "/healthz"
	JWKS                = "/.well-known/jwks.json"
	ProtectedResource   = "/.well-known/oauth-protected-resource"
	AuthorizationServer = "/.well-known/oauth-authorization-server"
	OpenIDConfiguration = "/.well-known/openid-configuration"
)
