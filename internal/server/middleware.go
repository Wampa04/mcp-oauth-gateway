package server

import (
	"context"
	"log"
	"net/http"
	"strings"
	"time"

	"mcp-oauth-gateway/internal/token"
)

type ctxKey int

const subjectKey ctxKey = 0

type Middleware struct {
	Validator           *token.Validator
	ResourceMetadataURL string
}

// Auth validates the Bearer token before proxying. On failure it returns 401
// with a WWW-Authenticate header pointing at the protected resource metadata.
func (m *Middleware) Auth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw := bearerToken(r)
		if raw == "" {
			// No credentials: bare challenge with no error code (RFC 6750 §3.1).
			m.challenge(w, "")
			return
		}
		claims, err := m.Validator.Validate(raw)
		if err != nil {
			m.challenge(w, "invalid_token")
			return
		}
		ctx := context.WithValue(r.Context(), subjectKey, claims.Subject)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (m *Middleware) challenge(w http.ResponseWriter, errCode string) {
	params := `Bearer resource_metadata="` + m.ResourceMetadataURL + `"`
	if errCode != "" {
		params = `Bearer error="` + errCode + `", resource_metadata="` + m.ResourceMetadataURL + `"`
	}
	w.Header().Set("WWW-Authenticate", params)
	if errCode != "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"` + errCode + `"}`))
		return
	}
	w.WriteHeader(http.StatusUnauthorized)
}

func bearerToken(r *http.Request) string {
	h := r.Header.Get("Authorization")
	const prefix = "Bearer "
	if len(h) > len(prefix) && strings.EqualFold(h[:len(prefix)], prefix) {
		return strings.TrimSpace(h[len(prefix):])
	}
	return ""
}

// CORS allows browser-based MCP clients (e.g. the MCP Inspector) to call the
// gateway cross-origin and short-circuits preflight requests before auth.
func CORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if origin := r.Header.Get("Origin"); origin != "" {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Add("Vary", "Origin")
		} else {
			w.Header().Set("Access-Control-Allow-Origin", "*")
		}
		reqHeaders := r.Header.Get("Access-Control-Request-Headers")
		if reqHeaders == "" {
			reqHeaders = "Authorization, Content-Type, Mcp-Session-Id, Mcp-Protocol-Version, Last-Event-ID"
		}
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", reqHeaders)
		w.Header().Set("Access-Control-Expose-Headers", "WWW-Authenticate, Mcp-Session-Id")
		w.Header().Set("Access-Control-Max-Age", "600")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// Logging records method, path and status without leaking tokens.
func Logging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(sw, r)
		log.Printf("%s %s %d %s", r.Method, r.URL.Path, sw.status, time.Since(start).Round(time.Millisecond))
	})
}

type statusWriter struct {
	http.ResponseWriter
	status      int
	wroteHeader bool
}

func (w *statusWriter) WriteHeader(code int) {
	if !w.wroteHeader {
		w.status = code
		w.wroteHeader = true
	}
	w.ResponseWriter.WriteHeader(code)
}

// Unwrap lets http.ResponseController reach the underlying writer's Flusher and
// Hijacker, so SSE streaming and connection upgrades survive the logging wrapper.
func (w *statusWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }
