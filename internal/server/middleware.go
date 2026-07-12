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
			m.challenge(w, "missing bearer token")
			return
		}
		claims, err := m.Validator.Validate(raw)
		if err != nil {
			m.challenge(w, "invalid token")
			return
		}
		ctx := context.WithValue(r.Context(), subjectKey, claims.Subject)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (m *Middleware) challenge(w http.ResponseWriter, desc string) {
	w.Header().Set("WWW-Authenticate",
		`Bearer error="invalid_token", error_description="`+desc+`", resource_metadata="`+m.ResourceMetadataURL+`"`)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)
	_, _ = w.Write([]byte(`{"error":"invalid_token"}`))
}

func bearerToken(r *http.Request) string {
	h := r.Header.Get("Authorization")
	const prefix = "Bearer "
	if len(h) > len(prefix) && strings.EqualFold(h[:len(prefix)], prefix) {
		return strings.TrimSpace(h[len(prefix):])
	}
	return ""
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

// Flush implements http.Flusher so SSE streaming survives the logging wrapper.
func (w *statusWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}
