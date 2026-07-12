package server

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCORSPreflightShortCircuits(t *testing.T) {
	called := false
	h := CORS(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true }))

	req := httptest.NewRequest(http.MethodOptions, "/token", nil)
	req.Header.Set("Origin", "http://localhost:6274")
	req.Header.Set("Access-Control-Request-Method", "POST")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if called {
		t.Fatal("preflight must not reach the next handler")
	}
	if rr.Code != http.StatusNoContent {
		t.Fatalf("preflight status = %d, want 204", rr.Code)
	}
	if got := rr.Header().Get("Access-Control-Allow-Origin"); got != "http://localhost:6274" {
		t.Fatalf("ACAO = %q, want reflected origin", got)
	}
}

func TestCORSReflectsOriginOnNormalRequest(t *testing.T) {
	h := CORS(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest(http.MethodGet, "/.well-known/oauth-authorization-server", nil)
	req.Header.Set("Origin", "http://localhost:6274")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d", rr.Code)
	}
	if rr.Header().Get("Access-Control-Allow-Origin") != "http://localhost:6274" {
		t.Fatal("expected reflected ACAO on normal request")
	}
}
