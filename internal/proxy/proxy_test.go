package proxy

import (
	"net/http/httptest"
	"testing"
)

func TestStripsAuthorizationHeader(t *testing.T) {
	rp, err := New("http://upstream:9000")
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest("GET", "http://gateway/mcp", nil)
	req.Header.Set("Authorization", "Bearer gateway-token")
	rp.Director(req)
	if got := req.Header.Get("Authorization"); got != "" {
		t.Fatalf("Authorization must be stripped before forwarding, got %q", got)
	}
}

func TestRejectsNonAbsoluteUpstream(t *testing.T) {
	if _, err := New("not-a-url"); err == nil {
		t.Fatal("expected error for non-absolute upstream")
	}
}
