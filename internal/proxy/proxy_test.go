package proxy

import (
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"testing"
)

func TestStripsCredentialAndForwardingHeaders(t *testing.T) {
	rp, err := New("http://upstream:9000")
	if err != nil {
		t.Fatal(err)
	}
	in := httptest.NewRequest("GET", "http://gateway/mcp", nil)
	in.Header.Set("Authorization", "Bearer gateway-token")
	in.Header.Set("Cookie", "session=abc")
	in.Header.Set("X-Forwarded-For", "9.9.9.9") // spoofed by client
	out := in.Clone(in.Context())
	rp.Rewrite(&httputil.ProxyRequest{In: in, Out: out})

	if out.Header.Get("Authorization") != "" {
		t.Error("Authorization must be stripped before forwarding")
	}
	if out.Header.Get("Cookie") != "" {
		t.Error("Cookie must be stripped before forwarding")
	}
	// SetXForwarded replaces the client-supplied value with the real peer IP.
	if xff := out.Header.Get("X-Forwarded-For"); xff == "9.9.9.9" || xff == "" {
		t.Errorf("X-Forwarded-For must be reset to the real peer, got %q", xff)
	}
}

func TestModifyResponseStripsUpstreamCORS(t *testing.T) {
	rp, err := New("http://upstream:9000")
	if err != nil {
		t.Fatal(err)
	}
	resp := &http.Response{Header: http.Header{}}
	resp.Header.Set("Access-Control-Allow-Origin", "*")
	resp.Header.Set("Access-Control-Allow-Credentials", "true")
	resp.Header.Set("Content-Type", "application/json")

	if err := rp.ModifyResponse(resp); err != nil {
		t.Fatal(err)
	}
	if resp.Header.Get("Access-Control-Allow-Origin") != "" ||
		resp.Header.Get("Access-Control-Allow-Credentials") != "" {
		t.Error("upstream CORS headers must be stripped")
	}
	if resp.Header.Get("Content-Type") != "application/json" {
		t.Error("non-CORS headers must be preserved")
	}
}

func TestRejectsNonAbsoluteUpstream(t *testing.T) {
	if _, err := New("not-a-url"); err == nil {
		t.Fatal("expected error for non-absolute upstream")
	}
}
