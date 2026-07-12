package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func writeConfig(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "gateway.yaml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

const validYAML = `
issuer: https://mcp.example.com
upstream: http://osmmcp:8000
github:
  client_id: cid
  client_secret: secret
allowed_github_ids: [42, 99]
`

func TestLoadValid(t *testing.T) {
	cfg, err := Load(writeConfig(t, validYAML))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Resource != "https://mcp.example.com" {
		t.Errorf("Resource = %q, want issuer without slash", cfg.Resource)
	}
	if cfg.Listen != ":8080" {
		t.Errorf("Listen default = %q", cfg.Listen)
	}
	if cfg.TokenTTL != time.Hour {
		t.Errorf("TokenTTL default = %v", cfg.TokenTTL)
	}
	if !cfg.Consent() {
		t.Error("Consent should default to true")
	}
}

func TestEmptyAllowlistRejected(t *testing.T) {
	body := `
issuer: https://mcp.example.com
upstream: http://osmmcp:8000
github: {client_id: cid, client_secret: secret}
`
	if _, err := Load(writeConfig(t, body)); err == nil {
		t.Fatal("expected error for empty allowlist")
	}
}

func TestEmptyAllowlistOptIn(t *testing.T) {
	body := `
issuer: https://mcp.example.com
upstream: http://osmmcp:8000
github: {client_id: cid, client_secret: secret}
allow_empty_allowlist: true
`
	if _, err := Load(writeConfig(t, body)); err != nil {
		t.Fatalf("opt-in empty allowlist should load: %v", err)
	}
}

func TestNonHTTPSIssuerRejected(t *testing.T) {
	body := `
issuer: http://mcp.example.com
upstream: http://osmmcp:8000
github: {client_id: cid, client_secret: secret}
allowed_github_ids: [1]
`
	if _, err := Load(writeConfig(t, body)); err == nil {
		t.Fatal("expected error for non-https issuer")
	}
}

func TestLocalhostHTTPAllowed(t *testing.T) {
	body := `
issuer: http://localhost:8080
upstream: http://localhost:9000
github: {client_id: cid, client_secret: secret}
allowed_github_ids: [1]
`
	if _, err := Load(writeConfig(t, body)); err != nil {
		t.Fatalf("localhost http should be allowed: %v", err)
	}
}

func TestMissingGitHubCreds(t *testing.T) {
	body := `
issuer: https://mcp.example.com
upstream: http://osmmcp:8000
allowed_github_ids: [1]
`
	if _, err := Load(writeConfig(t, body)); err == nil {
		t.Fatal("expected error for missing github creds")
	}
}

func TestEnvOverridesSecrets(t *testing.T) {
	body := `
issuer: https://mcp.example.com
upstream: http://osmmcp:8000
allowed_github_ids: [1]
`
	t.Setenv("GITHUB_CLIENT_ID", "envid")
	t.Setenv("GITHUB_CLIENT_SECRET", "envsecret")
	cfg, err := Load(writeConfig(t, body))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.GitHub.ClientID != "envid" || cfg.GitHub.ClientSecret != "envsecret" {
		t.Errorf("env override not applied: %+v", cfg.GitHub)
	}
}

func TestConsentDisabled(t *testing.T) {
	body := validYAML + "\nrequire_consent: false\n"
	cfg, err := Load(writeConfig(t, body))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Consent() {
		t.Error("Consent should be false when disabled")
	}
}

func TestTLSPairRequired(t *testing.T) {
	body := validYAML + "\ntls:\n  cert_file: cert.pem\n"
	if _, err := Load(writeConfig(t, body)); err == nil {
		t.Fatal("expected error when only cert_file is set")
	}
}
