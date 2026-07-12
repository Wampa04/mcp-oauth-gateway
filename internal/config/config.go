// Package config loads and validates the gateway configuration. Validation is
// fail-closed: a misconfigured gateway refuses to start.
package config

import (
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Issuer   string `yaml:"issuer"`   // external base URL, e.g. https://mcp.example.com
	Listen   string `yaml:"listen"`   // bind address, e.g. ":8080"
	Upstream string `yaml:"upstream"` // internal URL of the unauth'd MCP server
	Resource string `yaml:"resource"` // token audience (RFC 8707); defaults to Issuer

	GitHub GitHubConfig `yaml:"github"`

	AllowedGitHubIDs    []int64 `yaml:"allowed_github_ids"`
	AllowEmptyAllowlist bool    `yaml:"allow_empty_allowlist"`

	KeyPath string `yaml:"key_path"`

	TokenTTL    time.Duration `yaml:"-"`
	TokenTTLRaw string        `yaml:"token_ttl"`

	RequireConsent    *bool `yaml:"require_consent"` // default true
	requireConsentVal bool

	TLS TLSConfig `yaml:"tls"`
}

type GitHubConfig struct {
	ClientID     string `yaml:"client_id"`
	ClientSecret string `yaml:"client_secret"`
}

type TLSConfig struct {
	CertFile string `yaml:"cert_file"`
	KeyFile  string `yaml:"key_file"`
}

func (c *Config) Consent() bool    { return c.requireConsentVal }
func (c *Config) TLSEnabled() bool { return c.TLS.CertFile != "" && c.TLS.KeyFile != "" }

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config %q: %w", path, err)
	}
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse config %q: %w", path, err)
	}
	if err := cfg.applyEnvAndDefaults(); err != nil {
		return nil, err
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func (c *Config) applyEnvAndDefaults() error {
	for _, o := range []struct {
		env string
		dst *string
	}{
		{"GITHUB_CLIENT_ID", &c.GitHub.ClientID},
		{"GITHUB_CLIENT_SECRET", &c.GitHub.ClientSecret},
		{"ISSUER", &c.Issuer},
		{"UPSTREAM", &c.Upstream},
		{"LISTEN", &c.Listen},
		{"KEY_PATH", &c.KeyPath},
	} {
		if v := os.Getenv(o.env); v != "" {
			*o.dst = v
		}
	}

	c.Issuer = strings.TrimRight(c.Issuer, "/")
	if c.Listen == "" {
		c.Listen = ":8080"
	}
	if c.KeyPath == "" {
		c.KeyPath = "keys/signing.pem"
	}
	if c.Resource == "" {
		c.Resource = c.Issuer
	}
	c.Resource = strings.TrimRight(c.Resource, "/")

	c.TokenTTL = time.Hour
	if c.TokenTTLRaw != "" {
		d, err := time.ParseDuration(c.TokenTTLRaw)
		if err != nil {
			return fmt.Errorf("invalid token_ttl %q: %w", c.TokenTTLRaw, err)
		}
		c.TokenTTL = d
	}

	c.requireConsentVal = true
	if c.RequireConsent != nil {
		c.requireConsentVal = *c.RequireConsent
	}
	return nil
}

func (c *Config) Validate() error {
	if c.Issuer == "" {
		return fmt.Errorf("config: issuer is required")
	}
	iss, err := url.Parse(c.Issuer)
	if err != nil {
		return fmt.Errorf("config: invalid issuer %q: %w", c.Issuer, err)
	}
	if iss.Scheme != "https" && !isLocalhost(iss.Hostname()) {
		return fmt.Errorf("config: issuer must use https (got %q); only localhost may use http", c.Issuer)
	}
	if c.Upstream == "" {
		return fmt.Errorf("config: upstream is required")
	}
	if _, err := url.Parse(c.Upstream); err != nil {
		return fmt.Errorf("config: invalid upstream %q: %w", c.Upstream, err)
	}
	if c.GitHub.ClientID == "" || c.GitHub.ClientSecret == "" {
		return fmt.Errorf("config: github.client_id and github.client_secret are required")
	}
	if len(c.AllowedGitHubIDs) == 0 && !c.AllowEmptyAllowlist {
		return fmt.Errorf("config: allowed_github_ids is empty; set allow_empty_allowlist: true to override")
	}
	if c.TokenTTL <= 0 {
		return fmt.Errorf("config: token_ttl must be positive")
	}
	if (c.TLS.CertFile == "") != (c.TLS.KeyFile == "") {
		return fmt.Errorf("config: tls.cert_file and tls.key_file must be set together")
	}
	return nil
}

func isLocalhost(host string) bool {
	return host == "localhost" || host == "127.0.0.1" || host == "::1"
}
