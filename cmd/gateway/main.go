package main

import (
	"context"
	"errors"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"mcp-oauth-gateway/internal/allowlist"
	"mcp-oauth-gateway/internal/config"
	"mcp-oauth-gateway/internal/discovery"
	"mcp-oauth-gateway/internal/github"
	"mcp-oauth-gateway/internal/keys"
	"mcp-oauth-gateway/internal/oauth"
	"mcp-oauth-gateway/internal/proxy"
	"mcp-oauth-gateway/internal/routes"
	"mcp-oauth-gateway/internal/server"
	"mcp-oauth-gateway/internal/token"
)

func main() {
	if err := run(); err != nil {
		log.Fatalf("gateway: %v", err)
	}
}

func run() error {
	cfgPath := flag.String("config", envOr("CONFIG_PATH", "gateway.yaml"), "path to config file")
	flag.Parse()

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}

	signer, err := keys.LoadOrGenerate(cfg.KeyPath)
	if err != nil {
		return err
	}

	issuer := token.NewIssuer(signer.Private, signer.KID, cfg.Issuer)
	validator := token.NewValidator(&signer.Private.PublicKey, cfg.Issuer, cfg.Resource)

	store := oauth.NewStore()
	go gcLoop(store)

	oauthH := &oauth.Handlers{
		Issuer:          cfg.Issuer,
		Resource:        cfg.Resource,
		ResourceOrigin:  oauth.OriginOf(cfg.Resource),
		CallbackURL:     cfg.Issuer + routes.Callback,
		TokenTTL:        cfg.TokenTTL,
		RefreshTokenTTL: cfg.RefreshTokenTTL,
		Consent:         cfg.Consent(),
		Store:           store,
		Allow:           allowlist.New(cfg.AllowedGitHubIDs),
		Tokens:          issuer,
		GitHub:          github.New(cfg.GitHub.ClientID, cfg.GitHub.ClientSecret),
	}

	disc := &discovery.Handlers{Issuer: cfg.Issuer, Resource: cfg.Resource, Signer: signer}

	rp, err := proxy.New(cfg.Upstream)
	if err != nil {
		return err
	}

	mw := &server.Middleware{
		Validator:           validator,
		ResourceMetadataURL: cfg.Issuer + routes.ProtectedResource,
	}

	handler := server.New(disc, oauthH, mw, rp, cfg.MCPPath)

	srv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		// No WriteTimeout: SSE streams are long-lived.
	}

	go func() {
		log.Printf("gateway listening on %s (issuer %s, upstream %s)", cfg.Listen, cfg.Issuer, cfg.Upstream)
		var serveErr error
		if cfg.TLSEnabled() {
			serveErr = srv.ListenAndServeTLS(cfg.TLS.CertFile, cfg.TLS.KeyFile)
		} else {
			serveErr = srv.ListenAndServe()
		}
		if serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
			log.Fatalf("gateway: server error: %v", serveErr)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	<-stop

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return srv.Shutdown(ctx)
}

func gcLoop(store *oauth.Store) {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for range t.C {
		store.GC()
	}
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
