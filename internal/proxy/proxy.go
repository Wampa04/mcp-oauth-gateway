// Package proxy forwards authenticated requests to the upstream MCP server. It
// is transparent and streaming-capable (SSE and streamable HTTP).
package proxy

import (
	"fmt"
	"net/http/httputil"
	"net/url"
)

func New(upstream string) (*httputil.ReverseProxy, error) {
	u, err := url.Parse(upstream)
	if err != nil {
		return nil, fmt.Errorf("parse upstream %q: %w", upstream, err)
	}
	if u.Scheme == "" || u.Host == "" {
		return nil, fmt.Errorf("upstream must be an absolute URL, got %q", upstream)
	}
	rp := httputil.NewSingleHostReverseProxy(u)
	rp.FlushInterval = -1 // flush immediately for SSE / long-lived streams
	return rp, nil
}
