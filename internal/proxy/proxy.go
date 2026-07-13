// Package proxy forwards authenticated requests to the upstream MCP server. It
// is transparent and streaming-capable (SSE and streamable HTTP).
package proxy

import (
	"fmt"
	"net/http"
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
	return &httputil.ReverseProxy{
		FlushInterval: -1, // flush immediately for SSE / long-lived streams
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(u)
			pr.Out.Host = pr.In.Host
			// Set clean X-Forwarded-* from the inbound peer, dropping any
			// client-supplied (spoofable) values.
			pr.SetXForwarded()
			// The upstream is outside the trust boundary: never forward the
			// client's gateway token or cookies (MCP spec forbids token passthrough).
			pr.Out.Header.Del("Authorization")
			pr.Out.Header.Del("Cookie")
		},
		ModifyResponse: func(resp *http.Response) error {
			// The gateway sets its own CORS headers; drop the upstream's so
			// browsers don't see duplicate Access-Control-* values.
			for _, h := range corsResponseHeaders {
				resp.Header.Del(h)
			}
			return nil
		},
	}, nil
}

var corsResponseHeaders = []string{
	"Access-Control-Allow-Origin",
	"Access-Control-Allow-Methods",
	"Access-Control-Allow-Headers",
	"Access-Control-Allow-Credentials",
	"Access-Control-Expose-Headers",
	"Access-Control-Max-Age",
}
