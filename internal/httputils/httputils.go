// Package httputils holds small HTTP helpers shared across packages.
package httputils

import (
	"encoding/json"
	"net/http"
)

// WriteJSON writes v as JSON with the given status and optional Cache-Control.
func WriteJSON(w http.ResponseWriter, status int, cacheControl string, v any) {
	w.Header().Set("Content-Type", "application/json")
	if cacheControl != "" {
		w.Header().Set("Cache-Control", cacheControl)
	}
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// IsLoopbackHost reports whether host is a loopback name/address.
func IsLoopbackHost(host string) bool {
	return host == "localhost" || host == "127.0.0.1" || host == "::1"
}
