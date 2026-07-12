// Package token issues and validates the gateway's own RS256 access tokens.
package token

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/hex"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type Issuer struct {
	key *rsa.PrivateKey
	kid string
	iss string
}

func NewIssuer(key *rsa.PrivateKey, kid, iss string) *Issuer {
	return &Issuer{key: key, kid: kid, iss: iss}
}

// Issue signs an access token for sub with the given audience (the MCP resource).
func (i *Issuer) Issue(sub, aud string, ttl time.Duration) (string, error) {
	now := time.Now()
	claims := jwt.MapClaims{
		"iss": i.iss,
		"sub": sub,
		"aud": aud,
		"iat": now.Unix(),
		"exp": now.Add(ttl).Unix(),
		"jti": randomJTI(),
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = i.kid
	return tok.SignedString(i.key)
}

func randomJTI() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}
