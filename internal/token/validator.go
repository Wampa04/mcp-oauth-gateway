package token

import (
	"crypto/rsa"
	"fmt"

	"github.com/golang-jwt/jwt/v5"
)

type Claims struct {
	Subject string
}

type Validator struct {
	pub      *rsa.PublicKey
	iss      string
	resource string
}

func NewValidator(pub *rsa.PublicKey, iss, resource string) *Validator {
	return &Validator{pub: pub, iss: iss, resource: resource}
}

// Validate verifies signature, issuer, audience (must match the MCP resource)
// and expiry. The signing method is pinned to RS256 to prevent alg confusion.
func (v *Validator) Validate(raw string) (*Claims, error) {
	parsed, err := jwt.Parse(raw, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method %q", t.Header["alg"])
		}
		return v.pub, nil
	},
		jwt.WithValidMethods([]string{"RS256"}),
		jwt.WithIssuer(v.iss),
		jwt.WithAudience(v.resource),
		jwt.WithExpirationRequired(),
	)
	if err != nil {
		return nil, err
	}
	claims, ok := parsed.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("unexpected claims type")
	}
	sub, _ := claims["sub"].(string)
	if sub == "" {
		return nil, fmt.Errorf("token has no subject")
	}
	return &Claims{Subject: sub}, nil
}
