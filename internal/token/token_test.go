package token

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	testIss = "https://mcp.example.com"
	testRes = "https://mcp.example.com"
)

func testKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestValidToken(t *testing.T) {
	key := testKey(t)
	iss := NewIssuer(key, "kid1", testIss)
	val := NewValidator(&key.PublicKey, testIss, testRes)

	raw, err := iss.Issue("12345", testRes, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	claims, err := val.Validate(raw)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if claims.Subject != "12345" {
		t.Errorf("Subject = %q, want 12345", claims.Subject)
	}
}

func TestWrongSignatureRejected(t *testing.T) {
	signKey := testKey(t)
	otherKey := testKey(t)
	iss := NewIssuer(signKey, "kid1", testIss)
	val := NewValidator(&otherKey.PublicKey, testIss, testRes)

	raw, _ := iss.Issue("12345", testRes, time.Hour)
	if _, err := val.Validate(raw); err == nil {
		t.Fatal("expected signature validation to fail")
	}
}

func TestWrongIssuerRejected(t *testing.T) {
	key := testKey(t)
	iss := NewIssuer(key, "kid1", "https://evil.example.com")
	val := NewValidator(&key.PublicKey, testIss, testRes)

	raw, _ := iss.Issue("12345", testRes, time.Hour)
	if _, err := val.Validate(raw); err == nil {
		t.Fatal("expected issuer mismatch to fail")
	}
}

func TestWrongAudienceRejected(t *testing.T) {
	key := testKey(t)
	iss := NewIssuer(key, "kid1", testIss)
	val := NewValidator(&key.PublicKey, testIss, testRes)

	raw, _ := iss.Issue("12345", "https://other-resource.example.com", time.Hour)
	if _, err := val.Validate(raw); err == nil {
		t.Fatal("expected audience mismatch to fail (audience binding)")
	}
}

func TestExpiredTokenRejected(t *testing.T) {
	key := testKey(t)
	iss := NewIssuer(key, "kid1", testIss)
	val := NewValidator(&key.PublicKey, testIss, testRes)

	raw, _ := iss.Issue("12345", testRes, -time.Minute)
	if _, err := val.Validate(raw); err == nil {
		t.Fatal("expected expired token to fail")
	}
}

func TestNoneAlgRejected(t *testing.T) {
	key := testKey(t)
	val := NewValidator(&key.PublicKey, testIss, testRes)

	claims := jwt.MapClaims{
		"iss": testIss, "sub": "12345", "aud": testRes,
		"exp": time.Now().Add(time.Hour).Unix(),
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodNone, claims)
	raw, err := tok.SignedString(jwt.UnsafeAllowNoneSignatureType)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := val.Validate(raw); err == nil {
		t.Fatal("expected alg:none token to be rejected")
	}
}

func TestHS256Rejected(t *testing.T) {
	key := testKey(t)
	val := NewValidator(&key.PublicKey, testIss, testRes)

	claims := jwt.MapClaims{
		"iss": testIss, "sub": "12345", "aud": testRes,
		"exp": time.Now().Add(time.Hour).Unix(),
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	raw, err := tok.SignedString([]byte("shared-secret"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := val.Validate(raw); err == nil {
		t.Fatal("expected HS256 token to be rejected (alg confusion)")
	}
}
