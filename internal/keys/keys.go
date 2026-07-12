// Package keys manages the RSA signing key: load from disk or generate and
// persist, and expose the public key as a JWK set.
package keys

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"log"
	"os"
	"path/filepath"
)

type Signer struct {
	Private *rsa.PrivateKey
	KID     string
}

func LoadOrGenerate(path string) (*Signer, error) {
	data, err := os.ReadFile(path)
	if err == nil {
		key, perr := parsePEM(data)
		if perr != nil {
			return nil, fmt.Errorf("parse key %q: %w", path, perr)
		}
		return newSigner(key), nil
	}
	if !os.IsNotExist(err) {
		return nil, fmt.Errorf("read key %q: %w", path, err)
	}

	log.Printf("keys: no signing key at %q; generating a new one — persist this path (e.g. a volume) or clients will reject tokens after restarts", path)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("generate key: %w", err)
	}
	if err := persist(path, key); err != nil {
		return nil, err
	}
	return newSigner(key), nil
}

func newSigner(key *rsa.PrivateKey) *Signer {
	der, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	sum := sha256.Sum256(der)
	return &Signer{Private: key, KID: base64.RawURLEncoding.EncodeToString(sum[:])}
}

func persist(path string, key *rsa.PrivateKey) error {
	if dir := filepath.Dir(path); dir != "" {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("create key dir: %w", err)
		}
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return fmt.Errorf("marshal key: %w", err)
	}
	block := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	if err := os.WriteFile(path, block, 0o600); err != nil {
		return fmt.Errorf("write key %q: %w", path, err)
	}
	return nil
}

func parsePEM(data []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found")
	}
	if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		rk, ok := key.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("key is not RSA")
		}
		return rk, nil
	}
	return x509.ParsePKCS1PrivateKey(block.Bytes)
}
