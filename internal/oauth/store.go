package oauth

import (
	"crypto/rand"
	"encoding/base64"
	"sync"
	"time"
)

type Client struct {
	ID           string
	RedirectURIs []string
	Name         string
	CreatedAt    time.Time
}

type AuthCode struct {
	ClientID      string
	RedirectURI   string
	CodeChallenge string
	Resource      string
	GitHubUserID  int64
	Scope         string
	Expiry        time.Time
}

// PendingFlow links a GitHub callback (keyed by our state) back to the original
// client authorization request.
type PendingFlow struct {
	ClientID      string
	RedirectURI   string
	ClientState   string
	CodeChallenge string
	Resource      string
	Scope         string
	Expiry        time.Time
}

type Store struct {
	mu      sync.Mutex
	clients map[string]*Client
	codes   map[string]*AuthCode
	pending map[string]*PendingFlow
}

func NewStore() *Store {
	return &Store{
		clients: make(map[string]*Client),
		codes:   make(map[string]*AuthCode),
		pending: make(map[string]*PendingFlow),
	}
}

func (s *Store) SaveClient(c *Client) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.clients[c.ID] = c
}

func (s *Store) GetClient(id string) (*Client, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.clients[id]
	return c, ok
}

func (s *Store) SavePending(state string, p *PendingFlow) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pending[state] = p
}

// TakePending removes and returns a pending flow; ok is false if missing/expired.
func (s *Store) TakePending(state string) (*PendingFlow, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.pending[state]
	if !ok {
		return nil, false
	}
	delete(s.pending, state)
	if time.Now().After(p.Expiry) {
		return nil, false
	}
	return p, true
}

func (s *Store) SaveCode(code string, a *AuthCode) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.codes[code] = a
}

// TakeCode removes and returns an auth code (single use); ok is false if
// missing/expired.
func (s *Store) TakeCode(code string) (*AuthCode, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.codes[code]
	if !ok {
		return nil, false
	}
	delete(s.codes, code)
	if time.Now().After(a.Expiry) {
		return nil, false
	}
	return a, true
}

// GC drops expired codes and pending flows. Call periodically.
func (s *Store) GC() {
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, v := range s.codes {
		if now.After(v.Expiry) {
			delete(s.codes, k)
		}
	}
	for k, v := range s.pending {
		if now.After(v.Expiry) {
			delete(s.pending, k)
		}
	}
}

func randomToken() string {
	var b [32]byte
	_, _ = rand.Read(b[:])
	return base64.RawURLEncoding.EncodeToString(b[:])
}
