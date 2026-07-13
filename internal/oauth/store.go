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

type consentGrant struct {
	clientID string
	expiry   time.Time
}

// These caps bound the in-memory maps so unauthenticated traffic cannot exhaust
// memory. When full we reject new entries rather than evict existing ones (which
// would let a flood knock out established registrations).
const (
	maxClients  = 10000
	maxPending  = 10000
	maxConsents = 10000
)

type Store struct {
	mu       sync.Mutex
	clients  map[string]*Client
	codes    map[string]*AuthCode
	pending  map[string]*PendingFlow
	consents map[string]consentGrant
}

func NewStore() *Store {
	return &Store{
		clients:  make(map[string]*Client),
		codes:    make(map[string]*AuthCode),
		pending:  make(map[string]*PendingFlow),
		consents: make(map[string]consentGrant),
	}
}

// SaveClient registers a client; returns false if the registry is full.
func (s *Store) SaveClient(c *Client) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.clients) >= maxClients {
		return false
	}
	s.clients[c.ID] = c
	return true
}

func (s *Store) GetClient(id string) (*Client, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.clients[id]
	return c, ok
}

// SavePending stores a pending flow; returns false if the map is full even
// after reclaiming expired entries.
func (s *Store) SavePending(state string, p *PendingFlow) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.pending) >= maxPending {
		s.gcLocked()
		if len(s.pending) >= maxPending {
			return false
		}
	}
	s.pending[state] = p
	return true
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

// SaveConsent stores a one-time consent token bound to a client; returns false
// if the map is full even after reclaiming expired entries.
func (s *Store) SaveConsent(token, clientID string, ttl time.Duration) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.consents) >= maxConsents {
		s.gcLocked()
		if len(s.consents) >= maxConsents {
			return false
		}
	}
	s.consents[token] = consentGrant{clientID: clientID, expiry: time.Now().Add(ttl)}
	return true
}

// TakeConsent consumes a consent token, returning the bound client; ok is false
// if missing/expired.
func (s *Store) TakeConsent(token string) (string, bool) {
	if token == "" {
		return "", false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	g, ok := s.consents[token]
	if !ok {
		return "", false
	}
	delete(s.consents, token)
	if time.Now().After(g.expiry) {
		return "", false
	}
	return g.clientID, true
}

// GC drops expired codes, pending flows and consent tokens. Call periodically.
func (s *Store) GC() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.gcLocked()
}

// gcLocked sweeps expired entries. Caller holds mu.
func (s *Store) gcLocked() {
	now := time.Now()
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
	for k, v := range s.consents {
		if now.After(v.expiry) {
			delete(s.consents, k)
		}
	}
}

func randomToken() string {
	var b [32]byte
	_, _ = rand.Read(b[:])
	return base64.RawURLEncoding.EncodeToString(b[:])
}
