package oauth

import (
	"strconv"
	"testing"
	"time"
)

func TestSaveClientRejectsWhenFull(t *testing.T) {
	s := NewStore()
	for i := 0; i < maxClients; i++ {
		if !s.SaveClient(&Client{ID: strconv.Itoa(i)}) {
			t.Fatalf("client %d below cap should be accepted", i)
		}
	}
	if s.SaveClient(&Client{ID: "overflow"}) {
		t.Fatal("registry full: new client must be rejected, not accepted by evicting an established one")
	}
}

func TestSaveRefreshTokenRejectsWhenFull(t *testing.T) {
	s := NewStore()
	for i := 0; i < maxRefreshToken; i++ {
		if !s.SaveRefreshToken(strconv.Itoa(i), &RefreshToken{ClientID: "c", Expiry: time.Now().Add(time.Hour)}) {
			t.Fatalf("refresh token %d below cap should be accepted", i)
		}
	}
	if s.SaveRefreshToken("overflow", &RefreshToken{ClientID: "c", Expiry: time.Now().Add(time.Hour)}) {
		t.Fatal("store full: new refresh token must be rejected, not accepted by evicting an established one")
	}
}

func TestRefreshTokenSingleUseStore(t *testing.T) {
	s := NewStore()
	rt := &RefreshToken{ClientID: "client1", GitHubUserID: 42, Expiry: time.Now().Add(time.Hour)}
	if !s.SaveRefreshToken("tok", rt) {
		t.Fatal("save should succeed")
	}
	got, ok := s.TakeRefreshToken("tok")
	if !ok || got.ClientID != "client1" {
		t.Fatalf("first take should return client1, got %+v ok=%v", got, ok)
	}
	if _, ok := s.TakeRefreshToken("tok"); ok {
		t.Fatal("second take must fail (single-use)")
	}
}

func TestRefreshTokenExpired(t *testing.T) {
	s := NewStore()
	s.SaveRefreshToken("tok", &RefreshToken{ClientID: "client1", Expiry: time.Now().Add(-time.Minute)})
	if _, ok := s.TakeRefreshToken("tok"); ok {
		t.Fatal("expired refresh token must be rejected")
	}
}

func TestConsentTokenSingleUse(t *testing.T) {
	s := NewStore()
	if !s.SaveConsent("tok", "client1", time.Minute) {
		t.Fatal("save should succeed")
	}
	if cid, ok := s.TakeConsent("tok"); !ok || cid != "client1" {
		t.Fatalf("first take should return client1, got %q ok=%v", cid, ok)
	}
	if _, ok := s.TakeConsent("tok"); ok {
		t.Fatal("second take must fail (single-use)")
	}
}
