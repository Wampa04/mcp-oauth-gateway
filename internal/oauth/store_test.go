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
