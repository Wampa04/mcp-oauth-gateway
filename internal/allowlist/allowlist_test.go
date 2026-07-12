package allowlist

import "testing"

func TestAllowed(t *testing.T) {
	a := New([]int64{42, 99})
	if !a.IsAllowed(42) {
		t.Error("42 should be allowed")
	}
	if !a.IsAllowed(99) {
		t.Error("99 should be allowed")
	}
}

func TestUnknownDenied(t *testing.T) {
	a := New([]int64{42})
	if a.IsAllowed(7) {
		t.Error("7 should be denied")
	}
}

func TestEmptyDeniesAll(t *testing.T) {
	a := New(nil)
	if a.IsAllowed(42) {
		t.Error("empty allowlist must deny everyone")
	}
}

func TestNilDeniesAll(t *testing.T) {
	var a *Allowlist
	if a.IsAllowed(42) {
		t.Error("nil allowlist must deny")
	}
}
