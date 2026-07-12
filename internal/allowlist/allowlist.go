// Package allowlist gates access by GitHub numeric user ID. It is fail-closed:
// an ID is denied unless it was explicitly listed.
package allowlist

type Allowlist struct {
	ids map[int64]struct{}
}

func New(ids []int64) *Allowlist {
	m := make(map[int64]struct{}, len(ids))
	for _, id := range ids {
		m[id] = struct{}{}
	}
	return &Allowlist{ids: m}
}

func (a *Allowlist) IsAllowed(id int64) bool {
	if a == nil {
		return false
	}
	_, ok := a.ids[id]
	return ok
}