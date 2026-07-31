package oauth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"mcp-oauth-gateway/internal/allowlist"
	"mcp-oauth-gateway/internal/token"
)

const (
	testIssuer   = "https://mcp.example.com"
	testRedirect = "https://client.test/callback"
	testVerifier = "averylongpkceverifierstring-1234567890-abcdefghij"
)

type fakeBridge struct {
	lastState   string
	userID      int64
	exchangeErr error
}

func (f *fakeBridge) AuthURL(state, _ string) string {
	f.lastState = state
	return "https://github.test/login/oauth/authorize?state=" + state
}

func (f *fakeBridge) Exchange(_ context.Context, _, _ string) (int64, string, error) {
	return f.userID, "octocat", f.exchangeErr
}

func newTestHandlers(t *testing.T, allowed []int64, userID int64) (*Handlers, *fakeBridge) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	br := &fakeBridge{userID: userID}
	return &Handlers{
		Issuer:          testIssuer,
		Resource:        testIssuer,
		CallbackURL:     testIssuer + "/callback",
		TokenTTL:        time.Hour,
		RefreshTokenTTL: 30 * 24 * time.Hour,
		Consent:         false,
		Store:           NewStore(),
		Allow:           allowlist.New(allowed),
		Tokens:          token.NewIssuer(key, "kid", testIssuer),
		GitHub:          br,
	}, br
}

func registerClient(t *testing.T, h *Handlers) string {
	t.Helper()
	body := `{"redirect_uris":["` + testRedirect + `"],"client_name":"Test Client"}`
	rr := httptest.NewRecorder()
	h.Register(rr, httptest.NewRequest(http.MethodPost, "/register", strings.NewReader(body)))
	if rr.Code != http.StatusCreated {
		t.Fatalf("Register status = %d, body %s", rr.Code, rr.Body.String())
	}
	var resp registrationResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.ClientID == "" {
		t.Fatal("empty client_id")
	}
	return resp.ClientID
}

// runAuthorize walks /authorize then /callback and returns the client-facing
// redirect Location from the callback.
func runAuthorize(t *testing.T, h *Handlers, br *fakeBridge, clientID string) *url.URL {
	t.Helper()
	q := url.Values{}
	q.Set("response_type", "code")
	q.Set("client_id", clientID)
	q.Set("redirect_uri", testRedirect)
	q.Set("code_challenge", ChallengeS256(testVerifier))
	q.Set("code_challenge_method", "S256")
	q.Set("state", "client-state-xyz")
	q.Set("resource", testIssuer)

	rr := httptest.NewRecorder()
	h.Authorize(rr, httptest.NewRequest(http.MethodGet, "/authorize?"+q.Encode(), nil))
	if rr.Code != http.StatusFound {
		t.Fatalf("Authorize status = %d, body %s", rr.Code, rr.Body.String())
	}
	if br.lastState == "" {
		t.Fatal("bridge did not receive a state")
	}

	cb := httptest.NewRecorder()
	h.Callback(cb, httptest.NewRequest(http.MethodGet, "/callback?state="+br.lastState+"&code=ghcode", nil))
	if cb.Code != http.StatusFound {
		t.Fatalf("Callback status = %d, body %s", cb.Code, cb.Body.String())
	}
	loc, err := url.Parse(cb.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	return loc
}

func postToken(h *Handlers, form url.Values) *httptest.ResponseRecorder {
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	h.Token(rr, req)
	return rr
}

func TestFullFlow(t *testing.T) {
	h, br := newTestHandlers(t, []int64{42}, 42)
	clientID := registerClient(t, h)

	loc := runAuthorize(t, h, br, clientID)
	if loc.Query().Get("state") != "client-state-xyz" {
		t.Errorf("state not echoed: %q", loc.Query().Get("state"))
	}
	code := loc.Query().Get("code")
	if code == "" {
		t.Fatalf("no code in callback redirect: %s", loc.String())
	}

	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", testRedirect)
	form.Set("client_id", clientID)
	form.Set("code_verifier", testVerifier)

	rr := postToken(h, form)
	if rr.Code != http.StatusOK {
		t.Fatalf("Token status = %d, body %s", rr.Code, rr.Body.String())
	}
	var tok tokenResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &tok); err != nil {
		t.Fatal(err)
	}
	if tok.AccessToken == "" || tok.TokenType != "Bearer" {
		t.Fatalf("bad token response: %+v", tok)
	}
}

func TestRefreshTokenIssuedAndUsable(t *testing.T) {
	h, br := newTestHandlers(t, []int64{42}, 42)
	clientID := registerClient(t, h)
	code := runAuthorize(t, h, br, clientID).Query().Get("code")

	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", testRedirect)
	form.Set("client_id", clientID)
	form.Set("code_verifier", testVerifier)

	rr := postToken(h, form)
	if rr.Code != http.StatusOK {
		t.Fatalf("Token status = %d, body %s", rr.Code, rr.Body.String())
	}
	var tok tokenResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &tok); err != nil {
		t.Fatal(err)
	}
	if tok.RefreshToken == "" {
		t.Fatal("expected a refresh_token in the authorization_code response")
	}

	refreshForm := url.Values{}
	refreshForm.Set("grant_type", "refresh_token")
	refreshForm.Set("refresh_token", tok.RefreshToken)
	refreshForm.Set("client_id", clientID)

	rr2 := postToken(h, refreshForm)
	if rr2.Code != http.StatusOK {
		t.Fatalf("refresh Token status = %d, body %s", rr2.Code, rr2.Body.String())
	}
	var tok2 tokenResponse
	if err := json.Unmarshal(rr2.Body.Bytes(), &tok2); err != nil {
		t.Fatal(err)
	}
	if tok2.AccessToken == "" || tok2.RefreshToken == "" {
		t.Fatalf("bad refresh response: %+v", tok2)
	}
	if tok2.RefreshToken == tok.RefreshToken {
		t.Fatal("expected refresh token to rotate, got the same one back")
	}
}

func TestRefreshTokenConcurrentUseOnlyOneSucceeds(t *testing.T) {
	h, br := newTestHandlers(t, []int64{42}, 42)
	clientID := registerClient(t, h)
	code := runAuthorize(t, h, br, clientID).Query().Get("code")

	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", testRedirect)
	form.Set("client_id", clientID)
	form.Set("code_verifier", testVerifier)
	rr := postToken(h, form)
	var tok tokenResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &tok); err != nil {
		t.Fatal(err)
	}

	refreshForm := url.Values{}
	refreshForm.Set("grant_type", "refresh_token")
	refreshForm.Set("refresh_token", tok.RefreshToken)
	refreshForm.Set("client_id", clientID)

	const n = 20
	codes := make([]int, n)
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func(i int) {
			defer wg.Done()
			codes[i] = postToken(h, refreshForm).Code
		}(i)
	}
	wg.Wait()

	successes := 0
	for _, c := range codes {
		if c == http.StatusOK {
			successes++
		}
	}
	if successes != 1 {
		t.Fatalf("expected exactly one concurrent refresh to succeed, got %d", successes)
	}
}

func TestRefreshTokenSingleUse(t *testing.T) {
	h, br := newTestHandlers(t, []int64{42}, 42)
	clientID := registerClient(t, h)
	code := runAuthorize(t, h, br, clientID).Query().Get("code")

	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", testRedirect)
	form.Set("client_id", clientID)
	form.Set("code_verifier", testVerifier)
	rr := postToken(h, form)
	var tok tokenResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &tok); err != nil {
		t.Fatal(err)
	}

	refreshForm := url.Values{}
	refreshForm.Set("grant_type", "refresh_token")
	refreshForm.Set("refresh_token", tok.RefreshToken)
	refreshForm.Set("client_id", clientID)

	if rr := postToken(h, refreshForm); rr.Code != http.StatusOK {
		t.Fatalf("first refresh failed: %d %s", rr.Code, rr.Body.String())
	}
	if rr := postToken(h, refreshForm); rr.Code == http.StatusOK {
		t.Fatal("expected refresh token reuse to be rejected")
	}
}

func TestRefreshTokenClientMismatchRejected(t *testing.T) {
	h, br := newTestHandlers(t, []int64{42}, 42)
	clientID := registerClient(t, h)
	code := runAuthorize(t, h, br, clientID).Query().Get("code")

	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", testRedirect)
	form.Set("client_id", clientID)
	form.Set("code_verifier", testVerifier)
	rr := postToken(h, form)
	var tok tokenResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &tok); err != nil {
		t.Fatal(err)
	}

	refreshForm := url.Values{}
	refreshForm.Set("grant_type", "refresh_token")
	refreshForm.Set("refresh_token", tok.RefreshToken)
	refreshForm.Set("client_id", "someone-elses-client")

	if rr := postToken(h, refreshForm); rr.Code == http.StatusOK {
		t.Fatal("expected client_id mismatch on refresh to be rejected")
	}

	// The mismatched attempt must not have burned the token: a retry with the
	// correct client_id should still work.
	refreshForm.Set("client_id", clientID)
	if rr := postToken(h, refreshForm); rr.Code != http.StatusOK {
		t.Fatalf("token must survive a client_id-mismatch attempt, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestRefreshTokenRevokedAllowlistRejected(t *testing.T) {
	h, br := newTestHandlers(t, []int64{42}, 42)
	clientID := registerClient(t, h)
	code := runAuthorize(t, h, br, clientID).Query().Get("code")

	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", testRedirect)
	form.Set("client_id", clientID)
	form.Set("code_verifier", testVerifier)
	rr := postToken(h, form)
	var tok tokenResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &tok); err != nil {
		t.Fatal(err)
	}

	h.Allow = allowlist.New(nil) // user removed from the allowlist

	refreshForm := url.Values{}
	refreshForm.Set("grant_type", "refresh_token")
	refreshForm.Set("refresh_token", tok.RefreshToken)
	refreshForm.Set("client_id", clientID)

	rr2 := postToken(h, refreshForm)
	if rr2.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for de-allowlisted user, got %d", rr2.Code)
	}

	// Not burned either: re-adding the user to the allowlist lets the same
	// refresh token succeed, instead of forcing a full GitHub re-login.
	h.Allow = allowlist.New([]int64{42})
	if rr := postToken(h, refreshForm); rr.Code != http.StatusOK {
		t.Fatalf("token must survive a de-allowlisted attempt, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestRefreshTokenNotBurnedWhenStoreFull(t *testing.T) {
	h, br := newTestHandlers(t, []int64{42}, 42)
	clientID := registerClient(t, h)
	code := runAuthorize(t, h, br, clientID).Query().Get("code")

	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", testRedirect)
	form.Set("client_id", clientID)
	form.Set("code_verifier", testVerifier)
	rr := postToken(h, form)
	var tok tokenResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &tok); err != nil {
		t.Fatal(err)
	}

	// Fill the refresh-token store to capacity (the presented token is already
	// counted in it) so SaveRefreshToken for the replacement must fail.
	for i := 0; i < maxRefreshToken-1; i++ {
		if !h.Store.SaveRefreshToken(strconv.Itoa(i), &RefreshToken{ClientID: clientID, Expiry: time.Now().Add(time.Hour)}) {
			t.Fatalf("filler token %d should be accepted", i)
		}
	}

	refreshForm := url.Values{}
	refreshForm.Set("grant_type", "refresh_token")
	refreshForm.Set("refresh_token", tok.RefreshToken)
	refreshForm.Set("client_id", clientID)

	rr2 := postToken(h, refreshForm)
	if rr2.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 when refresh store is full, got %d: %s", rr2.Code, rr2.Body.String())
	}

	// Free up room and retry with the SAME token: it must not have been burned
	// by the failed attempt.
	h.Store.TakeRefreshToken("0")
	if rr := postToken(h, refreshForm); rr.Code != http.StatusOK {
		t.Fatalf("token must survive a store-full attempt, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestPKCEMismatchRejected(t *testing.T) {
	h, br := newTestHandlers(t, []int64{42}, 42)
	clientID := registerClient(t, h)
	code := runAuthorize(t, h, br, clientID).Query().Get("code")

	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", testRedirect)
	form.Set("client_id", clientID)
	form.Set("code_verifier", "the-wrong-verifier")

	if rr := postToken(h, form); rr.Code == http.StatusOK {
		t.Fatal("expected PKCE mismatch to be rejected")
	}
}

func TestCodeReuseRejected(t *testing.T) {
	h, br := newTestHandlers(t, []int64{42}, 42)
	clientID := registerClient(t, h)
	code := runAuthorize(t, h, br, clientID).Query().Get("code")

	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", testRedirect)
	form.Set("client_id", clientID)
	form.Set("code_verifier", testVerifier)

	if rr := postToken(h, form); rr.Code != http.StatusOK {
		t.Fatalf("first exchange failed: %d %s", rr.Code, rr.Body.String())
	}
	if rr := postToken(h, form); rr.Code == http.StatusOK {
		t.Fatal("expected code reuse to be rejected")
	}
}

func TestUnregisteredRedirectRejected(t *testing.T) {
	h, _ := newTestHandlers(t, []int64{42}, 42)
	clientID := registerClient(t, h)

	q := url.Values{}
	q.Set("response_type", "code")
	q.Set("client_id", clientID)
	q.Set("redirect_uri", "https://evil.test/steal")
	q.Set("code_challenge", ChallengeS256(testVerifier))
	q.Set("code_challenge_method", "S256")
	q.Set("resource", testIssuer)

	rr := httptest.NewRecorder()
	h.Authorize(rr, httptest.NewRequest(http.MethodGet, "/authorize?"+q.Encode(), nil))
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for unregistered redirect_uri, got %d", rr.Code)
	}
}

func TestNonAllowlistedUserDenied(t *testing.T) {
	h, br := newTestHandlers(t, []int64{42}, 999) // GitHub returns 999, not allowed
	clientID := registerClient(t, h)

	loc := runAuthorize(t, h, br, clientID)
	if loc.Query().Get("code") != "" {
		t.Fatal("non-allowlisted user must not receive a code")
	}
	if loc.Query().Get("error") != "access_denied" {
		t.Fatalf("expected access_denied, got %q", loc.Query().Get("error"))
	}
}

func TestConsentRequiresServerToken(t *testing.T) {
	h, br := newTestHandlers(t, []int64{42}, 42)
	h.Consent = true
	clientID := registerClient(t, h)

	q := url.Values{}
	q.Set("response_type", "code")
	q.Set("client_id", clientID)
	q.Set("redirect_uri", testRedirect)
	q.Set("code_challenge", ChallengeS256(testVerifier))
	q.Set("code_challenge_method", "S256")
	q.Set("resource", testIssuer)

	// No consent_token: render the consent page, do NOT start the GitHub flow.
	rr := httptest.NewRecorder()
	h.Authorize(rr, httptest.NewRequest(http.MethodGet, "/authorize?"+q.Encode(), nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("expected consent page (200), got %d", rr.Code)
	}
	if br.lastState != "" {
		t.Fatal("GitHub flow must not start without consent")
	}

	// Forged/guessed token: still no bypass.
	q.Set("consent_token", "forged-token")
	rr = httptest.NewRecorder()
	h.Authorize(rr, httptest.NewRequest(http.MethodGet, "/authorize?"+q.Encode(), nil))
	if br.lastState != "" {
		t.Fatal("forged consent token must not start the GitHub flow")
	}

	// Valid server-issued token: proceeds.
	ct := randomToken()
	h.Store.SaveConsent(ct, clientID, time.Minute)
	q.Set("consent_token", ct)
	rr = httptest.NewRecorder()
	h.Authorize(rr, httptest.NewRequest(http.MethodGet, "/authorize?"+q.Encode(), nil))
	if rr.Code != http.StatusFound {
		t.Fatalf("valid consent should redirect to GitHub, got %d", rr.Code)
	}
	if br.lastState == "" {
		t.Fatal("GitHub flow should have started after consent")
	}

	// Single-use: the same token cannot be replayed.
	br.lastState = ""
	rr = httptest.NewRecorder()
	h.Authorize(rr, httptest.NewRequest(http.MethodGet, "/authorize?"+q.Encode(), nil))
	if br.lastState != "" {
		t.Fatal("consent token must be single-use")
	}
}

func TestConsentTokenBoundToClient(t *testing.T) {
	h, br := newTestHandlers(t, []int64{42}, 42)
	h.Consent = true
	clientID := registerClient(t, h)

	// Token issued for a different client must not authorize this one.
	ct := randomToken()
	h.Store.SaveConsent(ct, "some-other-client", time.Minute)

	q := url.Values{}
	q.Set("response_type", "code")
	q.Set("client_id", clientID)
	q.Set("redirect_uri", testRedirect)
	q.Set("code_challenge", ChallengeS256(testVerifier))
	q.Set("code_challenge_method", "S256")
	q.Set("resource", testIssuer)
	q.Set("consent_token", ct)

	rr := httptest.NewRecorder()
	h.Authorize(rr, httptest.NewRequest(http.MethodGet, "/authorize?"+q.Encode(), nil))
	if br.lastState != "" {
		t.Fatal("consent token bound to another client must not authorize this one")
	}
}

func TestResourceUnderOriginAccepted(t *testing.T) {
	h, br := newTestHandlers(t, []int64{42}, 42)
	clientID := registerClient(t, h)

	q := url.Values{}
	q.Set("response_type", "code")
	q.Set("client_id", clientID)
	q.Set("redirect_uri", testRedirect)
	q.Set("code_challenge", ChallengeS256(testVerifier))
	q.Set("code_challenge_method", "S256")
	q.Set("resource", testIssuer+"/mcp") // full endpoint URL, same origin

	rr := httptest.NewRecorder()
	h.Authorize(rr, httptest.NewRequest(http.MethodGet, "/authorize?"+q.Encode(), nil))
	if rr.Code != http.StatusFound || br.lastState == "" {
		t.Fatalf("resource under gateway origin should be accepted, got %d", rr.Code)
	}
}

func TestResourceDefaultPortAccepted(t *testing.T) {
	h, br := newTestHandlers(t, []int64{42}, 42)
	clientID := registerClient(t, h)

	q := url.Values{}
	q.Set("response_type", "code")
	q.Set("client_id", clientID)
	q.Set("redirect_uri", testRedirect)
	q.Set("code_challenge", ChallengeS256(testVerifier))
	q.Set("code_challenge_method", "S256")
	q.Set("resource", "https://mcp.example.com:443/mcp") // explicit default port

	rr := httptest.NewRecorder()
	h.Authorize(rr, httptest.NewRequest(http.MethodGet, "/authorize?"+q.Encode(), nil))
	if rr.Code != http.StatusFound || br.lastState == "" {
		t.Fatalf("explicit default port should be treated as same origin, got %d", rr.Code)
	}
}

func TestForeignResourceRejected(t *testing.T) {
	h, br := newTestHandlers(t, []int64{42}, 42)
	clientID := registerClient(t, h)

	q := url.Values{}
	q.Set("response_type", "code")
	q.Set("client_id", clientID)
	q.Set("redirect_uri", testRedirect)
	q.Set("code_challenge", ChallengeS256(testVerifier))
	q.Set("code_challenge_method", "S256")
	q.Set("resource", "https://evil.example.com/mcp")

	rr := httptest.NewRecorder()
	h.Authorize(rr, httptest.NewRequest(http.MethodGet, "/authorize?"+q.Encode(), nil))
	if br.lastState != "" {
		t.Fatal("foreign-origin resource must not start the flow")
	}
	loc, _ := url.Parse(rr.Header().Get("Location"))
	if loc.Query().Get("error") != "invalid_target" {
		t.Fatalf("expected invalid_target, got %q", loc.Query().Get("error"))
	}
}

func TestMissingPKCERejected(t *testing.T) {
	h, _ := newTestHandlers(t, []int64{42}, 42)
	clientID := registerClient(t, h)

	q := url.Values{}
	q.Set("response_type", "code")
	q.Set("client_id", clientID)
	q.Set("redirect_uri", testRedirect)
	q.Set("resource", testIssuer)

	rr := httptest.NewRecorder()
	h.Authorize(rr, httptest.NewRequest(http.MethodGet, "/authorize?"+q.Encode(), nil))
	if rr.Code != http.StatusFound {
		t.Fatalf("expected redirect with error, got %d", rr.Code)
	}
	loc, _ := url.Parse(rr.Header().Get("Location"))
	if loc.Query().Get("error") != "invalid_request" {
		t.Fatalf("expected invalid_request, got %q", loc.Query().Get("error"))
	}
}
