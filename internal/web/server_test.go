package web_test

import (
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stephen-bee/endpoint-monitor/internal/model"
	"github.com/stephen-bee/endpoint-monitor/internal/store"
	"github.com/stephen-bee/endpoint-monitor/internal/web"
)

var webTime = time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)

type harness struct {
	t      *testing.T
	srv    *web.Server
	http   *httptest.Server
	client *http.Client
	store  *store.Store
}

// newHarness starts the dashboard over httptest with a seeded store.
func newHarness(t *testing.T) *harness {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(dir, func() time.Time { return webTime })
	if err != nil {
		t.Fatal(err)
	}
	seed(t, st)

	srv, err := web.New(web.Options{
		RepoPath: dir, Store: st, Version: "test",
		Now: func() time.Time { return webTime },
	})
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	jar, _ := cookiejar.New(nil)
	client := &http.Client{
		Jar: jar,
		// Redirects are inspected rather than followed, because the redirect
		// itself is part of the login contract.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	return &harness{t: t, srv: srv, http: ts, client: client, store: st}
}

func seed(t *testing.T, st *store.Store) {
	t.Helper()
	if err := st.LinkUpstream(model.Upstream{
		Host: "api.acme.com",
		Repo: model.RepoRef{Provider: model.ProviderGitHub, GitHost: "github.com", Owner: "acme", Name: "billing"},
		Role: model.RoleSpecOnly, Source: model.SourceCLI, Status: "active",
	}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := st.UpsertFindings([]model.Finding{{
		Fingerprint: "fp_seeded1", Signal: "openapi.path_removed",
		Severity: model.SeverityBreaking, Confidence: 0.9,
		Title: "Path removed: /api/v1/invoices", Host: "api.acme.com",
		Repo:      model.RepoRef{Provider: model.ProviderGitHub, GitHost: "github.com", Owner: "acme", Name: "billing"},
		Status:    model.StatusOpen,
		Endpoints: []model.EndpointRef{{ID: "c1", Method: "GET", Path: "/api/v1/invoices", CallSite: "client.go:10"}},
	}}); err != nil {
		t.Fatal(err)
	}
}

// url builds an absolute URL against the test server.
func (h *harness) url(path string) string { return h.http.URL + path }

// do issues a request with a loopback Host header, as a browser would.
func (h *harness) do(method, path string, body string, hdrs map[string]string) *http.Response {
	h.t.Helper()
	var r *http.Request
	var err error
	if body == "" {
		r, err = http.NewRequest(method, h.url(path), nil)
	} else {
		r, err = http.NewRequest(method, h.url(path), strings.NewReader(body))
	}
	if err != nil {
		h.t.Fatal(err)
	}
	u, _ := url.Parse(h.http.URL)
	r.Host = "127.0.0.1:" + u.Port()
	for k, v := range hdrs {
		r.Header.Set(k, v)
	}
	resp, err := h.client.Do(r)
	if err != nil {
		h.t.Fatalf("%s %s: %v", method, path, err)
	}
	return resp
}

// login exchanges the capability token for a session.
func (h *harness) login() {
	h.t.Helper()
	tok := tokenFrom(h.t, h.srv.LoginURL())
	resp := h.do("GET", "/login?t="+tok, "", nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		h.t.Fatalf("login status = %d, want 303", resp.StatusCode)
	}
}

func tokenFrom(t *testing.T, loginURL string) string {
	t.Helper()
	u, err := url.Parse(loginURL)
	if err != nil {
		t.Fatal(err)
	}
	tok := u.Query().Get("t")
	if tok == "" {
		t.Fatalf("no token in %q", loginURL)
	}
	return tok
}

// The dashboard exposes internal hostnames, file paths and upstream diffs, so
// an unauthenticated request must get nothing.
func TestAPIRequiresAuthentication(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	resp := h.do("GET", "/api/summary", "", nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}
	if len(resp.Cookies()) != 0 {
		t.Error("an unauthenticated response must not set cookies")
	}
	var body map[string]any
	json.NewDecoder(resp.Body).Decode(&body)
	// The error must not describe what is behind the wall.
	if s, _ := body["error"].(string); s != "unauthorized" {
		t.Errorf("body = %+v, want a bare unauthorized error", body)
	}
}

// /healthz is open on purpose so another invocation can identify the port, so it
// must contain no project data.
func TestHealthIsOpenButLeaksNothing(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	resp := h.do("GET", "/healthz", "", nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	var body map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body["app"] != "api-integrity-tool" {
		t.Errorf("health should identify the app: %+v", body)
	}
	for _, forbidden := range []string{"repo", "findings", "hosts", "endpoints"} {
		if _, ok := body[forbidden]; ok {
			t.Errorf("health must not expose %q", forbidden)
		}
	}
}

func TestLoginFlowAndCookieFlags(t *testing.T) {
	t.Parallel()
	h := newHarness(t)

	bad := h.do("GET", "/login?t=not-the-token", "", nil)
	bad.Body.Close()
	if bad.StatusCode != http.StatusUnauthorized {
		t.Fatalf("bad token status = %d, want 401", bad.StatusCode)
	}

	tok := tokenFrom(t, h.srv.LoginURL())
	resp := h.do("GET", "/login?t="+tok, "", nil)
	defer resp.Body.Close()
	// Redirecting immediately gets the token out of the address bar, the
	// history and any Referer before the page renders.
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303", resp.StatusCode)
	}
	if loc := resp.Header.Get("Location"); loc != "/" {
		t.Errorf("Location = %q, want /", loc)
	}
	if p := resp.Header.Get("Referrer-Policy"); p != "no-referrer" {
		t.Errorf("Referrer-Policy = %q, want no-referrer", p)
	}

	var sess, csrf *http.Cookie
	for _, c := range resp.Cookies() {
		switch c.Name {
		case "aitk_session":
			sess = c
		case "aitk_csrf":
			csrf = c
		}
	}
	if sess == nil || csrf == nil {
		t.Fatalf("expected both cookies, got %+v", resp.Cookies())
	}
	if !sess.HttpOnly {
		t.Error("the session cookie must be HttpOnly")
	}
	// Secure must NOT be set over plain http, or browsers drop the cookie and
	// login silently fails on localhost.
	if sess.Secure {
		t.Error("the session cookie must not be Secure without TLS")
	}
	if sess.SameSite != http.SameSiteLaxMode {
		t.Errorf("SameSite = %v, want Lax", sess.SameSite)
	}
	// The CSRF cookie is deliberately readable by the page.
	if csrf.HttpOnly {
		t.Error("the CSRF cookie must be readable by the page for double-submit")
	}

	// The session now works.
	ok := h.do("GET", "/api/summary", "", nil)
	defer ok.Body.Close()
	if ok.StatusCode != http.StatusOK {
		t.Fatalf("authenticated request status = %d", ok.StatusCode)
	}
	var sum web.Summary
	if err := json.NewDecoder(ok.Body).Decode(&sum); err != nil {
		t.Fatal(err)
	}
	if sum.Counts.Breaking != 1 || len(sum.Findings) != 1 {
		t.Errorf("summary should reflect the seeded finding: %+v", sum.Counts)
	}
	if sum.Findings[0].Title == "" || len(sum.Findings[0].Endpoints) != 1 {
		t.Errorf("finding = %+v", sum.Findings[0])
	}
}

// Any page the developer visits can point DNS at 127.0.0.1. A non-loopback Host
// header is the signal for that, and it must be refused.
func TestDNSRebindingIsRejected(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	h.login()

	r, _ := http.NewRequest("GET", h.url("/api/summary"), nil)
	r.Host = "evil.example.com"
	resp, err := h.client.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMisdirectedRequest {
		t.Errorf("status = %d, want 421 for a foreign Host header", resp.StatusCode)
	}
}

func TestCrossOriginRequestsAreRejected(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	h.login()
	resp := h.do("GET", "/api/summary", "", map[string]string{"Origin": "https://evil.example.com"})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d, want 403 for a foreign Origin", resp.StatusCode)
	}
	// And no CORS header may ever be sent.
	if h := resp.Header.Get("Access-Control-Allow-Origin"); h != "" {
		t.Errorf("Access-Control-Allow-Origin was set to %q", h)
	}
}

func TestMutationsRequireCSRFAndJSON(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	h.login()
	csrf := h.csrfToken()

	// No token at all.
	resp := h.do("POST", "/api/findings/fp_seeded1/status", `{"action":"ack"}`,
		map[string]string{"Content-Type": "application/json"})
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("without a CSRF token: status = %d, want 403", resp.StatusCode)
	}

	// Wrong token.
	resp = h.do("POST", "/api/findings/fp_seeded1/status", `{"action":"ack"}`,
		map[string]string{"Content-Type": "application/json", "X-CSRF-Token": "wrong"})
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("with a wrong CSRF token: status = %d, want 403", resp.StatusCode)
	}

	// A form content type is how a cross-origin HTML form would post, and it
	// cannot set a custom header, so it must be refused outright.
	resp = h.do("POST", "/api/findings/fp_seeded1/status", "action=ack",
		map[string]string{"Content-Type": "application/x-www-form-urlencoded", "X-CSRF-Token": csrf})
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnsupportedMediaType {
		t.Errorf("form content type: status = %d, want 415", resp.StatusCode)
	}

	// The real thing works.
	resp = h.do("POST", "/api/findings/fp_seeded1/status", `{"action":"ack","note":"known"}`,
		map[string]string{"Content-Type": "application/json", "X-CSRF-Token": csrf})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("valid mutation status = %d", resp.StatusCode)
	}
	state, _ := h.store.Read()
	if state.Findings[0].Status != model.StatusAcked {
		t.Errorf("finding status = %q, want acked", state.Findings[0].Status)
	}
}

// csrfToken reads the double-submit cookie the way the page's script does.
func (h *harness) csrfToken() string {
	h.t.Helper()
	u, _ := url.Parse(h.http.URL)
	for _, c := range h.client.Jar.Cookies(u) {
		if c.Name == "aitk_csrf" {
			return c.Value
		}
	}
	h.t.Fatal("no CSRF cookie")
	return ""
}

func TestLoginRateLimitLocksOut(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	for i := 0; i < 5; i++ {
		resp := h.do("GET", "/login?t=wrong", "", nil)
		resp.Body.Close()
	}
	// The next attempt is throttled regardless of what it carries.
	resp := h.do("GET", "/login?t=wrong", "", nil)
	resp.Body.Close()
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429 after repeated failures", resp.StatusCode)
	}
	if resp.Header.Get("Retry-After") == "" {
		t.Error("a throttled response should say when to retry")
	}
	// Crucially, the lockout applies even to the correct token: otherwise it is
	// only a speed bump for an attacker who eventually guesses right.
	tok := tokenFrom(t, h.srv.LoginURL())
	resp = h.do("GET", "/login?t="+tok, "", nil)
	resp.Body.Close()
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Errorf("status = %d, want the lockout to apply to the correct token too", resp.StatusCode)
	}
}

func TestLogoutInvalidatesTheSession(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	h.login()
	csrf := h.csrfToken()

	resp := h.do("POST", "/logout", `{}`,
		map[string]string{"Content-Type": "application/json", "X-CSRF-Token": csrf})
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("logout status = %d", resp.StatusCode)
	}
	after := h.do("GET", "/api/summary", "", nil)
	after.Body.Close()
	if after.StatusCode != http.StatusUnauthorized {
		t.Errorf("status after logout = %d, want 401", after.StatusCode)
	}
}

func TestSecurityHeadersOnEveryResponse(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	h.login()
	for _, path := range []string{"/", "/healthz", "/api/summary", "/static/app.js"} {
		resp := h.do("GET", path, "", nil)
		resp.Body.Close()
		csp := resp.Header.Get("Content-Security-Policy")
		if !strings.Contains(csp, "default-src 'none'") || !strings.Contains(csp, "frame-ancestors 'none'") {
			t.Errorf("%s: CSP = %q", path, csp)
		}
		// The policy has no 'unsafe-inline', which only holds because the assets
		// carry no inline script.
		if strings.Contains(csp, "unsafe-inline") {
			t.Errorf("%s: CSP allows inline script", path)
		}
		if resp.Header.Get("X-Content-Type-Options") != "nosniff" {
			t.Errorf("%s: missing nosniff", path)
		}
		if resp.Header.Get("Referrer-Policy") != "no-referrer" {
			t.Errorf("%s: missing no-referrer", path)
		}
	}
}

// The auth model assumes the port is unreachable from the network, so binding
// anywhere but loopback must be refused rather than quietly allowed.
func TestNonLoopbackBindIsRefused(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	st, err := store.Open(dir, func() time.Time { return webTime })
	if err != nil {
		t.Fatal(err)
	}
	for _, bind := range []string{"0.0.0.0", "192.168.1.10", ""} {
		if bind == "" {
			continue
		}
		if _, err := web.New(web.Options{RepoPath: dir, Store: st, Bind: bind}); err == nil {
			t.Errorf("binding to %s should be refused", bind)
		}
	}
	// Loopback is fine.
	if _, err := web.New(web.Options{RepoPath: dir, Store: st, Bind: "127.0.0.1"}); err != nil {
		t.Errorf("loopback bind failed: %v", err)
	}
}

// Two servers must not share a capability token, or one session would
// authenticate against the other.
func TestTokensAreUniquePerServer(t *testing.T) {
	t.Parallel()
	a, b := newHarness(t), newHarness(t)
	if tokenFrom(t, a.srv.LoginURL()) == tokenFrom(t, b.srv.LoginURL()) {
		t.Fatal("two servers minted the same capability token")
	}
	// A token from one must not work on the other.
	resp := b.do("GET", "/login?t="+tokenFrom(t, a.srv.LoginURL()), "", nil)
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401 for another server's token", resp.StatusCode)
	}
}

func TestCheckButtonUnavailableWithoutASource(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	h.login()
	resp := h.do("POST", "/api/checks", `{}`,
		map[string]string{"Content-Type": "application/json", "X-CSRF-Token": h.csrfToken()})
	resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503 when no GitHub source is configured", resp.StatusCode)
	}
}
