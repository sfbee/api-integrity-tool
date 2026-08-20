package web

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/stephen-bee/endpoint-monitor/internal/config"
	"github.com/stephen-bee/endpoint-monitor/internal/ghsource"
	"github.com/stephen-bee/endpoint-monitor/internal/index"
	"github.com/stephen-bee/endpoint-monitor/internal/model"
	"github.com/stephen-bee/endpoint-monitor/internal/monitor"
	"github.com/stephen-bee/endpoint-monitor/internal/store"
)

//go:embed assets
var assetFS embed.FS

// DefaultPort is the documented port for the results dashboard.
const DefaultPort = 6969

// Options configures a server.
type Options struct {
	RepoPath string
	Store    *store.Store
	Config   *config.File
	// NewSource builds a GitHub client for checks triggered from the dashboard.
	// Nil disables that button.
	NewSource func(cfg *config.File) (ghsource.GitHubSource, error)
	Port      int
	// Bind is the listen address. Only loopback is supported: the whole auth
	// model assumes it.
	Bind    string
	TLS     bool
	Now     func() time.Time
	Logf    func(format string, args ...any)
	Version string
}

// Server is the dashboard.
type Server struct {
	opt      Options
	sessions *sessionStore
	// token is the capability token minted at startup. It is held only in
	// memory, so nothing usable survives the process.
	token string
	mux   *http.ServeMux
	now   func() time.Time
	// runningCheck guards against two dashboard-triggered checks at once.
	runningCheck chan struct{}
}

// New builds a server and mints its capability token.
func New(opt Options) (*Server, error) {
	if opt.Port == 0 {
		opt.Port = DefaultPort
	}
	if opt.Bind == "" {
		opt.Bind = "127.0.0.1"
	}
	if !isLoopback(opt.Bind) {
		// The dashboard exposes internal hostnames, file paths and upstream
		// diffs, and its auth model assumes an attacker cannot reach the port.
		// Binding it to a network interface would quietly invalidate that.
		return nil, fmt.Errorf("refusing to bind %s: the results dashboard is loopback-only", opt.Bind)
	}
	if opt.Now == nil {
		opt.Now = time.Now
	}
	tok, err := newToken()
	if err != nil {
		return nil, err
	}
	s := &Server{
		opt: opt, token: tok, now: opt.Now,
		sessions:     newSessionStore(opt.Now),
		runningCheck: make(chan struct{}, 1),
	}
	s.routes()
	return s, nil
}

// LoginURL is the one-time URL a human opens. It carries the capability token
// in the query string, which is why /login redirects immediately and every
// response sets Referrer-Policy: no-referrer.
func (s *Server) LoginURL() string {
	return fmt.Sprintf("%s://127.0.0.1:%d/login?t=%s", s.scheme(), s.opt.Port, s.token)
}

// BaseURL is the dashboard root.
func (s *Server) BaseURL() string {
	return fmt.Sprintf("%s://127.0.0.1:%d/", s.scheme(), s.opt.Port)
}

func (s *Server) scheme() string {
	if s.opt.TLS {
		return "https"
	}
	return "http"
}

func (s *Server) logf(format string, args ...any) {
	if s.opt.Logf != nil {
		s.opt.Logf(format, args...)
	}
}

// Handler returns the wrapped mux, for tests and for embedding.
func (s *Server) Handler() http.Handler { return s.wrap(s.mux) }

// Serve listens and serves until the context is cancelled.
func (s *Server) Serve(ctx context.Context) error {
	addr := net.JoinHostPort(s.opt.Bind, fmt.Sprint(s.opt.Port))
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", addr, err)
	}
	// Port 0 means "pick one"; report what was actually chosen.
	if tcp, ok := ln.Addr().(*net.TCPAddr); ok {
		s.opt.Port = tcp.Port
	}
	srv := &http.Server{
		Handler:           s.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    32 << 10,
	}
	go func() {
		<-ctx.Done()
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutCtx)
	}()
	if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// Port reports the bound port, which differs from the request when 0 was given.
func (s *Server) Port() int { return s.opt.Port }

func (s *Server) routes() {
	m := http.NewServeMux()

	// Open endpoints. /healthz deliberately exposes no project data: it exists
	// so another invocation can tell whether the port is ours.
	m.HandleFunc("GET /healthz", s.handleHealth)
	m.HandleFunc("GET /login", s.handleLogin)
	m.HandleFunc("GET /static/{file}", s.handleStatic)

	m.HandleFunc("POST /logout", s.requireSession(s.requireCSRF(s.handleLogout)))
	m.HandleFunc("GET /", s.requireSession(s.handleIndex))
	m.HandleFunc("GET /api/summary", s.requireSession(s.handleSummary))
	m.HandleFunc("GET /api/findings", s.requireSession(s.handleFindings))
	m.HandleFunc("GET /api/endpoints", s.requireSession(s.handleEndpoints))
	m.HandleFunc("GET /api/hosts", s.requireSession(s.handleHosts))
	m.HandleFunc("GET /api/runs", s.requireSession(s.handleRuns))
	m.HandleFunc("POST /api/findings/{id}/status", s.requireSession(s.requireCSRF(s.handleFindingStatus)))
	m.HandleFunc("POST /api/checks", s.requireSession(s.requireCSRF(s.handleRunCheck)))
	s.mux = m
}

// wrap applies the checks that must hold for every request.
func (s *Server) wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		securityHeaders(w)
		// A page on any domain can point DNS at 127.0.0.1; only a loopback Host
		// header is legitimate.
		if !allowedHost(r.Host, s.opt.Port) {
			http.Error(w, "misdirected request", http.StatusMisdirectedRequest)
			return
		}
		// No CORS headers are ever sent, so a cross-origin read cannot succeed;
		// this rejects the attempt explicitly for clarity.
		if origin := r.Header.Get("Origin"); origin != "" && !s.sameOrigin(origin) {
			http.Error(w, "cross-origin requests are not allowed", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// sameOrigin reports whether an Origin header names this dashboard. Like the
// Host check, only the hostname matters: the port is whatever the browser
// connected to.
func (s *Server) sameOrigin(origin string) bool {
	u, err := url.Parse(origin)
	if err != nil {
		return false
	}
	return allowedHost(u.Host, 0)
}

// requireSession gates a handler on a valid session cookie.
func (s *Server) requireSession(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie(sessionCookie)
		if err != nil {
			s.unauthorized(w, r)
			return
		}
		sess, ok := s.sessions.lookup(c.Value)
		if !ok {
			s.unauthorized(w, r)
			return
		}
		next(w, r.WithContext(withSession(r.Context(), sess)))
	}
}

// requireCSRF enforces the double-submit token and a JSON content type.
//
// SameSite=Lax alone is not sufficient across all browsers and methods, and
// requiring application/json blocks the cross-origin HTML form post, which
// cannot set a custom header.
func (s *Server) requireCSRF(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if ct := r.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
			http.Error(w, "expected application/json", http.StatusUnsupportedMediaType)
			return
		}
		if site := r.Header.Get("Sec-Fetch-Site"); site != "" && site != "same-origin" && site != "none" {
			http.Error(w, "cross-site request rejected", http.StatusForbidden)
			return
		}
		sess := sessionFrom(r.Context())
		header := r.Header.Get("X-CSRF-Token")
		if sess == nil || header == "" || !sameToken(header, sess.csrf) {
			http.Error(w, "missing or invalid CSRF token", http.StatusForbidden)
			return
		}
		next(w, r)
	}
}

func (s *Server) unauthorized(w http.ResponseWriter, r *http.Request) {
	// An unauthenticated response must not hint at what exists behind it.
	if strings.HasPrefix(r.URL.Path, "/api/") {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		io.WriteString(w, `{"error":"unauthorized"}`)
		return
	}
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"status":  "ok",
		"app":     "api-integrity-tool",
		"version": s.opt.Version,
		"port":    s.opt.Port,
	})
}

// handleLogin exchanges the capability token for a session.
//
// On success it redirects immediately, so the token leaves the address bar, the
// browser history and any Referer before the dashboard renders.
func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	tok := r.URL.Query().Get("t")
	if tok == "" {
		s.serveAsset(w, "assets/login.html", "text/html; charset=utf-8")
		return
	}
	key := clientKey(r)
	if ok, retry := s.sessions.allowAttempt(key); !ok {
		w.Header().Set("Retry-After", fmt.Sprint(int(retry.Seconds())+1))
		http.Error(w, "too many attempts", http.StatusTooManyRequests)
		return
	}
	if !sameToken(tok, s.token) {
		s.sessions.recordFailure(key)
		time.Sleep(failDelay)
		http.Error(w, "invalid token", http.StatusUnauthorized)
		return
	}
	s.sessions.recordSuccess(key)
	sess, err := s.sessions.create()
	if err != nil {
		http.Error(w, "could not create a session", http.StatusInternalServerError)
		return
	}
	setSessionCookies(w, sess, s.opt.TLS)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(sessionCookie); err == nil {
		s.sessions.destroy(c.Value)
	}
	if r.URL.Query().Get("all") == "1" {
		s.sessions.destroyAll()
	}
	clearSessionCookies(w, s.opt.TLS)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	s.serveAsset(w, "assets/index.html", "text/html; charset=utf-8")
}

func (s *Server) handleStatic(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("file")
	switch name {
	case "app.css":
		s.serveAsset(w, "assets/app.css", "text/css; charset=utf-8")
	case "app.js":
		s.serveAsset(w, "assets/app.js", "text/javascript; charset=utf-8")
	default:
		http.NotFound(w, r)
	}
}

func (s *Server) serveAsset(w http.ResponseWriter, path, contentType string) {
	data, err := assetFS.ReadFile(path)
	if err != nil {
		http.Error(w, "asset missing", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", contentType)
	w.WriteHeader(http.StatusOK)
	w.Write(data)
}

// Summary is everything the dashboard needs for its first paint.
type Summary struct {
	Repo          string        `json:"repo"`
	Commit        string        `json:"commit,omitempty"`
	Version       string        `json:"version"`
	Counts        model.Counts  `json:"counts"`
	EndpointCount int           `json:"endpoint_count"`
	HostCount     int           `json:"host_count"`
	LinkedHosts   int           `json:"linked_hosts"`
	UnlinkedHosts int           `json:"unlinked_hosts"`
	LastCheck     string        `json:"last_check,omitempty"`
	Findings      []Finding     `json:"findings"`
	Endpoints     []EndpointRow `json:"endpoints"`
	Hosts         []HostRow     `json:"hosts"`
	Runs          []store.Run   `json:"runs"`
	CanCheck      bool          `json:"can_check"`
}

// Finding is a finding as the dashboard renders it.
type Finding struct {
	ID         string              `json:"id"`
	Signal     string              `json:"signal"`
	Severity   string              `json:"severity"`
	Confidence float64             `json:"confidence"`
	Title      string              `json:"title"`
	Detail     string              `json:"detail,omitempty"`
	Suggestion string              `json:"suggestion,omitempty"`
	Host       string              `json:"host"`
	Repo       string              `json:"repo"`
	Status     string              `json:"status"`
	Endpoints  []model.EndpointRef `json:"endpoints,omitempty"`
	Evidence   []model.Evidence    `json:"evidence,omitempty"`
}

// EndpointRow is one indexed call.
type EndpointRow struct {
	Method     string `json:"method"`
	Host       string `json:"host"`
	Path       string `json:"path"`
	Confidence string `json:"confidence"`
	Language   string `json:"language"`
	File       string `json:"file"`
	Line       int    `json:"line"`
}

// HostRow is one host with its upstream.
type HostRow struct {
	Host  string `json:"host"`
	Calls int    `json:"calls"`
	Paths int    `json:"paths"`
	Repo  string `json:"repo,omitempty"`
	Role  string `json:"role,omitempty"`
}

func (s *Server) handleSummary(w http.ResponseWriter, r *http.Request) {
	sum, err := s.summary()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, sum)
}

func (s *Server) summary() (*Summary, error) {
	out := &Summary{
		Repo: s.opt.RepoPath, Version: s.opt.Version,
		CanCheck:  s.opt.NewSource != nil,
		Findings:  []Finding{},
		Endpoints: []EndpointRow{},
		Hosts:     []HostRow{},
		Runs:      []store.Run{},
	}
	state, err := s.opt.Store.Read()
	if err != nil {
		return nil, err
	}
	upstreamFor := map[string]model.Upstream{}
	for _, u := range state.Upstreams {
		if _, seen := upstreamFor[u.Host]; !seen {
			upstreamFor[u.Host] = u
		}
	}

	if idx, ierr := index.Load(s.opt.RepoPath); ierr == nil && idx != nil {
		out.Commit = idx.Scan.Commit
		out.EndpointCount = len(idx.Calls)
		out.HostCount = len(idx.Hosts)
		for _, c := range idx.Calls {
			out.Endpoints = append(out.Endpoints, EndpointRow{
				Method: c.Method, Host: c.Host, Path: c.Path,
				Confidence: string(c.Confidence), Language: string(c.Language),
				File: c.Location.File, Line: c.Location.Line,
			})
		}
		for _, h := range idx.Hosts {
			row := HostRow{Host: h.HostKey, Calls: h.CallCount, Paths: h.PathCount}
			if u, ok := upstreamFor[h.HostKey]; ok {
				row.Repo, row.Role = u.Repo.Canonical(), string(u.Role)
				out.LinkedHosts++
			} else {
				out.UnlinkedHosts++
			}
			out.Hosts = append(out.Hosts, row)
		}
	}

	var open []model.Finding
	for _, f := range state.Findings {
		if f.Status != model.StatusOpen {
			continue
		}
		open = append(open, f)
	}
	model.SortFindings(open)
	out.Counts = model.CountBySeverity(open)
	for _, f := range open {
		out.Findings = append(out.Findings, toWebFinding(f))
	}
	if len(state.Runs) > 0 {
		out.LastCheck = state.Runs[0].StartedAt.Format(time.RFC3339)
		out.Runs = state.Runs
	}
	return out, nil
}

func toWebFinding(f model.Finding) Finding {
	return Finding{
		ID: f.Fingerprint, Signal: f.Signal, Severity: string(f.Severity),
		Confidence: f.Confidence, Title: f.Title, Detail: f.Detail,
		Suggestion: f.Suggestion, Host: f.Host, Repo: f.Repo.Canonical(),
		Status: f.Status, Endpoints: f.Endpoints, Evidence: f.Evidence,
	}
}

func (s *Server) handleFindings(w http.ResponseWriter, r *http.Request) {
	state, err := s.opt.Store.Read()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	status := r.URL.Query().Get("status")
	if status == "" {
		status = model.StatusOpen
	}
	var out []Finding
	for _, f := range state.Findings {
		if status != "all" && f.Status != status {
			continue
		}
		out = append(out, toWebFinding(f))
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleEndpoints(w http.ResponseWriter, r *http.Request) {
	sum, err := s.summary()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, sum.Endpoints)
}

func (s *Server) handleHosts(w http.ResponseWriter, r *http.Request) {
	sum, err := s.summary()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, sum.Hosts)
}

func (s *Server) handleRuns(w http.ResponseWriter, r *http.Request) {
	state, err := s.opt.Store.Read()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, state.Runs)
}

// statusRequest is the body of a finding status change.
type statusRequest struct {
	Action string `json:"action"`
	Note   string `json:"note"`
	Days   int    `json:"days"`
}

func (s *Server) handleFindingStatus(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var req statusRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&req); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	var status string
	var until *time.Time
	switch req.Action {
	case "ack":
		status = model.StatusAcked
	case "mute":
		status = model.StatusMuted
		days := req.Days
		if days <= 0 {
			days = 30
		}
		t := s.now().Add(time.Duration(days) * 24 * time.Hour).UTC()
		until = &t
	case "resolve":
		status = model.StatusResolved
	case "reopen", "unmute":
		status = model.StatusOpen
	default:
		http.Error(w, "unknown action", http.StatusBadRequest)
		return
	}
	if err := s.opt.Store.SetFindingStatus(id, status, req.Note, "dashboard", until); err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"id": id, "status": status})
}

func (s *Server) handleRunCheck(w http.ResponseWriter, r *http.Request) {
	if s.opt.NewSource == nil {
		http.Error(w, "checks are not available in this session", http.StatusServiceUnavailable)
		return
	}
	// One check at a time: a second concurrent run would duplicate API calls
	// and race on the same state.
	select {
	case s.runningCheck <- struct{}{}:
		defer func() { <-s.runningCheck }()
	default:
		http.Error(w, "a check is already running", http.StatusConflict)
		return
	}
	src, err := s.opt.NewSource(s.opt.Config)
	if err != nil {
		http.Error(w, ghsource.Redact(err.Error()), http.StatusBadGateway)
		return
	}
	idx, err := index.Load(s.opt.RepoPath)
	if err != nil || idx == nil {
		http.Error(w, "no index; run a scan first", http.StatusPreconditionFailed)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 4*time.Minute)
	defer cancel()
	res, err := monitor.Run(ctx, monitor.Options{
		Store: s.opt.Store, Source: src, Index: idx, Config: s.opt.Config,
		Trigger: "dashboard", Now: s.now,
	})
	if err != nil {
		http.Error(w, ghsource.Redact(err.Error()), http.StatusBadGateway)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"run_id": res.RunID, "checked": res.Checked, "skipped": res.Skipped,
		"new_findings": len(res.New), "counts": res.Counts,
	})
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
}

func isLoopback(bind string) bool {
	switch bind {
	case "127.0.0.1", "localhost", "::1", "[::1]":
		return true
	}
	ip := net.ParseIP(strings.Trim(bind, "[]"))
	return ip != nil && ip.IsLoopback()
}

// sessionCtxKey is the context key for the authenticated session.
type sessionCtxKey struct{}

func withSession(ctx context.Context, s *session) context.Context {
	return context.WithValue(ctx, sessionCtxKey{}, s)
}

func sessionFrom(ctx context.Context) *session {
	s, _ := ctx.Value(sessionCtxKey{}).(*session)
	return s
}
