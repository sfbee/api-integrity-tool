// Package web serves the results dashboard on localhost.
//
// The threat model is worth stating, because "it's only localhost" is the usual
// reason these dashboards end up unauthenticated. Any web page the developer
// visits can issue requests to http://127.0.0.1:6969, and this dashboard
// exposes internal hostnames, source file paths and upstream diffs. So it is
// authenticated, it rejects requests whose Host header is not a loopback name
// (the DNS-rebinding defence that most localhost dashboards miss), and it sends
// no CORS headers at all.
package web

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Cookie names.
const (
	sessionCookie = "aitk_session"
	csrfCookie    = "aitk_csrf"
)

// Session lifetime. Sliding within TTL, hard-capped at MaxAge.
const (
	sessionTTL    = 12 * time.Hour
	sessionMaxAge = 7 * 24 * time.Hour
)

// Login throttling. Five attempts per window, then a growing lockout.
const (
	loginAttempts   = 5
	loginWindow     = 15 * time.Minute
	lockoutBase     = 15 * time.Minute
	lockoutMaxDelay = time.Hour
	// failDelay blunts brute forcing and timing analysis without making a
	// legitimate login feel broken.
	failDelay = 250 * time.Millisecond
)

// newToken returns a URL-safe 32-byte random token.
func newToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// hashToken returns the SHA-256 of a token. Comparing hashes rather than raw
// values means the comparison is fixed-length, so it cannot leak the token's
// length, and nothing secret has to be held in comparable form.
func hashToken(tok string) string {
	sum := sha256.Sum256([]byte(tok))
	return hex.EncodeToString(sum[:])
}

// sameToken compares two tokens in constant time.
func sameToken(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(hashToken(a)), []byte(hashToken(b))) == 1
}

// session is one logged-in browser.
type session struct {
	id        string
	csrf      string
	createdAt time.Time
	lastSeen  time.Time
}

// sessionStore holds sessions in memory. They are deliberately not persisted:
// the capability token is ephemeral, so a restart should invalidate everything.
type sessionStore struct {
	mu       sync.Mutex
	byID     map[string]*session
	now      func() time.Time
	attempts map[string]*attemptRecord
}

type attemptRecord struct {
	count       int
	windowStart time.Time
	lockedUntil time.Time
	lockouts    int
}

func newSessionStore(now func() time.Time) *sessionStore {
	if now == nil {
		now = time.Now
	}
	return &sessionStore{
		byID:     map[string]*session{},
		attempts: map[string]*attemptRecord{},
		now:      now,
	}
}

// create mints a session and its CSRF token.
func (s *sessionStore) create() (*session, error) {
	id, err := newToken()
	if err != nil {
		return nil, err
	}
	csrf, err := newToken()
	if err != nil {
		return nil, err
	}
	now := s.now()
	sess := &session{id: id, csrf: csrf, createdAt: now, lastSeen: now}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.byID[hashToken(id)] = sess
	return sess, nil
}

// lookup returns the live session for a cookie value, refreshing its activity.
func (s *sessionStore) lookup(id string) (*session, bool) {
	if id == "" {
		return nil, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.byID[hashToken(id)]
	if !ok {
		return nil, false
	}
	now := s.now()
	if now.Sub(sess.lastSeen) > sessionTTL || now.Sub(sess.createdAt) > sessionMaxAge {
		delete(s.byID, hashToken(id))
		return nil, false
	}
	sess.lastSeen = now
	return sess, true
}

// destroy removes one session.
func (s *sessionStore) destroy(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.byID, hashToken(id))
}

// destroyAll revokes every session.
func (s *sessionStore) destroyAll() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.byID = map[string]*session{}
}

// count reports the number of live sessions, for tests and the health endpoint.
func (s *sessionStore) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.byID)
}

// allowAttempt reports whether a login attempt from addr may proceed, and how
// long the caller must wait if not.
func (s *sessionStore) allowAttempt(addr string) (bool, time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	// Bound the map so a flood of spoofed addresses cannot exhaust memory.
	if len(s.attempts) > 1024 {
		for k, r := range s.attempts {
			if now.After(r.lockedUntil) && now.Sub(r.windowStart) > loginWindow {
				delete(s.attempts, k)
			}
		}
	}
	r, ok := s.attempts[addr]
	if !ok {
		r = &attemptRecord{windowStart: now}
		s.attempts[addr] = r
	}
	if now.Before(r.lockedUntil) {
		return false, r.lockedUntil.Sub(now)
	}
	if now.Sub(r.windowStart) > loginWindow {
		r.count, r.windowStart = 0, now
	}
	return true, 0
}

// recordFailure counts a failed attempt and locks out when the limit is hit.
func (s *sessionStore) recordFailure(addr string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	r, ok := s.attempts[addr]
	if !ok {
		r = &attemptRecord{windowStart: now}
		s.attempts[addr] = r
	}
	r.count++
	if r.count >= loginAttempts {
		delay := lockoutBase * (1 << r.lockouts)
		if delay > lockoutMaxDelay {
			delay = lockoutMaxDelay
		}
		r.lockedUntil = now.Add(delay)
		r.lockouts++
		r.count = 0
	}
}

// recordSuccess clears the throttle for an address.
func (s *sessionStore) recordSuccess(addr string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.attempts, addr)
}

// clientKey identifies a requester for throttling.
func clientKey(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// setSessionCookies writes the session and CSRF cookies.
//
// Secure is set only under TLS. Setting it unconditionally would be the
// "safer-looking" choice and would silently break login, because browsers
// refuse Secure cookies over plain http on localhost.
func setSessionCookies(w http.ResponseWriter, sess *session, tls bool) {
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookie, Value: sess.id, Path: "/",
		HttpOnly: true, SameSite: http.SameSiteLaxMode, Secure: tls,
		MaxAge: int(sessionTTL.Seconds()),
	})
	// The CSRF cookie is readable by the page on purpose: the double-submit
	// pattern needs the script to echo it back in a header.
	http.SetCookie(w, &http.Cookie{
		Name: csrfCookie, Value: sess.csrf, Path: "/",
		HttpOnly: false, SameSite: http.SameSiteLaxMode, Secure: tls,
		MaxAge: int(sessionTTL.Seconds()),
	})
}

func clearSessionCookies(w http.ResponseWriter, tls bool) {
	for _, name := range []string{sessionCookie, csrfCookie} {
		http.SetCookie(w, &http.Cookie{
			Name: name, Value: "", Path: "/", MaxAge: -1,
			HttpOnly: name == sessionCookie, SameSite: http.SameSiteLaxMode, Secure: tls,
		})
	}
}

// allowedHost reports whether the Host header names a loopback address.
//
// Without this check a page on any domain can point DNS at 127.0.0.1 and read
// the dashboard from the browser's origin. It is the cheapest meaningful
// defence available and almost universally omitted.
//
// Only the hostname is checked, not the port. The port a browser sends is
// necessarily the one it connected to, so comparing it adds no security while
// making the server unusable behind any port remapping.
func allowedHost(host string, _ int) bool {
	h := host
	if hostPart, _, err := net.SplitHostPort(host); err == nil {
		h = hostPart
	}
	h = strings.Trim(strings.ToLower(h), "[]")
	switch h {
	case "127.0.0.1", "localhost", "::1", "0:0:0:0:0:0:0:1":
		return true
	}
	// Any address in 127.0.0.0/8 is loopback.
	if ip := net.ParseIP(h); ip != nil && ip.IsLoopback() {
		return true
	}
	return false
}

// securityHeaders applies the same hardening to every response.
func securityHeaders(w http.ResponseWriter) {
	h := w.Header()
	// The dashboard serves its own script and style from embed.FS, with no
	// inline script and no CDN, so a strict policy actually holds.
	h.Set("Content-Security-Policy",
		"default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; "+
			"connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("X-Frame-Options", "DENY")
	// The login URL carries the capability token in its query string, so no
	// referrer may ever leave this origin.
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("Cache-Control", "no-store")
}
