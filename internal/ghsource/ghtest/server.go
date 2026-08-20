// Package ghtest provides a fake GitHub API for tests.
//
// It is a real HTTP server rather than a stub implementation of GitHubSource on
// purpose: that way the tests exercise the actual client -- conditional
// requests, Link pagination, header parsing, rate-limit classification and
// backoff -- instead of bypassing the code most likely to be wrong.
package ghtest

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// Call records one request the server saw.
type Call struct {
	Method string
	Path   string
	Query  string
	Header http.Header
}

// Server is a fake GitHub.
type Server struct {
	*httptest.Server

	mu    sync.Mutex
	calls []Call

	routes map[string]http.HandlerFunc
	etags  map[string]string

	rateRemaining int
	rateLimit     int
	rateReset     time.Time

	secondaryEnabled bool
	secondaryAfter   int
	secondaryRetry   time.Duration
	served           int
}

// Option configures a Server.
type Option func(*Server)

// New starts a fake GitHub. Routes are registered with JSON, File or Handle.
func New(t *testing.T, opts ...Option) *Server {
	t.Helper()
	s := &Server{
		routes:        map[string]http.HandlerFunc{},
		etags:         map[string]string{},
		rateRemaining: 4999,
		rateLimit:     5000,
		rateReset:     time.Now().Add(time.Hour),
	}
	for _, o := range opts {
		o(s)
	}
	s.Server = httptest.NewServer(http.HandlerFunc(s.serve))
	t.Cleanup(s.Close)
	return s
}

// WithRate sets the rate-limit headers the server reports.
func WithRate(remaining, limit int, reset time.Time) Option {
	return func(s *Server) {
		s.rateRemaining, s.rateLimit, s.rateReset = remaining, limit, reset
	}
}

// WithSecondaryLimit makes the server trip a secondary rate limit after n
// successful requests, so backoff can be tested. n of 0 trips immediately.
func WithSecondaryLimit(afterCalls int, retryAfter time.Duration) Option {
	return func(s *Server) {
		s.secondaryEnabled = true
		s.secondaryAfter, s.secondaryRetry = afterCalls, retryAfter
	}
}

// JSON registers a JSON body for a path.
func (s *Server) JSON(path string, body any) *Server {
	data, err := json.Marshal(body)
	if err != nil {
		panic(err)
	}
	return s.Handle(path, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(data)
	})
}

// ETagJSON registers a JSON body guarded by an ETag, so a matching
// If-None-Match yields 304.
func (s *Server) ETagJSON(path, etag string, body any) *Server {
	data, err := json.Marshal(body)
	if err != nil {
		panic(err)
	}
	return s.Handle(path, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("ETag", etag)
		if r.Header.Get("If-None-Match") == etag {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(data)
	})
}

// Contents registers a file for the contents endpoint, base64 encoded the way
// GitHub returns it.
func (s *Server) Contents(owner, name, path, ref, body string) *Server {
	full := fmt.Sprintf("/repos/%s/%s/contents/%s", owner, name, path)
	prev := s.routes[full]
	return s.Handle(full, func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.Query().Get("ref"); got != ref && ref != "" {
			if prev != nil {
				prev(w, r)
				return
			}
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"path": path, "sha": "sha-" + ref, "encoding": "base64",
			"size":    len(body),
			"content": base64.StdEncoding.EncodeToString([]byte(body)),
		})
	})
}

// Status registers a bare status code for a path.
func (s *Server) Status(path string, code int, body string) *Server {
	return s.Handle(path, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(code)
		w.Write([]byte(body))
	})
}

// Paged registers a path that returns pages joined by Link headers, so
// pagination handling can be tested.
func (s *Server) Paged(path string, pages []any) *Server {
	return s.Handle(path, func(w http.ResponseWriter, r *http.Request) {
		page := 1
		if v := r.URL.Query().Get("page"); v != "" {
			page, _ = strconv.Atoi(v)
		}
		if page < 1 || page > len(pages) {
			w.Write([]byte("[]"))
			return
		}
		if page < len(pages) {
			next := fmt.Sprintf("%s%s?page=%d", s.URL, path, page+1)
			w.Header().Set("Link", fmt.Sprintf(`<%s>; rel="next"`, next))
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(pages[page-1])
	})
}

// Handle registers a raw handler.
func (s *Server) Handle(path string, h http.HandlerFunc) *Server {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.routes[path] = h
	return s
}

func (s *Server) serve(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	s.calls = append(s.calls, Call{
		Method: r.Method, Path: r.URL.Path, Query: r.URL.RawQuery, Header: r.Header.Clone(),
	})
	s.served++
	served := s.served
	h, ok := s.routes[r.URL.Path]
	secondaryEnabled, secondaryAfter, secondaryRetry := s.secondaryEnabled, s.secondaryAfter, s.secondaryRetry
	remaining, limit, reset := s.rateRemaining, s.rateLimit, s.rateReset
	s.mu.Unlock()

	w.Header().Set("X-RateLimit-Limit", strconv.Itoa(limit))
	w.Header().Set("X-RateLimit-Remaining", strconv.Itoa(remaining))
	w.Header().Set("X-RateLimit-Reset", strconv.FormatInt(reset.Unix(), 10))
	w.Header().Set("X-RateLimit-Resource", "core")

	if secondaryEnabled && served > secondaryAfter {
		w.Header().Set("Retry-After", strconv.Itoa(int(secondaryRetry.Seconds())))
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte(`{"message":"You have exceeded a secondary rate limit"}`))
		return
	}
	if !ok {
		http.NotFound(w, r)
		return
	}
	h(w, r)
}

// Calls returns every request seen.
func (s *Server) Calls() []Call {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Call(nil), s.calls...)
}

// CountPath returns how many requests hit paths containing substr.
func (s *Server) CountPath(substr string) int {
	n := 0
	for _, c := range s.Calls() {
		if strings.Contains(c.Path, substr) {
			n++
		}
	}
	return n
}

// Reset clears the recorded calls.
func (s *Server) Reset() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls = nil
	s.served = 0
}

// RepoJSON is a convenience body for the repository endpoint.
func RepoJSON(owner, name, branch string, pushedAt time.Time) map[string]any {
	return map[string]any{
		"full_name":      owner + "/" + name,
		"html_url":       "https://github.com/" + owner + "/" + name,
		"default_branch": branch,
		"pushed_at":      pushedAt.UTC().Format(time.RFC3339),
	}
}

// CompareJSON is a convenience body for the compare endpoint.
func CompareJSON(baseSHA, headSHA string, files []map[string]any, commits []map[string]any) map[string]any {
	return map[string]any{
		"status":        "ahead",
		"ahead_by":      len(commits),
		"total_commits": len(commits),
		"html_url":      "https://github.com/o/r/compare/" + baseSHA + "..." + headSHA,
		"base_commit":   map[string]any{"sha": baseSHA},
		"commits":       commits,
		"files":         files,
	}
}

// FileJSON is a convenience entry for a changed file.
func FileJSON(name, status, patch string) map[string]any {
	return map[string]any{
		"filename": name, "status": status, "patch": patch,
		"changes": strings.Count(patch, "\n"), "sha": "blob-" + name,
		"blob_url": "https://github.com/o/r/blob/head/" + name,
	}
}

// CommitJSON is a convenience entry for a commit.
func CommitJSON(sha, message string) map[string]any {
	return map[string]any{
		"sha": sha, "html_url": "https://github.com/o/r/commit/" + sha,
		"commit": map[string]any{
			"message": message,
			"author":  map[string]any{"name": "Someone", "date": time.Now().UTC().Format(time.RFC3339)},
		},
	}
}
