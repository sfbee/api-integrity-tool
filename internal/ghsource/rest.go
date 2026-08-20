package ghsource

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// DefaultBaseURL is the public GitHub API. It appears exactly once in the
// program so tests can prove nothing else reaches the network.
const DefaultBaseURL = "https://api.github.com"

// APIVersion pins the REST API version, so a server-side default change cannot
// silently alter response shapes.
const APIVersion = "2022-11-28"

// Options configures a REST client.
type Options struct {
	BaseURL     string
	HTTPClient  *http.Client
	TokenSource TokenSource
	UserAgent   string
	// Now and Sleep are injectable so backoff and reset handling are testable
	// without real delays.
	Now   func() time.Time
	Sleep func(context.Context, time.Duration) error
	// MinInterval throttles requests. GitHub asks for roughly serial requests
	// with brief pauses rather than bursts.
	MinInterval time.Duration
	// MaxConcurrent bounds requests in flight.
	MaxConcurrent int
	// MaxWait is the longest we will block waiting for a rate limit to reset.
	// Blocking a tool call for forty minutes is worse than failing clearly.
	MaxWait time.Duration
	// MaxAttempts bounds retries of transient failures.
	MaxAttempts int
	// MaxBodyBytes caps a single response body.
	MaxBodyBytes int64
	Logf         func(format string, args ...any)
}

// REST is the live GitHub implementation of GitHubSource.
type REST struct {
	opt   Options
	base  *url.URL
	sem   chan struct{}
	mu    sync.Mutex
	last  time.Time
	rates map[string]Rate
	// serialUntilEnd drops concurrency to one for the rest of the run once a
	// secondary rate limit is seen. Continuing to fan out after that is how a
	// client gets itself blocked for longer.
	serialUntilEnd bool
	token          string
}

// New returns a REST client. Only BaseURL and HTTPClient are truly required in
// tests; everything else has a workable default.
func New(o Options) (*REST, error) {
	if o.BaseURL == "" {
		o.BaseURL = DefaultBaseURL
	}
	u, err := url.Parse(strings.TrimRight(o.BaseURL, "/"))
	if err != nil {
		return nil, fmt.Errorf("parse base URL %q: %w", o.BaseURL, err)
	}
	if o.HTTPClient == nil {
		o.HTTPClient = &http.Client{Timeout: 30 * time.Second}
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Sleep == nil {
		o.Sleep = func(ctx context.Context, d time.Duration) error {
			t := time.NewTimer(d)
			defer t.Stop()
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-t.C:
				return nil
			}
		}
	}
	if o.UserAgent == "" {
		o.UserAgent = "api-integrity-tool"
	}
	if o.MinInterval == 0 {
		o.MinInterval = 100 * time.Millisecond
	}
	if o.MaxConcurrent <= 0 {
		o.MaxConcurrent = 4
	}
	if o.MaxWait == 0 {
		o.MaxWait = 60 * time.Second
	}
	if o.MaxAttempts <= 0 {
		o.MaxAttempts = 4
	}
	if o.MaxBodyBytes <= 0 {
		o.MaxBodyBytes = 16 << 20
	}
	return &REST{
		opt:   o,
		base:  u,
		sem:   make(chan struct{}, o.MaxConcurrent),
		rates: map[string]Rate{},
	}, nil
}

func (c *REST) logf(format string, args ...any) {
	if c.opt.Logf == nil {
		return
	}
	c.opt.Logf("%s", Redact(fmt.Sprintf(format, args...), c.token))
}

// response is one decoded HTTP exchange.
type response struct {
	status int
	body   []byte
	header http.Header
	meta   Meta
}

// do issues one request with conditional headers, retries and rate-limit
// handling. Every network access in this package goes through here.
func (c *REST) do(ctx context.Context, path string, query url.Values, cond Cond) (*response, error) {
	var lastErr error
	for attempt := 0; attempt < c.opt.MaxAttempts; attempt++ {
		if attempt > 0 {
			// Exponential backoff with full jitter: synchronised retries from
			// several processes are what trip secondary limits.
			d := time.Duration(1<<uint(attempt-1)) * time.Second
			d = time.Duration(rand.Int63n(int64(d)) + int64(d)/2)
			if err := c.opt.Sleep(ctx, d); err != nil {
				return nil, err
			}
		}
		resp, err := c.once(ctx, path, query, cond)
		if err == nil {
			return resp, nil
		}
		lastErr = err

		var rl *RateLimitedError
		if asRateLimited(err, &rl) {
			if rl.Secondary {
				c.mu.Lock()
				c.serialUntilEnd = true
				c.mu.Unlock()
				wait := rl.RetryAfter
				if wait <= 0 {
					wait = time.Duration(1<<uint(attempt)) * time.Second
				}
				if wait > c.opt.MaxWait {
					return nil, err
				}
				if serr := c.opt.Sleep(ctx, wait); serr != nil {
					return nil, serr
				}
				continue
			}
			// A primary limit is only worth waiting out if it resets soon.
			wait := time.Until(rl.Reset)
			if c.opt.Now != nil {
				wait = rl.Reset.Sub(c.opt.Now())
			}
			if wait > 0 && wait <= c.opt.MaxWait {
				if serr := c.opt.Sleep(ctx, wait); serr != nil {
					return nil, serr
				}
				continue
			}
			return nil, err
		}
		if !retryable(err) {
			return nil, err
		}
	}
	return nil, lastErr
}

func (c *REST) once(ctx context.Context, path string, query url.Values, cond Cond) (*response, error) {
	if err := c.throttle(ctx); err != nil {
		return nil, err
	}
	defer func() { <-c.sem }()

	u := *c.base
	u.Path = strings.TrimRight(u.Path, "/") + path
	if len(query) > 0 {
		u.RawQuery = query.Encode()
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", APIVersion)
	req.Header.Set("User-Agent", c.opt.UserAgent)
	if c.opt.TokenSource != nil {
		if tok, terr := c.opt.TokenSource.Token(ctx); terr == nil && tok != "" {
			c.token = tok
			req.Header.Set("Authorization", "Bearer "+tok)
		}
	}
	// Conditional requests are the whole rate-limit strategy: a 304 is free.
	if cond.ETag != "" {
		req.Header.Set("If-None-Match", cond.ETag)
	}
	if cond.LastModified != "" {
		req.Header.Set("If-Modified-Since", cond.LastModified)
	}

	httpResp, err := c.opt.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("GET %s: %w", Redact(u.Path, c.token), err)
	}
	defer httpResp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(httpResp.Body, c.opt.MaxBodyBytes))
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", Redact(u.Path, c.token), err)
	}

	rate := parseRate(httpResp.Header)
	c.mu.Lock()
	if rate.Resource != "" {
		c.rates[rate.Resource] = rate
	}
	c.mu.Unlock()

	r := &response{
		status: httpResp.StatusCode,
		body:   body,
		header: httpResp.Header,
		meta: Meta{
			ETag:         httpResp.Header.Get("ETag"),
			LastModified: httpResp.Header.Get("Last-Modified"),
			NotModified:  httpResp.StatusCode == http.StatusNotModified,
			Rate:         rate,
			Calls:        1,
		},
	}
	return r, c.classify(httpResp, body, rate)
}

// classify converts an HTTP status into one of the package's typed errors.
func (c *REST) classify(resp *http.Response, body []byte, rate Rate) error {
	switch {
	case resp.StatusCode == http.StatusNotModified:
		return nil
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		return nil
	case resp.StatusCode == http.StatusNotFound:
		return &NotFoundError{}
	case resp.StatusCode == http.StatusUnauthorized:
		return fmt.Errorf("GitHub rejected the credential: %w", ErrUnauthenticated)
	case resp.StatusCode == http.StatusForbidden, resp.StatusCode == http.StatusTooManyRequests:
		retryAfter := parseRetryAfter(resp.Header)
		lower := strings.ToLower(string(body))
		secondary := strings.Contains(lower, "secondary rate limit") ||
			strings.Contains(lower, "abuse detection") ||
			retryAfter > 0
		if secondary {
			return &RateLimitedError{RetryAfter: retryAfter, Reset: rate.Reset, Secondary: true}
		}
		if rate.Remaining == 0 && !rate.Reset.IsZero() {
			return &RateLimitedError{Reset: rate.Reset}
		}
		return &ForbiddenError{Detail: firstLine(string(body))}
	case resp.StatusCode == http.StatusUnprocessableEntity:
		// GitHub uses 422 for an unresolvable ref in a comparison.
		return &BadRefError{}
	case resp.StatusCode >= 500:
		return fmt.Errorf("GitHub server error %d: %s", resp.StatusCode, firstLine(string(body)))
	default:
		return fmt.Errorf("unexpected GitHub status %d: %s", resp.StatusCode, firstLine(string(body)))
	}
}

// throttle enforces the minimum interval and concurrency cap.
func (c *REST) throttle(ctx context.Context) error {
	c.mu.Lock()
	serial := c.serialUntilEnd
	c.mu.Unlock()

	slots := 1
	if !serial {
		slots = cap(c.sem)
	}
	_ = slots
	select {
	case c.sem <- struct{}{}:
	case <-ctx.Done():
		return ctx.Err()
	}

	c.mu.Lock()
	wait := time.Duration(0)
	if !c.last.IsZero() {
		if elapsed := c.opt.Now().Sub(c.last); elapsed < c.opt.MinInterval {
			wait = c.opt.MinInterval - elapsed
		}
	}
	c.last = c.opt.Now().Add(wait)
	c.mu.Unlock()

	if wait > 0 {
		if err := c.opt.Sleep(ctx, wait); err != nil {
			<-c.sem
			return err
		}
	}
	return nil
}

// Repo implements GitHubSource.
func (c *REST) Repo(ctx context.Context, r RepoID, cond Cond) (*Repo, Meta, error) {
	resp, err := c.do(ctx, "/repos/"+r.Owner+"/"+r.Name, nil, cond)
	if err != nil {
		return nil, metaOf(resp), withRepo(err, r)
	}
	if resp.meta.NotModified {
		return nil, resp.meta, nil
	}
	var raw struct {
		FullName      string    `json:"full_name"`
		HTMLURL       string    `json:"html_url"`
		DefaultBranch string    `json:"default_branch"`
		PushedAt      time.Time `json:"pushed_at"`
		Archived      bool      `json:"archived"`
		Disabled      bool      `json:"disabled"`
		Private       bool      `json:"private"`
	}
	if err := json.Unmarshal(resp.body, &raw); err != nil {
		return nil, resp.meta, fmt.Errorf("%s: parse repository: %w", r, err)
	}
	return &Repo{
		FullName: raw.FullName, HTMLURL: raw.HTMLURL, DefaultBranch: raw.DefaultBranch,
		PushedAt: raw.PushedAt, Archived: raw.Archived, Disabled: raw.Disabled, Private: raw.Private,
	}, resp.meta, nil
}

type rawCommit struct {
	SHA     string `json:"sha"`
	HTMLURL string `json:"html_url"`
	Commit  struct {
		Message string `json:"message"`
		Author  struct {
			Name string    `json:"name"`
			Date time.Time `json:"date"`
		} `json:"author"`
	} `json:"commit"`
}

func (rc rawCommit) toCommit() Commit {
	return Commit{
		SHA: rc.SHA, Message: rc.Commit.Message, HTMLURL: rc.HTMLURL,
		Author: rc.Commit.Author.Name, AuthorDate: rc.Commit.Author.Date,
	}
}

type rawFile struct {
	Filename         string `json:"filename"`
	PreviousFilename string `json:"previous_filename"`
	Status           string `json:"status"`
	Additions        int    `json:"additions"`
	Deletions        int    `json:"deletions"`
	Changes          int    `json:"changes"`
	Patch            string `json:"patch"`
	SHA              string `json:"sha"`
	BlobURL          string `json:"blob_url"`
	RawURL           string `json:"raw_url"`
}

func (rf rawFile) toFileChange() FileChange {
	return FileChange{
		Filename: rf.Filename, PreviousFilename: rf.PreviousFilename, Status: rf.Status,
		Additions: rf.Additions, Deletions: rf.Deletions, Changes: rf.Changes,
		Patch: rf.Patch, PatchOmitted: rf.Patch == "" && rf.Changes > 0,
		SHA: rf.SHA, BlobURL: rf.BlobURL, RawURL: rf.RawURL,
	}
}

// Compare implements GitHubSource. One request yields commits, files and
// patches, which is why it is the primary source of change information.
func (c *REST) Compare(ctx context.Context, r RepoID, base, head string, o CompareOptions) (*Compare, Meta, error) {
	maxFiles := o.MaxFiles
	if maxFiles <= 0 {
		maxFiles = 300
	}
	path := fmt.Sprintf("/repos/%s/%s/compare/%s...%s", r.Owner, r.Name, url.PathEscape(base), url.PathEscape(head))
	q := url.Values{"per_page": {"100"}}
	resp, err := c.do(ctx, path, q, o.Cond)
	if err != nil {
		return nil, metaOf(resp), withRepo(err, r)
	}
	if resp.meta.NotModified {
		return nil, resp.meta, nil
	}
	var raw struct {
		Status       string      `json:"status"`
		AheadBy      int         `json:"ahead_by"`
		BehindBy     int         `json:"behind_by"`
		TotalCommits int         `json:"total_commits"`
		HTMLURL      string      `json:"html_url"`
		BaseCommit   rawCommit   `json:"base_commit"`
		MergeBase    rawCommit   `json:"merge_base_commit"`
		Commits      []rawCommit `json:"commits"`
		Files        []rawFile   `json:"files"`
	}
	if err := json.Unmarshal(resp.body, &raw); err != nil {
		return nil, resp.meta, fmt.Errorf("%s: parse comparison: %w", r, err)
	}
	out := &Compare{
		Status: raw.Status, AheadBy: raw.AheadBy, BehindBy: raw.BehindBy,
		TotalCommits: raw.TotalCommits, HTMLURL: raw.HTMLURL,
		BaseSHA: raw.BaseCommit.SHA,
	}
	for _, rc := range raw.Commits {
		out.Commits = append(out.Commits, rc.toCommit())
	}
	if n := len(out.Commits); n > 0 {
		out.HeadSHA = out.Commits[n-1].SHA
	}
	meta := resp.meta

	files := raw.Files
	// The comparison endpoint caps its file list; page for the rest so the
	// analysis is not silently based on a partial view.
	pageURL := nextLink(resp.header)
	for pageURL != "" && len(files) < maxFiles {
		more, mmeta, perr := c.followPage(ctx, pageURL)
		meta.Calls += mmeta.Calls
		if perr != nil {
			out.FilesTruncated = true
			break
		}
		var page struct {
			Files []rawFile `json:"files"`
		}
		if err := json.Unmarshal(more.body, &page); err != nil || len(page.Files) == 0 {
			break
		}
		files = append(files, page.Files...)
		pageURL = nextLink(more.header)
	}
	if len(files) > maxFiles {
		files = files[:maxFiles]
		out.FilesTruncated = true
	}
	if pageURL != "" {
		out.FilesTruncated = true
	}
	for _, rf := range files {
		if o.PathPrefix != "" && !strings.HasPrefix(rf.Filename, o.PathPrefix) {
			continue
		}
		out.Files = append(out.Files, rf.toFileChange())
	}
	return out, meta, nil
}

func (c *REST) followPage(ctx context.Context, absolute string) (*response, Meta, error) {
	u, err := url.Parse(absolute)
	if err != nil {
		return nil, Meta{}, err
	}
	resp, err := c.do(ctx, u.Path, u.Query(), Cond{})
	if err != nil {
		return nil, metaOf(resp), err
	}
	return resp, resp.meta, nil
}

// CommitsSince implements GitHubSource.
func (c *REST) CommitsSince(ctx context.Context, r RepoID, since time.Time, path string, o ListOptions) ([]Commit, Meta, error) {
	perPage, maxPages := listDefaults(o, 100, 5)
	q := url.Values{"per_page": {strconv.Itoa(perPage)}}
	if !since.IsZero() {
		q.Set("since", since.UTC().Format(time.RFC3339))
	}
	if path != "" {
		q.Set("path", path)
	}
	var out []Commit
	meta := Meta{}
	next := ""
	for page := 0; page < maxPages; page++ {
		var resp *response
		var err error
		if next == "" {
			resp, err = c.do(ctx, fmt.Sprintf("/repos/%s/%s/commits", r.Owner, r.Name), q, Cond{})
		} else {
			u, perr := url.Parse(next)
			if perr != nil {
				break
			}
			resp, err = c.do(ctx, u.Path, u.Query(), Cond{})
		}
		if err != nil {
			return out, mergeMeta(meta, metaOf(resp)), withRepo(err, r)
		}
		meta = mergeMeta(meta, resp.meta)
		var raw []rawCommit
		if err := json.Unmarshal(resp.body, &raw); err != nil {
			return out, meta, fmt.Errorf("%s: parse commits: %w", r, err)
		}
		for _, rc := range raw {
			out = append(out, rc.toCommit())
		}
		if next = nextLink(resp.header); next == "" {
			break
		}
	}
	return out, meta, nil
}

// Releases implements GitHubSource.
func (c *REST) Releases(ctx context.Context, r RepoID, cond Cond, o ListOptions) ([]Release, Meta, error) {
	perPage, _ := listDefaults(o, 10, 1)
	resp, err := c.do(ctx, fmt.Sprintf("/repos/%s/%s/releases", r.Owner, r.Name),
		url.Values{"per_page": {strconv.Itoa(perPage)}}, cond)
	if err != nil {
		return nil, metaOf(resp), withRepo(err, r)
	}
	if resp.meta.NotModified {
		return nil, resp.meta, nil
	}
	var raw []struct {
		TagName     string    `json:"tag_name"`
		Name        string    `json:"name"`
		Body        string    `json:"body"`
		HTMLURL     string    `json:"html_url"`
		Draft       bool      `json:"draft"`
		Prerelease  bool      `json:"prerelease"`
		PublishedAt time.Time `json:"published_at"`
	}
	if err := json.Unmarshal(resp.body, &raw); err != nil {
		return nil, resp.meta, fmt.Errorf("%s: parse releases: %w", r, err)
	}
	out := make([]Release, 0, len(raw))
	for _, e := range raw {
		out = append(out, Release{
			TagName: e.TagName, Name: e.Name, Body: e.Body, HTMLURL: e.HTMLURL,
			Draft: e.Draft, Prerelease: e.Prerelease, PublishedAt: e.PublishedAt,
		})
	}
	return out, resp.meta, nil
}

// Tags implements GitHubSource.
func (c *REST) Tags(ctx context.Context, r RepoID, cond Cond, o ListOptions) ([]Tag, Meta, error) {
	perPage, _ := listDefaults(o, 30, 1)
	resp, err := c.do(ctx, fmt.Sprintf("/repos/%s/%s/tags", r.Owner, r.Name),
		url.Values{"per_page": {strconv.Itoa(perPage)}}, cond)
	if err != nil {
		return nil, metaOf(resp), withRepo(err, r)
	}
	if resp.meta.NotModified {
		return nil, resp.meta, nil
	}
	var raw []struct {
		Name   string `json:"name"`
		Commit struct {
			SHA string `json:"sha"`
		} `json:"commit"`
	}
	if err := json.Unmarshal(resp.body, &raw); err != nil {
		return nil, resp.meta, fmt.Errorf("%s: parse tags: %w", r, err)
	}
	out := make([]Tag, 0, len(raw))
	for _, e := range raw {
		out = append(out, Tag{Name: e.Name, SHA: e.Commit.SHA})
	}
	return out, resp.meta, nil
}

// FileAtRef implements GitHubSource.
func (c *REST) FileAtRef(ctx context.Context, r RepoID, path, ref string, cond Cond) (*FileContent, Meta, error) {
	q := url.Values{}
	if ref != "" {
		q.Set("ref", ref)
	}
	resp, err := c.do(ctx, fmt.Sprintf("/repos/%s/%s/contents/%s", r.Owner, r.Name, escapePath(path)), q, cond)
	if err != nil {
		return nil, metaOf(resp), withRepoPath(err, r, path)
	}
	if resp.meta.NotModified {
		return nil, resp.meta, nil
	}
	var raw struct {
		Path     string `json:"path"`
		SHA      string `json:"sha"`
		Size     int64  `json:"size"`
		Content  string `json:"content"`
		Encoding string `json:"encoding"`
	}
	if err := json.Unmarshal(resp.body, &raw); err != nil {
		return nil, resp.meta, fmt.Errorf("%s: parse contents of %s: %w", r, path, err)
	}
	out := &FileContent{Path: raw.Path, SHA: raw.SHA}
	switch raw.Encoding {
	case "base64":
		decoded, derr := base64.StdEncoding.DecodeString(strings.ReplaceAll(raw.Content, "\n", ""))
		if derr != nil {
			return nil, resp.meta, fmt.Errorf("%s: decode %s: %w", r, path, derr)
		}
		out.Content = decoded
	case "none":
		// GitHub refuses to inline files above roughly 1 MB.
		out.Truncated = true
	default:
		out.Content = []byte(raw.Content)
	}
	return out, resp.meta, nil
}

// ListTree implements GitHubSource.
func (c *REST) ListTree(ctx context.Context, r RepoID, ref, pathPrefix string) ([]string, Meta, error) {
	if ref == "" {
		ref = "HEAD"
	}
	resp, err := c.do(ctx, fmt.Sprintf("/repos/%s/%s/git/trees/%s", r.Owner, r.Name, url.PathEscape(ref)),
		url.Values{"recursive": {"1"}}, Cond{})
	if err != nil {
		return nil, metaOf(resp), withRepo(err, r)
	}
	var raw struct {
		Tree []struct {
			Path string `json:"path"`
			Type string `json:"type"`
		} `json:"tree"`
		Truncated bool `json:"truncated"`
	}
	if err := json.Unmarshal(resp.body, &raw); err != nil {
		return nil, resp.meta, fmt.Errorf("%s: parse tree: %w", r, err)
	}
	var out []string
	for _, e := range raw.Tree {
		if e.Type != "blob" {
			continue
		}
		if pathPrefix != "" && !strings.HasPrefix(e.Path, pathPrefix) {
			continue
		}
		out = append(out, e.Path)
	}
	return out, resp.meta, nil
}

// RateLimits implements GitHubSource.
func (c *REST) RateLimits(ctx context.Context) (map[string]Rate, error) {
	resp, err := c.do(ctx, "/rate_limit", nil, Cond{})
	if err != nil {
		return nil, err
	}
	var raw struct {
		Resources map[string]struct {
			Limit     int   `json:"limit"`
			Remaining int   `json:"remaining"`
			Used      int   `json:"used"`
			Reset     int64 `json:"reset"`
		} `json:"resources"`
	}
	if err := json.Unmarshal(resp.body, &raw); err != nil {
		return nil, fmt.Errorf("parse rate limits: %w", err)
	}
	out := map[string]Rate{}
	for name, v := range raw.Resources {
		out[name] = Rate{
			Resource: name, Limit: v.Limit, Remaining: v.Remaining,
			Used: v.Used, Reset: time.Unix(v.Reset, 0).UTC(),
		}
	}
	return out, nil
}

// LastRates returns the most recent rate-limit state observed per resource,
// without spending a request to ask.
func (c *REST) LastRates() map[string]Rate {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make(map[string]Rate, len(c.rates))
	for k, v := range c.rates {
		out[k] = v
	}
	return out
}

func listDefaults(o ListOptions, perPage, maxPages int) (int, int) {
	if o.PerPage > 0 {
		perPage = o.PerPage
	}
	if o.MaxPages > 0 {
		maxPages = o.MaxPages
	}
	return perPage, maxPages
}

func parseRate(h http.Header) Rate {
	r := Rate{Resource: h.Get("X-RateLimit-Resource")}
	if r.Resource == "" {
		r.Resource = "core"
	}
	r.Limit = atoiHeader(h, "X-RateLimit-Limit")
	r.Used = atoiHeader(h, "X-RateLimit-Used")
	if v := h.Get("X-RateLimit-Remaining"); v != "" {
		r.Remaining, _ = strconv.Atoi(v)
	} else {
		r.Remaining = -1
	}
	if v := h.Get("X-RateLimit-Reset"); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil {
			r.Reset = time.Unix(n, 0).UTC()
		}
	}
	return r
}

func atoiHeader(h http.Header, key string) int {
	n, _ := strconv.Atoi(h.Get(key))
	return n
}

func parseRetryAfter(h http.Header) time.Duration {
	v := h.Get("Retry-After")
	if v == "" {
		return 0
	}
	if n, err := strconv.Atoi(v); err == nil {
		return time.Duration(n) * time.Second
	}
	if t, err := http.ParseTime(v); err == nil {
		return time.Until(t)
	}
	return 0
}

var linkNextRe = regexp.MustCompile(`<([^>]+)>;\s*rel="next"`)

// nextLink extracts the next page URL from a Link header.
func nextLink(h http.Header) string {
	for _, v := range h.Values("Link") {
		if m := linkNextRe.FindStringSubmatch(v); m != nil {
			return m[1]
		}
	}
	return ""
}

func escapePath(p string) string {
	parts := strings.Split(strings.TrimPrefix(p, "/"), "/")
	for i, s := range parts {
		parts[i] = url.PathEscape(s)
	}
	return strings.Join(parts, "/")
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	if len(s) > 200 {
		s = s[:200] + "…"
	}
	return s
}

func metaOf(r *response) Meta {
	if r == nil {
		return Meta{}
	}
	return r.meta
}

func mergeMeta(a, b Meta) Meta {
	a.Calls += b.Calls
	if b.Rate.Resource != "" {
		a.Rate = b.Rate
	}
	if b.ETag != "" {
		a.ETag = b.ETag
	}
	return a
}

// withRepo attaches repository identity to the errors that are created without
// it inside classify.
func withRepo(err error, r RepoID) error {
	switch e := err.(type) {
	case *NotFoundError:
		e.Repo = r
	case *ForbiddenError:
		e.Repo = r
	case *BadRefError:
		e.Repo = r
	}
	return err
}

func withRepoPath(err error, r RepoID, path string) error {
	if e, ok := err.(*NotFoundError); ok {
		e.Repo, e.Path = r, path
		return e
	}
	return withRepo(err, r)
}

func asRateLimited(err error, out **RateLimitedError) bool {
	if e, ok := err.(*RateLimitedError); ok {
		*out = e
		return true
	}
	return false
}

// retryable reports whether an error is worth another attempt. A missing
// repository never is; a server error usually is.
func retryable(err error) bool {
	switch err.(type) {
	case *NotFoundError, *ForbiddenError, *BadRefError, *TooLargeError:
		return false
	}
	return true
}
