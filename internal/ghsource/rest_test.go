package ghsource_test

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/sfbee/api-integrity-tool/internal/ghsource"
	"github.com/sfbee/api-integrity-tool/internal/ghsource/ghtest"
)

// newClient builds a REST client pointed at a fake GitHub. Sleep is stubbed so
// backoff is instantaneous and deterministic.
func newClient(t *testing.T, srv *ghtest.Server, tune ...func(*ghsource.Options)) *ghsource.REST {
	t.Helper()
	var slept []time.Duration
	opt := ghsource.Options{
		BaseURL:     srv.URL,
		HTTPClient:  srv.Client(),
		TokenSource: ghsource.StaticToken("ghp_testtokentesttoken1234"),
		MinInterval: 0,
		Sleep: func(_ context.Context, d time.Duration) error {
			slept = append(slept, d)
			return nil
		},
	}
	for _, f := range tune {
		f(&opt)
	}
	c, err := ghsource.New(opt)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

var repoID = ghsource.RepoID{Owner: "acme", Name: "billing"}

func TestRepoSendsRequiredHeaders(t *testing.T) {
	t.Parallel()
	srv := ghtest.New(t)
	srv.JSON("/repos/acme/billing", ghtest.RepoJSON("acme", "billing", "main", time.Now()))
	c := newClient(t, srv)

	got, _, err := c.Repo(context.Background(), repoID, ghsource.Cond{})
	if err != nil {
		t.Fatal(err)
	}
	if got.DefaultBranch != "main" {
		t.Errorf("DefaultBranch = %q", got.DefaultBranch)
	}
	calls := srv.Calls()
	if len(calls) != 1 {
		t.Fatalf("want 1 call, got %d", len(calls))
	}
	h := calls[0].Header
	if h.Get("Accept") != "application/vnd.github+json" {
		t.Errorf("Accept = %q", h.Get("Accept"))
	}
	if h.Get("X-Github-Api-Version") != ghsource.APIVersion {
		t.Errorf("API version header = %q, want %q", h.Get("X-Github-Api-Version"), ghsource.APIVersion)
	}
	if !strings.HasPrefix(h.Get("Authorization"), "Bearer ") {
		t.Errorf("Authorization = %q", h.Get("Authorization"))
	}
}

// A 304 costs nothing against the rate limit, which is the entire reason the
// client stores validators. If this breaks, frequent checking becomes expensive.
func TestConditionalRequestYieldsNotModified(t *testing.T) {
	t.Parallel()
	srv := ghtest.New(t)
	srv.ETagJSON("/repos/acme/billing", `"etag-1"`, ghtest.RepoJSON("acme", "billing", "main", time.Now()))
	c := newClient(t, srv)

	_, meta, err := c.Repo(context.Background(), repoID, ghsource.Cond{})
	if err != nil {
		t.Fatal(err)
	}
	if meta.ETag != `"etag-1"` {
		t.Fatalf("ETag = %q", meta.ETag)
	}
	repo, meta2, err := c.Repo(context.Background(), repoID, ghsource.Cond{ETag: meta.ETag})
	if err != nil {
		t.Fatal(err)
	}
	if !meta2.NotModified {
		t.Error("second request should have been 304 Not Modified")
	}
	if repo != nil {
		t.Error("a 304 must not return a body")
	}
}

func TestRateLimitHeadersAreParsed(t *testing.T) {
	t.Parallel()
	reset := time.Now().Add(30 * time.Minute).Truncate(time.Second)
	srv := ghtest.New(t, ghtest.WithRate(4711, 5000, reset))
	srv.JSON("/repos/acme/billing", ghtest.RepoJSON("acme", "billing", "main", time.Now()))
	c := newClient(t, srv)

	_, meta, err := c.Repo(context.Background(), repoID, ghsource.Cond{})
	if err != nil {
		t.Fatal(err)
	}
	if meta.Rate.Remaining != 4711 || meta.Rate.Limit != 5000 {
		t.Errorf("rate = %+v", meta.Rate)
	}
	if !meta.Rate.Reset.Equal(reset.UTC()) {
		t.Errorf("reset = %v, want %v", meta.Rate.Reset, reset.UTC())
	}
}

func TestNotFoundIsTyped(t *testing.T) {
	t.Parallel()
	srv := ghtest.New(t)
	c := newClient(t, srv)
	_, _, err := c.Repo(context.Background(), repoID, ghsource.Cond{})
	if !ghsource.IsNotFound(err) {
		t.Fatalf("err = %v, want a NotFoundError", err)
	}
	var nf *ghsource.NotFoundError
	if !errors.As(err, &nf) || nf.Repo != repoID {
		t.Errorf("error should carry the repository identity: %v", err)
	}
	// A missing repository must not be retried; that would waste quota on
	// something that cannot succeed.
	if n := len(srv.Calls()); n != 1 {
		t.Errorf("made %d requests for a 404, want 1", n)
	}
}

func TestUnresolvableRefIsTyped(t *testing.T) {
	t.Parallel()
	srv := ghtest.New(t)
	srv.Status("/repos/acme/billing/compare/deadbeef...main", http.StatusUnprocessableEntity, `{"message":"No common ancestor"}`)
	c := newClient(t, srv)
	_, _, err := c.Compare(context.Background(), repoID, "deadbeef", "main", ghsource.CompareOptions{})
	if !ghsource.IsBadRef(err) {
		t.Fatalf("err = %v, want a BadRefError", err)
	}
}

// A secondary limit is time-based, so it must be waited out and concurrency
// must drop. Retrying immediately gets the client blocked for longer.
func TestSecondaryRateLimitBacksOffThenSucceeds(t *testing.T) {
	t.Parallel()
	srv := ghtest.New(t, ghtest.WithSecondaryLimit(0, 2*time.Second))
	srv.JSON("/repos/acme/billing", ghtest.RepoJSON("acme", "billing", "main", time.Now()))

	var slept []time.Duration
	c := newClient(t, srv, func(o *ghsource.Options) {
		o.MaxAttempts = 3
		o.Sleep = func(_ context.Context, d time.Duration) error {
			slept = append(slept, d)
			return nil
		}
	})
	_, _, err := c.Repo(context.Background(), repoID, ghsource.Cond{})
	if !ghsource.IsRateLimited(err) {
		t.Fatalf("err = %v, want a RateLimitedError after exhausting attempts", err)
	}
	if len(slept) == 0 {
		t.Fatal("expected the client to back off before retrying")
	}
	// Retry-After must be honoured exactly rather than guessed at.
	if slept[0] != 2*time.Second {
		t.Errorf("first backoff = %v, want the 2s Retry-After", slept[0])
	}
}

func TestServerErrorsAreRetried(t *testing.T) {
	t.Parallel()
	srv := ghtest.New(t)
	var hits int
	srv.Handle("/repos/acme/billing", func(w http.ResponseWriter, r *http.Request) {
		hits++
		if hits < 3 {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		w.Write([]byte(`{"default_branch":"main"}`))
	})
	c := newClient(t, srv)
	got, _, err := c.Repo(context.Background(), repoID, ghsource.Cond{})
	if err != nil {
		t.Fatalf("expected the retry to succeed: %v", err)
	}
	if got.DefaultBranch != "main" || hits != 3 {
		t.Errorf("hits = %d, branch = %q", hits, got.DefaultBranch)
	}
}

func TestComparePaginatesFiles(t *testing.T) {
	t.Parallel()
	srv := ghtest.New(t)
	page1 := ghtest.CompareJSON("base1", "head1",
		[]map[string]any{ghtest.FileJSON("a.yaml", "modified", "@@\n-old\n+new\n")},
		[]map[string]any{ghtest.CommitJSON("head1", "first")})
	page2 := map[string]any{"files": []map[string]any{ghtest.FileJSON("b.yaml", "modified", "@@\n-x\n")}}
	srv.Paged("/repos/acme/billing/compare/base1...main", []any{page1, page2})

	c := newClient(t, srv)
	got, meta, err := c.Compare(context.Background(), repoID, "base1", "main", ghsource.CompareOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Files) != 2 {
		t.Fatalf("files = %d, want both pages: %+v", len(got.Files), got.Files)
	}
	if meta.Calls != 2 {
		t.Errorf("Calls = %d, want 2 requests accounted for", meta.Calls)
	}
	if got.FilesTruncated {
		t.Error("FilesTruncated should be false when every page was read")
	}
}

// Truncation must be reported, because absence of a file in a truncated list
// proves nothing and the analysis has to degrade rather than conclude.
func TestCompareReportsTruncation(t *testing.T) {
	t.Parallel()
	srv := ghtest.New(t)
	var files []map[string]any
	for i := 0; i < 5; i++ {
		files = append(files, ghtest.FileJSON("f"+string(rune('a'+i))+".go", "modified", "@@\n-x\n"))
	}
	srv.JSON("/repos/acme/billing/compare/base1...main",
		ghtest.CompareJSON("base1", "head1", files, []map[string]any{ghtest.CommitJSON("head1", "m")}))
	c := newClient(t, srv)
	got, _, err := c.Compare(context.Background(), repoID, "base1", "main", ghsource.CompareOptions{MaxFiles: 2})
	if err != nil {
		t.Fatal(err)
	}
	if !got.FilesTruncated {
		t.Error("want FilesTruncated when the cap was hit")
	}
	if len(got.Files) != 2 {
		t.Errorf("files = %d, want the cap respected", len(got.Files))
	}
}

func TestCompareFiltersByPathPrefix(t *testing.T) {
	t.Parallel()
	srv := ghtest.New(t)
	srv.JSON("/repos/acme/billing/compare/base1...main", ghtest.CompareJSON("base1", "head1",
		[]map[string]any{
			ghtest.FileJSON("services/billing/openapi.yaml", "modified", "@@\n-a\n"),
			ghtest.FileJSON("services/identity/openapi.yaml", "modified", "@@\n-b\n"),
		},
		[]map[string]any{ghtest.CommitJSON("head1", "m")}))
	c := newClient(t, srv)
	got, _, err := c.Compare(context.Background(), repoID, "base1", "main",
		ghsource.CompareOptions{PathPrefix: "services/billing"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Files) != 1 || !strings.Contains(got.Files[0].Filename, "billing") {
		t.Errorf("files = %+v, want only the billing subtree", got.Files)
	}
}

func TestFileAtRefDecodesBase64(t *testing.T) {
	t.Parallel()
	srv := ghtest.New(t)
	srv.Contents("acme", "billing", "openapi.yaml", "abc123", "openapi: 3.0.0\n")
	c := newClient(t, srv)
	got, _, err := c.FileAtRef(context.Background(), repoID, "openapi.yaml", "abc123", ghsource.Cond{})
	if err != nil {
		t.Fatal(err)
	}
	if string(got.Content) != "openapi: 3.0.0\n" {
		t.Errorf("content = %q", got.Content)
	}
}

// GitHub refuses to inline files above roughly a megabyte, reporting
// encoding "none". That must surface as truncation, not as an empty file that
// would look like every endpoint had been deleted.
func TestFileAtRefReportsTruncation(t *testing.T) {
	t.Parallel()
	srv := ghtest.New(t)
	srv.JSON("/repos/acme/billing/contents/huge.yaml", map[string]any{
		"path": "huge.yaml", "sha": "s1", "encoding": "none", "size": 4 << 20, "content": "",
	})
	c := newClient(t, srv)
	got, _, err := c.FileAtRef(context.Background(), repoID, "huge.yaml", "main", ghsource.Cond{})
	if err != nil {
		t.Fatal(err)
	}
	if !got.Truncated {
		t.Error("want Truncated for a file GitHub refused to inline")
	}
}

func TestListTreeFiltersBlobsAndPrefix(t *testing.T) {
	t.Parallel()
	srv := ghtest.New(t)
	srv.JSON("/repos/acme/billing/git/trees/main", map[string]any{
		"tree": []map[string]any{
			{"path": "spec/openapi.yaml", "type": "blob"},
			{"path": "spec", "type": "tree"},
			{"path": "src/main.go", "type": "blob"},
		},
	})
	c := newClient(t, srv)
	got, _, err := c.ListTree(context.Background(), repoID, "main", "spec/")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0] != "spec/openapi.yaml" {
		t.Errorf("tree = %v, want only the blob under spec/", got)
	}
}

func TestCommitsSinceUsesSinceAndPath(t *testing.T) {
	t.Parallel()
	srv := ghtest.New(t)
	srv.JSON("/repos/acme/billing/commits", []map[string]any{ghtest.CommitJSON("c1", "hello")})
	c := newClient(t, srv)
	since := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	got, _, err := c.CommitsSince(context.Background(), repoID, since, "services/billing", ghsource.ListOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].SHA != "c1" {
		t.Fatalf("commits = %+v", got)
	}
	q := srv.Calls()[0].Query
	if !strings.Contains(q, "since=2026-01-01") || !strings.Contains(q, "path=services") {
		t.Errorf("query = %q, want since and path", q)
	}
}
