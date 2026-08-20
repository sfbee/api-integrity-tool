package scan

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stephen-bee/endpoint-monitor/internal/classify"
	"github.com/stephen-bee/endpoint-monitor/internal/detect"
	"github.com/stephen-bee/endpoint-monitor/internal/gitmeta"
	"github.com/stephen-bee/endpoint-monitor/internal/index"
	"github.com/stephen-bee/endpoint-monitor/internal/walk"
)

var update = flag.Bool("update", false, "rewrite golden files")

// fixtureOpts builds scan options that are fully deterministic: a fixed clock, a
// fixed commit, and a fixed version. Without all three, goldens would differ on
// every run and on every machine.
func fixtureOpts(t *testing.T, root string) Options {
	t.Helper()
	fixedTime := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	return Options{
		RepoPath:  root,
		Version:   "test",
		KeepDrops: true,
		Git: gitmeta.Static{I: gitmeta.Info{
			Root:       root,
			Commit:     "0000000000000000000000000000000000000000",
			Branch:     "main",
			HasCommits: true,
		}},
		Now:  func() time.Time { return fixedTime },
		Walk: walk.Options{RespectGitignore: true},
	}
}

// copyFixture copies a fixture tree into a temp dir. Fixtures are copied rather
// than scanned in place so a test can never write into the source tree, and so
// the scanned root is never inside this module's own git repository.
//
// The destination leaf is named after the fixture rather than left as the raw
// temp directory: the index records the repository root's basename, so a random
// leaf name would leak into every golden file and make it machine-specific.
func copyFixture(t *testing.T, name string) string {
	t.Helper()
	src := filepath.Join("..", "..", "testdata", "fixtures", name)
	dst := filepath.Join(t.TempDir(), name)
	if err := os.MkdirAll(dst, 0o755); err != nil {
		t.Fatal(err)
	}
	err := filepath.WalkDir(src, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, p)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)
		if d.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		data, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		return os.WriteFile(target, data, 0o644)
	})
	if err != nil {
		t.Fatalf("copy fixture %s: %v", name, err)
	}
	return dst
}

func runFixture(t *testing.T, name string, tweak func(*Options)) *Result {
	t.Helper()
	root := copyFixture(t, name)
	opts := fixtureOpts(t, root)
	opts.Walk.RespectGitignore = true
	if tweak != nil {
		tweak(&opts)
	}
	res, err := Run(context.Background(), opts)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	return res
}

// summary renders the parts of a scan a human would check, in a stable form.
func summary(res *Result) string {
	var b strings.Builder
	for _, c := range res.Index.Calls {
		fmt.Fprintf(&b, "%s %s%s\t%s\tscore=%d\t%s:%d\n",
			c.Method, c.Host, c.Path, c.Confidence, c.Score, c.Location.File, c.Location.Line)
	}
	return b.String()
}

func TestScanGoFixture(t *testing.T) {
	t.Parallel()
	res := runFixture(t, "go-client", nil)

	want := []string{
		"GET audit.acme.example.com/api/v2/events",
		"POST api.acme.example.com/api/v1/user/add",
		"GET api.acme.example.com/api/v1/users/{user_id}",
		"GET api.stripe.com/v1/invoices",
		"POST api.stripe.com/v1/charges",
		"GET ${env:SEARCH_BASE_URL}/search",
		"GET api.stripe.com/v1/reports",
	}
	got := map[string]bool{}
	for _, c := range res.Index.Calls {
		got[c.Method+" "+c.Host+c.Path] = true
	}
	// The audit call is a POST; assert the set rather than the order here and
	// let the golden file pin the exact ordering.
	for _, w := range want[1:] {
		if !got[w] {
			t.Errorf("missing endpoint %q\nfound:\n%s", w, summary(res))
		}
	}
	if !got["POST audit.acme.example.com/api/v2/events"] {
		t.Errorf("missing cross-file constant endpoint\nfound:\n%s", summary(res))
	}
	if n := len(res.Index.Calls); n != 7 {
		t.Errorf("got %d calls, want 7:\n%s", n, summary(res))
	}
}

// Everything the scan refused must be refused for a stated reason. This is the
// test that catches a regression which starts silently swallowing real calls.
func TestScanDropsAreExplained(t *testing.T) {
	t.Parallel()
	res := runFixture(t, "go-client", nil)

	byReason := map[string]int{}
	for _, d := range res.Drops {
		byReason[d.Reason]++
	}
	for _, want := range []string{classify.DropTestFile, classify.DropRoute, classify.DropLocalHost} {
		if byReason[want] == 0 {
			t.Errorf("no drops recorded with reason %q; got %v", want, byReason)
		}
	}
	// The drop counters in Stats must agree with the retained explanations.
	for reason, n := range byReason {
		if res.Index.Stats.SitesDropped[reason] != n {
			t.Errorf("reason %q: Stats says %d, drops list says %d",
				reason, res.Index.Stats.SitesDropped[reason], n)
		}
	}
	// Vendored, gitignored and node_modules trees must never be read at all, so
	// their calls appear neither as endpoints nor as drops.
	for _, c := range res.Index.Calls {
		for _, forbidden := range []string{"vendored-dependency", "gitignored", "node-modules"} {
			if strings.Contains(c.Host, forbidden) {
				t.Errorf("indexed a call from an excluded tree: %s", c.Host)
			}
		}
	}
}

// A worker pool is the classic source of nondeterministic output. Byte-identical
// results across worker counts is the property that makes goldens trustworthy.
func TestScanIsDeterministicAcrossJobCounts(t *testing.T) {
	t.Parallel()
	// One fixture copy, several worker counts: the only thing varying is the
	// concurrency, which is exactly what this test is about.
	root := copyFixture(t, "go-client")
	var reference []byte
	for _, jobs := range []int{1, 2, 7, 16} {
		opts := fixtureOpts(t, root)
		opts.Jobs = jobs
		res, err := Run(context.Background(), opts)
		if err != nil {
			t.Fatalf("jobs=%d: %v", jobs, err)
		}
		encoded, err := index.Encode(res.Index)
		if err != nil {
			t.Fatal(err)
		}
		if reference == nil {
			reference = encoded
			continue
		}
		if !bytes.Equal(reference, encoded) {
			t.Fatalf("output differs at jobs=%d", jobs)
		}
	}
}

func TestScanGolden(t *testing.T) {
	t.Parallel()
	res := runFixture(t, "go-client", nil)
	encoded, err := index.Encode(res.Index)
	if err != nil {
		t.Fatal(err)
	}
	compareGolden(t, "go-client.index.json", encoded)

	drops, err := json.MarshalIndent(res.Drops, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	compareGolden(t, "go-client.drops.json", append(drops, '\n'))
}

func compareGolden(t *testing.T, name string, got []byte) {
	t.Helper()
	p := filepath.Join("..", "..", "testdata", "golden", name)
	if *update {
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, got, 0o644); err != nil {
			t.Fatal(err)
		}
		t.Logf("updated %s", p)
		return
	}
	want, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("read golden %s: %v (run: go test ./internal/scan -update)", p, err)
	}
	if !bytes.Equal(want, got) {
		t.Errorf("%s does not match the golden file.\n--- want ---\n%s\n--- got ---\n%s", name, want, got)
	}
}

// No golden file and no index may contain a machine-specific path, or the index
// stops being reviewable in a diff and the tests stop being portable.
func TestScanEmitsNoAbsolutePaths(t *testing.T) {
	t.Parallel()
	res := runFixture(t, "go-client", nil)
	encoded, err := index.Encode(res.Index)
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{os.TempDir(), "/Users/", "/home/", "/var/folders"} {
		if bad != "" && bytes.Contains(encoded, []byte(bad)) {
			t.Errorf("index leaks an absolute path fragment %q", bad)
		}
	}
	for _, c := range res.Index.Calls {
		if filepath.IsAbs(c.Location.File) || strings.Contains(c.Location.File, `\`) {
			t.Errorf("location %q is not a repo-relative slash path", c.Location.File)
		}
	}
}

func TestScanRespectsLanguageFilterAndMarksPartial(t *testing.T) {
	t.Parallel()
	res := runFixture(t, "go-client", func(o *Options) {
		o.Languages = []detect.Language{detect.LangGo}
	})
	if !res.Index.Scan.Partial {
		t.Error("a language-filtered scan must be marked partial so merging cannot delete unseen calls")
	}
	if len(res.Index.Scan.Filters) == 0 {
		t.Error("Filters should record what narrowed the scan")
	}
}

func TestScanIncludeTestsAddsFlaggedCalls(t *testing.T) {
	t.Parallel()
	base := runFixture(t, "go-client", nil)
	withTests := runFixture(t, "go-client", func(o *Options) {
		o.Classify = classify.Options{IncludeTests: true}
	})
	if len(withTests.Index.Calls) <= len(base.Index.Calls) {
		t.Fatalf("including tests did not add calls: %d vs %d", len(withTests.Index.Calls), len(base.Index.Calls))
	}
	found := false
	for _, c := range withTests.Index.Calls {
		if strings.Contains(c.Host, "test-only") {
			found = true
			for _, f := range c.Flags {
				if f == "test_file" {
					return
				}
			}
			t.Errorf("test call %s is not flagged test_file: %v", c.Host, c.Flags)
		}
	}
	if !found {
		t.Error("test-only host not indexed with --include-tests")
	}
}

func TestScanIsIdempotentOnDisk(t *testing.T) {
	t.Parallel()
	root := copyFixture(t, "go-client")
	opts := fixtureOpts(t, root)
	opts.Walk.RespectGitignore = true

	first, err := Run(context.Background(), opts)
	if err != nil {
		t.Fatal(err)
	}
	if err := Save(root, first); err != nil {
		t.Fatal(err)
	}
	second, err := Run(context.Background(), opts)
	if err != nil {
		t.Fatal(err)
	}
	if second.Report.Changed() {
		t.Errorf("re-scanning unchanged code reported changes: %+v", second.Report)
	}
	if second.Report.Added != 0 || second.Report.Removed != 0 {
		t.Errorf("report = %+v, want no additions or removals", second.Report)
	}
	// Lifecycle history must survive the round trip through disk.
	for _, c := range second.Index.Calls {
		if c.Lifecycle.FirstSeenScan == "" {
			t.Errorf("call %s lost its first-seen scan", c.ID)
		}
	}
}

func TestScanUnknownRepoPathFails(t *testing.T) {
	t.Parallel()
	opts := fixtureOpts(t, filepath.Join(t.TempDir(), "does-not-exist"))
	if _, err := Run(context.Background(), opts); err == nil {
		t.Error("want an error for a missing repo path")
	}
}
