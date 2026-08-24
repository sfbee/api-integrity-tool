package monitor_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/sfbee/api-integrity-tool/internal/ghsource"
	"github.com/sfbee/api-integrity-tool/internal/ghsource/ghtest"
	"github.com/sfbee/api-integrity-tool/internal/index"
	"github.com/sfbee/api-integrity-tool/internal/model"
	"github.com/sfbee/api-integrity-tool/internal/monitor"
	"github.com/sfbee/api-integrity-tool/internal/store"
)

var fixedTime = time.Date(2026, 4, 1, 9, 0, 0, 0, time.UTC)

const specBase = `
openapi: 3.0.0
info: {version: 1.0.0}
servers: [{url: "https://api.acme.com"}]
paths:
  /api/v1/invoices:
    get:
      parameters:
        - name: limit
          in: query
          required: false
          schema: {type: integer}
      responses:
        "200":
          content:
            application/json:
              schema:
                type: object
                required: [id]
                properties:
                  id: {type: string}
                  legacy_note: {type: string}
  /api/v1/unused:
    get:
      responses:
        "200": {description: ok}
`

// harness wires a monitor against a fake GitHub and a temporary store.
type harness struct {
	t     *testing.T
	srv   *ghtest.Server
	store *store.Store
	idx   *index.Index
	src   ghsource.GitHubSource
}

func newHarness(t *testing.T, paths ...string) *harness {
	t.Helper()
	return newHarnessWithHost(t, "api.acme.com", paths...)
}

// newHarnessWithHost lets a test record calls under a host that differs from the
// linked one, which is how a symbolic host behaves before mapping.
func newHarnessWithHost(t *testing.T, callHost string, paths ...string) *harness {
	t.Helper()
	if len(paths) == 0 {
		paths = []string{"/api/v1/invoices"}
	}
	srv := ghtest.New(t)
	st, err := store.Open(t.TempDir(), func() time.Time { return fixedTime })
	if err != nil {
		t.Fatal(err)
	}
	if err := st.LinkUpstream(model.Upstream{
		Host: "api.acme.com",
		Repo: model.RepoRef{Provider: model.ProviderGitHub, GitHost: "github.com", Owner: "acme", Name: "billing"},
		Role: model.RoleSpecOnly, Source: model.SourceCLI, Status: "active",
	}); err != nil {
		t.Fatal(err)
	}
	var calls []index.Call
	for i, p := range paths {
		calls = append(calls, index.Call{
			ID: "c" + string(rune('1'+i)), Host: callHost, Method: "GET", Path: p,
			Score: 90, Kind: index.KindHTTP,
			Location:  index.Location{File: "internal/client.go", Line: 10 + i},
			Lifecycle: index.Lifecycle{Status: index.StatusActive},
		})
	}
	src, err := ghsource.New(ghsource.Options{
		BaseURL: srv.URL, HTTPClient: srv.Client(), MinInterval: 0,
		Sleep: func(context.Context, time.Duration) error { return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	return &harness{t: t, srv: srv, store: st, idx: &index.Index{Calls: calls}, src: src}
}

func (h *harness) repo(pushed time.Time) {
	h.srv.JSON("/repos/acme/billing", ghtest.RepoJSON("acme", "billing", "main", pushed))
}

func (h *harness) run() *monitor.Result {
	h.t.Helper()
	res, err := monitor.Run(context.Background(), monitor.Options{
		Store: h.store, Source: h.src, Index: h.idx,
		Now: func() time.Time { return fixedTime }, Trigger: "test",
	})
	if err != nil {
		h.t.Fatalf("Run: %v", err)
	}
	return res
}

// baseline performs the first run, which establishes state without reporting.
func (h *harness) baseline() {
	h.t.Helper()
	h.srv.JSON("/repos/acme/billing/commits", []map[string]any{ghtest.CommitJSON("base-sha", "initial")})
	h.srv.JSON("/repos/acme/billing/git/trees/main", map[string]any{
		"tree": []map[string]any{{"path": "openapi.yaml", "type": "blob"}},
	})
	h.srv.JSON("/repos/acme/billing/releases", []map[string]any{})
	res := h.run()
	if len(res.New) != 0 {
		h.t.Fatalf("the first run must report nothing, got %d findings", len(res.New))
	}
}

// findBySignal returns the first finding with a signal prefix.
func findBySignal(fs []model.Finding, prefix string) (model.Finding, bool) {
	for _, f := range fs {
		if strings.HasPrefix(f.Signal, prefix) {
			return f, true
		}
	}
	return model.Finding{}, false
}

func signals(fs []model.Finding) []string {
	out := make([]string, 0, len(fs))
	for _, f := range fs {
		out = append(out, f.Signal+"="+string(f.Severity))
	}
	return out
}

// The first sight of an upstream must produce a baseline and no findings.
// Reporting a repository's entire history on day one destroys trust and none of
// it is actionable.
func TestFirstRunEstablishesBaselineWithoutFindings(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	h.repo(fixedTime)
	h.baseline()

	st, _ := h.store.Read()
	cs := st.Checks["github|github.com|acme|billing|"]
	if cs.LastHeadSHA == "" {
		t.Error("baseline should record a head SHA")
	}
	if len(cs.SpecPaths) == 0 {
		t.Error("baseline should discover the specification path")
	}
}

// A repository that has not been pushed since the last check is skipped without
// a comparison request. This is the single largest saving in the whole design.
func TestUnchangedUpstreamIsSkippedWithoutComparing(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	h.repo(fixedTime)
	h.baseline()
	h.srv.Reset()

	res := h.run()
	if res.Skipped != 1 || res.Checked != 0 {
		t.Errorf("checked=%d skipped=%d, want it skipped", res.Checked, res.Skipped)
	}
	if n := h.srv.CountPath("/compare/"); n != 0 {
		t.Errorf("made %d comparison requests for an unchanged repository, want 0", n)
	}
}

// setChange arranges a comparison between the baseline and a new head, with the
// specification differing between the two refs.
func (h *harness) setChange(baseSpec, headSpec string, files []map[string]any, commits []map[string]any) {
	h.t.Helper()
	h.repo(fixedTime.Add(time.Hour))
	h.srv.JSON("/repos/acme/billing/compare/base-sha...main",
		ghtest.CompareJSON("base-sha", "head-sha", files, commits))
	h.srv.ContentsByRef("acme", "billing", "openapi.yaml", map[string]string{
		"base-sha": baseSpec,
		"head-sha": headSpec,
	})
}

func specFiles() []map[string]any {
	return []map[string]any{ghtest.FileJSON("openapi.yaml", "modified", "@@ -1 +1 @@\n-old\n+new\n")}
}

func specCommits(msg string) []map[string]any {
	return []map[string]any{ghtest.CommitJSON("head-sha", msg)}
}

// The clearest possible break: the specification no longer contains a path this
// repository calls.
func TestSpecPathRemovedIsBreaking(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	h.repo(fixedTime)
	h.baseline()

	head := strings.Replace(specBase, "  /api/v1/invoices:", "  /api/v1/invoices-renamed:", 1)
	h.setChange(specBase, head, specFiles(), specCommits("rename invoices"))

	res := h.run()
	f, ok := findBySignal(res.New, "openapi.path_removed")
	if !ok {
		t.Fatalf("want openapi.path_removed, got %v", signals(res.New))
	}
	if f.Severity != model.SeverityBreaking {
		t.Errorf("severity = %q, want breaking", f.Severity)
	}
	if len(f.Endpoints) != 1 || f.Endpoints[0].Path != "/api/v1/invoices" {
		t.Errorf("endpoints = %+v, want the affected call cited", f.Endpoints)
	}
	// Evidence must point somewhere a reviewer can check.
	if len(f.Evidence) == 0 || f.Evidence[0].JSONPointer == "" {
		t.Errorf("evidence = %+v, want a JSON pointer into the specification", f.Evidence)
	}
	if !strings.Contains(f.Evidence[0].PermalinkURL, "head-sha") {
		t.Errorf("permalink %q should be pinned to a commit", f.Evidence[0].PermalinkURL)
	}
}

// A new required parameter breaks every existing caller, which is exactly the
// change a textual diff cannot recognise.
func TestNewRequiredParameterIsBreaking(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	h.repo(fixedTime)
	h.baseline()

	head := strings.Replace(specBase, `        - name: limit`, `        - name: tenant
          in: query
          required: true
          schema: {type: string}
        - name: limit`, 1)
	h.setChange(specBase, head, specFiles(), specCommits("require tenant"))

	res := h.run()
	f, ok := findBySignal(res.New, "openapi.required_param_added")
	if !ok {
		t.Fatalf("want openapi.required_param_added, got %v", signals(res.New))
	}
	if f.Severity != model.SeverityBreaking {
		t.Errorf("severity = %q, want breaking", f.Severity)
	}
}

// Removing an optional response field is a risk, not a certainty: the caller
// may never have read it.
func TestOptionalResponseFieldRemovalIsRisky(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	h.repo(fixedTime)
	h.baseline()

	head := strings.Replace(specBase, "                  legacy_note: {type: string}\n", "", 1)
	h.setChange(specBase, head, specFiles(), specCommits("drop legacy_note"))

	res := h.run()
	f, ok := findBySignal(res.New, "openapi.response_field_removed")
	if !ok {
		t.Fatalf("want openapi.response_field_removed, got %v", signals(res.New))
	}
	if f.Severity != model.SeverityRisky {
		t.Errorf("severity = %q, want risky for an optional field", f.Severity)
	}
}

// Changes to operations this repository does not call must collapse into one
// informational line. A real specification commit touches hundreds of
// operations, and reporting each one is what makes a monitor unusable.
func TestUnrelatedSpecChangesCollapseIntoOneRollup(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	h.repo(fixedTime)
	h.baseline()

	// Remove the operation this repository never calls, and add three new ones.
	head := strings.Replace(specBase, `  /api/v1/unused:
    get:
      responses:
        "200": {description: ok}
`, `  /api/v1/added-a:
    get:
      responses:
        "200": {description: ok}
  /api/v1/added-b:
    get:
      responses:
        "200": {description: ok}
`, 1)
	h.setChange(specBase, head, specFiles(), specCommits("shuffle unrelated endpoints"))

	res := h.run()
	for _, f := range res.New {
		if f.Severity == model.SeverityBreaking {
			t.Errorf("an unrelated change produced a breaking finding: %s (%s)", f.Signal, f.Title)
		}
	}
	roll, ok := findBySignal(res.New, "openapi.unrelated_rollup")
	if !ok {
		t.Fatalf("want a rollup finding, got %v", signals(res.New))
	}
	if roll.Severity != model.SeverityInfo {
		t.Errorf("rollup severity = %q, want info", roll.Severity)
	}
	if len(res.New) > 2 {
		t.Errorf("unrelated changes produced %d findings, want them collapsed: %v", len(res.New), signals(res.New))
	}
}

// An identical specification across the window must produce nothing at all.
func TestNoSpecChangeProducesNoFindings(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	h.repo(fixedTime)
	h.baseline()
	h.setChange(specBase, specBase, specFiles(), specCommits("unrelated refactor"))

	res := h.run()
	if len(res.New) != 0 {
		t.Errorf("want no findings for an unchanged specification, got %v", signals(res.New))
	}
}

// A path literal that disappears from one line and reappears on another is a
// move or a reformat. Treating it as a removal is the single largest false
// positive in line-level diff scanning.
func TestRemovedLiteralReaddedIsAMoveNotABreak(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	h.repo(fixedTime)
	h.baseline()

	patch := "@@ -10,4 +10,4 @@\n-\trouter.Get(\"/api/v1/invoices\", h)\n+\trouter.Get(\"/api/v1/invoices\", handler2)\n"
	h.setChange(specBase, specBase,
		[]map[string]any{ghtest.FileJSON("internal/routes.go", "modified", patch)},
		specCommits("refactor handler"))

	res := h.run()
	f, ok := findBySignal(res.New, "diff.route_moved")
	if !ok {
		t.Fatalf("want diff.route_moved, got %v", signals(res.New))
	}
	if f.Severity != model.SeverityInfo {
		t.Errorf("severity = %q, want info for a move", f.Severity)
	}
}

// The same literal genuinely removed from a route file is real evidence, but
// line-level scanning is capped at RISKY by design: the identical text also
// appears in tests, logs and client code, so only the structural specification
// and route analyzers may claim an endpoint is actually gone.
func TestRemovedLiteralInRouteFileIsRiskyNotBreaking(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	h.repo(fixedTime)
	h.baseline()

	patch := "@@ -10,3 +10,2 @@\n-\trouter.Get(\"/api/v1/invoices\", h)\n \tother()\n"
	h.setChange(specBase, specBase,
		[]map[string]any{ghtest.FileJSON("internal/routes.go", "modified", patch)},
		specCommits("remove invoices route"))

	res := h.run()
	f, ok := findBySignal(res.New, "diff.removed_path_literal")
	if !ok {
		t.Fatalf("want diff.removed_path_literal, got %v", signals(res.New))
	}
	if f.Severity != model.SeverityRisky {
		t.Errorf("severity = %q, want risky: diff scanning is capped below breaking", f.Severity)
	}
	if len(f.Evidence) == 0 || f.Evidence[0].Hunk == "" {
		t.Error("want the diff hunk as evidence")
	}
}

// The same removal inside test data must never be breaking, however confident
// the match: a fixture is not an interface.
func TestRemovedLiteralInTestDataCannotBreak(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	h.repo(fixedTime)
	h.baseline()

	patch := "@@ -1,3 +1,2 @@\n-\t\"/api/v1/invoices\",\n \tother\n"
	h.setChange(specBase, specBase,
		[]map[string]any{ghtest.FileJSON("internal/testdata/fixtures.go", "modified", patch)},
		specCommits("tidy fixtures"))

	res := h.run()
	for _, f := range res.New {
		if f.Severity == model.SeverityBreaking {
			t.Errorf("a test-data change produced a breaking finding: %s", f.Signal)
		}
	}
}

// A finding must not be reported twice. Re-reporting is how a monitor teaches
// people to ignore it.
func TestFindingsAreNotReportedTwice(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	h.repo(fixedTime)
	h.baseline()

	head := strings.Replace(specBase, "  /api/v1/invoices:", "  /api/v1/invoices-renamed:", 1)
	h.setChange(specBase, head, specFiles(), specCommits("rename"))

	first := h.run()
	if len(first.New) == 0 {
		t.Fatal("expected findings on the first change")
	}
	// Re-run against the same head: the upstream has not moved again.
	second := h.run()
	if len(second.New) != 0 {
		t.Errorf("the same change was reported again: %v", signals(second.New))
	}
}

// A base SHA that no longer resolves means history was rewritten. There is
// nothing to diff, so the tool must re-anchor and say so rather than invent a
// change.
func TestForcePushReanchorsInsteadOfReporting(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	h.repo(fixedTime)
	h.baseline()

	h.repo(fixedTime.Add(time.Hour))
	h.srv.Status("/repos/acme/billing/compare/base-sha...main", 422, `{"message":"No common ancestor"}`)
	h.srv.JSON("/repos/acme/billing/commits", []map[string]any{ghtest.CommitJSON("new-base", "rewritten")})

	res := h.run()
	if len(res.New) != 0 {
		t.Errorf("want no findings after a history rewrite, got %v", signals(res.New))
	}
	found := false
	for _, d := range res.Degraded {
		if d == "history_rewritten" {
			found = true
		}
	}
	if !found {
		t.Errorf("degraded = %v, want history_rewritten reported", res.Degraded)
	}
}

// An inaccessible repository must be reported as an error, not crash the run.
func TestMissingRepositoryIsReportedNotFatal(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	res := h.run()
	if len(res.Errors) != 1 {
		t.Fatalf("errors = %+v, want one", res.Errors)
	}
	if !strings.Contains(res.Errors[0].Err, "not found") {
		t.Errorf("error = %q", res.Errors[0].Err)
	}
}
