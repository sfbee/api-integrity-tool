package monitor_test

import (
	"context"
	"strings"
	"testing"

	"github.com/stephen-bee/endpoint-monitor/internal/config"
	"github.com/stephen-bee/endpoint-monitor/internal/ghsource/ghtest"
	"github.com/stephen-bee/endpoint-monitor/internal/monitor"
)

// kaSpec mirrors the shape of a real the upstream specification: the version prefix lives
// in the server URL, and the path parameters are named nothing like ours.
const kaSpec = `
openapi: 3.0.0
info: {title: Partner API 3.0, version: 1.0.0}
servers:
  - url: "https://api.acme.com/api/partner/v3"
paths:
  /keys:
    get:
      responses: {"200": {description: ok}}
    post:
      responses: {"200": {description: ok}}
  /keys/{keyNumberOrActivationCode}:
    get:
      responses: {"200": {description: ok}}
    delete:
      responses: {"200": {description: ok}}
`

func (h *harness) coverage(t *testing.T) []monitor.CoverageResult {
	t.Helper()
	res, _, err := monitor.Coverage(context.Background(), monitor.CoverageOptions{
		Store: h.store, Source: h.src, Index: h.idx,
	})
	if err != nil {
		t.Fatalf("Coverage: %v", err)
	}
	return res
}

func (h *harness) tree(paths ...string) {
	entries := make([]map[string]any, 0, len(paths))
	for _, p := range paths {
		entries = append(entries, map[string]any{"path": p, "type": "blob"})
	}
	h.srv.JSON("/repos/acme/billing/git/trees/main", map[string]any{"tree": entries})
}

// A specification declares paths relative to its servers, while our index may
// record the server's prefix as part of the path. Both must match, or every call
// looks undocumented.
func TestCoverageMatchesAcrossTheServerPrefix(t *testing.T) {
	t.Parallel()
	h := newHarness(t,
		"/keys", // relative, as a symbolic base yields
		"/api/partner/v3/keys/{keyid}", // absolute, prefix baked in
	)
	h.repo(fixedTime)
	h.tree("assets/openapi/partner-v3-api.yml")
	h.srv.Contents("acme", "billing", "assets/openapi/partner-v3-api.yml", "main", kaSpec)

	got := h.coverage(t)
	if len(got) != 1 {
		t.Fatalf("got %d results, want 1", len(got))
	}
	r := got[0]
	if len(r.Specs) != 1 || r.Specs[0] != "assets/openapi/partner-v3-api.yml" {
		t.Fatalf("Specs = %v", r.Specs)
	}
	if u := r.Undocumented(); len(u) != 0 {
		t.Errorf("both endpoints should be documented, got undocumented: %+v", u)
	}
	for _, e := range r.Endpoints {
		if !e.Documented {
			t.Errorf("%s %s reported undocumented", e.Method, e.Path)
			continue
		}
		if e.Spec == "" || e.SpecOp == "" {
			t.Errorf("%s %s documented but the spec is not named: %+v", e.Method, e.Path, e)
		}
	}
}

// The parameter names differ between caller and specification; template
// normalisation is what makes them compare equal.
func TestCoverageIgnoresParameterNaming(t *testing.T) {
	t.Parallel()
	h := newHarness(t, "/keys/{my_own_name}")
	h.repo(fixedTime)
	h.tree("assets/openapi/partner-v3-api.yml")
	h.srv.Contents("acme", "billing", "assets/openapi/partner-v3-api.yml", "main", kaSpec)

	r := h.coverage(t)[0]
	if len(r.Undocumented()) != 0 {
		t.Errorf("/keys/{my_own_name} should match /keys/{keyNumberOrActivationCode}: %+v", r.Endpoints)
	}
}

func TestCoverageFlagsUndocumentedEndpoints(t *testing.T) {
	t.Parallel()
	h := newHarness(t, "/keys", "/keys/{id}/billable-usage", "/secret/backdoor")
	h.repo(fixedTime)
	h.tree("assets/openapi/partner-v3-api.yml")
	h.srv.Contents("acme", "billing", "assets/openapi/partner-v3-api.yml", "main", kaSpec)

	res, findings, err := monitor.Coverage(context.Background(), monitor.CoverageOptions{
		Store: h.store, Source: h.src, Index: h.idx,
	})
	if err != nil {
		t.Fatal(err)
	}
	r := res[0]
	undoc := map[string]bool{}
	for _, e := range r.Undocumented() {
		undoc[e.Path] = true
	}
	if !undoc["/keys/{id}/billable-usage"] || !undoc["/secret/backdoor"] {
		t.Errorf("undocumented set = %v, want both billable-usage and backdoor", undoc)
	}
	if undoc["/keys"] {
		t.Error("/keys is declared and must not be flagged")
	}

	if len(findings) != 2 {
		t.Fatalf("got %d findings, want 2", len(findings))
	}
	for _, f := range findings {
		if f.Signal != monitor.SignalUndocumented {
			t.Errorf("Signal = %q, want %q", f.Signal, monitor.SignalUndocumented)
		}
		// This is a standing risk, not a regression: it is logged, never
		// escalated to breaking.
		if string(f.Severity) != "info" {
			t.Errorf("Severity = %q, want info", f.Severity)
		}
		if len(f.Endpoints) != 1 {
			t.Errorf("finding should cite exactly one endpoint: %+v", f.Endpoints)
		}
		if !strings.Contains(f.Detail, "partner-v3-api.yml") {
			t.Errorf("Detail should name the specifications consulted: %q", f.Detail)
		}
	}
}

// Any spec counts as documentation, and the finding records which one matched.
func TestCoverageAcceptsAnySpecification(t *testing.T) {
	t.Parallel()
	const otherSpec = `
openapi: 3.0.0
info: {title: Portal 10, version: 1.0.0}
servers: [{url: "https://api.acme.com/api/portal/v1"}]
paths:
  /keys/{keyNumber}/upgrades:
    get:
      responses: {"200": {description: ok}}
`
	h := newHarness(t, "/keys/{id}/upgrades")
	h.repo(fixedTime)
	h.tree("assets/openapi/partner-v3-api.yml", "assets/openapi/portal-v1-api.yml")
	h.srv.Contents("acme", "billing", "assets/openapi/partner-v3-api.yml", "main", kaSpec)
	h.srv.Contents("acme", "billing", "assets/openapi/portal-v1-api.yml", "main", otherSpec)

	r := h.coverage(t)[0]
	if len(r.Specs) != 2 {
		t.Fatalf("Specs = %v, want both", r.Specs)
	}
	if len(r.Undocumented()) != 0 {
		t.Fatalf("endpoint should be covered by the portal spec: %+v", r.Endpoints)
	}
	if got := r.Endpoints[0].Spec; got != "assets/openapi/portal-v1-api.yml" {
		t.Errorf("Spec = %q, want the portal specification that actually declares it", got)
	}
}

// With no specification at all, reporting every endpoint as undocumented would
// be noise rather than news.
func TestCoverageWithNoSpecificationReportsNothingActionable(t *testing.T) {
	t.Parallel()
	h := newHarness(t, "/keys")
	h.repo(fixedTime)
	h.tree("README.md", "src/main.java")

	res, findings, err := monitor.Coverage(context.Background(), monitor.CoverageOptions{
		Store: h.store, Source: h.src, Index: h.idx,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Errorf("got %d findings, want none when there is nothing to be documented by", len(findings))
	}
	if len(res) != 1 || res[0].Note == "" {
		t.Errorf("the result should explain why coverage is unknown: %+v", res)
	}
}

// Coverage is state-based: it must work when nothing has changed upstream, which
// is exactly when the change-driven path short-circuits.
func TestCoverageRunsWhenTheUpstreamHasNotMoved(t *testing.T) {
	t.Parallel()
	h := newHarness(t, "/secret/backdoor")
	h.repo(fixedTime)
	h.tree("assets/openapi/partner-v3-api.yml")
	h.srv.Contents("acme", "billing", "assets/openapi/partner-v3-api.yml", "main", kaSpec)
	h.srv.JSON("/repos/acme/billing/releases", []map[string]any{})
	h.srv.JSON("/repos/acme/billing/commits", []map[string]any{ghtest.CommitJSON("base-sha", "initial")})

	// Establish state, then re-run the change-driven check: it skips.
	h.baseline()
	if res := h.run(); res.Skipped == 0 {
		t.Fatalf("expected the unchanged upstream to be skipped, got %+v", res)
	}
	// Coverage still reports.
	_, findings, err := monitor.Coverage(context.Background(), monitor.CoverageOptions{
		Store: h.store, Source: h.src, Index: h.idx,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1 even though the upstream did not move", len(findings))
	}
}

// A symbolic host must resolve to the linked hostname through host_mappings.
// Without this the user would have to link an internal variable name.
func TestCoverageResolvesSymbolicHostsViaMappings(t *testing.T) {
	t.Parallel()
	h := newHarnessWithHost(t, "${sym:self.base}", "/keys")
	h.repo(fixedTime)
	h.tree("assets/openapi/partner-v3-api.yml")
	h.srv.Contents("acme", "billing", "assets/openapi/partner-v3-api.yml", "main", kaSpec)

	// Without a mapping the upstream sees no endpoints at all.
	res, _, err := monitor.Coverage(context.Background(), monitor.CoverageOptions{
		Store: h.store, Source: h.src, Index: h.idx,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(res) != 0 {
		t.Fatalf("without a mapping the symbolic host should match nothing, got %+v", res)
	}

	// With one, it behaves exactly as a literal host would.
	cfg := &config.File{HostMappings: map[string][]string{"${sym:self.base}": {"api.acme.com"}}}
	res, _, err = monitor.Coverage(context.Background(), monitor.CoverageOptions{
		Store: h.store, Source: h.src, Index: h.idx, Config: cfg,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(res) != 1 {
		t.Fatalf("got %d results, want 1", len(res))
	}
	if len(res[0].Undocumented()) != 0 {
		t.Errorf("/keys is declared and should be documented: %+v", res[0].Endpoints)
	}
}
