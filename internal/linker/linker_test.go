package linker

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stephen-bee/endpoint-monitor/internal/config"
	"github.com/stephen-bee/endpoint-monitor/internal/index"
	"github.com/stephen-bee/endpoint-monitor/internal/model"
	"github.com/stephen-bee/endpoint-monitor/internal/normalize"
	"github.com/stephen-bee/endpoint-monitor/internal/store"
)

func newLinker(t *testing.T, configBody string) (*Linker, string) {
	t.Helper()
	dir := t.TempDir()
	if configBody != "" {
		if err := os.WriteFile(filepath.Join(dir, ".api-integrity.yml"), []byte(configBody), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	cfg, err := config.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	st, err := store.Open(dir, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	return &Linker{Store: st, Config: cfg, Now: func() time.Time { return now }}, dir
}

func req(host string, n int) HostRequest {
	return HostRequest{
		Host: host, EndpointCount: n,
		Symbolic:        strings.HasPrefix(host, "${"),
		SampleEndpoints: []model.EndpointRef{{Method: "GET", Path: "/v1/x"}},
	}
}

// The curated table is what makes linking mostly invisible, so it must apply
// without being asked.
func TestAutoLinkAppliesWellKnownHosts(t *testing.T) {
	t.Parallel()
	l, _ := newLinker(t, "")
	rep, err := l.AutoLink([]HostRequest{req("api.stripe.com", 3), req("api.mystery.example", 1)})
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Linked) != 1 || rep.Linked[0].Repo.Slug() != "stripe/openapi" {
		t.Fatalf("linked = %+v, want stripe/openapi", rep.Linked)
	}
	// A third-party API published as a spec must be linked as spec_only, or the
	// checker would run route analysis against a repository with no routes.
	if rep.Linked[0].Role != model.RoleSpecOnly {
		t.Errorf("role = %q, want spec_only", rep.Linked[0].Role)
	}
	if len(rep.NeedsLink) != 1 || rep.NeedsLink[0].Host != "api.mystery.example" {
		t.Errorf("needs_linking = %+v", rep.NeedsLink)
	}
}

func TestConfigUpstreamsAreImported(t *testing.T) {
	t.Parallel()
	l, _ := newLinker(t, `
upstreams:
  api.acme.com:
    - repo: github.com/acme/monorepo//services/billing
      path_prefix: /billing/
`)
	rep, err := l.AutoLink([]HostRequest{req("api.acme.com", 5)})
	if err != nil {
		t.Fatal(err)
	}
	if rep.AlreadyLinked != 1 || len(rep.NeedsLink) != 0 {
		t.Fatalf("config link not applied: %+v", rep)
	}
	st, _ := l.Store.Read()
	got := st.UpstreamsForEndpoint("api.acme.com", "/billing/charge")
	if len(got) != 1 || got[0].Repo.Subpath != "services/billing" {
		t.Errorf("upstream = %+v", got)
	}
}

// Deleting an entry from the config file must actually remove the link;
// otherwise config becomes append-only and impossible to correct.
func TestConfigLinksAreReplacedNotAccumulated(t *testing.T) {
	t.Parallel()
	l, dir := newLinker(t, "upstreams:\n  api.acme.com: github.com/acme/one\n")
	if err := l.SyncConfig(); err != nil {
		t.Fatal(err)
	}
	// A link added at runtime must survive a config reload.
	if _, err := l.Link("api.other.com", "github.com/other/repo", LinkOptions{Source: model.SourceCLI}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".api-integrity.yml"),
		[]byte("upstreams:\n  api.acme.com: github.com/acme/two\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	l.Config = cfg
	if err := l.SyncConfig(); err != nil {
		t.Fatal(err)
	}
	st, _ := l.Store.Read()
	var acme, other []string
	for _, u := range st.Upstreams {
		switch u.Host {
		case "api.acme.com":
			acme = append(acme, u.Repo.Name)
		case "api.other.com":
			other = append(other, u.Repo.Name)
		}
	}
	if len(acme) != 1 || acme[0] != "two" {
		t.Errorf("config-sourced links = %v, want exactly [two]", acme)
	}
	if len(other) != 1 {
		t.Errorf("a runtime link was lost on config reload: %v", other)
	}
}

func TestUnmonitoredHostsAreNotReported(t *testing.T) {
	t.Parallel()
	l, _ := newLinker(t, "unmonitored:\n  - host: api.internal.corp\n    reason: internal\n")
	rep, err := l.AutoLink([]HostRequest{req("api.internal.corp", 2)})
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.NeedsLink) != 0 {
		t.Errorf("an unmonitored host was still reported: %+v", rep.NeedsLink)
	}
	if len(rep.Unmonitored) != 1 {
		t.Errorf("unmonitored = %+v", rep.Unmonitored)
	}
}

// Prompting must never happen without a terminal. In MCP mode stdin is the
// JSON-RPC transport, so reading it would corrupt the session; in CI it would
// hang the build.
func TestPromptIsANoOpWhenNotInteractive(t *testing.T) {
	t.Parallel()
	l, _ := newLinker(t, "")
	needs := []NeedsLink{{Host: "api.x.com", EndpointCount: 1}}
	got, err := l.Prompt(needs, PromptOptions{Interactive: false, In: strings.NewReader("github.com/o/r\n")})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("want the host returned unanswered, got %+v", got)
	}
	st, _ := l.Store.Read()
	if len(st.Upstreams) != 0 {
		t.Errorf("nothing should have been linked: %+v", st.Upstreams)
	}
}

func TestPromptLinksSkipsAndRefuses(t *testing.T) {
	t.Parallel()
	l, _ := newLinker(t, "")
	needs := []NeedsLink{
		{Host: "api.one.com", EndpointCount: 1},
		{Host: "api.two.com", EndpointCount: 1},
		{Host: "api.three.com", EndpointCount: 1},
	}
	// Answer: a repository, then skip, then never (with a reason).
	input := "github.com/acme/one\ns\nn\ninternal\n"
	var out strings.Builder
	remaining, err := l.Prompt(needs, PromptOptions{
		Interactive: true, In: strings.NewReader(input), Out: &out,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(remaining) != 0 {
		t.Errorf("remaining = %+v, want none", remaining)
	}
	st, _ := l.Store.Read()
	if len(st.Upstreams) != 1 || st.Upstreams[0].Host != "api.one.com" {
		t.Errorf("upstreams = %+v", st.Upstreams)
	}
	byHost := map[string]model.Decision{}
	for _, d := range st.Decisions {
		byHost[d.Host] = d
	}
	if d, ok := byHost["api.two.com"]; !ok || d.Kind != model.DecisionLater {
		t.Errorf("skip should defer: %+v", byHost["api.two.com"])
	}
	if d, ok := byHost["api.three.com"]; !ok || d.Kind != model.DecisionUnmonitored || d.Reason != "internal" {
		t.Errorf("never should record an unmonitored decision with a reason: %+v", byHost["api.three.com"])
	}
}

// Running out of input must end the loop, not spin on EOF.
func TestPromptStopsAtEndOfInput(t *testing.T) {
	t.Parallel()
	l, _ := newLinker(t, "")
	needs := []NeedsLink{{Host: "a.example.com"}, {Host: "b.example.com"}}
	var out strings.Builder
	remaining, err := l.Prompt(needs, PromptOptions{Interactive: true, In: strings.NewReader(""), Out: &out})
	if err != nil {
		t.Fatal(err)
	}
	if len(remaining) != 2 {
		t.Errorf("remaining = %d, want both hosts unanswered", len(remaining))
	}
}

func TestHostRequestsFromIndexOrdersByCallCount(t *testing.T) {
	t.Parallel()
	idx := &index.Index{Calls: []index.Call{
		{ID: "c1", Host: "quiet.example.com", Method: "GET", Path: "/a", Score: 90,
			Location: index.Location{File: "a.go", Line: 1}, Lifecycle: index.Lifecycle{Status: index.StatusActive}},
		{ID: "c2", Host: "busy.example.com", Method: "GET", Path: "/b", Score: 50,
			Location: index.Location{File: "b.go", Line: 2}, Lifecycle: index.Lifecycle{Status: index.StatusActive}},
		{ID: "c3", Host: "busy.example.com", Method: "POST", Path: "/c", Score: 95,
			Location: index.Location{File: "c.go", Line: 3}, Lifecycle: index.Lifecycle{Status: index.StatusActive}},
		{ID: "c4", Host: "gone.example.com", Method: "GET", Path: "/d",
			Location: index.Location{File: "d.go", Line: 4}, Lifecycle: index.Lifecycle{Status: index.StatusRemoved}},
	}}
	got := HostRequestsFromIndex(idx, "")
	if len(got) != 2 {
		t.Fatalf("want 2 hosts (removed calls excluded), got %d: %+v", len(got), got)
	}
	if got[0].Host != "busy.example.com" || got[0].EndpointCount != 2 {
		t.Errorf("first = %+v, want the busiest host first", got[0])
	}
	// Samples are ordered by confidence so the strongest evidence is shown.
	if got[0].SampleEndpoints[0].Path != "/c" {
		t.Errorf("samples = %+v, want the highest-scoring call first", got[0].SampleEndpoints)
	}
}

// A symbolic host is flagged so the report can suggest a host_mappings entry
// rather than a repository, which is almost always the right fix.
func TestSymbolicHostsAreFlagged(t *testing.T) {
	t.Parallel()
	idx := &index.Index{Calls: []index.Call{{
		ID: "c1", Host: "${env:BILLING_URL}", HostKind: normalize.HostEnv, Method: "GET", Path: "/charge",
		Location: index.Location{File: "a.go", Line: 1}, Lifecycle: index.Lifecycle{Status: index.StatusActive},
	}}}
	got := HostRequestsFromIndex(idx, "")
	if len(got) != 1 || !got[0].Symbolic {
		t.Fatalf("symbolic host not flagged: %+v", got)
	}
	l, _ := newLinker(t, "")
	rep, err := l.AutoLink(got)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.NeedsLink) != 1 || !rep.NeedsLink[0].Symbolic {
		t.Errorf("needs_linking = %+v", rep.NeedsLink)
	}
	if rep.NeedsLink[0].SuggestedRepo != "" {
		t.Errorf("a symbolic host should get no repository suggestion, got %q", rep.NeedsLink[0].SuggestedRepo)
	}
}
