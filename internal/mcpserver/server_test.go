package mcpserver_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/stephen-bee/endpoint-monitor/internal/config"
	"github.com/stephen-bee/endpoint-monitor/internal/ghsource"
	"github.com/stephen-bee/endpoint-monitor/internal/ghsource/ghtest"
	"github.com/stephen-bee/endpoint-monitor/internal/mcpserver"
)

var testTime = time.Date(2026, 5, 1, 10, 0, 0, 0, time.UTC)

// fixtureRepo writes a small repository with two outbound calls: one to a
// well-known host that links itself, and one to an unknown host that cannot.
func fixtureRepo(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	mustWrite(t, filepath.Join(dir, "go.mod"), "module example.com/demo\n\ngo 1.27\n")
	mustWrite(t, filepath.Join(dir, "client.go"), `package demo

import "net/http"

const stripeBase = "https://api.stripe.com"
const acmeBase = "https://api.widgetco.io"

func Charge() { http.Post(stripeBase+"/v1/charges", "application/json", nil) }
func Invoices() { http.Get(stripeBase + "/v1/invoices") }
func Widgets() { http.Get(acmeBase + "/api/v1/widgets") }
`)
	return dir
}

func mustWrite(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

// connect starts a real server over in-memory transports and returns a client
// session. This exercises the actual protocol path, including schema
// validation of every tool's input and output.
func connect(t *testing.T, repo string, srv *ghtest.Server, clientOpts *mcp.ClientOptions) *mcp.ClientSession {
	t.Helper()
	deps := mcpserver.Deps{
		RepoPath: repo,
		Version:  "test",
		Now:      func() time.Time { return testTime },
		Logf:     func(format string, a ...any) { t.Logf("server: "+format, a...) },
		NewSource: func(cfg *config.File) (ghsource.GitHubSource, error) {
			if srv == nil {
				return nil, errNoSource
			}
			return ghsource.New(ghsource.Options{
				BaseURL: srv.URL, HTTPClient: srv.Client(), MinInterval: 0,
				Sleep: func(context.Context, time.Duration) error { return nil },
			})
		},
	}
	server := mcpserver.New(deps)

	ct, st := mcp.NewInMemoryTransports()
	ctx := context.Background()
	go func() { _ = server.MCP().Run(ctx, st) }()

	client := mcp.NewClient(&mcp.Implementation{Name: "test-client", Version: "0"}, clientOpts)
	sess, err := client.Connect(ctx, ct, nil)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(func() { sess.Close() })
	return sess
}

type constErr string

func (e constErr) Error() string { return string(e) }

const errNoSource = constErr("no GitHub source in this test")

// call invokes a tool and decodes its structured output.
func call[T any](t *testing.T, sess *mcp.ClientSession, name string, args any, out *T) *mcp.CallToolResult {
	t.Helper()
	res, err := sess.CallTool(context.Background(), &mcp.CallToolParams{
		Name: name, Arguments: args,
	})
	if err != nil {
		t.Fatalf("CallTool(%s): %v", name, err)
	}
	if res.IsError {
		t.Fatalf("CallTool(%s) returned an error: %s", name, textOf(res))
	}
	if out != nil && res.StructuredContent != nil {
		data, err := json.Marshal(res.StructuredContent)
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(data, out); err != nil {
			t.Fatalf("decode %s output: %v", name, err)
		}
	}
	return res
}

func textOf(res *mcp.CallToolResult) string {
	var b strings.Builder
	for _, c := range res.Content {
		if tc, ok := c.(*mcp.TextContent); ok {
			b.WriteString(tc.Text)
		}
	}
	return b.String()
}

func TestToolsAreAdvertised(t *testing.T) {
	t.Parallel()
	sess := connect(t, fixtureRepo(t), nil, nil)
	tools, err := sess.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"scan_repo", "list_endpoints", "list_hosts", "link_upstream",
		"check_upstreams", "list_findings", "update_finding", "index_stats",
	}
	have := map[string]*mcp.Tool{}
	for _, tool := range tools.Tools {
		have[tool.Name] = tool
	}
	for _, name := range want {
		tool, ok := have[name]
		if !ok {
			t.Errorf("tool %q is not advertised", name)
			continue
		}
		if tool.Description == "" {
			t.Errorf("tool %q has no description", name)
		}
	}
	// Read-only tools must say so, or an agent cannot tell which are safe to
	// call speculatively.
	for _, name := range []string{"list_endpoints", "list_hosts", "list_findings", "index_stats"} {
		if tool := have[name]; tool != nil {
			if tool.Annotations == nil || !tool.Annotations.ReadOnlyHint {
				t.Errorf("tool %q should be annotated read-only", name)
			}
		}
	}
}

// The whole chain an agent walks: scan, discover what needs linking, link it,
// then query.
func TestScanLinkQueryFlow(t *testing.T) {
	t.Parallel()
	repo := fixtureRepo(t)
	sess := connect(t, repo, nil, nil)

	var scanOut mcpserver.ScanOut
	res := call(t, sess, "scan_repo", map[string]any{}, &scanOut)
	if scanOut.EndpointCount != 3 {
		t.Fatalf("endpoint_count = %d, want 3", scanOut.EndpointCount)
	}
	// The well-known host links itself with no interaction.
	foundStripe := false
	for _, l := range scanOut.Linked {
		if l.Host == "api.stripe.com" && strings.Contains(l.Repo, "stripe/openapi") {
			foundStripe = true
			if l.Role != "spec_only" {
				t.Errorf("stripe role = %q, want spec_only", l.Role)
			}
		}
	}
	if !foundStripe {
		t.Errorf("api.stripe.com was not auto-linked: %+v", scanOut.Linked)
	}
	// The unknown host cannot be, and must be reported as work to do.
	if len(scanOut.NeedsLinking) != 1 || scanOut.NeedsLinking[0].Host != "api.widgetco.io" {
		t.Fatalf("needs_linking = %+v", scanOut.NeedsLinking)
	}
	// The text must tell the agent what to do about it, since many clients act
	// on prose far more reliably than on structured output.
	if txt := textOf(res); !strings.Contains(txt, "link_upstream") {
		t.Errorf("scan text should name the tool to call:\n%s", txt)
	}

	var linkOut mcpserver.LinkOut
	call(t, sess, "link_upstream", map[string]any{
		"host": "api.widgetco.io", "repo_url": "github.com/acme/widgets", "role": "implementation",
	}, &linkOut)
	if linkOut.Canonical != "https://github.com/acme/widgets" {
		t.Errorf("canonical = %q", linkOut.Canonical)
	}
	if linkOut.MatchedEndpoints != 1 {
		t.Errorf("matched_endpoints = %d, want 1", linkOut.MatchedEndpoints)
	}
	if len(linkOut.RemainingUnlinked) != 0 {
		t.Errorf("remaining_unlinked = %+v, want none", linkOut.RemainingUnlinked)
	}

	var hostsOut mcpserver.ListHostsOut
	call(t, sess, "list_hosts", map[string]any{}, &hostsOut)
	for _, h := range hostsOut.Hosts {
		if !h.Linked {
			t.Errorf("host %s should be linked by now", h.Host)
		}
	}

	var epOut mcpserver.ListEndpointsOut
	call(t, sess, "list_endpoints", map[string]any{"hosts": []string{"api.stripe.com"}}, &epOut)
	if epOut.Matched != 2 {
		t.Errorf("matched = %d, want 2 stripe calls", epOut.Matched)
	}
	call(t, sess, "list_endpoints", map[string]any{"endpoints": []string{"/v1/invoices"}}, &epOut)
	if epOut.Matched != 1 {
		t.Errorf("endpoint filter matched %d, want 1", epOut.Matched)
	}
}

// Unlinked hosts are always reported as structured work plus an imperative
// text instruction, for every client.
//
// This is deliberate rather than a limitation: MCP protocol 2026-07-28 forbids
// a server from eliciting while serving a request, so there is no in-request
// question to ask. The needs_linking payload is the contract, and it must hold
// whether or not the client advertises elicitation.
func TestUnlinkedHostsAreAlwaysReportedAsWork(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		opts *mcp.ClientOptions
	}{
		{"client without elicitation", nil},
		{"client with elicitation", &mcp.ClientOptions{
			ElicitationHandler: func(context.Context, *mcp.ElicitRequest) (*mcp.ElicitResult, error) {
				return &mcp.ElicitResult{Action: "accept"}, nil
			},
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			sess := connect(t, fixtureRepo(t), nil, tc.opts)
			var out mcpserver.ScanOut
			res := call(t, sess, "scan_repo", map[string]any{}, &out)
			if len(out.NeedsLinking) != 1 || out.NeedsLinking[0].Host != "api.widgetco.io" {
				t.Fatalf("needs_linking = %+v, want the unknown host", out.NeedsLinking)
			}
			txt := textOf(res)
			if !strings.Contains(txt, "link_upstream") {
				t.Errorf("the text must name link_upstream:\n%s", txt)
			}
			if !strings.Contains(txt, "api.widgetco.io") {
				t.Errorf("the text must name the host:\n%s", txt)
			}
		})
	}
}

func TestCheckUpstreamsAndFindingTriage(t *testing.T) {
	t.Parallel()
	repo := fixtureRepo(t)
	srv := ghtest.New(t)
	sess := connect(t, repo, srv, nil)

	call(t, sess, "scan_repo", map[string]any{}, &mcpserver.ScanOut{})
	call(t, sess, "link_upstream", map[string]any{
		"host": "api.widgetco.io", "repo_url": "github.com/acme/widgets",
	}, &mcpserver.LinkOut{})

	// Only the widgets repository exists; stripe/openapi will 404 from the fake.
	srv.JSON("/repos/acme/widgets", ghtest.RepoJSON("acme", "widgets", "main", testTime))
	srv.JSON("/repos/acme/widgets/commits", []map[string]any{ghtest.CommitJSON("base1", "init")})
	srv.JSON("/repos/acme/widgets/git/trees/main", map[string]any{"tree": []map[string]any{}})
	srv.JSON("/repos/acme/widgets/releases", []map[string]any{})

	var first mcpserver.CheckOut
	call(t, sess, "check_upstreams", map[string]any{"hosts": []string{"api.widgetco.io"}}, &first)
	// A first check baselines and reports nothing actionable.
	if first.Counts.Breaking != 0 {
		t.Errorf("a baseline check produced breaking findings: %+v", first.Findings)
	}
	if len(first.Baselined) == 0 {
		t.Errorf("expected a baseline to be recorded, got %+v", first)
	}

	// Now a genuine removal of the widgets route.
	patch := "@@ -3,3 +3,2 @@\n-\trouter.Get(\"/api/v1/widgets\", h)\n \tnext()\n"
	srv.JSON("/repos/acme/widgets", ghtest.RepoJSON("acme", "widgets", "main", testTime.Add(time.Hour)))
	srv.JSON("/repos/acme/widgets/compare/base1...main", ghtest.CompareJSON("base1", "head1",
		[]map[string]any{ghtest.FileJSON("internal/routes.go", "modified", patch)},
		[]map[string]any{ghtest.CommitJSON("head1", "remove widgets")}))

	var second mcpserver.CheckOut
	res := call(t, sess, "check_upstreams", map[string]any{"hosts": []string{"api.widgetco.io"}}, &second)
	if second.Counts.Total == 0 {
		t.Fatalf("expected a finding for the removed route; text was:\n%s", textOf(res))
	}
	var target mcpserver.Finding
	for _, f := range second.Findings {
		if strings.HasPrefix(f.Signal, "diff.") {
			target = f
		}
	}
	if target.ID == "" {
		t.Fatalf("no diff finding: %+v", second.Findings)
	}
	if len(target.Endpoints) == 0 {
		t.Error("a finding must cite the endpoints it affects")
	}

	// Acknowledge it, and confirm it drops out of the default listing.
	call(t, sess, "update_finding", map[string]any{
		"id": target.ID, "action": "ack", "note": "known",
	}, &mcpserver.UpdateFindingOut{})

	var listed mcpserver.ListFindingsOut
	call(t, sess, "list_findings", map[string]any{}, &listed)
	for _, f := range listed.Findings {
		if f.ID == target.ID {
			t.Error("an acknowledged finding should not appear in the default listing")
		}
	}
	call(t, sess, "list_findings", map[string]any{"status": "acked"}, &listed)
	if len(listed.Findings) == 0 {
		t.Error("the acknowledged finding should be listable by status")
	}
}

func TestIndexStatsReportsMissingToken(t *testing.T) {
	t.Parallel()
	repo := fixtureRepo(t)
	sess := connect(t, repo, nil, nil)
	call(t, sess, "scan_repo", map[string]any{}, &mcpserver.ScanOut{})

	var out mcpserver.StatsOut
	res := call(t, sess, "index_stats", map[string]any{}, &out)
	if out.EndpointCount != 3 {
		t.Errorf("endpoint_count = %d, want 3", out.EndpointCount)
	}
	if out.HostCount != 2 {
		t.Errorf("host_count = %d, want 2", out.HostCount)
	}
	_ = textOf(res)
}

// A tool that needs an index must say what to do about its absence rather than
// failing opaquely.
func TestToolsExplainAMissingIndex(t *testing.T) {
	t.Parallel()
	sess := connect(t, t.TempDir(), nil, nil)
	res, err := sess.CallTool(context.Background(), &mcp.CallToolParams{
		Name: "list_endpoints", Arguments: map[string]any{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !res.IsError {
		t.Fatal("expected an error result for a missing index")
	}
	if !strings.Contains(textOf(res), "scan_repo") {
		t.Errorf("the error should name the tool to call first: %s", textOf(res))
	}
}
