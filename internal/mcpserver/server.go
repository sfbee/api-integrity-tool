// Package mcpserver exposes the tool over the Model Context Protocol, so an
// agent can scan a repository, link its API hosts and check them for breaking
// changes without a human driving the CLI.
//
// One rule dominates the design of this package: stdout belongs to JSON-RPC.
// A stray fmt.Println anywhere reachable from here corrupts the protocol
// stream and the session dies with an unhelpful parse error, so all diagnostics
// go to stderr and an integration test asserts stdout purity.
package mcpserver

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/stephen-bee/endpoint-monitor/internal/config"
	"github.com/stephen-bee/endpoint-monitor/internal/detect"
	"github.com/stephen-bee/endpoint-monitor/internal/ghsource"
	"github.com/stephen-bee/endpoint-monitor/internal/index"
	"github.com/stephen-bee/endpoint-monitor/internal/linker"
	"github.com/stephen-bee/endpoint-monitor/internal/model"
	"github.com/stephen-bee/endpoint-monitor/internal/monitor"
	"github.com/stephen-bee/endpoint-monitor/internal/query"
	"github.com/stephen-bee/endpoint-monitor/internal/scan"
	"github.com/stephen-bee/endpoint-monitor/internal/store"
)

// Why there is no elicitation here: on MCP protocol version 2026-07-28 a server
// may not send elicitation/create while it is serving a request. The SDK
// rejects the attempt outright, pointing at the multi-round-trip InputRequests
// mechanism (SEP-2322) as the sanctioned replacement. Rather than carry a code
// path that only works against older protocol versions, unlinked hosts are
// always returned as a structured needs_linking payload plus an imperative text
// instruction to call link_upstream. That was designed as the fallback and is
// the path real clients take anyway; InputRequests can be added later without
// changing this contract.
//
// Deps are the collaborators a server needs. Everything is injectable so the
// integration tests can drive a real server against a fake GitHub.
type Deps struct {
	// RepoPath is the repository the tools operate on by default.
	RepoPath string
	// NewSource builds the GitHub client. Injected so tests never reach the
	// network.
	NewSource func(cfg *config.File) (ghsource.GitHubSource, error)
	Now       func() time.Time
	// Logf receives diagnostics. It must never write to stdout.
	Logf func(format string, args ...any)
	// Version is reported to the client.
	Version string
}

func (d Deps) now() time.Time {
	if d.Now != nil {
		return d.Now()
	}
	return time.Now()
}

func (d Deps) logf(format string, args ...any) {
	if d.Logf != nil {
		d.Logf(format, args...)
	}
}

// Server wraps an MCP server with this tool's state.
type Server struct {
	deps Deps
	mcp  *mcp.Server
}

// New builds the MCP server and registers every tool.
func New(deps Deps) *Server {
	if deps.Version == "" {
		deps.Version = "dev"
	}
	impl := &mcp.Implementation{
		Name:    "api-integrity-tool",
		Version: deps.Version,
		Title:   "API integrity",
	}
	s := &Server{deps: deps, mcp: mcp.NewServer(impl, &mcp.ServerOptions{
		Instructions: "Indexes the outbound API calls a repository makes, links each API host " +
			"to the upstream repository behind it, and reports upstream changes that would break " +
			"those calls. Start with scan_repo, satisfy any needs_linking entries with " +
			"link_upstream, then run check_upstreams.",
	})}
	s.register()
	return s
}

// MCP exposes the underlying server, for tests that need to connect a transport.
func (s *Server) MCP() *mcp.Server { return s.mcp }

// Run serves over stdio until the client disconnects.
func (s *Server) Run(ctx context.Context) error {
	return s.mcp.Run(ctx, &mcp.StdioTransport{})
}

// readOnly marks a tool that cannot change anything.
func readOnly(title string) *mcp.ToolAnnotations {
	return &mcp.ToolAnnotations{Title: title, ReadOnlyHint: true}
}

// mutating marks a tool that changes stored state.
func mutating(title string, idempotent bool) *mcp.ToolAnnotations {
	return &mcp.ToolAnnotations{Title: title, IdempotentHint: idempotent}
}

func (s *Server) register() {
	mcp.AddTool(s.mcp, &mcp.Tool{
		Name:        "scan_repo",
		Description: "Scan a repository and index every outbound API call it makes. Returns the hosts found and, for any host with no upstream repository linked, a needs_linking entry to satisfy with link_upstream.",
		Annotations: mutating("Scan repository", true),
	}, s.scanRepo)

	mcp.AddTool(s.mcp, &mcp.Tool{
		Name:        "list_endpoints",
		Description: "Query the indexed API calls, filtered by host, endpoint path, HTTP method, language or confidence.",
		Annotations: readOnly("List endpoints"),
	}, s.listEndpoints)

	mcp.AddTool(s.mcp, &mcp.Tool{
		Name:        "list_hosts",
		Description: "List the API hosts this repository calls, with call counts and whether each is linked to an upstream repository.",
		Annotations: readOnly("List hosts"),
	}, s.listHosts)

	mcp.AddTool(s.mcp, &mcp.Tool{
		Name:        "link_upstream",
		Description: "Link an API host to the repository that implements or specifies it, or record that the host is deliberately not monitored. Use role spec_only when the repository holds only an OpenAPI description, which is the usual case for a third-party API.",
		Annotations: mutating("Link upstream repository", true),
	}, s.linkUpstream)

	mcp.AddTool(s.mcp, &mcp.Tool{
		Name:        "check_upstreams",
		Description: "Check the linked upstream repositories for changes that would break this repository's API calls. The first check of an upstream records a baseline and reports nothing.",
		Annotations: mutating("Check upstreams", false),
	}, s.checkUpstreams)

	mcp.AddTool(s.mcp, &mcp.Tool{
		Name:        "list_findings",
		Description: "List findings from previous checks, most severe first.",
		Annotations: readOnly("List findings"),
	}, s.listFindings)

	mcp.AddTool(s.mcp, &mcp.Tool{
		Name:        "update_finding",
		Description: "Acknowledge, mute, resolve or reopen a finding. An acknowledged finding resurfaces only if its severity increases.",
		Annotations: mutating("Update finding", true),
	}, s.updateFinding)

	mcp.AddTool(s.mcp, &mcp.Tool{
		Name:        "index_stats",
		Description: "Summarise the index, upstream links and findings, plus the GitHub rate-limit budget.",
		Annotations: readOnly("Index stats"),
	}, s.indexStats)
}

// ---------- scan_repo ----------

// ScanIn is the input to scan_repo.
type ScanIn struct {
	Path         string   `json:"path,omitempty" jsonschema:"repository to scan; defaults to the server's repository"`
	Languages    []string `json:"languages,omitempty" jsonschema:"restrict to these languages, e.g. go, python, typescript; empty means all"`
	IncludeTests bool     `json:"include_tests,omitempty" jsonschema:"also index calls made from test files"`
	AutoLink     *bool    `json:"auto_link,omitempty" jsonschema:"apply the built-in well-known host mappings (default true)"`
	Write        *bool    `json:"write,omitempty" jsonschema:"write the index to .api-integrity/index.json (default true)"`
}

// LinkedHost describes a host with an upstream repository.
type LinkedHost struct {
	Host string `json:"host"`
	Repo string `json:"repo"`
	Role string `json:"role"`
}

// ScanOut is the result of scan_repo.
type ScanOut struct {
	Commit        string             `json:"commit,omitempty"`
	EndpointCount int                `json:"endpoint_count"`
	HostCount     int                `json:"host_count"`
	New           int                `json:"new_endpoints"`
	Removed       int                `json:"removed_endpoints"`
	Rejected      map[string]int     `json:"rejected_call_sites,omitempty" jsonschema:"call sites deliberately not indexed, by reason"`
	Hosts         []HostSummary      `json:"hosts,omitempty"`
	Linked        []LinkedHost       `json:"linked_hosts,omitempty"`
	NeedsLinking  []linker.NeedsLink `json:"needs_linking,omitempty" jsonschema:"hosts with no upstream repository; call link_upstream for each"`
	Unmonitored   []string           `json:"unmonitored,omitempty"`
	DurationMS    int64              `json:"duration_ms"`
	Warnings      []string           `json:"warnings,omitempty"`
}

// HostSummary is a per-host roll-up.
type HostSummary struct {
	Host     string `json:"host"`
	Kind     string `json:"kind"`
	Calls    int    `json:"calls"`
	Paths    int    `json:"paths"`
	Linked   bool   `json:"linked"`
	Repo     string `json:"repo,omitempty"`
	Symbolic bool   `json:"symbolic,omitempty"`
}

func (s *Server) scanRepo(ctx context.Context, req *mcp.CallToolRequest, in ScanIn) (*mcp.CallToolResult, ScanOut, error) {
	root := in.Path
	if root == "" {
		root = s.deps.RepoPath
	}
	cfg, err := config.Load(root)
	if err != nil {
		return nil, ScanOut{}, err
	}
	opts := scan.Options{
		RepoPath:  root,
		Version:   s.deps.Version,
		KeepDrops: true,
	}
	opts.Classify.IncludeTests = in.IncludeTests || cfg.Scan.IncludeTests
	for _, l := range in.Languages {
		opts.Languages = append(opts.Languages, detect.Language(l))
	}
	res, err := scan.Run(ctx, opts)
	if err != nil {
		return nil, ScanOut{}, err
	}
	if in.Write == nil || *in.Write {
		if err := index.Save(root, res.Index); err != nil {
			return nil, ScanOut{}, err
		}
	}

	st, err := store.Open(root, s.deps.Now)
	if err != nil {
		return nil, ScanOut{}, err
	}
	lk := &linker.Linker{Store: st, Config: cfg, Now: s.deps.Now}
	reqs := linker.HostRequestsFromIndex(res.Index, "")

	out := ScanOut{
		Commit:        res.Index.Scan.Commit,
		EndpointCount: len(res.Index.Calls),
		HostCount:     len(res.Index.Hosts),
		New:           res.Report.Added,
		Removed:       res.Report.Removed,
		Rejected:      res.Index.Stats.SitesDropped,
		DurationMS:    res.Index.Scan.DurationMS,
		Warnings:      res.Errors,
	}

	if in.AutoLink == nil || *in.AutoLink {
		rep, lerr := lk.AutoLink(reqs)
		if lerr != nil {
			return nil, out, lerr
		}
		for _, u := range rep.Linked {
			out.Linked = append(out.Linked, LinkedHost{Host: u.Host, Repo: u.Repo.Canonical(), Role: string(u.Role)})
		}
		out.Unmonitored = rep.Unmonitored
		out.NeedsLinking = rep.NeedsLink
	}

	out.Hosts = s.hostSummaries(res.Index, st)
	return &mcp.CallToolResult{Content: scanText(out)}, out, nil
}

// scanText renders the imperative summary. Many clients act on text far more
// reliably than on structured output, so the instruction to call link_upstream
// is stated in prose as well as in the schema.
func scanText(out ScanOut) []mcp.Content {
	var b strings.Builder
	fmt.Fprintf(&b, "Indexed %d outbound API call(s) across %d host(s).",
		out.EndpointCount, out.HostCount)
	if out.New > 0 || out.Removed > 0 {
		fmt.Fprintf(&b, " %d new, %d removed.", out.New, out.Removed)
	}
	if n := totalOf(out.Rejected); n > 0 {
		fmt.Fprintf(&b, " %d call site(s) deliberately not indexed (%s).", n, joinCounts(out.Rejected))
	}
	for _, l := range out.Linked {
		fmt.Fprintf(&b, "\nLinked %s to %s (%s).", l.Host, l.Repo, l.Role)
	}
	if len(out.NeedsLinking) > 0 {
		fmt.Fprintf(&b, "\n\n%d host(s) need an upstream repository before they can be monitored. "+
			"For each, call link_upstream{host, repo_url}, or "+
			"link_upstream{host, action:\"unmonitored\", reason:\"...\"} to stop being asked:",
			len(out.NeedsLinking))
		for _, n := range out.NeedsLinking {
			fmt.Fprintf(&b, "\n  - %s (%d call(s)", n.Host, n.EndpointCount)
			if n.SuggestedRepo != "" {
				fmt.Fprintf(&b, ", suggestion: %s", n.SuggestedRepo)
			}
			if n.Symbolic {
				b.WriteString(", symbolic host: probably wants a host_mappings entry rather than a repository")
			}
			b.WriteString(")")
		}
	} else if out.EndpointCount > 0 {
		b.WriteString("\nEvery host has an upstream repository. Run check_upstreams next.")
	}
	return []mcp.Content{&mcp.TextContent{Text: b.String()}}
}

func (s *Server) hostSummaries(idx *index.Index, st *store.Store) []HostSummary {
	state, err := st.Read()
	if err != nil {
		return nil
	}
	out := make([]HostSummary, 0, len(idx.Hosts))
	for _, h := range idx.Hosts {
		hs := HostSummary{
			Host: h.HostKey, Kind: string(h.HostKind),
			Calls: h.CallCount, Paths: h.PathCount,
			Symbolic: strings.HasPrefix(h.HostKey, "${") || h.HostKey == "self",
		}
		if ups := state.UpstreamsForHost(h.HostKey); len(ups) > 0 {
			hs.Linked = true
			hs.Repo = ups[0].Repo.Canonical()
		}
		out = append(out, hs)
	}
	return out
}

// ---------- list_endpoints ----------

// ListEndpointsIn filters the index.
type ListEndpointsIn struct {
	Path          string   `json:"path,omitempty" jsonschema:"repository to read; defaults to the server's repository"`
	Hosts         []string `json:"hosts,omitempty" jsonschema:"only these hosts; globs allowed"`
	Endpoints     []string `json:"endpoints,omitempty" jsonschema:"only these endpoint paths, e.g. /api/v1/user/add"`
	Methods       []string `json:"methods,omitempty" jsonschema:"only these HTTP methods"`
	Languages     []string `json:"languages,omitempty"`
	MinConfidence string   `json:"min_confidence,omitempty" jsonschema:"low, medium or high"`
	Limit         int      `json:"limit,omitempty" jsonschema:"maximum entries to return (default 200)"`
}

// Endpoint is one indexed call.
type Endpoint struct {
	ID         string `json:"id"`
	Host       string `json:"host"`
	Method     string `json:"method"`
	Path       string `json:"path"`
	Language   string `json:"language"`
	Client     string `json:"client,omitempty"`
	Confidence string `json:"confidence"`
	File       string `json:"file"`
	Line       int    `json:"line"`
	RawExpr    string `json:"raw_expr,omitempty"`
}

// ListEndpointsOut is the result of list_endpoints.
type ListEndpointsOut struct {
	Total     int        `json:"total_in_index"`
	Matched   int        `json:"matched"`
	Truncated bool       `json:"truncated,omitempty"`
	Endpoints []Endpoint `json:"endpoints"`
}

func (s *Server) listEndpoints(ctx context.Context, req *mcp.CallToolRequest, in ListEndpointsIn) (*mcp.CallToolResult, ListEndpointsOut, error) {
	idx, err := s.loadIndex(in.Path)
	if err != nil {
		return nil, ListEndpointsOut{}, err
	}
	// Reuse the CLI's filter semantics rather than growing a second, subtly
	// different implementation: OR within a dimension, AND across dimensions,
	// exclude always wins.
	sel, err := query.Compile(query.Filters{
		Hosts: in.Hosts, Endpoints: in.Endpoints, Methods: in.Methods,
		Languages: in.Languages, MinConfidence: index.Confidence(in.MinConfidence),
	})
	if err != nil {
		return nil, ListEndpointsOut{}, err
	}
	limit := in.Limit
	if limit <= 0 {
		limit = 200
	}
	out := ListEndpointsOut{Total: len(idx.Calls)}
	for _, c := range idx.Calls {
		if ok, _ := sel.Match(c); !ok {
			continue
		}
		out.Matched++
		if len(out.Endpoints) >= limit {
			out.Truncated = true
			continue
		}
		out.Endpoints = append(out.Endpoints, Endpoint{
			ID: c.ID, Host: c.Host, Method: c.Method, Path: c.Path,
			Language: string(c.Language), Client: c.Client,
			Confidence: string(c.Confidence),
			File:       c.Location.File, Line: c.Location.Line, RawExpr: c.RawExpr,
		})
	}
	text := fmt.Sprintf("%d of %d indexed call(s) matched.", out.Matched, out.Total)
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: text}}}, out, nil
}

// ---------- list_hosts ----------

// ListHostsIn selects hosts.
type ListHostsIn struct {
	Path         string `json:"path,omitempty"`
	OnlyUnlinked bool   `json:"only_unlinked,omitempty" jsonschema:"only hosts with no upstream repository linked"`
}

// ListHostsOut is the result of list_hosts.
type ListHostsOut struct {
	Hosts        []HostSummary      `json:"hosts"`
	NeedsLinking []linker.NeedsLink `json:"needs_linking,omitempty"`
}

func (s *Server) listHosts(ctx context.Context, req *mcp.CallToolRequest, in ListHostsIn) (*mcp.CallToolResult, ListHostsOut, error) {
	root := s.root(in.Path)
	idx, err := s.loadIndex(in.Path)
	if err != nil {
		return nil, ListHostsOut{}, err
	}
	st, err := store.Open(root, s.deps.Now)
	if err != nil {
		return nil, ListHostsOut{}, err
	}
	cfg, err := config.Load(root)
	if err != nil {
		return nil, ListHostsOut{}, err
	}
	lk := &linker.Linker{Store: st, Config: cfg, Now: s.deps.Now}
	rep, err := lk.AutoLink(linker.HostRequestsFromIndex(idx, ""))
	if err != nil {
		return nil, ListHostsOut{}, err
	}
	out := ListHostsOut{Hosts: s.hostSummaries(idx, st), NeedsLinking: rep.NeedsLink}
	if in.OnlyUnlinked {
		var keep []HostSummary
		for _, h := range out.Hosts {
			if !h.Linked {
				keep = append(keep, h)
			}
		}
		out.Hosts = keep
	}
	text := fmt.Sprintf("%d host(s); %d need an upstream repository.", len(out.Hosts), len(out.NeedsLinking))
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: text}}}, out, nil
}

// ---------- link_upstream ----------

// LinkIn is the input to link_upstream.
type LinkIn struct {
	Path       string `json:"path,omitempty"`
	Host       string `json:"host" jsonschema:"API host from the index, e.g. api.stripe.com"`
	Action     string `json:"action,omitempty" jsonschema:"link (default), unlink, unmonitored, or reset"`
	RepoURL    string `json:"repo_url,omitempty" jsonschema:"https://github.com/org/repo, git@github.com:org/repo.git, org/repo, or org/repo//services/api for a monorepo subpath"`
	PathPrefix string `json:"path_prefix,omitempty" jsonschema:"only endpoints whose path starts with this prefix belong to this repository"`
	Role       string `json:"role,omitempty" jsonschema:"implementation (default), spec_only for a repository holding only an OpenAPI description, or gateway"`
	Ref        string `json:"ref,omitempty" jsonschema:"branch or tag to watch; defaults to the repository default branch"`
	Reason     string `json:"reason,omitempty" jsonschema:"why unmonitored: closed_source, internal, third_party_no_repo, noise or other"`
	Note       string `json:"note,omitempty"`
}

// LinkOut is the result of link_upstream.
type LinkOut struct {
	Host              string             `json:"host"`
	Action            string             `json:"action_taken"`
	Canonical         string             `json:"canonical_url,omitempty"`
	Role              string             `json:"role,omitempty"`
	MatchedEndpoints  int                `json:"matched_endpoints"`
	RemainingUnlinked []linker.NeedsLink `json:"remaining_unlinked,omitempty"`
}

func (s *Server) linkUpstream(ctx context.Context, req *mcp.CallToolRequest, in LinkIn) (*mcp.CallToolResult, LinkOut, error) {
	root := s.root(in.Path)
	if strings.TrimSpace(in.Host) == "" {
		return nil, LinkOut{}, fmt.Errorf("host is required")
	}
	st, err := store.Open(root, s.deps.Now)
	if err != nil {
		return nil, LinkOut{}, err
	}
	cfg, err := config.Load(root)
	if err != nil {
		return nil, LinkOut{}, err
	}
	lk := &linker.Linker{Store: st, Config: cfg, Now: s.deps.Now}
	out := LinkOut{Host: in.Host, Action: in.Action}

	switch in.Action {
	case "", "link":
		out.Action = "link"
		u, lerr := lk.Link(in.Host, in.RepoURL, linker.LinkOptions{
			PathPrefix: in.PathPrefix, Role: model.Role(in.Role), Ref: in.Ref,
			Note: in.Note, Source: model.SourceMCP,
		})
		if lerr != nil {
			return nil, out, lerr
		}
		out.Canonical, out.Role = u.Repo.Canonical(), string(u.Role)
	case "unmonitored":
		if err := lk.Unmonitor(in.Host, in.Reason, model.SourceMCP); err != nil {
			return nil, out, err
		}
	case "unlink":
		if _, err := st.UnlinkHost(in.Host); err != nil {
			return nil, out, err
		}
	case "reset":
		if err := st.ClearDecision(in.Host); err != nil {
			return nil, out, err
		}
	default:
		return nil, out, fmt.Errorf("unknown action %q: want link, unlink, unmonitored or reset", in.Action)
	}

	if idx, ierr := s.loadIndex(in.Path); ierr == nil {
		for _, c := range idx.Calls {
			if c.Host == in.Host {
				out.MatchedEndpoints++
			}
		}
		rep, rerr := lk.AutoLink(linker.HostRequestsFromIndex(idx, ""))
		if rerr == nil {
			out.RemainingUnlinked = rep.NeedsLink
		}
	}

	text := fmt.Sprintf("%s: %s", in.Host, out.Action)
	if out.Canonical != "" {
		text = fmt.Sprintf("Linked %s to %s (%s), covering %d call(s).", in.Host, out.Canonical, out.Role, out.MatchedEndpoints)
	}
	if len(out.RemainingUnlinked) > 0 {
		text += fmt.Sprintf(" %d host(s) still need linking.", len(out.RemainingUnlinked))
	}
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: text}}}, out, nil
}

// ---------- check_upstreams ----------

// CheckIn is the input to check_upstreams.
type CheckIn struct {
	Path        string   `json:"path,omitempty"`
	Hosts       []string `json:"hosts,omitempty" jsonschema:"limit to these hosts; empty means every linked host"`
	Repos       []string `json:"upstreams,omitempty" jsonschema:"limit to these upstream repository URLs"`
	MinSeverity string   `json:"min_severity,omitempty" jsonschema:"info (default), risky or breaking"`
	Force       bool     `json:"force,omitempty" jsonschema:"ignore cached validators and re-analyze the whole window"`
	TimeoutSecs int      `json:"timeout_seconds,omitempty" jsonschema:"give up after this many seconds (default 55, staying under the usual client tool timeout)"`
}

// Finding is one reported risk.
type Finding struct {
	ID         string   `json:"id"`
	Signal     string   `json:"signal"`
	Severity   string   `json:"severity"`
	Confidence float64  `json:"confidence"`
	Title      string   `json:"title"`
	Detail     string   `json:"detail,omitempty"`
	Suggestion string   `json:"suggestion,omitempty"`
	Host       string   `json:"host"`
	Repo       string   `json:"repo"`
	CompareURL string   `json:"compare_url,omitempty"`
	Endpoints  []string `json:"affected_endpoints,omitempty"`
	Evidence   string   `json:"evidence,omitempty"`
	Status     string   `json:"status"`
}

// CheckOut is the result of check_upstreams.
type CheckOut struct {
	RunID         string       `json:"run_id"`
	Complete      bool         `json:"complete"`
	Checked       int          `json:"upstreams_checked"`
	Skipped       int          `json:"upstreams_skipped"`
	Baselined     []string     `json:"baselined,omitempty" jsonschema:"upstreams seen for the first time; a baseline reports nothing by design"`
	Counts        model.Counts `json:"counts"`
	Findings      []Finding    `json:"new_findings,omitempty"`
	Degraded      []string     `json:"degraded,omitempty" jsonschema:"analysis limitations encountered, e.g. files_truncated or spec_unparseable"`
	Errors        []string     `json:"errors,omitempty"`
	RateRemaining int          `json:"github_rate_remaining,omitempty"`
}

func (s *Server) checkUpstreams(ctx context.Context, req *mcp.CallToolRequest, in CheckIn) (*mcp.CallToolResult, CheckOut, error) {
	root := s.root(in.Path)
	idx, err := s.loadIndex(in.Path)
	if err != nil {
		return nil, CheckOut{}, err
	}
	cfg, err := config.Load(root)
	if err != nil {
		return nil, CheckOut{}, err
	}
	st, err := store.Open(root, s.deps.Now)
	if err != nil {
		return nil, CheckOut{}, err
	}
	min, err := model.ParseSeverity(in.MinSeverity)
	if err != nil {
		return nil, CheckOut{}, err
	}
	if s.deps.NewSource == nil {
		return nil, CheckOut{}, fmt.Errorf("no GitHub source configured")
	}
	src, err := s.deps.NewSource(cfg)
	if err != nil {
		return nil, CheckOut{}, err
	}

	// Stay inside the client's tool timeout: returning partial results with a
	// run id beats the whole call failing after a minute of work.
	timeout := time.Duration(in.TimeoutSecs) * time.Second
	if timeout <= 0 {
		timeout = 55 * time.Second
	}
	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	progress := s.progressFunc(ctx, req)
	minRemaining := 100
	if cfg.GitHub.MinRemaining > 0 {
		minRemaining = cfg.GitHub.MinRemaining
	}
	res, err := monitor.Run(runCtx, monitor.Options{
		Store: st, Source: src, Index: idx, Config: cfg,
		Hosts: in.Hosts, Repos: in.Repos, MinSeverity: min, Force: in.Force,
		Trigger: "mcp", Progress: progress, MinRateRemaining: minRemaining,
	})
	if err != nil {
		return nil, CheckOut{}, err
	}

	out := CheckOut{
		RunID: res.RunID, Complete: res.Complete,
		Checked: res.Checked, Skipped: res.Skipped,
		Baselined: res.Baselined, Counts: res.Counts,
		Degraded: res.Degraded, RateRemaining: res.Rate.Remaining,
	}
	for _, e := range res.Errors {
		out.Errors = append(out.Errors, e.Host+": "+e.Err)
	}
	for _, f := range res.New {
		out.Findings = append(out.Findings, toFinding(f))
	}
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: checkText(out)}}}, out, nil
}

func checkText(out CheckOut) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Checked %d upstream(s), skipped %d.", out.Checked, out.Skipped)
	if len(out.Baselined) > 0 {
		fmt.Fprintf(&b, " Baseline recorded for %s; a first check reports nothing by design.",
			strings.Join(out.Baselined, ", "))
	}
	if out.Counts.Total == 0 {
		b.WriteString(" No new findings.")
	} else {
		fmt.Fprintf(&b, " %d new finding(s): %d breaking, %d risky, %d info.",
			out.Counts.Total, out.Counts.Breaking, out.Counts.Risky, out.Counts.Info)
		for _, f := range out.Findings {
			if f.Severity == string(model.SeverityBreaking) || f.Severity == string(model.SeverityRisky) {
				fmt.Fprintf(&b, "\n  [%s] %s", strings.ToUpper(f.Severity), f.Title)
				if len(f.Endpoints) > 0 {
					fmt.Fprintf(&b, " — affects %s", strings.Join(f.Endpoints, ", "))
				}
			}
		}
	}
	if !out.Complete {
		b.WriteString("\nThe run did not finish; call check_upstreams again to continue where it stopped.")
	}
	if len(out.Degraded) > 0 {
		fmt.Fprintf(&b, "\nAnalysis was limited by: %s.", strings.Join(out.Degraded, ", "))
	}
	for _, e := range out.Errors {
		fmt.Fprintf(&b, "\nError: %s", e)
	}
	return b.String()
}

func toFinding(f model.Finding) Finding {
	out := Finding{
		ID: f.Fingerprint, Signal: f.Signal, Severity: string(f.Severity),
		Confidence: f.Confidence, Title: f.Title, Detail: f.Detail,
		Suggestion: f.Suggestion, Host: f.Host, Repo: f.Repo.Canonical(),
		CompareURL: f.CompareURL, Status: f.Status,
	}
	for _, e := range f.Endpoints {
		out.Endpoints = append(out.Endpoints, e.Method+" "+e.Path+" ("+e.CallSite+")")
	}
	if len(f.Evidence) > 0 {
		e := f.Evidence[0]
		switch {
		case e.JSONPointer != "":
			out.Evidence = e.File + " " + e.JSONPointer
			if e.Before != "" || e.After != "" {
				out.Evidence += fmt.Sprintf(" (%q -> %q)", e.Before, e.After)
			}
		case e.Hunk != "":
			out.Evidence = e.File + "\n" + e.Hunk
		default:
			out.Evidence = e.PermalinkURL
		}
	}
	return out
}

// progressFunc reports progress when the client supplied a token.
func (s *Server) progressFunc(ctx context.Context, req *mcp.CallToolRequest) func(int, int, string) {
	token := req.Params.GetProgressToken()
	if token == nil {
		return nil
	}
	return func(done, total int, msg string) {
		_ = req.Session.NotifyProgress(ctx, &mcp.ProgressNotificationParams{
			ProgressToken: token,
			Progress:      float64(done),
			Total:         float64(total),
			Message:       msg,
		})
	}
}

// ---------- list_findings / update_finding ----------

// ListFindingsIn filters stored findings.
type ListFindingsIn struct {
	Path        string   `json:"path,omitempty"`
	MinSeverity string   `json:"min_severity,omitempty" jsonschema:"info (default), risky or breaking"`
	Status      string   `json:"status,omitempty" jsonschema:"open (default), acked, muted, resolved, or all"`
	Hosts       []string `json:"hosts,omitempty"`
	Limit       int      `json:"limit,omitempty"`
}

// ListFindingsOut is the result of list_findings.
type ListFindingsOut struct {
	Counts   model.Counts `json:"counts"`
	Findings []Finding    `json:"findings"`
}

func (s *Server) listFindings(ctx context.Context, req *mcp.CallToolRequest, in ListFindingsIn) (*mcp.CallToolResult, ListFindingsOut, error) {
	st, err := store.Open(s.root(in.Path), s.deps.Now)
	if err != nil {
		return nil, ListFindingsOut{}, err
	}
	state, err := st.Read()
	if err != nil {
		return nil, ListFindingsOut{}, err
	}
	min, err := model.ParseSeverity(in.MinSeverity)
	if err != nil {
		return nil, ListFindingsOut{}, err
	}
	status := in.Status
	if status == "" {
		status = model.StatusOpen
	}
	hostSet := map[string]bool{}
	for _, h := range in.Hosts {
		hostSet[h] = true
	}
	limit := in.Limit
	if limit <= 0 {
		limit = 100
	}

	var kept []model.Finding
	for _, f := range state.Findings {
		if status != "all" && f.Status != status {
			continue
		}
		if !f.Severity.AtLeast(min) {
			continue
		}
		if len(hostSet) > 0 && !hostSet[f.Host] {
			continue
		}
		kept = append(kept, f)
	}
	model.SortFindings(kept)
	out := ListFindingsOut{Counts: model.CountBySeverity(kept)}
	for i, f := range kept {
		if i >= limit {
			break
		}
		out.Findings = append(out.Findings, toFinding(f))
	}
	text := fmt.Sprintf("%d finding(s): %d breaking, %d risky, %d info.",
		out.Counts.Total, out.Counts.Breaking, out.Counts.Risky, out.Counts.Info)
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: text}}}, out, nil
}

// UpdateFindingIn changes a finding's triage state.
type UpdateFindingIn struct {
	Path     string `json:"path,omitempty"`
	ID       string `json:"id" jsonschema:"the finding id reported by check_upstreams or list_findings"`
	Action   string `json:"action" jsonschema:"ack, mute, unmute, resolve or reopen"`
	Note     string `json:"note,omitempty"`
	MuteDays int    `json:"mute_days,omitempty" jsonschema:"how long to mute, in days (default 30)"`
}

// UpdateFindingOut confirms the change.
type UpdateFindingOut struct {
	ID     string `json:"id"`
	Status string `json:"status"`
	Note   string `json:"note,omitempty"`
}

func (s *Server) updateFinding(ctx context.Context, req *mcp.CallToolRequest, in UpdateFindingIn) (*mcp.CallToolResult, UpdateFindingOut, error) {
	st, err := store.Open(s.root(in.Path), s.deps.Now)
	if err != nil {
		return nil, UpdateFindingOut{}, err
	}
	var status string
	var until *time.Time
	switch in.Action {
	case "ack":
		status = model.StatusAcked
	case "mute":
		status = model.StatusMuted
		days := in.MuteDays
		if days <= 0 {
			days = 30
		}
		t := s.deps.now().Add(time.Duration(days) * 24 * time.Hour).UTC()
		until = &t
	case "unmute", "reopen":
		status = model.StatusOpen
	case "resolve":
		status = model.StatusResolved
	default:
		return nil, UpdateFindingOut{}, fmt.Errorf("unknown action %q: want ack, mute, unmute, resolve or reopen", in.Action)
	}
	if err := st.SetFindingStatus(in.ID, status, in.Note, "mcp", until); err != nil {
		return nil, UpdateFindingOut{}, err
	}
	out := UpdateFindingOut{ID: in.ID, Status: status, Note: in.Note}
	text := fmt.Sprintf("Finding %s is now %s.", in.ID, status)
	if status == model.StatusAcked {
		text += " It will resurface only if its severity increases."
	}
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: text}}}, out, nil
}

// ---------- index_stats ----------

// StatsIn selects a repository.
type StatsIn struct {
	Path string `json:"path,omitempty"`
}

// StatsOut summarises everything at a glance.
type StatsOut struct {
	Repo          string         `json:"repo"`
	Commit        string         `json:"commit,omitempty"`
	EndpointCount int            `json:"endpoint_count"`
	HostCount     int            `json:"host_count"`
	LinkedHosts   int            `json:"linked_hosts"`
	UnlinkedHosts int            `json:"unlinked_hosts"`
	Unmonitored   int            `json:"unmonitored_hosts"`
	ByLanguage    map[string]int `json:"by_language,omitempty"`
	Rejected      map[string]int `json:"rejected_call_sites,omitempty"`
	Findings      model.Counts   `json:"open_findings"`
	LastCheck     string         `json:"last_check,omitempty"`
	HasToken      bool           `json:"github_token_available"`
	ConfigPath    string         `json:"config_path,omitempty"`
}

func (s *Server) indexStats(ctx context.Context, req *mcp.CallToolRequest, in StatsIn) (*mcp.CallToolResult, StatsOut, error) {
	root := s.root(in.Path)
	out := StatsOut{Repo: root}
	cfg, err := config.Load(root)
	if err != nil {
		return nil, out, err
	}
	out.ConfigPath = cfg.Path

	if idx, ierr := index.Load(root); ierr == nil && idx != nil {
		out.Commit = idx.Scan.Commit
		out.EndpointCount = len(idx.Calls)
		out.HostCount = len(idx.Hosts)
		out.ByLanguage = idx.Stats.ByLanguage
		out.Rejected = idx.Stats.SitesDropped
	}
	st, err := store.Open(root, s.deps.Now)
	if err != nil {
		return nil, out, err
	}
	state, err := st.Read()
	if err != nil {
		return nil, out, err
	}
	linked := map[string]bool{}
	for _, u := range state.Upstreams {
		linked[u.Host] = true
	}
	out.LinkedHosts = len(linked)
	out.UnlinkedHosts = out.HostCount - out.LinkedHosts
	if out.UnlinkedHosts < 0 {
		out.UnlinkedHosts = 0
	}
	out.Unmonitored = len(state.Decisions)
	var open []model.Finding
	for _, f := range state.Findings {
		if f.Status == model.StatusOpen {
			open = append(open, f)
		}
	}
	out.Findings = model.CountBySeverity(open)
	if len(state.Runs) > 0 {
		out.LastCheck = state.Runs[0].StartedAt.Format(time.RFC3339)
	}
	tokens := &ghsource.ChainTokenSource{Getenv: os.Getenv}
	if _, terr := tokens.Token(ctx); terr == nil {
		out.HasToken = true
	}

	var b strings.Builder
	fmt.Fprintf(&b, "%d endpoint(s) across %d host(s); %d linked, %d unlinked, %d unmonitored. ",
		out.EndpointCount, out.HostCount, out.LinkedHosts, out.UnlinkedHosts, out.Unmonitored)
	fmt.Fprintf(&b, "Open findings: %d breaking, %d risky, %d info.",
		out.Findings.Breaking, out.Findings.Risky, out.Findings.Info)
	if !out.HasToken {
		b.WriteString(" No GitHub token is available, so check_upstreams cannot run; set GITHUB_TOKEN or run `gh auth login`.")
	}
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: b.String()}}}, out, nil
}

// ---------- helpers ----------

func (s *Server) root(path string) string {
	if path != "" {
		return path
	}
	return s.deps.RepoPath
}

func (s *Server) loadIndex(path string) (*index.Index, error) {
	root := s.root(path)
	idx, err := index.Load(root)
	if err != nil {
		return nil, err
	}
	if idx == nil {
		return nil, fmt.Errorf("no index found under %s; call scan_repo first", root)
	}
	return idx, nil
}

func totalOf(m map[string]int) int {
	n := 0
	for _, v := range m {
		n += v
	}
	return n
}

func joinCounts(m map[string]int) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s=%d", k, m[k]))
	}
	return strings.Join(parts, ", ")
}
