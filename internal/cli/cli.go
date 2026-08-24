// Package cli implements the command-line interface.
//
// Subcommands are dispatched with one flag.FlagSet each, in the style of the
// standard library rather than a framework: the dependency surface stays small
// and startup stays instant, which matters because this same binary is launched
// as an MCP server on every session.
//
// One rule is absolute: in MCP mode stdout carries JSON-RPC and nothing else.
// Every diagnostic in this package goes to stderr, and there is an integration
// test that feeds an initialize frame and asserts stdout purity.
package cli

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"runtime/debug"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/sfbee/api-integrity-tool/internal/classify"
	"github.com/sfbee/api-integrity-tool/internal/config"
	"github.com/sfbee/api-integrity-tool/internal/detect"
	"github.com/sfbee/api-integrity-tool/internal/index"
	"github.com/sfbee/api-integrity-tool/internal/normalize"
	"github.com/sfbee/api-integrity-tool/internal/query"
	"github.com/sfbee/api-integrity-tool/internal/scan"
	"github.com/sfbee/api-integrity-tool/internal/walk"
)

// Exit codes. `check` uses 1 for "findings at or above the threshold" so it can
// gate CI, and 2 for real errors -- conflating the two would make a broken
// token look like a breaking change.
const (
	ExitOK       = 0
	ExitFindings = 1
	ExitError    = 2
)

// Env carries the process environment so tests can drive Main without touching
// globals or the real filesystem.
type Env struct {
	Args   []string
	Stdout io.Writer
	Stderr io.Writer
	Stdin  io.Reader
	Getenv func(string) string
	Cwd    string
}

// OSEnv returns the real process environment.
func OSEnv(args []string) Env {
	cwd, _ := os.Getwd()
	return Env{
		Args: args, Stdout: os.Stdout, Stderr: os.Stderr, Stdin: os.Stdin,
		Getenv: os.Getenv, Cwd: cwd,
	}
}

// Version returns the build version, preferring the linker-injected value and
// falling back to module build info.
func Version() string {
	if version != "" {
		return version
	}
	if bi, ok := debug.ReadBuildInfo(); ok && bi.Main.Version != "" && bi.Main.Version != "(devel)" {
		return bi.Main.Version
	}
	return "dev"
}

// version is set with -ldflags "-X .../internal/cli.version=v1.2.3".
var version string

const usageText = `api-integrity-tool indexes the outbound API calls a repository makes, links each
API host to the upstream repository behind it, and watches those upstreams for
changes that would break the calls.

usage:
	api-integrity-tool <command> [flags]
	api-integrity-tool --view-results

indexing:
	scan        index the outbound API calls in a repository
	list        query the indexed calls
	hosts       show API hosts and their call counts

upstream repositories:
	link-hosts  link every scanned host it can, and report what it cannot
	link        link one host to a repository
	unlink      remove a host's links
	unmonitor   record that a host is deliberately not watched
	upstreams   show the current links and decisions

monitoring:
	check       look for upstream changes that would break your calls
	coverage    report which called endpoints the upstream documents
	findings    list what previous checks found
	ack         acknowledge a finding
	mute        silence a finding for a while

viewing:
	serve       run the results dashboard (alias: --view-results)

agents:
	mcp         serve the Model Context Protocol over stdio

other:
	config      init or show .api-integrity.yml
	doctor      report configuration, credentials and rate limits
	version     print the version

run "api-integrity-tool <command> -h" for a command's flags.
`

// Main runs the CLI and returns a process exit code.
func Main(env Env) int {
	if len(env.Args) == 0 {
		fmt.Fprint(env.Stderr, usageText)
		return ExitError
	}

	// --view-results is documented as a top-level flag because that is how a
	// human naturally reaches for it; it is an alias for "serve --open".
	if env.Args[0] == "--view-results" || env.Args[0] == "-view-results" {
		if err := runServe(env, append([]string{"--open"}, env.Args[1:]...)); err != nil {
			fmt.Fprintf(env.Stderr, "error: %v\n", err)
			return ExitError
		}
		return ExitOK
	}

	cmd, rest := env.Args[0], env.Args[1:]
	var err error
	switch cmd {
	case "scan":
		err = runScan(env, rest)
	case "list":
		err = runList(env, rest)
	case "hosts":
		err = runHosts(env, rest)
	case "link":
		err = runLink(env, rest)
	case "unlink":
		err = runUnlink(env, rest)
	case "unmonitor":
		err = runUnmonitor(env, rest)
	case "link-hosts":
		err = runSyncLinks(env, rest)
	case "upstreams":
		err = runUpstreams(env, rest)
	case "config":
		err = runConfig(env, rest)
	case "coverage":
		err = runCoverage(env, rest)
	case "check":
		err = runCheck(env, rest)
	case "findings":
		err = runFindings(env, rest)
	case "ack":
		err = runAck(env, rest)
	case "mute":
		err = runMute(env, rest)
	case "doctor":
		err = runDoctor(env, rest)
	case "mcp":
		err = runMCP(env, rest)
	case "serve":
		err = runServe(env, rest)
	case "version":
		fmt.Fprintln(env.Stdout, Version())
	case "help", "-h", "--help":
		fmt.Fprint(env.Stdout, usageText)
	default:
		fmt.Fprintf(env.Stderr, "unknown command %q\n\n%s", cmd, usageText)
		return ExitError
	}
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return ExitError
		}
		var fe *findingsError
		if errors.As(err, &fe) {
			fmt.Fprintln(env.Stderr, fe.Error())
			return ExitFindings
		}
		fmt.Fprintf(env.Stderr, "error: %v\n", err)
		return ExitError
	}
	return ExitOK
}

// findingsError signals "the command worked and found something you asked to be
// warned about", which is exit code 1 rather than an error.
type findingsError struct{ msg string }

func (e *findingsError) Error() string { return e.msg }

// repeatedFlag collects a flag that may be given more than once.
type repeatedFlag []string

func (r *repeatedFlag) String() string { return strings.Join(*r, ",") }

func (r *repeatedFlag) Set(v string) error {
	// Accept both repeated flags and comma-separated lists; users try both.
	for _, part := range strings.Split(v, ",") {
		if part = strings.TrimSpace(part); part != "" {
			*r = append(*r, part)
		}
	}
	return nil
}

func newFlagSet(env Env, name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(env.Stderr)
	return fs
}

func runScan(env Env, args []string) error {
	fs := newFlagSet(env, "scan")
	repoPath := fs.String("repo-path", "", "repository to scan (default: current directory)")
	jobs := fs.Int("jobs", 0, "detection concurrency (default: number of CPUs)")
	format := fs.String("format", "text", "output format: text or json")
	write := fs.Bool("write", true, "write the index to .api-integrity/index.json")
	check := fs.Bool("check", false, "exit 1 if the on-disk index would change; implies -write=false")
	explainDrops := fs.Bool("explain-drops", false, "list every call site that was rejected, and why")
	includeTests := fs.Bool("include-tests", false, "index calls in test files")
	includeInternal := fs.Bool("include-internal", false, "index calls to localhost, private IPs and single-label hosts")
	includeRoutes := fs.Bool("include-suspected-routes", false, "index ambiguous sites that look like server route definitions")
	noGitignore := fs.Bool("no-gitignore", false, "do not honour .gitignore")
	maxFileSize := fs.Int64("max-file-size", walk.DefaultMaxFileSize, "skip files larger than this many bytes")
	collapseNumeric := fs.Bool("collapse-numeric-ids", false, "rewrite all-digit path segments to {id}")
	var langs, pathGlobs, excludeGlobs, includeGlobs repeatedFlag
	fs.Var(&langs, "lang", "restrict to a language (repeatable)")
	fs.Var(&pathGlobs, "path-glob", "only scan paths matching this glob (repeatable)")
	fs.Var(&excludeGlobs, "exclude-path", "skip paths matching this glob (repeatable)")
	fs.Var(&includeGlobs, "include-path", "force-include paths matching this glob, beating every exclusion (repeatable)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	root := *repoPath
	if root == "" {
		root = env.Cwd
	}
	if *check {
		*write = false
	}

	opts := scan.Options{
		RepoPath:  root,
		Jobs:      *jobs,
		Version:   Version(),
		KeepDrops: *explainDrops,
		Walk: walk.Options{
			RespectGitignore: !*noGitignore,
			MaxFileSize:      *maxFileSize,
			PathGlobs:        pathGlobs,
			ExcludeGlobs:     excludeGlobs,
			IncludeGlobs:     includeGlobs,
		},
		Classify: classify.Options{
			IncludeTests:           *includeTests,
			IncludeInternal:        *includeInternal,
			IncludeSuspectedRoutes: *includeRoutes,
			IncludePaths:           includeGlobs,
			ExtraExcludePaths:      excludeGlobs,
		},
		Normalize: normalize.Options{CollapseNumericIDs: *collapseNumeric},
	}
	for _, l := range langs {
		opts.Languages = append(opts.Languages, detect.Language(l))
	}

	res, err := scan.Run(context.Background(), opts)
	if err != nil {
		return err
	}
	if *write {
		if err := scan.Save(root, res); err != nil {
			return err
		}
	}

	if *format == "json" {
		if err := writeJSON(env.Stdout, map[string]any{
			"scan":   res.Index.Scan,
			"stats":  res.Index.Stats,
			"merge":  res.Report,
			"drops":  res.Drops,
			"errors": res.Errors,
		}); err != nil {
			return err
		}
	} else {
		printScanSummary(env.Stderr, res, *explainDrops)
	}

	if *check && res.Report.Changed() {
		return &findingsError{msg: "the index is out of date; run `api-integrity-tool scan` and commit the result"}
	}
	return nil
}

func printScanSummary(w io.Writer, res *scan.Result, explainDrops bool) {
	i := res.Index
	active := 0
	for _, c := range i.Calls {
		if c.Lifecycle.Status == index.StatusActive {
			active++
		}
	}
	fmt.Fprintf(w, "==> Scanned %d files (%d skipped) in %dms\n",
		i.Stats.FilesScanned, totalCounts(i.Stats.FilesSkipped), i.Scan.DurationMS)
	fmt.Fprintf(w, "    %d outbound calls across %d hosts\n", active, len(i.Hosts))
	r := res.Report
	fmt.Fprintf(w, "    %d new, %d removed, %d moved, %d unchanged\n",
		r.Added, r.Removed, len(r.Relocated), r.Unchanged)

	if dropped := totalCounts(i.Stats.SitesDropped); dropped > 0 {
		fmt.Fprintf(w, "    %d call sites rejected:", dropped)
		for _, k := range sortedCountKeys(i.Stats.SitesDropped) {
			fmt.Fprintf(w, " %s=%d", k, i.Stats.SitesDropped[k])
		}
		fmt.Fprintln(w)
		if !explainDrops {
			fmt.Fprintln(w, "    (re-run with --explain-drops to see each one)")
		}
	}
	if len(i.Stats.UnresolvedTop) > 0 {
		fmt.Fprintf(w, "    unresolved symbols blocking full resolution: %s\n",
			strings.Join(i.Stats.UnresolvedTop, ", "))
	}
	if n := len(res.Errors); n > 0 {
		fmt.Fprintf(w, "    %d files could not be fully parsed (calls in them may be missing)\n", n)
	}

	if explainDrops && len(res.Drops) > 0 {
		fmt.Fprintln(w, "\n    rejected sites:")
		tw := tabwriter.NewWriter(w, 0, 8, 2, ' ', 0)
		fmt.Fprintln(tw, "    LOCATION\tREASON\tEXPRESSION")
		for _, d := range res.Drops {
			fmt.Fprintf(tw, "    %s:%d\t%s\t%s\n", d.File, d.Line, d.Reason, truncate(d.Src, 60))
		}
		tw.Flush()
	}
}

func runList(env Env, args []string) error {
	fs := newFlagSet(env, "list")
	repoPath := fs.String("repo-path", "", "repository to read (default: current directory)")
	format := fs.String("format", "table", "output format: table, json or csv")
	minConf := fs.String("min-confidence", "", "only show calls at this confidence or better: low, medium, high")
	includeRemoved := fs.Bool("include-removed", false, "include calls that have disappeared from the code")
	var hosts, vendors, endpoints, regexes, methods, languages repeatedFlag
	var exHosts, exEndpoints repeatedFlag
	fs.Var(&hosts, "host", "only this host, glob allowed (repeatable)")
	fs.Var(&vendors, "vendor", "only this vendor (repeatable)")
	fs.Var(&endpoints, "endpoint", "only this endpoint path, e.g. /api/v1/user/add (repeatable)")
	fs.Var(&regexes, "regex", "only calls whose URL matches this RE2 pattern (repeatable)")
	fs.Var(&methods, "method", "only this HTTP method (repeatable)")
	fs.Var(&languages, "lang", "only this language (repeatable)")
	fs.Var(&exHosts, "exclude-host", "exclude this host (repeatable)")
	fs.Var(&exEndpoints, "exclude-endpoint", "exclude this endpoint (repeatable)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	idx, root, err := loadIndex(env, *repoPath)
	if err != nil {
		return err
	}

	// Without the mappings, "--host api.example.com" finds nothing whenever the
	// scanner recorded the host symbolically -- which is exactly the case for a
	// base URL resolved at runtime, and exactly the host the user linked. The
	// filter knows how to invert a mapping; it just has to be given one.
	cfg, err := config.Load(root)
	if err != nil {
		return err
	}

	f := query.Filters{
		Hosts: hosts, Vendors: vendors, Endpoints: endpoints, Regexes: regexes,
		Methods: methods, Languages: languages,
		MinConfidence:  index.Confidence(*minConf),
		IncludeRemoved: *includeRemoved,
		HostMappings:   cfg.HostMappings,
	}
	if len(exHosts) > 0 || len(exEndpoints) > 0 {
		f.Exclude = &query.Filters{Hosts: exHosts, Endpoints: exEndpoints, HostMappings: cfg.HostMappings}
	}
	sel, err := query.Compile(f)
	if err != nil {
		return err
	}
	matched := sel.Apply(idx.Calls)

	switch *format {
	case "json":
		return writeJSON(env.Stdout, matched)
	case "csv":
		fmt.Fprintln(env.Stdout, "method,host,path,confidence,score,language,file,line")
		for _, c := range matched {
			fmt.Fprintf(env.Stdout, "%s,%s,%s,%s,%d,%s,%s,%d\n",
				c.Method, c.Host, c.Path, c.Confidence, c.Score, c.Language, c.Location.File, c.Location.Line)
		}
		return nil
	default:
		if len(matched) == 0 {
			fmt.Fprintf(env.Stderr, "no calls matched (index holds %d)\n", len(idx.Calls))
			return nil
		}
		tw := tabwriter.NewWriter(env.Stdout, 0, 8, 2, ' ', 0)
		fmt.Fprintln(tw, "METHOD\tHOST\tPATH\tCONF\tLANG\tLOCATION")
		for _, c := range matched {
			loc := fmt.Sprintf("%s:%d", c.Location.File, c.Location.Line)
			marker := ""
			if c.Lifecycle.Status == index.StatusRemoved {
				marker = " (removed)"
			}
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s%s\n",
				c.Method, c.Host, c.Path, c.Confidence, c.Language, loc, marker)
		}
		tw.Flush()
		fmt.Fprintf(env.Stderr, "\n%d of %d calls shown (index at %s)\n", len(matched), len(idx.Calls), shortSHA(idx.Scan.Commit))
		_ = root
		return nil
	}
}

func runHosts(env Env, args []string) error {
	fs := newFlagSet(env, "hosts")
	repoPath := fs.String("repo-path", "", "repository to read (default: current directory)")
	format := fs.String("format", "table", "output format: table or json")
	unresolved := fs.Bool("unresolved", false, "only hosts that could not be resolved to a real hostname")
	if err := fs.Parse(args); err != nil {
		return err
	}
	idx, _, err := loadIndex(env, *repoPath)
	if err != nil {
		return err
	}
	groups := idx.Hosts
	if *unresolved {
		var keep []index.HostGroup
		for _, h := range groups {
			if h.HostKind != normalize.HostLiteral {
				keep = append(keep, h)
			}
		}
		groups = keep
	}
	if *format == "json" {
		return writeJSON(env.Stdout, groups)
	}
	if len(groups) == 0 {
		fmt.Fprintln(env.Stderr, "no hosts in the index; run `api-integrity-tool scan` first")
		return nil
	}
	tw := tabwriter.NewWriter(env.Stdout, 0, 8, 2, ' ', 0)
	fmt.Fprintln(tw, "HOST\tKIND\tCALLS\tPATHS\tMETHODS\tCONF")
	for _, h := range groups {
		fmt.Fprintf(tw, "%s\t%s\t%d\t%d\t%s\t%s\n",
			h.HostKey, h.HostKind, h.CallCount, h.PathCount, strings.Join(h.Methods, ","), h.MaxConfidence)
	}
	tw.Flush()
	return nil
}

func loadIndex(env Env, repoPath string) (*index.Index, string, error) {
	root := repoPath
	if root == "" {
		root = env.Cwd
	}
	idx, err := index.Load(root)
	if err != nil {
		return nil, root, err
	}
	if idx == nil {
		return nil, root, fmt.Errorf("no index found under %s; run `api-integrity-tool scan` first", root)
	}
	return idx, root, nil
}

func writeJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(v)
}

func totalCounts(m map[string]int) int {
	n := 0
	for _, v := range m {
		n += v
	}
	return n
}

func sortedCountKeys(m map[string]int) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func truncate(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n-1]) + "…"
}

func shortSHA(sha string) string {
	if len(sha) > 8 {
		return sha[:8]
	}
	if sha == "" {
		return "no commit"
	}
	return sha
}
