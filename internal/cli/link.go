package cli

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/sfbee/api-integrity-tool/internal/config"
	"github.com/sfbee/api-integrity-tool/internal/gitmeta"
	"github.com/sfbee/api-integrity-tool/internal/linker"
	"github.com/sfbee/api-integrity-tool/internal/model"
	"github.com/sfbee/api-integrity-tool/internal/store"
	"github.com/sfbee/api-integrity-tool/internal/upstream"
)

// newLinker builds a linker for a repository, loading its config and store.
func newLinker(env Env, repoPath string) (*linker.Linker, string, error) {
	root := repoPath
	if root == "" {
		root = env.Cwd
	}
	if r := gitmeta.FindRoot(root); r != "" {
		root = r
	}
	// The origin remote is used only to improve upstream guesses, so a failure
	// here degrades the suggestion rather than the command.
	var remote string
	if gi, err := (gitmeta.Git{}).Info(context.Background(), root); err == nil {
		remote = gi.Remote
	}
	cfg, err := config.Load(root)
	if err != nil {
		return nil, root, err
	}
	st, err := store.Open(root, nil)
	if err != nil {
		return nil, root, err
	}
	return &linker.Linker{Store: st, Config: cfg, Remote: remote}, root, nil
}

func runLink(env Env, args []string) error {
	fs := newFlagSet(env, "link")
	repoPath := fs.String("repo-path", "", "repository to update (default: current directory)")
	repo := fs.String("repo", "", "upstream repository URL, e.g. github.com/stripe/openapi")
	prefix := fs.String("path-prefix", "", "only endpoints under this path belong to this repository")
	role := fs.String("role", "implementation", "what the repository holds: implementation, spec_only or gateway")
	ref := fs.String("ref", "", "branch or tag to watch (default: the repository default branch)")
	note := fs.String("note", "", "free-text note")
	priority := fs.Int("priority", 0, "tie-break order when several repositories match; lower wins")
	rest, err := parsePositionals(fs, args)
	if err != nil {
		return err
	}
	if len(rest) != 1 {
		return fmt.Errorf("usage: link <host> --repo <url>\n\nexample:\n  api-integrity-tool link api.stripe.com --repo github.com/stripe/openapi --role spec_only")
	}
	if strings.TrimSpace(*repo) == "" {
		return fmt.Errorf("--repo is required; try --repo github.com/owner/name")
	}
	l, _, lerr := newLinker(env, *repoPath)
	if lerr != nil {
		return lerr
	}
	u, err := l.Link(rest[0], *repo, linker.LinkOptions{
		PathPrefix: *prefix, Role: model.Role(*role), Ref: *ref,
		Note: *note, Priority: *priority, Source: model.SourceCLI,
	})
	if err != nil {
		return err
	}
	fmt.Fprintf(env.Stdout, "linked %s -> %s (%s)\n", u.Host, u.Repo.Canonical(), u.Role)
	if u.Role == model.RoleImplementation {
		if _, ok := lookupSpecOnlyHint(u.Host); ok {
			fmt.Fprintf(env.Stderr, "note: most third-party APIs are closed source and publish only a specification.\n"+
				"      If this repository holds just an OpenAPI file, re-link it with --role spec_only\n"+
				"      so the checker uses the structural spec diff instead of route analysis.\n")
		}
	}
	return nil
}

func runUnlink(env Env, args []string) error {
	fs := newFlagSet(env, "unlink")
	repoPath := fs.String("repo-path", "", "repository to update (default: current directory)")
	rest, err := parsePositionals(fs, args)
	if err != nil {
		return err
	}
	if len(rest) != 1 {
		return fmt.Errorf("usage: unlink <host>")
	}
	l, _, err := newLinker(env, *repoPath)
	if err != nil {
		return err
	}
	n, err := l.Store.UnlinkHost(rest[0])
	if err != nil {
		return err
	}
	if n == 0 {
		fmt.Fprintf(env.Stderr, "%s had no upstream links\n", rest[0])
		return nil
	}
	fmt.Fprintf(env.Stdout, "removed %d link(s) for %s\n", n, rest[0])
	return nil
}

func runUnmonitor(env Env, args []string) error {
	fs := newFlagSet(env, "unmonitor")
	repoPath := fs.String("repo-path", "", "repository to update (default: current directory)")
	reason := fs.String("reason", "", "why: closed_source, internal, third_party_no_repo, noise or other")
	clear := fs.Bool("clear", false, "forget the decision so the host is asked about again")
	rest, err := parsePositionals(fs, args)
	if err != nil {
		return err
	}
	if len(rest) != 1 {
		return fmt.Errorf("usage: unmonitor <host> [--reason internal]")
	}
	host := rest[0]
	l, _, lerr := newLinker(env, *repoPath)
	if lerr != nil {
		return lerr
	}
	if *clear {
		if err := l.Store.ClearDecision(host); err != nil {
			return err
		}
		fmt.Fprintf(env.Stdout, "%s will be asked about again\n", host)
		return nil
	}
	if err := l.Unmonitor(host, *reason, model.SourceCLI); err != nil {
		return err
	}
	fmt.Fprintf(env.Stdout, "%s will not be monitored\n", host)
	return nil
}

// runSyncLinks applies config and the well-known table to the scanned hosts,
// then reports or prompts for whatever is left.
func runSyncLinks(env Env, args []string) error {
	fs := newFlagSet(env, "link-hosts")
	repoPath := fs.String("repo-path", "", "repository to update (default: current directory)")
	interactive := fs.Bool("interactive", false, "prompt for each unlinked host (requires a terminal)")
	format := fs.String("format", "text", "output format: text or json")
	if err := fs.Parse(args); err != nil {
		return err
	}
	l, root, err := newLinker(env, *repoPath)
	if err != nil {
		return err
	}
	idx, _, err := loadIndex(env, root)
	if err != nil {
		return err
	}
	reqs := linker.HostRequestsFromIndex(idx, l.Remote)
	rep, err := l.AutoLink(reqs)
	if err != nil {
		return err
	}

	// Only prompt when a human is genuinely present. Reading stdin when it is a
	// pipe hangs a build, and doing it in MCP mode would corrupt the JSON-RPC
	// stream, because there stdin is the transport.
	if *interactive && isTerminal(os.Stdin) && isTerminal(os.Stderr) && os.Getenv("CI") == "" {
		remaining, perr := l.Prompt(rep.NeedsLink, linker.PromptOptions{
			In: os.Stdin, Out: env.Stderr, Interactive: true,
		})
		if perr != nil {
			return perr
		}
		rep.NeedsLink = remaining
	} else if *interactive {
		fmt.Fprintln(env.Stderr, "not attached to a terminal; reporting unlinked hosts instead of prompting")
	}

	if *format == "json" {
		return writeJSON(env.Stdout, rep)
	}
	printLinkReport(env, rep)
	return nil
}

func printLinkReport(env Env, rep linker.Report) {
	if len(rep.Linked) > 0 {
		fmt.Fprintf(env.Stdout, "==> Linked %d host(s) automatically\n", len(rep.Linked))
		for _, u := range rep.Linked {
			fmt.Fprintf(env.Stdout, "    %s -> %s (%s)\n", u.Host, u.Repo.Canonical(), u.Role)
		}
	}
	if rep.AlreadyLinked > 0 {
		fmt.Fprintf(env.Stdout, "    %d host(s) already linked\n", rep.AlreadyLinked)
	}
	if len(rep.Unmonitored) > 0 {
		fmt.Fprintf(env.Stdout, "    %d host(s) deliberately unmonitored: %s\n",
			len(rep.Unmonitored), strings.Join(rep.Unmonitored, ", "))
	}
	if len(rep.NeedsLink) == 0 {
		fmt.Fprintln(env.Stdout, "\nEvery host has an upstream repository.")
		return
	}
	fmt.Fprintf(env.Stdout, "\n%d host(s) still need an upstream repository:\n\n", len(rep.NeedsLink))
	for _, n := range rep.NeedsLink {
		fmt.Fprintf(env.Stdout, "  %s — %d call(s)\n", n.Host, n.EndpointCount)
		for _, s := range n.SampleEndpoints {
			fmt.Fprintf(env.Stdout, "      %s\n", s)
		}
		if n.Symbolic {
			fmt.Fprintf(env.Stdout, "      this host came from a variable; consider a host_mappings entry\n")
		}
		if n.SuggestedRepo != "" {
			fmt.Fprintf(env.Stdout, "      suggestion: %s (%s)\n", n.SuggestedRepo, n.SuggestedWhy)
		}
	}
	fmt.Fprintf(env.Stdout, "\nLink one with:\n  api-integrity-tool link <host> --repo <url>\n"+
		"Or record a deliberate decision not to:\n  api-integrity-tool unmonitor <host> --reason internal\n")
}

func runConfigInit(env Env, args []string) error {
	fs := newFlagSet(env, "config-init")
	repoPath := fs.String("repo-path", "", "repository to write into (default: current directory)")
	force := fs.Bool("force", false, "overwrite an existing config file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	root := *repoPath
	if root == "" {
		root = env.Cwd
	}
	if r := gitmeta.FindRoot(root); r != "" {
		root = r
	}
	if existing := config.Find(root); existing != "" && !*force {
		return fmt.Errorf("%s already exists; pass --force to overwrite it", existing)
	}
	path := root + "/" + config.FileNames[0]
	if err := os.WriteFile(path, []byte(config.Example), 0o644); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	fmt.Fprintf(env.Stdout, "wrote %s\n", path)
	return nil
}

// lookupSpecOnlyHint reports whether the curated table considers this host
// spec-only, so a manual link with the wrong role can be gently questioned
// rather than silently producing weaker analysis.
func lookupSpecOnlyHint(host string) (string, bool) {
	wk, ok := upstream.LookupWellKnown(host)
	if !ok || wk.Role != model.RoleSpecOnly {
		return "", false
	}
	return wk.Repo, true
}

// isTerminal reports whether f is a character device, which is the stdlib-only
// way to tell a terminal from a pipe or a file.
func isTerminal(f *os.File) bool {
	st, err := f.Stat()
	if err != nil {
		return false
	}
	return st.Mode()&os.ModeCharDevice != 0
}

// newTabwriter matches the column style used by the other commands.
func newTabwriter(w io.Writer) *tabwriter.Writer {
	return tabwriter.NewWriter(w, 0, 8, 2, ' ', 0)
}

func runUpstreams(env Env, args []string) error {
	fs := newFlagSet(env, "upstreams")
	repoPath := fs.String("repo-path", "", "repository to read (default: current directory)")
	format := fs.String("format", "table", "output format: table or json")
	if err := fs.Parse(args); err != nil {
		return err
	}
	l, _, err := newLinker(env, *repoPath)
	if err != nil {
		return err
	}
	if err := l.SyncConfig(); err != nil {
		return err
	}
	st, err := l.Store.Read()
	if err != nil {
		return err
	}
	if *format == "json" {
		return writeJSON(env.Stdout, map[string]any{
			"upstreams": st.Upstreams, "decisions": st.Decisions,
		})
	}
	if len(st.Upstreams) == 0 && len(st.Decisions) == 0 {
		fmt.Fprintln(env.Stderr, "no upstream links yet; run `api-integrity-tool link-hosts` after a scan")
		return nil
	}
	tw := newTabwriter(env.Stdout)
	if len(st.Upstreams) > 0 {
		fmt.Fprintln(tw, "HOST\tREPOSITORY\tROLE\tPREFIX\tSOURCE")
		for _, u := range st.Upstreams {
			prefix := u.PathPrefix
			if prefix == "" {
				prefix = "-"
			}
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", u.Host, u.Repo.Canonical(), u.Role, prefix, u.Source)
		}
	}
	tw.Flush()
	if len(st.Decisions) > 0 {
		fmt.Fprintf(env.Stdout, "\nDeliberately unmonitored:\n")
		for _, d := range st.Decisions {
			expiry := ""
			if d.ExpiresAt != nil {
				expiry = fmt.Sprintf(" (until %s)", d.ExpiresAt.Format(time.DateOnly))
			}
			fmt.Fprintf(env.Stdout, "  %s — %s%s\n", d.Host, d.Reason, expiry)
		}
	}
	return nil
}

// runConfig dispatches the config subcommands.
func runConfig(env Env, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: config init | config show")
	}
	switch args[0] {
	case "init":
		return runConfigInit(env, args[1:])
	case "show":
		return runConfigShow(env, args[1:])
	default:
		return fmt.Errorf("unknown config subcommand %q; want init or show", args[0])
	}
}

func runConfigShow(env Env, args []string) error {
	fs := newFlagSet(env, "config-show")
	repoPath := fs.String("repo-path", "", "repository to read (default: current directory)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	root := *repoPath
	if root == "" {
		root = env.Cwd
	}
	if r := gitmeta.FindRoot(root); r != "" {
		root = r
	}
	cfg, err := config.Load(root)
	if err != nil {
		return err
	}
	if cfg.Path == "" {
		fmt.Fprintf(env.Stderr, "no config file; create one with `api-integrity-tool config init`\n")
		return nil
	}
	fmt.Fprintf(env.Stdout, "%s\n", cfg.Path)
	return writeJSON(env.Stdout, cfg)
}

// parsePositionals parses flags that may appear before or after the positional
// arguments.
//
// Go's flag package stops at the first non-flag argument, so
// "link api.stripe.com --repo x" would leave --repo unparsed. Users reasonably
// write the subject first, so rather than making them remember flag order, this
// repeatedly parses and peels off leading positionals until only flags remain.
func parsePositionals(fs *flag.FlagSet, args []string) ([]string, error) {
	var positional []string
	rest := args
	for {
		if err := fs.Parse(rest); err != nil {
			return nil, err
		}
		remaining := fs.Args()
		if len(remaining) == 0 || strings.HasPrefix(remaining[0], "-") {
			// Anything left starting with "-" is a genuine parse stopper and is
			// reported by the final Parse below.
			positional = append(positional, remaining...)
			return positional, nil
		}
		positional = append(positional, remaining[0])
		rest = remaining[1:]
	}
}
