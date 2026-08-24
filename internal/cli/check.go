package cli

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/sfbee/api-integrity-tool/internal/config"
	"github.com/sfbee/api-integrity-tool/internal/ghsource"
	"github.com/sfbee/api-integrity-tool/internal/model"
	"github.com/sfbee/api-integrity-tool/internal/monitor"
)

// newGitHubSource builds the live client from configuration and environment.
func newGitHubSource(env Env, cfg *config.File) (ghsource.GitHubSource, error) {
	getenv := env.Getenv
	if getenv == nil {
		getenv = os.Getenv
	}
	gh := config.GitHubConfig{}
	if cfg != nil {
		gh = cfg.GitHub
	}
	tokens := &ghsource.ChainTokenSource{Getenv: getenv, Command: gh.TokenCommand}
	opt := ghsource.Options{
		BaseURL:     gh.BaseURL,
		TokenSource: tokens,
		UserAgent:   "api-integrity-tool/" + Version(),
	}
	if gh.MaxWaitSecs > 0 {
		opt.MaxWait = time.Duration(gh.MaxWaitSecs) * time.Second
	}
	return ghsource.New(opt)
}

func runCheck(env Env, args []string) error {
	fs := newFlagSet(env, "check")
	repoPath := fs.String("repo-path", "", "repository to check (default: current directory)")
	var hosts repeatedFlag
	fs.Var(&hosts, "host", "only check this host (repeatable)")
	var repos repeatedFlag
	fs.Var(&repos, "upstream", "only check this upstream repository (repeatable)")
	minSeverity := fs.String("min-severity", "info", "report findings at this severity or above: info, risky, breaking")
	failOn := fs.String("fail-on", "", "exit 1 if a finding at this severity or above is found")
	force := fs.Bool("force", false, "ignore cached validators and re-analyze the whole window")
	format := fs.String("format", "text", "output format: text or json")
	timeout := fs.Duration("timeout", 5*time.Minute, "give up after this long")
	if err := fs.Parse(args); err != nil {
		return err
	}

	min, err := model.ParseSeverity(*minSeverity)
	if err != nil {
		return err
	}
	l, root, err := newLinker(env, *repoPath)
	if err != nil {
		return err
	}
	if err := l.SyncConfig(); err != nil {
		return err
	}
	idx, _, err := loadIndex(env, root)
	if err != nil {
		return err
	}
	src, err := newGitHubSource(env, l.Config)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	// Carriage-return progress only makes sense on a terminal; in a pipe or a
	// CI log it produces one unreadable line, so fall back to nothing there.
	progress := func(int, int, string) {}
	if *format != "json" && isTerminal(os.Stderr) {
		progress = func(done, total int, msg string) {
			if total == 0 {
				return
			}
			fmt.Fprintf(env.Stderr, "\r    checking %d/%d %-50s", done, total, truncate(msg, 50))
			if done >= total {
				fmt.Fprintln(env.Stderr)
			}
		}
	}

	minRemaining := 100
	if l.Config != nil && l.Config.GitHub.MinRemaining > 0 {
		minRemaining = l.Config.GitHub.MinRemaining
	}
	res, err := monitor.Run(ctx, monitor.Options{
		Store: l.Store, Source: src, Index: idx, Config: l.Config,
		Hosts: hosts, Repos: repos, MinSeverity: min, Force: *force,
		Trigger: "cli", Progress: progress, MinRateRemaining: minRemaining,
	})
	if err != nil {
		return err
	}

	if *format == "json" {
		if err := writeJSON(env.Stdout, res); err != nil {
			return err
		}
	} else {
		printCheckResult(env, res)
	}

	if *failOn != "" {
		threshold, err := model.ParseSeverity(*failOn)
		if err != nil {
			return err
		}
		for _, f := range res.New {
			if f.Severity.AtLeast(threshold) {
				return &findingsError{msg: fmt.Sprintf("%d finding(s) at %s or above", countAtLeast(res.New, threshold), threshold)}
			}
		}
	}
	return nil
}

func countAtLeast(fs []model.Finding, min model.Severity) int {
	n := 0
	for _, f := range fs {
		if f.Severity.AtLeast(min) {
			n++
		}
	}
	return n
}

func printCheckResult(env Env, res *monitor.Result) {
	fmt.Fprintf(env.Stdout, "==> Checked %d upstream(s), skipped %d, %d API call(s)\n",
		res.Checked, res.Skipped, res.APICalls)
	if len(res.Baselined) > 0 {
		fmt.Fprintf(env.Stdout, "    baseline established for %s\n", strings.Join(res.Baselined, ", "))
		fmt.Fprintf(env.Stdout, "    (a first check records the current state and reports nothing)\n")
	}
	if res.Rate.Limit > 0 {
		fmt.Fprintf(env.Stdout, "    GitHub rate limit: %d/%d remaining\n", res.Rate.Remaining, res.Rate.Limit)
	}
	if len(res.Degraded) > 0 {
		fmt.Fprintf(env.Stdout, "    analysis limited by: %s\n", strings.Join(res.Degraded, ", "))
	}
	for _, e := range res.Errors {
		fmt.Fprintf(env.Stderr, "    %s (%s): %s\n", e.Host, e.Repo, e.Err)
	}
	if !res.Complete {
		fmt.Fprintf(env.Stderr, "    run did not finish; re-run to continue\n")
	}
	if len(res.New) == 0 {
		fmt.Fprintln(env.Stdout, "\nNo new findings.")
		return
	}
	fmt.Fprintf(env.Stdout, "\n%d new finding(s): %d breaking, %d risky, %d info\n\n",
		res.Counts.Total, res.Counts.Breaking, res.Counts.Risky, res.Counts.Info)
	printFindings(env, res.New, false)
}

func runFindings(env Env, args []string) error {
	fs := newFlagSet(env, "findings")
	repoPath := fs.String("repo-path", "", "repository to read (default: current directory)")
	severity := fs.String("severity", "", "only findings at this severity or above")
	status := fs.String("status", "open", "filter by status: open, acked, muted, resolved, or all")
	var hosts repeatedFlag
	fs.Var(&hosts, "host", "only this host (repeatable)")
	format := fs.String("format", "text", "output format: text or json")
	verbose := fs.Bool("v", false, "include evidence and suggestions")
	if err := fs.Parse(args); err != nil {
		return err
	}
	l, _, err := newLinker(env, *repoPath)
	if err != nil {
		return err
	}
	st, err := l.Store.Read()
	if err != nil {
		return err
	}
	var min model.Severity
	if *severity != "" {
		if min, err = model.ParseSeverity(*severity); err != nil {
			return err
		}
	}
	hostSet := map[string]bool{}
	for _, h := range hosts {
		hostSet[h] = true
	}

	var out []model.Finding
	for _, f := range st.Findings {
		if *status != "all" && f.Status != *status {
			continue
		}
		if min != "" && !f.Severity.AtLeast(min) {
			continue
		}
		if len(hostSet) > 0 && !hostSet[f.Host] {
			continue
		}
		out = append(out, f)
	}
	model.SortFindings(out)

	if *format == "json" {
		return writeJSON(env.Stdout, out)
	}
	if len(out) == 0 {
		fmt.Fprintf(env.Stderr, "no findings match (store holds %d)\n", len(st.Findings))
		return nil
	}
	printFindings(env, out, *verbose)
	return nil
}

func printFindings(env Env, fs []model.Finding, verbose bool) {
	for _, f := range fs {
		marker := severityMarker(f.Severity)
		fmt.Fprintf(env.Stdout, "%s %s\n", marker, f.Title)
		fmt.Fprintf(env.Stdout, "    %s  confidence %.2f  %s\n", f.Signal, f.Confidence, f.Repo.Slug())
		if f.Detail != "" {
			fmt.Fprintf(env.Stdout, "    %s\n", f.Detail)
		}
		for _, e := range f.Endpoints {
			fmt.Fprintf(env.Stdout, "    affects %s %s  (%s)\n", e.Method, e.Path, e.CallSite)
		}
		if verbose {
			if f.Suggestion != "" {
				fmt.Fprintf(env.Stdout, "    suggestion: %s\n", f.Suggestion)
			}
			for _, ev := range f.Evidence {
				if ev.JSONPointer != "" {
					fmt.Fprintf(env.Stdout, "    evidence: %s %s\n", ev.File, ev.JSONPointer)
				}
				if ev.Hunk != "" {
					for _, line := range strings.Split(strings.TrimRight(ev.Hunk, "\n"), "\n") {
						fmt.Fprintf(env.Stdout, "      %s\n", line)
					}
				}
				if ev.PermalinkURL != "" {
					fmt.Fprintf(env.Stdout, "    %s\n", ev.PermalinkURL)
				}
			}
			fmt.Fprintf(env.Stdout, "    id: %s\n", f.Fingerprint)
		}
		fmt.Fprintln(env.Stdout)
	}
	if !verbose {
		fmt.Fprintf(env.Stdout, "Run with -v for evidence, or `findings --format json` for everything.\n")
	}
}

func severityMarker(s model.Severity) string {
	switch s {
	case model.SeverityBreaking:
		return "[BREAKING]"
	case model.SeverityRisky:
		return "[RISKY]   "
	default:
		return "[info]    "
	}
}

func runAck(env Env, args []string) error {
	fs := newFlagSet(env, "ack")
	repoPath := fs.String("repo-path", "", "repository to update (default: current directory)")
	note := fs.String("note", "", "why this is acknowledged")
	rest, err := parsePositionals(fs, args)
	if err != nil {
		return err
	}
	if len(rest) != 1 {
		return fmt.Errorf("usage: ack <finding-id> [--note \"...\"]")
	}
	l, _, err := newLinker(env, *repoPath)
	if err != nil {
		return err
	}
	if err := l.Store.SetFindingStatus(rest[0], model.StatusAcked, *note, currentUser(env), nil); err != nil {
		return err
	}
	fmt.Fprintf(env.Stdout, "acknowledged %s\n", rest[0])
	fmt.Fprintf(env.Stderr, "note: it will resurface only if its severity increases\n")
	return nil
}

func runMute(env Env, args []string) error {
	fs := newFlagSet(env, "mute")
	repoPath := fs.String("repo-path", "", "repository to update (default: current directory)")
	forDur := fs.Duration("for", 30*24*time.Hour, "how long to mute it")
	note := fs.String("note", "", "why this is muted")
	rest, err := parsePositionals(fs, args)
	if err != nil {
		return err
	}
	if len(rest) != 1 {
		return fmt.Errorf("usage: mute <finding-id> [--for 720h]")
	}
	l, _, err := newLinker(env, *repoPath)
	if err != nil {
		return err
	}
	until := time.Now().Add(*forDur).UTC()
	if err := l.Store.SetFindingStatus(rest[0], model.StatusMuted, *note, currentUser(env), &until); err != nil {
		return err
	}
	fmt.Fprintf(env.Stdout, "muted %s until %s\n", rest[0], until.Format(time.RFC3339))
	return nil
}

func currentUser(env Env) string {
	getenv := env.Getenv
	if getenv == nil {
		getenv = os.Getenv
	}
	if u := getenv("USER"); u != "" {
		return u
	}
	return "cli"
}

func runDoctor(env Env, args []string) error {
	fs := newFlagSet(env, "doctor")
	repoPath := fs.String("repo-path", "", "repository to inspect (default: current directory)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	l, root, err := newLinker(env, *repoPath)
	if err != nil {
		return err
	}
	fmt.Fprintf(env.Stdout, "repository:   %s\n", root)
	if l.Config != nil && l.Config.Path != "" {
		fmt.Fprintf(env.Stdout, "config:       %s\n", l.Config.Path)
	} else {
		fmt.Fprintf(env.Stdout, "config:       none (create one with `config init`)\n")
	}
	fmt.Fprintf(env.Stdout, "state:        %s\n", l.Store.Path())

	if idx, _, ierr := loadIndex(env, root); ierr == nil {
		fmt.Fprintf(env.Stdout, "index:        %d calls across %d hosts\n", len(idx.Calls), len(idx.Hosts))
	} else {
		fmt.Fprintf(env.Stdout, "index:        none (run `scan`)\n")
	}

	st, err := l.Store.Read()
	if err != nil {
		return err
	}
	fmt.Fprintf(env.Stdout, "upstreams:    %d linked, %d deliberately unmonitored\n", len(st.Upstreams), len(st.Decisions))
	fmt.Fprintf(env.Stdout, "findings:     %d stored\n", len(st.Findings))

	// The credential is the most common reason a check cannot run, so it is
	// reported precisely rather than as a generic failure.
	getenv := env.Getenv
	if getenv == nil {
		getenv = os.Getenv
	}
	tokens := &ghsource.ChainTokenSource{Getenv: getenv}
	if _, terr := tokens.Token(context.Background()); terr != nil {
		fmt.Fprintf(env.Stdout, "github token: NOT FOUND\n")
		fmt.Fprintf(env.Stdout, "              set GITHUB_TOKEN, or run `gh auth login`.\n")
		fmt.Fprintf(env.Stdout, "              Everything except `check` works without one.\n")
		return nil
	}
	fmt.Fprintf(env.Stdout, "github token: found\n")

	src, err := newGitHubSource(env, l.Config)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	rates, err := src.RateLimits(ctx)
	if err != nil {
		fmt.Fprintf(env.Stdout, "github api:   unreachable or rejected: %v\n", ghsource.Redact(err.Error()))
		return nil
	}
	if core, ok := rates["core"]; ok {
		fmt.Fprintf(env.Stdout, "github api:   %d/%d requests remaining, resets %s\n",
			core.Remaining, core.Limit, core.Reset.Format(time.Kitchen))
	}
	return nil
}
