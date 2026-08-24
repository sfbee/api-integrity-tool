package cli

import (
	"context"
	"fmt"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/sfbee/api-integrity-tool/internal/monitor"
)

// runCoverage answers "which of the endpoints we call does the upstream
// actually document?".
//
// This is deliberately a separate command from `check` rather than part of it.
// `check` is change-driven and skips an upstream that has not moved; coverage is
// a standing property of the current state and has to be answerable at any time.
func runCoverage(env Env, args []string) error {
	fs := newFlagSet(env, "coverage")
	repoPath := fs.String("repo-path", "", "repository to inspect (default: current directory)")
	format := fs.String("format", "text", "output format: text or json")
	undocumentedOnly := fs.Bool("undocumented", false, "only list endpoints no specification declares")
	record := fs.Bool("record", true, "record undocumented endpoints as findings, so they appear in `findings` and the dashboard")
	timeout := fs.Duration("timeout", 2*time.Minute, "give up after this long")
	var hosts repeatedFlag
	fs.Var(&hosts, "host", "only this host (repeatable)")
	if err := fs.Parse(args); err != nil {
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

	results, findings, err := monitor.Coverage(ctx, monitor.CoverageOptions{
		Store: l.Store, Source: src, Index: idx, Config: l.Config, Hosts: hosts,
	})
	if err != nil {
		return err
	}

	added, updated, resolved := 0, 0, 0
	if *record {
		if len(findings) > 0 {
			added, updated, err = l.Store.UpsertFindings(findings)
			if err != nil {
				return err
			}
		}
		// Coverage recomputes every endpoint each run, so a stored finding this
		// run did not produce has stopped being true and is retracted. Only
		// complete results qualify: after a failed specification fetch the run
		// knows nothing, and retracting on that basis would erase real findings.
		live := make(map[string]bool, len(findings))
		for _, f := range findings {
			live[f.Fingerprint] = true
		}
		for _, r := range results {
			if r.Incomplete {
				continue
			}
			n, err := l.Store.ResolveStale(monitor.SignalUndocumented, r.RepoKey, live,
				"resolved: now declared in a specification, or no longer called")
			if err != nil {
				return err
			}
			resolved += n
		}
	}

	if *format == "json" {
		return writeJSON(env.Stdout, map[string]any{
			"upstreams":         results,
			"findings_added":    added,
			"findings_updated":  updated,
			"findings_resolved": resolved,
		})
	}
	printCoverage(env, results, *undocumentedOnly, added, resolved)
	return nil
}

func printCoverage(env Env, results []monitor.CoverageResult, undocumentedOnly bool, added, resolved int) {
	if len(results) == 0 {
		fmt.Fprintln(env.Stderr, "no linked upstream has any indexed endpoints; run `scan` and `link` first")
		return
	}
	for _, r := range results {
		undoc := r.Undocumented()
		fmt.Fprintf(env.Stdout, "==> %s (%s)\n", r.Host, r.Repo)
		if r.Note != "" {
			fmt.Fprintf(env.Stdout, "    %s\n", r.Note)
		}
		if len(r.Specs) > 0 {
			fmt.Fprintf(env.Stdout, "    %d specification(s): %s\n", len(r.Specs), strings.Join(r.Specs, ", "))
		}
		if r.Incomplete {
			fmt.Fprintf(env.Stdout, "    %d endpoint(s) called, coverage undetermined\n", len(r.Endpoints))
		} else {
			fmt.Fprintf(env.Stdout, "    %d endpoint(s) called, %d undocumented\n", len(r.Endpoints), len(undoc))
		}

		rows := r.Endpoints
		if undocumentedOnly {
			rows = undoc
		}
		if len(rows) == 0 {
			continue
		}
		tw := tabwriter.NewWriter(env.Stdout, 0, 8, 2, ' ', 0)
		fmt.Fprintln(tw, "    STATUS\tMETHOD\tPATH\tDOCUMENTED BY\tCALL SITE")
		for _, e := range rows {
			status, by := "MISSING", "-"
			if e.Documented {
				status, by = "ok", e.Spec
			} else if r.Incomplete {
				status, by = "?", "unknown"
			}
			fmt.Fprintf(tw, "    %s\t%s\t%s\t%s\t%s\n", status, e.Method, e.Path, by, e.CallSite)
		}
		tw.Flush()
	}
	if added > 0 {
		fmt.Fprintf(env.Stderr, "\n%d undocumented endpoint(s) recorded as findings\n", added)
	}
	if resolved > 0 {
		fmt.Fprintf(env.Stderr, "%d previously recorded finding(s) no longer apply and were resolved\n", resolved)
	}
}
