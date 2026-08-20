// Package monitor checks upstream repositories for changes that would break the
// API calls this repository makes.
//
// The orchestration here is mostly about restraint. A check that reports
// everything it notices is useless, and one that spends a developer's entire
// API quota to do it is worse, so the sequence is built around three ideas:
// skip upstreams that demonstrably have not moved, establish a baseline on
// first sight rather than reporting a repository's whole history, and let a
// finding's confidence lower its severity but never raise it.
package monitor

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/stephen-bee/endpoint-monitor/internal/config"
	"github.com/stephen-bee/endpoint-monitor/internal/ghsource"
	"github.com/stephen-bee/endpoint-monitor/internal/index"
	"github.com/stephen-bee/endpoint-monitor/internal/model"
	"github.com/stephen-bee/endpoint-monitor/internal/store"
)

// Options configures a check.
type Options struct {
	Store  *store.Store
	Source ghsource.GitHubSource
	Index  *index.Index
	Config *config.File

	Now func() time.Time
	// Hosts restricts the check to these hosts; empty means every linked host.
	Hosts []string
	// Repos restricts the check to these canonical repository URLs.
	Repos       []string
	MinSeverity model.Severity
	// Force ignores stored validators and re-analyzes the whole window.
	Force   bool
	Trigger string
	// Progress is called after each upstream so a long check can report itself.
	Progress func(done, total int, message string)

	// MaxFiles bounds how many changed files one comparison may yield.
	MaxFiles int
	// MaxSpecBytes bounds the total specification content fetched per run.
	MaxSpecBytes int64
	// MinRateRemaining stops scheduling new upstreams once the budget falls
	// below it, returning partial results rather than exhausting the quota.
	MinRateRemaining int
}

// UpstreamError records one upstream that could not be checked.
type UpstreamError struct {
	Host string `json:"host"`
	Repo string `json:"repo"`
	Err  string `json:"error"`
}

// Result is the outcome of a check.
type Result struct {
	RunID     string          `json:"run_id"`
	Complete  bool            `json:"complete"`
	Checked   int             `json:"upstreams_checked"`
	Skipped   int             `json:"upstreams_skipped"`
	New       []model.Finding `json:"new_findings,omitempty"`
	Updated   int             `json:"updated_findings"`
	Counts    model.Counts    `json:"counts"`
	Degraded  []string        `json:"degraded,omitempty"`
	Errors    []UpstreamError `json:"errors,omitempty"`
	Rate      ghsource.Rate   `json:"rate_limit"`
	APICalls  int             `json:"api_calls"`
	Baselined []string        `json:"baselined,omitempty"`
}

func (o Options) now() time.Time {
	if o.Now != nil {
		return o.Now()
	}
	return time.Now()
}

// Run performs a check across every linked upstream.
func Run(ctx context.Context, opts Options) (*Result, error) {
	if opts.Store == nil || opts.Source == nil {
		return nil, fmt.Errorf("monitor: a store and a GitHub source are required")
	}
	if opts.MaxFiles <= 0 {
		opts.MaxFiles = 300
	}
	if opts.MaxSpecBytes <= 0 {
		opts.MaxSpecBytes = 32 << 20
	}
	if opts.MinSeverity == "" {
		opts.MinSeverity = model.SeverityInfo
	}

	st, err := opts.Store.Read()
	if err != nil {
		return nil, err
	}
	targets := selectUpstreams(st, opts)

	run, err := opts.Store.StartRun(orDefault(opts.Trigger, "cli"))
	if err != nil {
		return nil, err
	}
	res := &Result{RunID: run.ID, Complete: true}

	budget := &specBudget{remaining: opts.MaxSpecBytes}
	var allFindings []model.Finding

	for i, u := range targets {
		if err := ctx.Err(); err != nil {
			res.Complete = false
			break
		}
		if opts.Progress != nil {
			opts.Progress(i, len(targets), u.Host+" -> "+u.Repo.Slug())
		}
		// Stop before spending the last of the quota; partial results the user
		// can act on beat a exhausted budget and nothing to show.
		if opts.MinRateRemaining > 0 && res.Rate.Remaining > 0 && res.Rate.Remaining < opts.MinRateRemaining {
			res.Complete = false
			res.Degraded = appendUnique(res.Degraded, "rate_budget_reached")
			res.Skipped += len(targets) - i
			break
		}

		out, err := checkUpstream(ctx, opts, st, u, budget)
		if out != nil {
			res.APICalls += out.calls
			if out.rate.Remaining > 0 || out.rate.Limit > 0 {
				res.Rate = out.rate
			}
			res.Degraded = appendUniqueAll(res.Degraded, out.degraded)
			if out.baselined {
				res.Baselined = append(res.Baselined, u.Host+" ("+u.Repo.Slug()+")")
			}
			if out.skipped {
				res.Skipped++
			} else {
				res.Checked++
			}
			allFindings = append(allFindings, out.findings...)
			if out.state != nil {
				if serr := opts.Store.SetCheckState(u.Repo.Key(), *out.state); serr != nil {
					return res, serr
				}
			}
		}
		if err != nil {
			res.Errors = append(res.Errors, UpstreamError{
				Host: u.Host, Repo: u.Repo.Canonical(),
				Err: ghsource.Redact(err.Error()),
			})
			if ghsource.IsRateLimited(err) {
				// Continuing would only collect more of the same error.
				res.Complete = false
				res.Degraded = appendUnique(res.Degraded, "rate_limited")
				res.Skipped += len(targets) - i - 1
				break
			}
		}
	}
	if opts.Progress != nil {
		opts.Progress(len(targets), len(targets), "done")
	}

	kept := filterSeverity(allFindings, opts.MinSeverity)
	added, updated, err := opts.Store.UpsertFindings(kept)
	if err != nil {
		return res, err
	}
	_ = added
	res.Updated = updated
	res.New = newOnly(kept, opts.Store)
	res.Counts = model.CountBySeverity(res.New)
	model.SortFindings(res.New)

	run.Checked, run.Skipped = res.Checked, res.Skipped
	run.APICalls, run.NewFindings = res.APICalls, len(res.New)
	run.Counts, run.Degraded = res.Counts, res.Degraded
	for _, e := range res.Errors {
		run.Errors = append(run.Errors, e.Host+": "+e.Err)
	}
	if err := opts.Store.FinishRun(run); err != nil {
		return res, err
	}
	return res, nil
}

// newOnly returns the findings that were not already present before this run.
// Re-reporting something the user has already seen is how a monitor trains
// people to ignore it.
func newOnly(fresh []model.Finding, s *store.Store) []model.Finding {
	st, err := s.Read()
	if err != nil {
		return fresh
	}
	firstSeen := map[string]int{}
	for _, f := range st.Findings {
		firstSeen[f.Fingerprint] = f.Occurrences
	}
	var out []model.Finding
	for _, f := range fresh {
		if firstSeen[f.Fingerprint] <= 1 {
			for _, stored := range st.Findings {
				if stored.Fingerprint == f.Fingerprint {
					out = append(out, stored)
					break
				}
			}
		}
	}
	return out
}

// selectUpstreams resolves which upstreams this run covers.
func selectUpstreams(st *store.State, opts Options) []model.Upstream {
	hostFilter := map[string]bool{}
	for _, h := range opts.Hosts {
		hostFilter[h] = true
	}
	repoFilter := map[string]bool{}
	for _, r := range opts.Repos {
		repoFilter[strings.ToLower(r)] = true
	}
	var out []model.Upstream
	for _, u := range st.Upstreams {
		if u.Status != "" && u.Status != "active" {
			continue
		}
		if len(hostFilter) > 0 && !hostFilter[u.Host] {
			continue
		}
		if len(repoFilter) > 0 && !repoFilter[strings.ToLower(u.Repo.Canonical())] && !repoFilter[strings.ToLower(u.Repo.Slug())] {
			continue
		}
		out = append(out, u)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Host != out[j].Host {
			return out[i].Host < out[j].Host
		}
		return out[i].Repo.Key() < out[j].Repo.Key()
	})
	return out
}

// specBudget bounds total specification bytes fetched in one run.
type specBudget struct{ remaining int64 }

func (b *specBudget) take(n int64) bool {
	if b.remaining < n {
		return false
	}
	b.remaining -= n
	return true
}

// upstreamResult is the per-upstream outcome.
type upstreamResult struct {
	findings  []model.Finding
	state     *store.UpstreamState
	degraded  []string
	calls     int
	rate      ghsource.Rate
	skipped   bool
	baselined bool
}

// checkUpstream runs the whole sequence for one upstream.
func checkUpstream(ctx context.Context, opts Options, st *store.State, u model.Upstream, budget *specBudget) (*upstreamResult, error) {
	res := &upstreamResult{}
	repoID := ghsource.RepoID{Owner: u.Repo.Owner, Name: u.Repo.Name}
	prev := st.Checks[u.Repo.Key()]
	next := prev
	if next.ETags == nil {
		next.ETags = map[string]string{}
	}

	cond := ghsource.Cond{}
	if !opts.Force {
		cond.ETag = prev.ETags["repo"]
	}
	repo, meta, err := opts.Source.Repo(ctx, repoID, cond)
	res.calls += meta.Calls
	res.rate = meta.Rate
	if err != nil {
		next.ConsecutiveFailures++
		next.LastError = ghsource.Redact(err.Error())
		if ghsource.IsNotFound(err) {
			next.Status = "inaccessible"
		}
		res.state = &next
		return res, err
	}
	if meta.ETag != "" {
		next.ETags["repo"] = meta.ETag
	}
	next.ConsecutiveFailures, next.LastError, next.Status = 0, "", "active"

	// The cheapest possible gate. Most repositories have not moved since the
	// last check, and skipping them here costs one conditional request that
	// often returns 304 for free.
	if repo == nil && meta.NotModified {
		res.skipped = true
		next.LastCheckedAt = opts.now().UTC()
		res.state = &next
		return res, nil
	}
	if repo != nil {
		next.DefaultBranch = repo.DefaultBranch
		if repo.Archived {
			next.Status = "archived"
			res.skipped = true
			next.LastCheckedAt = opts.now().UTC()
			res.state = &next
			res.degraded = appendUnique(res.degraded, "upstream_archived")
			res.state = &next
			return res, nil
		}
		if !opts.Force && !prev.PushedAtSeen.IsZero() && !repo.PushedAt.After(prev.PushedAtSeen) {
			res.skipped = true
			next.LastCheckedAt = opts.now().UTC()
			res.state = &next
			return res, nil
		}
		next.PushedAtSeen = repo.PushedAt
	}

	head := u.Repo.Ref
	if head == "" {
		head = next.DefaultBranch
	}
	if head == "" {
		head = "HEAD"
	}

	// First sight of an upstream establishes a baseline and reports nothing.
	// Emitting a repository's entire history as findings on day one destroys
	// trust permanently, and none of it is actionable anyway.
	if prev.LastHeadSHA == "" {
		next.LastHeadSHA = resolveHead(ctx, opts, repoID, head, res)
		next.LastCheckedAt = opts.now().UTC()
		next.SpecPaths = discoverSpecs(ctx, opts, repoID, head, u, res)
		if rel, tag := latestRelease(ctx, opts, repoID, res); rel != "" {
			next.LastReleaseTag = rel
			next.LastTagName = tag
		}
		res.baselined = true
		res.state = &next
		return res, nil
	}

	targets := targetsFor(opts.Index, u)
	if len(targets.Targets) == 0 {
		// Nothing in this repository depends on that upstream any more.
		res.skipped = true
		next.LastCheckedAt = opts.now().UTC()
		res.state = &next
		return res, nil
	}

	cmp, cmeta, cerr := opts.Source.Compare(ctx, repoID, prev.LastHeadSHA, head, ghsource.CompareOptions{
		MaxFiles:   opts.MaxFiles,
		PathPrefix: u.Repo.Subpath,
	})
	res.calls += cmeta.Calls
	if cmeta.Rate.Limit > 0 {
		res.rate = cmeta.Rate
	}
	if cerr != nil {
		// A base SHA that no longer resolves means history was rewritten. There
		// is nothing to diff against, so re-baseline and say so rather than
		// reporting a phantom change.
		if ghsource.IsBadRef(cerr) || ghsource.IsNotFound(cerr) {
			next.LastHeadSHA = resolveHead(ctx, opts, repoID, head, res)
			next.LastCheckedAt = opts.now().UTC()
			res.degraded = appendUnique(res.degraded, "history_rewritten")
			res.baselined = true
			res.state = &next
			return res, nil
		}
		res.state = &next
		return res, cerr
	}
	if cmp == nil || (cmp.Status != "" && cmp.Status != "ahead" && cmp.Status != "diverged") {
		// identical or behind: the branch was reset, so re-anchor quietly.
		if cmp != nil && cmp.HeadSHA != "" {
			next.LastHeadSHA = cmp.HeadSHA
		}
		res.skipped = true
		next.LastCheckedAt = opts.now().UTC()
		res.state = &next
		return res, nil
	}
	if cmp.FilesTruncated {
		// In a truncated list, a file's absence proves nothing, so the
		// line-level signals must not draw conclusions from it.
		res.degraded = appendUnique(res.degraded, "files_truncated")
	}

	headSHA := cmp.HeadSHA
	if headSHA == "" {
		headSHA = head
	}

	ac := &analysisContext{
		opts: opts, upstream: u, repoID: repoID, targets: targets,
		compare: cmp, baseSHA: prev.LastHeadSHA, headSHA: headSHA,
		budget: budget, specPaths: prev.SpecPaths,
	}
	res.findings = append(res.findings, ac.analyzeSpecs(ctx, res)...)
	if !cmp.FilesTruncated {
		res.findings = append(res.findings, ac.analyzeDiff()...)
	}
	res.findings = append(res.findings, ac.analyzeCommits()...)
	res.findings = append(res.findings, ac.analyzeReleases(ctx, &next, res)...)
	res.degraded = appendUniqueAll(res.degraded, ac.degraded)

	next.LastHeadSHA = headSHA
	next.LastCheckedAt = opts.now().UTC()
	if len(ac.foundSpecs) > 0 {
		next.SpecPaths = mergeStrings(next.SpecPaths, ac.foundSpecs)
	}
	res.state = &next
	return res, nil
}

// resolveHead finds the current head SHA, falling back to the ref name when it
// cannot be resolved.
func resolveHead(ctx context.Context, opts Options, id ghsource.RepoID, ref string, res *upstreamResult) string {
	commits, meta, err := opts.Source.CommitsSince(ctx, id, time.Time{}, "", ghsource.ListOptions{PerPage: 1, MaxPages: 1})
	res.calls += meta.Calls
	if err == nil && len(commits) > 0 {
		return commits[0].SHA
	}
	return ref
}

// discoverSpecs looks once for the API descriptions in a repository, so later
// runs know where to look without re-listing the tree.
func discoverSpecs(ctx context.Context, opts Options, id ghsource.RepoID, ref string, u model.Upstream, res *upstreamResult) []string {
	paths, meta, err := opts.Source.ListTree(ctx, id, ref, u.Repo.Subpath)
	res.calls += meta.Calls
	if err != nil {
		return nil
	}
	var out []string
	for _, p := range paths {
		if isSpecPath(p) {
			out = append(out, p)
		}
	}
	sort.Strings(out)
	if len(out) > 20 {
		out = out[:20]
	}
	return out
}

func latestRelease(ctx context.Context, opts Options, id ghsource.RepoID, res *upstreamResult) (string, string) {
	rels, meta, err := opts.Source.Releases(ctx, id, ghsource.Cond{}, ghsource.ListOptions{PerPage: 5, MaxPages: 1})
	res.calls += meta.Calls
	if err == nil {
		for _, r := range rels {
			if !r.Draft && !r.Prerelease {
				return r.TagName, r.TagName
			}
		}
	}
	return "", ""
}

// targetsFor builds the endpoint target set for one upstream, honouring the
// path prefix that scopes it.
func targetsFor(idx *index.Index, u model.Upstream) *TargetSet {
	if idx == nil {
		return NewTargetSet(nil)
	}
	var calls []index.Call
	for _, c := range idx.Calls {
		if c.Host != u.Host {
			continue
		}
		if !u.Matches(c.Path) {
			continue
		}
		calls = append(calls, c)
	}
	return NewTargetSet(calls)
}

func filterSeverity(fs []model.Finding, min model.Severity) []model.Finding {
	out := make([]model.Finding, 0, len(fs))
	for _, f := range fs {
		if f.Confidence < DropBelow && f.Severity == model.SeverityInfo {
			continue
		}
		if f.Severity.AtLeast(min) {
			out = append(out, f)
		}
	}
	return out
}

// fingerprint identifies a finding by what it claims, not when it was found, so
// the same upstream change is never reported twice.
func fingerprint(signal, repoKey, subject string, endpointIDs []string) string {
	sorted := append([]string(nil), endpointIDs...)
	sort.Strings(sorted)
	sum := sha256.Sum256([]byte(strings.Join(append([]string{signal, repoKey, subject}, sorted...), "\x00")))
	return "fp_" + hex.EncodeToString(sum[:])[:16]
}

func orDefault(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

func appendUnique(list []string, s string) []string {
	for _, e := range list {
		if e == s {
			return list
		}
	}
	return append(list, s)
}

func appendUniqueAll(list []string, more []string) []string {
	for _, s := range more {
		list = appendUnique(list, s)
	}
	return list
}

func mergeStrings(a, b []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range append(append([]string{}, a...), b...) {
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}
