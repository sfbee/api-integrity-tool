package monitor

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/sfbee/api-integrity-tool/internal/ghsource"
	"github.com/sfbee/api-integrity-tool/internal/model"
	"github.com/sfbee/api-integrity-tool/internal/monitor/analyze"
	"github.com/sfbee/api-integrity-tool/internal/monitor/analyze/openapi"
	"github.com/sfbee/api-integrity-tool/internal/store"
)

// analysisContext carries everything the analyzers need for one upstream.
type analysisContext struct {
	opts     Options
	upstream model.Upstream
	repoID   ghsource.RepoID
	targets  *TargetSet
	compare  *ghsource.Compare
	baseSHA  string
	headSHA  string
	budget   *specBudget
	// specPaths are the descriptions discovered when this upstream was first
	// seen, so a specification is still compared even if the comparison's file
	// list does not obviously name it.
	specPaths  []string
	foundSpecs []string
	degraded   []string
}

const maxSpecFileBytes = 8 << 20

// analyzeSpecs structurally diffs any API description that changed.
//
// This is the analyzer worth having. It fetches both whole documents rather
// than reading the patch, because GitHub omits the patch for large files and a
// textual diff cannot express "this parameter became required" anyway.
func (a *analysisContext) analyzeSpecs(ctx context.Context, res *upstreamResult) []model.Finding {
	changed := map[string]bool{}
	for _, f := range a.compare.Files {
		if isSpecPath(f.Filename) {
			changed[f.Filename] = true
			a.foundSpecs = append(a.foundSpecs, f.Filename)
		}
	}
	// A spec-only upstream exists to be diffed, so check its known
	// descriptions even when the file list did not obviously name one.
	if a.upstream.Role == model.RoleSpecOnly {
		for _, p := range a.specPaths {
			changed[p] = true
		}
	}
	if len(changed) == 0 {
		return nil
	}

	paths := make([]string, 0, len(changed))
	for p := range changed {
		paths = append(paths, p)
	}
	sort.Strings(paths)

	var out []model.Finding
	for _, p := range paths {
		if !a.budget.take(int64(maxSpecFileBytes) / 8) {
			a.degraded = appendUnique(a.degraded, "spec_budget_exhausted")
			break
		}
		baseDoc, ok1 := a.fetchSpec(ctx, p, a.baseSHA, res)
		headDoc, ok2 := a.fetchSpec(ctx, p, a.headSHA, res)
		if !ok1 || !ok2 {
			// A specification that appeared or disappeared wholesale is not a
			// structural diff; the file-level signals cover it.
			continue
		}
		changes := openapi.Diff(baseDoc, headDoc)
		if len(changes) == 0 {
			continue
		}
		out = append(out, a.findingsFromSpec(p, changes)...)
	}
	return out
}

func (a *analysisContext) fetchSpec(ctx context.Context, path, ref string, res *upstreamResult) (*openapi.Doc, bool) {
	fc, meta, err := a.opts.Source.FileAtRef(ctx, a.repoID, path, ref, ghsource.Cond{})
	res.calls += meta.Calls
	if err != nil || fc == nil {
		return nil, false
	}
	if fc.Truncated || len(fc.Content) == 0 {
		a.degraded = appendUnique(a.degraded, "spec_too_large")
		return nil, false
	}
	doc, err := openapi.Parse(fc.Content)
	if err != nil {
		// An unparseable description is reported once as information, and the
		// weaker line-level signals still run.
		a.degraded = appendUnique(a.degraded, "spec_unparseable")
		return nil, false
	}
	return doc, true
}

// findingsFromSpec converts specification changes into findings, keeping only
// those that touch an endpoint this repository actually calls.
func (a *analysisContext) findingsFromSpec(specPath string, changes []openapi.Change) []model.Finding {
	var out []model.Finding
	var unrelated int

	for _, c := range changes {
		var matched []Target
		quality := MatchExact
		switch {
		case c.Op.Path == "":
			// A document-wide change affects every endpoint on the host.
			matched = a.targets.Targets
			quality = MatchHost
		default:
			matched = a.targets.MatchOperation(c.Op.Method, c.Op.Path)
			if len(matched) == 0 && c.Op.Method == "" {
				matched = a.targets.MatchOperation("ANY", c.Op.Path)
			}
			if NormalizeTemplate(c.Op.Path) != c.Op.Path {
				quality = MatchTemplate
			}
		}
		if len(matched) == 0 {
			unrelated++
			continue
		}
		if c.Kind == openapi.SignalAdditive {
			unrelated++
			continue
		}

		proposed := model.SeverityRisky
		if c.Breaking {
			proposed = model.SeverityBreaking
		}
		switch c.Kind {
		case openapi.SignalDeprecated, openapi.SignalSunset, openapi.SignalMajorVersionBump:
			proposed = model.SeverityRisky
		case openapi.SignalStatusRemoved, openapi.SignalParamRemoved:
			proposed = model.SeverityRisky
		}

		sev, conf := Rate(c.Kind, proposed, quality, analyze.ClassSpec.Weight(), MeanScore(matched))
		refs := Refs(matched)
		ids := make([]string, 0, len(refs))
		for _, r := range refs {
			ids = append(ids, r.ID)
		}
		f := model.Finding{
			Fingerprint: fingerprint(c.Kind, a.upstream.Repo.Key(), c.Pointer+"|"+c.Before+"->"+c.After, ids),
			Signal:      c.Kind,
			Severity:    sev,
			Confidence:  conf,
			Title:       specTitle(c),
			Detail:      c.Detail,
			Suggestion:  specSuggestion(c),
			Host:        a.upstream.Host,
			Repo:        a.upstream.Repo,
			BaseSHA:     a.baseSHA,
			HeadSHA:     a.headSHA,
			CompareURL:  a.compare.HTMLURL,
			Endpoints:   refs,
			Evidence: []model.Evidence{{
				Kind:         model.EvidenceSpecNode,
				File:         specPath,
				JSONPointer:  c.Pointer,
				Before:       c.Before,
				After:        c.After,
				PermalinkURL: a.upstream.Repo.BlobURL(a.headSHA, specPath, 0),
			}},
			Status: model.StatusOpen,
		}
		out = append(out, f)
	}

	// Everything that does not touch my endpoints collapses into a single
	// informational line. This is the largest single reduction in noise the
	// monitor makes: a specification commit routinely changes hundreds of
	// operations, and almost none of them matter to any one caller.
	if unrelated > 0 {
		out = append(out, model.Finding{
			Fingerprint: fingerprint("openapi.unrelated_rollup", a.upstream.Repo.Key(), specPath+"@"+a.headSHA, nil),
			Signal:      "openapi.unrelated_rollup",
			Severity:    model.SeverityInfo,
			Confidence:  0.9,
			Title:       fmt.Sprintf("%s changed in %d other places", specPath, unrelated),
			Detail: fmt.Sprintf("%d specification changes did not affect any of the %d endpoints this repository calls.",
				unrelated, len(a.targets.Targets)),
			Host: a.upstream.Host, Repo: a.upstream.Repo,
			BaseSHA: a.baseSHA, HeadSHA: a.headSHA, CompareURL: a.compare.HTMLURL,
			Status: model.StatusOpen,
		})
	}
	return out
}

func specTitle(c openapi.Change) string {
	op := c.Op.String()
	if c.Op.Path == "" {
		op = "the specification"
	}
	switch c.Kind {
	case openapi.SignalPathRemoved:
		return "Path removed: " + c.Op.Path
	case openapi.SignalOperationRemoved:
		return "Operation removed: " + op
	case openapi.SignalRequiredParamAdded:
		return "New required parameter on " + op
	case openapi.SignalParamNowRequired:
		return "Parameter became required on " + op
	case openapi.SignalResponseFieldGone:
		return "Response field removed from " + op
	case openapi.SignalAuthChanged:
		return "Authentication requirement changed on " + op
	case openapi.SignalDeprecated:
		return "Deprecated: " + op
	case openapi.SignalSunset:
		return "Sunset announced for " + op
	case openapi.SignalServerChanged:
		return "Server URL changed"
	default:
		return strings.TrimPrefix(c.Kind, "openapi.") + " on " + op
	}
}

func specSuggestion(c openapi.Change) string {
	switch c.Kind {
	case openapi.SignalPathRemoved, openapi.SignalOperationRemoved:
		return "Find the replacement endpoint and update the call sites listed above."
	case openapi.SignalRequiredParamAdded, openapi.SignalParamNowRequired:
		return "Send the newly required parameter from every call site listed above."
	case openapi.SignalBodyNowRequired, openapi.SignalBodyPropRequired:
		return "Include the newly required request body field."
	case openapi.SignalResponseFieldGone:
		return "Stop depending on the removed response field."
	case openapi.SignalAuthChanged, openapi.SignalScopeAdded:
		return "Review the credentials and scopes these calls send."
	case openapi.SignalDeprecated, openapi.SignalSunset:
		return "Plan a migration before the endpoint is withdrawn."
	case openapi.SignalServerChanged:
		return "Update the base URL these calls use."
	default:
		return ""
	}
}

// analyzeDiff looks for endpoint paths on removed diff lines.
//
// This is the weakest of the path-level signals and needs the most guarding.
// Its single largest false positive is a rename or a reformat, where a literal
// disappears from one line and reappears on another, so any literal that is
// also added somewhere in the same window is downgraded.
func (a *analysisContext) analyzeDiff() []model.Finding {
	// Collect every added line first so removals can be cancelled.
	added := map[string]bool{}
	for _, f := range a.compare.Files {
		for _, h := range analyze.ParseHunks(f.Patch) {
			for _, l := range h.Lines {
				if l.Added() {
					for _, t := range a.targets.MatchText(l.Text) {
						added[t.ID] = true
					}
				}
			}
		}
	}

	type hit struct {
		target Target
		file   string
		class  analyze.Class
		line   analyze.Line
		hunk   analyze.Hunk
	}
	var hits []hit
	for _, f := range a.compare.Files {
		class := analyze.Classify(f.Filename)
		if class == analyze.ClassSpec {
			// The structural differ already covered this file properly.
			continue
		}
		for _, h := range analyze.ParseHunks(f.Patch) {
			for _, l := range h.Lines {
				if !l.Removed() {
					continue
				}
				for _, t := range a.targets.MatchText(l.Text) {
					hits = append(hits, hit{target: t, file: f.Filename, class: class, line: l, hunk: h})
				}
			}
		}
	}

	// Cap per endpoint so one sweeping refactor cannot produce fifty findings
	// that all say the same thing.
	const maxPerEndpoint = 3
	perEndpoint := map[string]int{}
	var out []model.Finding
	for _, h := range hits {
		if perEndpoint[h.target.ID] >= maxPerEndpoint {
			continue
		}
		perEndpoint[h.target.ID]++

		signal := "diff.removed_path_literal"
		proposed := model.SeverityRisky
		detail := fmt.Sprintf("The path %s was removed from %s.", h.target.Path, h.file)

		switch {
		case added[h.target.ID]:
			// The same path appears on an added line: this is a move or a
			// reformat, not a removal.
			signal = "diff.route_moved"
			proposed = model.SeverityInfo
			detail = fmt.Sprintf("The path %s moved within %s rather than being removed.", h.target.Path, h.file)
		case analyze.IsCommentLine(h.line.Text):
			proposed = model.SeverityInfo
			detail = fmt.Sprintf("The path %s was removed from a comment in %s.", h.target.Path, h.file)
		case h.class.CanBreak() && (h.class == analyze.ClassRoutes || analyze.HasMethodToken(h.line.Text)):
			// A route file, or a line that also names an HTTP verb, is the
			// strongest form this signal takes.
			proposed = model.SeverityRisky
		}

		sev, conf := Rate(signal, proposed, MatchVariant, h.class.Weight(), MeanScore([]Target{h.target}))

		// Line-level diff scanning is capped at RISKY, deliberately and
		// unconditionally. A path literal vanishing from a line is a hint, not
		// a statement about the interface: the same text appears in tests,
		// fixtures, logs, comments and client code, and only the structural
		// specification and route analyzers can say an endpoint is actually
		// gone. One false BREAKING costs more trust than ten missed hints, so
		// this signal is not allowed to make that claim.
		sev = Cap(sev, model.SeverityRisky)
		refs := Refs([]Target{h.target})
		out = append(out, model.Finding{
			Fingerprint: fingerprint(signal, a.upstream.Repo.Key(),
				h.file+":"+h.target.Path+":"+strconv.Itoa(h.line.OldLine), []string{h.target.ID}),
			Signal:     signal,
			Severity:   sev,
			Confidence: conf,
			Title:      fmt.Sprintf("%s %s removed in %s", h.target.Method, h.target.Path, h.file),
			Detail:     detail,
			Suggestion: "Confirm whether the endpoint still exists before relying on it.",
			Host:       a.upstream.Host, Repo: a.upstream.Repo,
			BaseSHA: a.baseSHA, HeadSHA: a.headSHA, CompareURL: a.compare.HTMLURL,
			Endpoints: refs,
			Evidence: []model.Evidence{{
				Kind: model.EvidenceDiffHunk, File: h.file, Line: h.line.OldLine,
				Hunk:         analyze.Snippet(h.hunk, 3, 24),
				PermalinkURL: a.upstream.Repo.BlobURL(a.baseSHA, h.file, h.line.OldLine),
			}},
			Status: model.StatusOpen,
		})
	}
	return out
}

// analyzeCommits reads commit messages for announced incompatibilities.
func (a *analysisContext) analyzeCommits() []model.Finding {
	var out []model.Finding
	for _, c := range a.compare.Commits {
		if !analyze.MentionsBreakingChange(c.Message) {
			continue
		}
		matched := a.targets.MatchText(c.Message)
		quality := MatchVariant
		if len(matched) == 0 {
			// An announced break that does not name one of my endpoints is
			// worth knowing about but cannot be attributed.
			matched = nil
			quality = MatchHost
		}
		ids := make([]string, 0, len(matched))
		for _, t := range matched {
			ids = append(ids, t.ID)
		}
		proposed := model.SeverityRisky
		if len(matched) == 0 {
			proposed = model.SeverityInfo
		}
		sev, conf := Rate("changelog.breaking_commit", proposed, quality, analyze.ClassSource.Weight(), MeanScore(matched))
		out = append(out, model.Finding{
			Fingerprint: fingerprint("changelog.breaking_commit", a.upstream.Repo.Key(), c.SHA, ids),
			Signal:      "changelog.breaking_commit",
			Severity:    sev,
			Confidence:  conf,
			Title:       "Upstream commit announces a breaking change",
			Detail:      firstLine(c.Message),
			Host:        a.upstream.Host, Repo: a.upstream.Repo,
			CommitSHA: c.SHA, BaseSHA: a.baseSHA, HeadSHA: a.headSHA,
			CompareURL: a.compare.HTMLURL,
			Endpoints:  Refs(matched),
			Evidence: []model.Evidence{{
				Kind: model.EvidenceCommitMessage, Before: firstLine(c.Message),
				PermalinkURL: c.HTMLURL,
			}},
			Status: model.StatusOpen,
		})
	}
	return out
}

// analyzeReleases reports a major version bump, which is the upstream telling
// you in its own words that something incompatible happened.
func (a *analysisContext) analyzeReleases(ctx context.Context, next *store.UpstreamState, res *upstreamResult) []model.Finding {
	rels, meta, err := a.opts.Source.Releases(ctx, a.repoID, ghsource.Cond{}, ghsource.ListOptions{PerPage: 10, MaxPages: 1})
	res.calls += meta.Calls
	if err != nil || len(rels) == 0 {
		return nil
	}
	var latest *ghsource.Release
	for i := range rels {
		if !rels[i].Draft && !rels[i].Prerelease {
			latest = &rels[i]
			break
		}
	}
	if latest == nil {
		return nil
	}
	prevTag := next.LastReleaseTag
	next.LastReleaseTag = latest.TagName
	if prevTag == "" || prevTag == latest.TagName {
		return nil
	}
	if !majorBump(prevTag, latest.TagName) {
		return nil
	}

	matched := a.targets.MatchText(latest.Body)
	proposed := model.SeverityRisky
	quality := MatchHost
	if len(matched) > 0 && analyze.MentionsBreakingChange(latest.Body) {
		// The release notes both announce a break and name one of my endpoints.
		proposed = model.SeverityBreaking
		quality = MatchVariant
	}
	ids := make([]string, 0, len(matched))
	for _, t := range matched {
		ids = append(ids, t.ID)
	}
	sev, conf := Rate("release.major_bump", proposed, quality, analyze.ClassSource.Weight(), MeanScore(matched))
	return []model.Finding{{
		Fingerprint: fingerprint("release.major_bump", a.upstream.Repo.Key(), prevTag+"->"+latest.TagName, ids),
		Signal:      "release.major_bump",
		Severity:    sev,
		Confidence:  conf,
		Title:       fmt.Sprintf("Major version bump: %s to %s", prevTag, latest.TagName),
		Detail:      firstLine(latest.Body),
		Suggestion:  "Read the release notes before upgrading, and check the endpoints listed above.",
		Host:        a.upstream.Host, Repo: a.upstream.Repo,
		BaseSHA: a.baseSHA, HeadSHA: a.headSHA,
		Endpoints: Refs(matched),
		Evidence: []model.Evidence{{
			Kind: model.EvidenceReleaseNote, Before: prevTag, After: latest.TagName,
			Hunk: truncate(latest.Body, 800), PermalinkURL: latest.HTMLURL,
		}},
		Status: model.StatusOpen,
	}}
}

// isSpecPath reports whether a repository path is an API description.
func isSpecPath(p string) bool { return analyze.IsSpecPath(p) }

// majorBump reports whether a semantic version's major component grew.
func majorBump(before, after string) bool {
	bm, ok1 := majorOf(before)
	am, ok2 := majorOf(after)
	return ok1 && ok2 && am > bm
}

func majorOf(v string) (int, bool) {
	v = strings.TrimPrefix(strings.TrimSpace(v), "v")
	if v == "" {
		return 0, false
	}
	if i := strings.IndexAny(v, ".-+"); i >= 0 {
		v = v[:i]
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return 0, false
	}
	return n, true
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	return truncate(s, 300)
}

func truncate(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n-1]) + "…"
}
