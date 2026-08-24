package monitor

import (
	"context"
	"fmt"
	"net/url"
	"sort"
	"strings"

	"github.com/sfbee/api-integrity-tool/internal/config"
	"github.com/sfbee/api-integrity-tool/internal/ghsource"
	"github.com/sfbee/api-integrity-tool/internal/index"
	"github.com/sfbee/api-integrity-tool/internal/model"
	"github.com/sfbee/api-integrity-tool/internal/monitor/analyze"
	"github.com/sfbee/api-integrity-tool/internal/monitor/analyze/openapi"
	"github.com/sfbee/api-integrity-tool/internal/store"
)

// SignalUndocumented marks an endpoint this repository calls that no upstream
// specification declares.
const SignalUndocumented = "spec.undocumented"

// Coverage answers a different question from the rest of the monitor.
//
// Everything else here is change-driven: it diffs two commits and reports what
// moved. This is state-driven: it asks whether the endpoints we call are
// declared anywhere in the upstream's specifications *right now*. An
// undocumented dependency is not a change — it is a standing risk, because
// nobody has promised to keep it working.
//
// That difference matters mechanically. checkUpstream returns early when the
// upstream has not been pushed since the last check, so a coverage check placed
// among the analyzers would only ever run on days the upstream happened to move.
// This runs outside that gate.
type CoverageOptions struct {
	Store  *store.Store
	Source ghsource.GitHubSource
	Index  *index.Index
	// Config supplies host_mappings, so a symbolic host resolves to the real
	// hostname the upstream is linked under.
	Config *config.File

	// Hosts restricts the check to these hosts; empty means every linked host.
	Hosts []string
	// MaxSpecBytes bounds the specification content fetched per run.
	MaxSpecBytes int64
}

// EndpointCoverage is the verdict for one endpoint we call.
type EndpointCoverage struct {
	EndpointID string `json:"endpoint_id"`
	Method     string `json:"method"`
	Path       string `json:"path"`
	CallSite   string `json:"call_site,omitempty"`
	Documented bool   `json:"documented"`
	// Spec is the specification that declares this endpoint, when one does.
	Spec string `json:"spec,omitempty"`
	// SpecOp is the operation as the specification spells it, which is often
	// worth seeing: the parameter names differ from ours.
	SpecOp string `json:"spec_operation,omitempty"`
}

// CoverageResult is the verdict for one upstream.
type CoverageResult struct {
	Host      string             `json:"host"`
	Repo      string             `json:"repo"`
	HeadSHA   string             `json:"head_sha,omitempty"`
	Specs     []string           `json:"specs"`
	Endpoints []EndpointCoverage `json:"endpoints"`
	// Note records why a result may be incomplete, e.g. no specifications found.
	Note string `json:"note,omitempty"`
}

// Undocumented returns only the endpoints no specification declares.
func (r CoverageResult) Undocumented() []EndpointCoverage {
	var out []EndpointCoverage
	for _, e := range r.Endpoints {
		if !e.Documented {
			out = append(out, e)
		}
	}
	return out
}

// DefaultMaxSpecBytes bounds specification fetching when the caller sets no cap.
const DefaultMaxSpecBytes = 32 << 20

// Coverage compares the indexed endpoints against every specification the
// upstream publishes, and returns both a per-upstream report and the findings to
// persist.
func Coverage(ctx context.Context, opts CoverageOptions) ([]CoverageResult, []model.Finding, error) {
	st, err := opts.Store.Read()
	if err != nil {
		return nil, nil, err
	}
	max := opts.MaxSpecBytes
	if max <= 0 {
		max = DefaultMaxSpecBytes
	}
	budget := &specBudget{remaining: max}

	wanted := map[string]bool{}
	for _, h := range opts.Hosts {
		wanted[strings.ToLower(h)] = true
	}

	var results []CoverageResult
	var findings []model.Finding
	for _, u := range st.Upstreams {
		if len(wanted) > 0 && !wanted[strings.ToLower(u.Host)] {
			continue
		}
		res, fs, err := coverUpstream(ctx, opts, st, u, budget)
		if err != nil {
			return results, findings, err
		}
		if res != nil {
			results = append(results, *res)
			findings = append(findings, fs...)
		}
	}
	sort.Slice(results, func(i, j int) bool {
		if results[i].Host != results[j].Host {
			return results[i].Host < results[j].Host
		}
		return results[i].Repo < results[j].Repo
	})
	return results, findings, nil
}

func coverUpstream(ctx context.Context, opts CoverageOptions, st *store.State, u model.Upstream, budget *specBudget) (*CoverageResult, []model.Finding, error) {
	targets := targetsFor(opts.Index, u, opts.Config)
	if len(targets.Targets) == 0 {
		return nil, nil, nil
	}
	id := ghsource.RepoID{Owner: u.Repo.Owner, Name: u.Repo.Name}
	out := &CoverageResult{Host: u.Host, Repo: u.Repo.Canonical()}

	ref := u.Repo.Ref
	if ref == "" {
		if cs, ok := st.Checks[u.Repo.Key()]; ok {
			ref = cs.DefaultBranch
		}
	}
	if ref == "" {
		repo, _, err := opts.Source.Repo(ctx, id, ghsource.Cond{})
		if err != nil {
			return nil, nil, fmt.Errorf("read %s: %w", u.Repo.Canonical(), err)
		}
		ref = repo.DefaultBranch
	}
	out.HeadSHA = ref

	specPaths := specPathsFor(ctx, opts, st, u, id, ref)
	if len(specPaths) == 0 {
		// With no specification there is nothing to be documented by, so
		// reporting every endpoint as undocumented would be noise, not news.
		out.Note = "no OpenAPI or Swagger specification found in the upstream; coverage cannot be determined"
		for _, t := range targets.Targets {
			out.Endpoints = append(out.Endpoints, EndpointCoverage{
				EndpointID: t.ID, Method: t.Method, Path: t.Path, CallSite: t.CallSite,
			})
		}
		sortCoverage(out.Endpoints)
		return out, nil, nil
	}

	declared := newDeclaredSet()
	for _, p := range specPaths {
		if !budget.take(1) {
			break
		}
		fc, _, err := opts.Source.FileAtRef(ctx, id, p, ref, ghsource.Cond{})
		if err != nil || fc == nil {
			continue
		}
		if !budget.take(int64(len(fc.Content))) {
			continue
		}
		doc, err := openapi.Parse(fc.Content)
		if err != nil || doc == nil {
			continue
		}
		declared.add(p, doc)
		out.Specs = append(out.Specs, p)
	}
	sort.Strings(out.Specs)
	if len(out.Specs) == 0 {
		out.Note = "specifications were found but none could be parsed"
	}

	for _, t := range targets.Targets {
		cov := EndpointCoverage{
			EndpointID: t.ID, Method: t.Method, Path: t.Path, CallSite: t.CallSite,
		}
		if spec, op, ok := declared.lookup(t); ok {
			cov.Documented, cov.Spec, cov.SpecOp = true, spec, op
		}
		out.Endpoints = append(out.Endpoints, cov)
	}
	sortCoverage(out.Endpoints)

	var findings []model.Finding
	for _, e := range out.Endpoints {
		if e.Documented {
			continue
		}
		findings = appendUndocumented(findings, u, e, out)
	}
	return out, findings, nil
}

func appendUndocumented(findings []model.Finding, u model.Upstream, e EndpointCoverage, out *CoverageResult) []model.Finding {
	subject := e.Method + " " + e.Path
	return append(findings, model.Finding{
		Fingerprint: fingerprint(SignalUndocumented, u.Repo.Key(), subject, []string{e.EndpointID}),
		Signal:      SignalUndocumented,
		Severity:    model.SeverityInfo,
		Confidence:  0.9,
		Title:       fmt.Sprintf("%s is not declared in any %s specification", subject, u.Host),
		Detail: fmt.Sprintf(
			"This repository calls %s, but none of the %d specification(s) published by %s declares it (%s). "+
				"An undocumented endpoint carries no compatibility promise, so it can change without any of the "+
				"signals this monitor watches for.",
			subject, len(out.Specs), u.Repo.Canonical(), strings.Join(out.Specs, ", ")),
		Suggestion: "Confirm the endpoint is intended for external use, or ask the upstream to document it.",
		Host:       u.Host,
		Repo:       u.Repo,
		Endpoints:  []model.EndpointRef{{ID: e.EndpointID, Method: e.Method, Path: e.Path, CallSite: e.CallSite}},
		Status:     model.StatusOpen,
	})
}

// declaredSet is every operation the upstream's specifications declare, keyed so
// a call can be looked up regardless of how the specification spells its
// parameters or where its server prefix lives.
type declaredSet struct {
	ops   map[string]declaredOp
	bases []string
}

type declaredOp struct {
	spec string
	op   string
}

func newDeclaredSet() *declaredSet {
	return &declaredSet{ops: map[string]declaredOp{}}
}

func (d *declaredSet) add(specPath string, doc *openapi.Doc) {
	bases := serverBasePaths(doc.Servers)
	for _, b := range bases {
		d.bases = appendUnique(d.bases, b)
	}
	for key, op := range doc.Operations {
		_ = op
		norm := NormalizeTemplate(key.Path)
		rec := declaredOp{spec: specPath, op: key.Method + " " + key.Path}
		d.put(key.Method, norm, rec)
		// A specification declares paths relative to its servers, while a call
		// site may have the server's prefix baked into the URL. Register both
		// spellings so either matches.
		for _, b := range bases {
			d.put(key.Method, NormalizeTemplate(b+key.Path), rec)
		}
	}
}

func (d *declaredSet) put(method, path string, rec declaredOp) {
	if _, exists := d.ops[opKey(method, path)]; !exists {
		d.ops[opKey(method, path)] = rec
	}
}

// lookup reports whether a target is declared, trying the path as recorded and
// then with each server prefix stripped.
func (d *declaredSet) lookup(t Target) (string, string, bool) {
	candidates := []string{t.NormTemplate}
	for _, b := range d.bases {
		if b == "" {
			continue
		}
		if trimmed, ok := stripPrefixPath(t.NormTemplate, b); ok {
			candidates = append(candidates, trimmed)
		}
	}
	methods := []string{t.Method}
	if t.Method != index.MethodAny {
		// A call whose method we could not determine matches any declaration,
		// and a declaration should not be missed because our method is unknown.
		methods = append(methods, index.MethodAny)
	}
	for _, p := range candidates {
		for _, m := range methods {
			if rec, ok := d.ops[opKey(m, p)]; ok {
				return rec.spec, rec.op, true
			}
		}
		if t.Method == index.MethodAny {
			// Unknown method: any declared method on this path counts.
			for _, m := range []string{"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"} {
				if rec, ok := d.ops[opKey(m, p)]; ok {
					return rec.spec, rec.op, true
				}
			}
		}
	}
	return "", "", false
}

// serverBasePaths extracts the path component of each declared server, which is
// where an API's version prefix usually lives -- "/30" or
// "/api/partner/v3".
func serverBasePaths(servers []string) []string {
	var out []string
	for _, s := range servers {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		p := s
		if u, err := url.Parse(s); err == nil && u.Path != "" {
			p = u.Path
		} else if !strings.HasPrefix(s, "/") {
			continue
		}
		p = "/" + strings.Trim(p, "/")
		if p == "/" {
			continue
		}
		out = appendUnique(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return len(out[i]) > len(out[j]) })
	return out
}

// stripPrefixPath removes a server prefix from a path on a segment boundary.
func stripPrefixPath(p, prefix string) (string, bool) {
	if prefix == "" || prefix == "/" {
		return p, false
	}
	if p == prefix {
		return "/", true
	}
	if strings.HasPrefix(p, prefix+"/") {
		return p[len(prefix):], true
	}
	return p, false
}

func sortCoverage(cs []EndpointCoverage) {
	sort.Slice(cs, func(i, j int) bool {
		if cs[i].Documented != cs[j].Documented {
			// Undocumented first: it is the actionable half.
			return !cs[i].Documented
		}
		if cs[i].Path != cs[j].Path {
			return cs[i].Path < cs[j].Path
		}
		return cs[i].Method < cs[j].Method
	})
}

// SpecPathsFor is exported for the coverage command; it prefers the paths
// already discovered by a previous check and falls back to listing the tree.
func specPathsFor(ctx context.Context, opts CoverageOptions, st *store.State, u model.Upstream, id ghsource.RepoID, ref string) []string {
	if cs, ok := st.Checks[u.Repo.Key()]; ok && len(cs.SpecPaths) > 0 {
		return cs.SpecPaths
	}
	paths, _, err := opts.Source.ListTree(ctx, id, ref, u.Repo.Subpath)
	if err != nil {
		return nil
	}
	var out []string
	for _, p := range paths {
		if analyze.IsSpecPath(p) {
			out = appendUnique(out, p)
		}
	}
	sort.Strings(out)
	return out
}
