// Package scan orchestrates a full repository scan: find files, detect call
// sites, resolve URLs, classify, and merge the result into the existing index.
//
// The pipeline is deliberately staged so that every stage is deterministic.
// Detection runs in parallel because it dominates the runtime, but results are
// written into a slice indexed by file position rather than accumulated through
// a map, so the output cannot depend on goroutine scheduling. There is a test
// that runs the same fixture at several worker counts and demands byte-identical
// output; that test is the reason this design is worth the small extra care.
package scan

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path"
	"runtime"
	"sort"
	"sync"
	"time"

	"github.com/stephen-bee/endpoint-monitor/internal/classify"
	"github.com/stephen-bee/endpoint-monitor/internal/detect"
	"github.com/stephen-bee/endpoint-monitor/internal/detect/golang"
	"github.com/stephen-bee/endpoint-monitor/internal/gitmeta"
	"github.com/stephen-bee/endpoint-monitor/internal/index"
	"github.com/stephen-bee/endpoint-monitor/internal/normalize"
	"github.com/stephen-bee/endpoint-monitor/internal/resolve"
	"github.com/stephen-bee/endpoint-monitor/internal/walk"
)

// Options configures one scan.
type Options struct {
	// RepoPath is the directory to scan. The repository root is discovered from
	// it, so scanning a subdirectory still produces repo-relative paths.
	RepoPath string
	// Jobs is the detection concurrency. Zero means GOMAXPROCS.
	Jobs int
	// Languages limits detection. Empty means every registered language.
	Languages []detect.Language

	Walk      walk.Options
	Classify  classify.Options
	Normalize normalize.Options
	Merge     index.MergeOptions

	// Registry supplies the detectors. Nil means DefaultRegistry.
	Registry *detect.Registry
	// Git supplies commit metadata. Nil means the real git provider.
	Git gitmeta.Provider
	// Now supplies the scan timestamp. Nil means time.Now.
	Now func() time.Time
	// Version is recorded in the index for provenance.
	Version string
	// KeepDrops records every rejected site so --explain-drops can show them.
	KeepDrops bool
}

// Drop is one rejected call site, retained for explanation.
type Drop struct {
	File     string          `json:"file"`
	Line     int             `json:"line"`
	Reason   string          `json:"reason"`
	Pattern  string          `json:"pattern,omitempty"`
	Language detect.Language `json:"language,omitempty"`
	Host     string          `json:"host,omitempty"`
	Path     string          `json:"path,omitempty"`
	Src      string          `json:"src,omitempty"`
}

// Result is the outcome of a scan.
type Result struct {
	Index  *index.Index
	Prev   *index.Index
	Report *index.MergeReport
	Drops  []Drop
	// Errors holds non-fatal problems: unparseable files, unreadable files.
	// A scan reports them and completes rather than failing.
	Errors []string
}

// DefaultRegistry returns the detectors compiled into this binary.
func DefaultRegistry() *detect.Registry {
	r := detect.NewRegistry()
	r.Register(golang.New())
	return r
}

// Run performs a scan and returns the merged index without writing it. The
// caller decides whether to persist, which is what makes `scan --check` and
// read-only checkouts possible.
func Run(ctx context.Context, opts Options) (*Result, error) {
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	started := now().UTC()

	reg := opts.Registry
	if reg == nil {
		reg = DefaultRegistry()
	}
	gitp := opts.Git
	if gitp == nil {
		gitp = gitmeta.Git{}
	}
	repoPath := opts.RepoPath
	if repoPath == "" {
		repoPath = "."
	}

	gi, err := gitp.Info(ctx, repoPath)
	if err != nil {
		return nil, fmt.Errorf("read git metadata: %w", err)
	}
	root := gi.Root
	if root == "" {
		root = repoPath
	}

	res := &Result{}
	wopts := opts.Walk
	wopts.Root = root
	if wopts.Extensions == nil {
		wopts.Extensions = extensionsFor(reg, opts.Languages)
	}
	if len(wopts.ExcludeDirs) == 0 {
		wopts.ExcludeDirs = defaultExcludeDirs()
	}

	candidates, wstats, err := walk.Find(ctx, wopts)
	if err != nil {
		return nil, err
	}

	// Read and detect in parallel, writing into a fixed slice so ordering is
	// independent of scheduling.
	type fileOut struct {
		cand   walk.Candidate
		src    *detect.SourceFile
		result *detect.FileResult
		skip   string
		err    error
	}
	outs := make([]fileOut, len(candidates))
	jobs := opts.Jobs
	if jobs <= 0 {
		jobs = max(4, runtime.GOMAXPROCS(0))
	}

	var wg sync.WaitGroup
	work := make(chan int)
	for range jobs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range work {
				outs[i] = detectOne(ctx, reg, candidates[i], root)
			}
		}()
	}
	var walkErr error
feed:
	for i := range candidates {
		select {
		case <-ctx.Done():
			walkErr = ctx.Err()
			break feed
		case work <- i:
		}
	}
	close(work)
	wg.Wait()
	if walkErr != nil {
		return nil, walkErr
	}

	stats := index.Stats{
		FilesWalked:  wstats.Walked,
		FilesSkipped: copyCounts(wstats.Skipped),
		ByLanguage:   map[string]int{},
		SitesDropped: map[string]int{},
	}
	if stats.FilesSkipped == nil {
		stats.FilesSkipped = map[string]int{}
	}

	// Group results for languages with cross-file scope, and collect per-group
	// module symbols before resolving anything.
	groupSymbols := map[string][]detect.SymbolDef{}
	type groupInput struct {
		files   []*detect.SourceFile
		results []*detect.FileResult
		det     detect.GroupDetector
	}
	groups := map[string]*groupInput{}
	for i := range outs {
		o := &outs[i]
		if o.skip != "" {
			stats.FilesSkipped[o.skip]++
			continue
		}
		if o.err != nil {
			res.Errors = append(res.Errors, o.err.Error())
			stats.FilesSkipped[walk.SkipUnreadable]++
			continue
		}
		if o.result == nil || o.src == nil {
			continue
		}
		stats.FilesScanned++
		stats.BytesScanned += o.src.Size
		stats.ByLanguage[string(o.src.Lang)] += len(o.result.Sites)
		stats.ParseErrors += len(o.result.Errors)
		for _, e := range o.result.Errors {
			res.Errors = append(res.Errors, e.Error())
		}
		det, ok := reg.ForLang(o.src.Lang)
		if !ok {
			continue
		}
		gd, ok := det.(detect.GroupDetector)
		if !ok {
			continue
		}
		key := string(o.src.Lang) + "\x00" + gd.GroupKey(o.src)
		g := groups[key]
		if g == nil {
			g = &groupInput{det: gd}
			groups[key] = g
		}
		g.files = append(g.files, o.src)
		g.results = append(g.results, o.result)
	}
	groupKeys := make([]string, 0, len(groups))
	for k := range groups {
		groupKeys = append(groupKeys, k)
	}
	sort.Strings(groupKeys)
	for _, k := range groupKeys {
		g := groups[k]
		groupSymbols[k] = g.det.ResolveGroup(ctx, g.files, g.results)
	}

	// Resolve, normalize and classify. Sequential: it is a small fraction of the
	// runtime and staying single-threaded here removes any chance of ordering
	// nondeterminism in the output.
	var calls []index.Call
	for i := range outs {
		o := &outs[i]
		if o.result == nil || o.src == nil || o.skip != "" {
			continue
		}
		stats.SitesDetected += len(o.result.Sites)

		syms := append([]detect.SymbolDef{}, o.result.Symbols...)
		if det, ok := reg.ForLang(o.src.Lang); ok {
			if gd, ok := det.(detect.GroupDetector); ok {
				syms = append(syms, groupSymbols[string(o.src.Lang)+"\x00"+gd.GroupKey(o.src)]...)
			}
		}
		table := resolve.NewSymbolTable(syms)
		bindings := map[string]*detect.Expr{}
		for _, b := range o.result.Bindings {
			bindings[b.InstanceName] = b.BaseURL
		}

		for _, site := range o.result.Sites {
			r := &resolve.Resolver{Symbols: table, Bindings: bindings, Func: site.Func}
			method := resolveMethod(r, site)
			for _, one := range r.ResolveWithBase(site.URLExpr, site.BaseHint) {
				canon := normalize.Canonicalize(one.Segments, opts.Normalize)
				dec := classify.Classify(classify.Input{
					File:      o.src.RelPath,
					Generated: o.src.Generated,
					Language:  o.src.Lang,
					Detector:  detectorName(o.src.Lang),
					Site:      site,
					Res:       one,
					Canon:     canon,
				}, opts.Classify)
				if !dec.Keep {
					stats.SitesDropped[dec.Reason]++
					if opts.KeepDrops {
						res.Drops = append(res.Drops, Drop{
							File: o.src.RelPath, Line: site.Pos.Line, Reason: dec.Reason,
							Pattern: site.Pattern, Language: o.src.Lang,
							Host: canon.Host, Path: canon.Path, Src: site.Src,
						})
					}
					continue
				}
				calls = append(calls, index.Call{
					Host: canon.Host, HostKind: canon.HostKind, Scheme: canon.Scheme,
					Port: canon.Port, Method: method, Path: canon.Path,
					PathVars: canon.PathVars, QueryKeys: canon.QueryKeys,
					Kind: index.KindHTTP, RawExpr: site.Src,
					Location: index.Location{
						File: o.src.RelPath, Line: site.Pos.Line,
						Column: site.Pos.Col, Function: site.Func,
					},
					Language: o.src.Lang, Client: site.Client, Pattern: site.Pattern,
					Detector: detectorName(o.src.Lang), Score: dec.Score,
					Confidence: index.ConfidenceFor(dec.Score),
					Flags:      dec.Flags, Unresolved: one.Unresolved,
				})
			}
		}
	}

	stats.UnresolvedTop = topUnresolved(calls, 10)
	index.AssignIdentity(calls)

	next := &index.Index{
		SchemaVersion: index.SchemaVersion,
		Tool: index.ToolInfo{
			Name: "api-integrity-tool", Version: opts.Version,
			DetectorVersion: index.DetectorVersion,
		},
		Repo: index.RepoInfo{
			Root: path.Base(root), Remote: gi.Remote, DefaultBranch: gi.DefaultBranch,
		},
		Scan: index.ScanInfo{
			ID: index.ScanID(gi.Commit, started), Commit: gi.Commit, Dirty: gi.Dirty,
			Branch: gi.Branch, StartedAt: started,
			DurationMS: now().UTC().Sub(started).Milliseconds(),
			Partial:    isPartial(opts),
			Filters:    describeFilters(opts),
		},
		Stats: stats,
		Calls: calls,
	}

	prev, err := index.Load(root)
	if err != nil {
		return nil, err
	}
	mopts := opts.Merge
	if mopts.PruneAfterMissingScans == 0 {
		mopts.PruneAfterMissingScans = index.DefaultPruneAfterMissingScans
	}
	mopts.Partial = next.Scan.Partial
	if mopts.Partial && mopts.PartialScope == nil {
		mopts.PartialScope = partialScopeFor(opts)
	}
	merged, report := index.Merge(prev, next, mopts)

	sort.Slice(res.Drops, func(i, j int) bool {
		if res.Drops[i].File != res.Drops[j].File {
			return res.Drops[i].File < res.Drops[j].File
		}
		if res.Drops[i].Line != res.Drops[j].Line {
			return res.Drops[i].Line < res.Drops[j].Line
		}
		return res.Drops[i].Reason < res.Drops[j].Reason
	})
	sort.Strings(res.Errors)
	res.Index, res.Prev, res.Report = merged, prev, report
	return res, nil
}

// Save persists a scan result to the repository.
func Save(root string, r *Result) error {
	return index.Save(gitmeta.FindRoot(root), r.Index)
}

func detectOne(ctx context.Context, reg *detect.Registry, c walk.Candidate, root string) (out struct {
	cand   walk.Candidate
	src    *detect.SourceFile
	result *detect.FileResult
	skip   string
	err    error
}) {
	out.cand = c
	det, ok := reg.ForExt(c.Ext)
	if !ok {
		out.skip = walk.SkipUnknownExt
		return out
	}
	content, err := os.ReadFile(c.AbsPath)
	if err != nil {
		out.err = fmt.Errorf("read %s: %w", c.RelPath, err)
		return out
	}
	if reason := walk.ContentSkipReason(content); reason != "" {
		out.skip = reason
		return out
	}
	src := &detect.SourceFile{
		RelPath:   c.RelPath,
		AbsPath:   c.AbsPath,
		Lang:      det.Language(),
		Content:   content,
		Size:      int64(len(content)),
		Hash:      sha256.Sum256(content),
		Generated: walk.IsGenerated(content),
	}
	result, err := det.Detect(ctx, src)
	if err != nil && !errors.Is(err, context.Canceled) {
		out.err = err
		return out
	}
	// Content is not retained past this point: detectors copy what they need.
	out.src = &detect.SourceFile{
		RelPath: src.RelPath, AbsPath: src.AbsPath, Lang: src.Lang,
		Size: src.Size, Hash: src.Hash, Generated: src.Generated,
	}
	out.result = result
	return out
}

func resolveMethod(r *resolve.Resolver, site detect.RawSite) string {
	if site.MethodExpr == nil {
		return index.MethodAny
	}
	for _, m := range r.Resolve(site.MethodExpr) {
		if lit, ok := m.LiteralString(); ok && lit != "" {
			return upper(lit)
		}
	}
	return index.MethodAny
}

func upper(s string) string {
	b := []byte(s)
	for i := range b {
		if b[i] >= 'a' && b[i] <= 'z' {
			b[i] -= 32
		}
	}
	return string(b)
}

func detectorName(l detect.Language) string {
	if l == detect.LangGo {
		return "go/ast"
	}
	return "regex/" + string(l)
}

func extensionsFor(reg *detect.Registry, langs []detect.Language) map[string]bool {
	want := map[detect.Language]bool{}
	for _, l := range langs {
		want[l] = true
	}
	out := map[string]bool{}
	for _, ext := range reg.Extensions() {
		d, ok := reg.ForExt(ext)
		if !ok {
			continue
		}
		if len(want) == 0 || want[d.Language()] {
			out[ext] = true
		}
	}
	return out
}

func defaultExcludeDirs() []string {
	return []string{
		"vendor", "node_modules", "bower_components", ".venv", "venv", "virtualenv",
		"site-packages", "target", "build", "dist", "out", "obj", ".next", ".nuxt",
		".svelte-kit", "coverage", ".git", ".idea", ".vscode", ".tox", ".mypy_cache",
		"__pycache__", ".gradle", ".m2", "Pods", "Carthage", "third_party",
		"3rdparty", "external", index.DirName,
	}
}

// isPartial reports whether traversal was narrowed. It matters for merging: a
// narrowed scan must not conclude that unseen calls were deleted.
func isPartial(opts Options) bool {
	return len(opts.Languages) > 0 || len(opts.Walk.PathGlobs) > 0 || len(opts.Walk.ExcludeGlobs) > 0
}

func describeFilters(opts Options) []string {
	var out []string
	for _, l := range opts.Languages {
		out = append(out, "lang="+string(l))
	}
	for _, g := range opts.Walk.PathGlobs {
		out = append(out, "path="+g)
	}
	for _, g := range opts.Walk.ExcludeGlobs {
		out = append(out, "exclude="+g)
	}
	sort.Strings(out)
	return out
}

// partialScopeFor builds the predicate that decides whether a previously-known
// call could have been seen by this narrowed scan.
func partialScopeFor(opts Options) func(index.Call) bool {
	langs := map[detect.Language]bool{}
	for _, l := range opts.Languages {
		langs[l] = true
	}
	globs := opts.Walk.PathGlobs
	return func(c index.Call) bool {
		if len(langs) > 0 && !langs[c.Language] {
			return false
		}
		if len(globs) > 0 {
			matched := false
			for _, g := range globs {
				if ok, _ := path.Match(g, c.Location.File); ok {
					matched = true
					break
				}
				trimmed := trimGlobDir(g)
				if trimmed != "" && (c.Location.File == trimmed || hasPrefixDir(c.Location.File, trimmed)) {
					matched = true
					break
				}
			}
			if !matched {
				return false
			}
		}
		return true
	}
}

func trimGlobDir(g string) string {
	for _, suf := range []string{"/**", "/*", "/"} {
		if len(g) > len(suf) && g[len(g)-len(suf):] == suf {
			return g[:len(g)-len(suf)]
		}
	}
	return g
}

func hasPrefixDir(p, dir string) bool {
	return len(p) > len(dir)+1 && p[:len(dir)] == dir && p[len(dir)] == '/'
}

func topUnresolved(calls []index.Call, n int) []string {
	counts := map[string]int{}
	for _, c := range calls {
		for _, u := range c.Unresolved {
			counts[u]++
		}
	}
	if len(counts) == 0 {
		return nil
	}
	keys := make([]string, 0, len(counts))
	for k := range counts {
		keys = append(keys, k)
	}
	// Most frequent first, name as the tiebreak so the list is stable.
	sort.Slice(keys, func(i, j int) bool {
		if counts[keys[i]] != counts[keys[j]] {
			return counts[keys[i]] > counts[keys[j]]
		}
		return keys[i] < keys[j]
	})
	if len(keys) > n {
		keys = keys[:n]
	}
	return keys
}

func copyCounts(in map[string]int) map[string]int {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]int, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}
