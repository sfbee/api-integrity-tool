package monitor

import (
	"regexp"
	"sort"
	"strings"

	"github.com/stephen-bee/endpoint-monitor/internal/index"
	"github.com/stephen-bee/endpoint-monitor/internal/model"
)

// Target is one of my endpoints, prepared for matching against upstream text.
//
// Matching precision starts here. A finding that cites the wrong endpoint is
// worse than no finding, and the cheapest way to be wrong is to match a path so
// generic that it appears everywhere.
type Target struct {
	ID       string
	Method   string
	Path     string
	CallSite string
	Score    int

	// NormTemplate collapses every placeholder to {} so /users/{userId} and
	// /users/{id} compare equal. Upstream authors do not name their parameters
	// the way our scanner does.
	NormTemplate string
	// Variants are the spellings the same route takes across frameworks:
	// {id}, :id, <id>, <int:id>, %s, #{id}, $id, [id].
	Variants []string
	Segments []string
	// Distinctive holds segments substantial enough to identify this endpoint.
	// Requiring one is what stops "/", "/v1" and "/health" from matching
	// everything in a diff.
	Distinctive []string

	pathRe *regexp.Regexp
}

// TargetSet indexes targets for a host.
type TargetSet struct {
	Targets []Target
	byOp    map[string][]int
	byLit   map[string][]int
}

// structuralTokens are path segments that carry no identifying information.
var structuralTokens = map[string]bool{
	"api": true, "rest": true, "public": true, "internal": true, "graphql": true,
	"latest": true, "current": true, "service": true, "services": true,
	"v1": true, "v2": true, "v3": true, "v4": true, "v5": true, "v6": true,
	"v7": true, "v8": true, "v9": true, "v10": true, "health": true, "status": true,
	"ping": true, "index": true, "root": true, "default": true,
}

var placeholderRe = regexp.MustCompile(`\{[^}]*\}`)

// NewTargetSet prepares the calls for a host.
func NewTargetSet(calls []index.Call) *TargetSet {
	ts := &TargetSet{byOp: map[string][]int{}, byLit: map[string][]int{}}
	for _, c := range calls {
		if c.Lifecycle.Status == index.StatusRemoved {
			continue
		}
		t := newTarget(c)
		ts.Targets = append(ts.Targets, t)
		i := len(ts.Targets) - 1
		ts.byOp[opKey(t.Method, t.NormTemplate)] = append(ts.byOp[opKey(t.Method, t.NormTemplate)], i)
		for _, v := range t.Variants {
			ts.byLit[v] = append(ts.byLit[v], i)
		}
	}
	return ts
}

func newTarget(c index.Call) Target {
	t := Target{
		ID: c.ID, Method: c.Method, Path: c.Path, Score: c.Score,
		CallSite:     c.Location.File + ":" + itoa(c.Location.Line),
		NormTemplate: NormalizeTemplate(c.Path),
	}
	for _, s := range strings.Split(strings.Trim(c.Path, "/"), "/") {
		if s == "" {
			continue
		}
		t.Segments = append(t.Segments, s)
		low := strings.ToLower(s)
		if len(s) >= 4 && !structuralTokens[low] && !strings.HasPrefix(s, "{") && s != "**" {
			t.Distinctive = append(t.Distinctive, s)
		}
	}
	t.Variants = variantsOf(c.Path)
	t.pathRe = pathRegexp(c.Path)
	return t
}

// NormalizeTemplate rewrites every placeholder to {} so two spellings of the
// same route compare equal.
func NormalizeTemplate(path string) string {
	p := placeholderRe.ReplaceAllString(path, "{}")
	p = regexp.MustCompile(`:[A-Za-z_][A-Za-z0-9_]*`).ReplaceAllString(p, "{}")
	p = regexp.MustCompile(`<[^>]*>`).ReplaceAllString(p, "{}")
	p = regexp.MustCompile(`\[[A-Za-z_.]+\]`).ReplaceAllString(p, "{}")
	p = strings.ReplaceAll(p, "%s", "{}")
	p = strings.ReplaceAll(p, "%d", "{}")
	if p != "/" {
		p = strings.TrimSuffix(p, "/")
	}
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	return p
}

// variantsOf renders a path in the spellings different frameworks use, so a
// literal search finds it however the upstream wrote it.
func variantsOf(path string) []string {
	segs := strings.Split(path, "/")
	styles := []func(name string) string{
		func(n string) string { return "{" + n + "}" },
		func(n string) string { return ":" + n },
		func(n string) string { return "<" + n + ">" },
		func(n string) string { return "[" + n + "]" },
		func(n string) string { return "*" },
	}
	seen := map[string]bool{}
	var out []string
	add := func(s string) {
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	add(path)
	hasPlaceholder := false
	for _, s := range segs {
		if strings.HasPrefix(s, "{") {
			hasPlaceholder = true
		}
	}
	if !hasPlaceholder {
		return out
	}
	for _, style := range styles {
		var b []string
		for _, s := range segs {
			if strings.HasPrefix(s, "{") && strings.HasSuffix(s, "}") {
				b = append(b, style(strings.Trim(s, "{}")))
				continue
			}
			b = append(b, s)
		}
		add(strings.Join(b, "/"))
	}
	return out
}

// pathRegexp builds a matcher where each placeholder consumes one segment.
func pathRegexp(path string) *regexp.Regexp {
	var b strings.Builder
	b.WriteString("^")
	for _, part := range strings.Split(path, "/") {
		if part == "" {
			continue
		}
		b.WriteString("/")
		switch {
		case part == "**":
			b.WriteString(".*")
		case strings.HasPrefix(part, "{"):
			b.WriteString(`[^/]+`)
		default:
			b.WriteString(regexp.QuoteMeta(part))
		}
	}
	b.WriteString("/?$")
	re, err := regexp.Compile(b.String())
	if err != nil {
		return nil
	}
	return re
}

func opKey(method, path string) string { return strings.ToUpper(method) + " " + path }

// MatchOperation returns the targets an upstream operation affects. A method of
// ANY on either side matches any method, since an undetermined verb should not
// silently exclude a real dependency.
func (ts *TargetSet) MatchOperation(method, path string) []Target {
	norm := NormalizeTemplate(path)
	var out []Target
	for _, i := range ts.byOp[opKey(method, norm)] {
		out = append(out, ts.Targets[i])
	}
	if len(out) > 0 {
		return out
	}
	for _, t := range ts.Targets {
		if t.NormTemplate != norm {
			continue
		}
		if strings.EqualFold(t.Method, method) || t.Method == index.MethodAny || strings.EqualFold(method, "any") {
			out = append(out, t)
		}
	}
	return out
}

// MatchText returns the targets whose path literal appears in a line of
// upstream source or diff.
//
// A match requires a distinctive segment and at least two path segments.
// Without those guards a target like "/v1" matches half of any diff, which is
// the fastest route to a tool nobody trusts.
func (ts *TargetSet) MatchText(line string) []Target {
	if strings.TrimSpace(line) == "" {
		return nil
	}
	var out []Target
	seen := map[string]bool{}
	for lit, idxs := range ts.byLit {
		if len(lit) < 2 || !strings.Contains(line, lit) {
			continue
		}
		for _, i := range idxs {
			t := ts.Targets[i]
			if len(t.Segments) < 2 || len(t.Distinctive) == 0 {
				continue
			}
			if seen[t.ID] {
				continue
			}
			// The distinctive part must be what matched, not just any substring.
			distinctiveHit := false
			for _, d := range t.Distinctive {
				if strings.Contains(line, d) {
					distinctiveHit = true
					break
				}
			}
			if !distinctiveHit {
				continue
			}
			seen[t.ID] = true
			out = append(out, t)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// Refs converts targets into the endpoint references a finding carries.
func Refs(ts []Target) []model.EndpointRef {
	out := make([]model.EndpointRef, 0, len(ts))
	for _, t := range ts {
		out = append(out, model.EndpointRef{ID: t.ID, Method: t.Method, Path: t.Path, CallSite: t.CallSite})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// MeanScore returns the average scanner confidence of the matched endpoints,
// normalised to 0..1. A finding about a low-confidence call inherits that
// uncertainty.
func MeanScore(ts []Target) float64 {
	if len(ts) == 0 {
		return 0.5
	}
	sum := 0
	for _, t := range ts {
		sum += t.Score
	}
	return float64(sum) / float64(len(ts)) / 100.0
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	neg := n < 0
	if neg {
		n = -n
	}
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}
