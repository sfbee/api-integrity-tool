// Package query filters an index.
//
// Four rules govern every filter, and they are worth stating plainly because
// users guess at them:
//
//  1. OR within a dimension.   --host=a.com --host=b.com  means either host.
//  2. AND across dimensions.   --host=a.com --endpoint=/x means both.
//  3. An empty dimension is a wildcard.
//  4. Exclude always beats include.
//
// Rule 2 is the non-obvious one. Somebody who combines dimensions is narrowing
// a search, not widening it, so intersecting is what they meant.
//
// Endpoint matching is template-insensitive: --endpoint=/users/:id matches an
// indexed /users/{user_id}, because the parameter's name is an implementation
// detail of the caller and nobody should have to guess how we spelled it.
package query

import (
	"fmt"
	"path"
	"regexp"
	"sort"
	"strings"

	"github.com/sfbee/api-integrity-tool/internal/detect"
	"github.com/sfbee/api-integrity-tool/internal/index"
	"github.com/sfbee/api-integrity-tool/internal/normalize"
)

// EndpointMode selects how endpoint patterns are matched.
type EndpointMode string

const (
	// EndpointExact matches the whole normalized path.
	EndpointExact EndpointMode = "exact"
	// EndpointPrefix matches on segment boundaries.
	EndpointPrefix EndpointMode = "prefix"
)

// RegexTarget selects what a --regex pattern is matched against.
type RegexTarget string

const (
	// RegexURL matches scheme://host/path, the default.
	RegexURL RegexTarget = "url"
	// RegexPath matches the normalized path only.
	RegexPath RegexTarget = "path"
	// RegexRaw matches the raw source expression, useful for finding all calls
	// built with Sprintf.
	RegexRaw RegexTarget = "raw"
	// RegexFile matches the source file path.
	RegexFile RegexTarget = "file"
)

// Filters is a filter specification. Every slice field is a dimension.
type Filters struct {
	Hosts     []string
	Vendors   []string
	Regexes   []string
	Endpoints []string
	Methods   []string
	Languages []string
	Clients   []string
	PathGlobs []string
	Kinds     []string

	RegexTarget   RegexTarget
	EndpointMode  EndpointMode
	MinConfidence index.Confidence

	// Exclude is applied after includes and always wins. It is one level deep:
	// nesting exclusions inside exclusions is a puzzle, not a feature.
	Exclude *Filters

	IncludeRemoved bool
	IncludeTests   bool
	// HostMappings resolves a symbolic host to the concrete hosts it stands for,
	// so --host=billing.acme.internal finds calls recorded against
	// ${env:BILLING_URL}. Mapping lives here, at query time, rather than in the
	// index: interpretation must not churn stored identity.
	HostMappings map[string][]string
}

// Selector is a compiled filter.
type Selector struct {
	f            Filters
	regexes      []*regexp.Regexp
	exclude      *Selector
	endpointSet  map[string]bool
	endpointPre  []string
	methods      map[string]bool
	languages    map[string]bool
	clients      map[string]bool
	kinds        map[string]bool
	vendors      map[string]bool
	minScoreBand int
	reverseHosts map[string][]string
}

// Compile validates and prepares f. It is the only place a bad regex or an
// unknown confidence level is reported, so callers get one clear error rather
// than a silent mismatch.
func Compile(f Filters) (*Selector, error) {
	s := &Selector{f: f}
	for _, r := range f.Regexes {
		re, err := regexp.Compile(r)
		if err != nil {
			return nil, fmt.Errorf("invalid --regex %q: %w", r, err)
		}
		s.regexes = append(s.regexes, re)
	}
	if len(f.Endpoints) > 0 {
		s.endpointSet = map[string]bool{}
		for _, e := range f.Endpoints {
			// A trailing /* or /** asks for prefix matching on this pattern
			// alone, which is friendlier than a separate mode flag.
			if trimmed, ok := trimWildcardSuffix(e); ok {
				s.endpointPre = append(s.endpointPre, PathTemplate(trimmed))
				continue
			}
			s.endpointSet[PathTemplate(e)] = true
		}
	}
	s.methods = upperSet(f.Methods)
	s.languages = lowerSet(f.Languages)
	s.clients = lowerSet(f.Clients)
	s.kinds = lowerSet(f.Kinds)
	s.vendors = lowerSet(f.Vendors)

	switch f.MinConfidence {
	case "", index.ConfLow:
		s.minScoreBand = 0
	case index.ConfMedium:
		s.minScoreBand = 50
	case index.ConfHigh:
		s.minScoreBand = 80
	default:
		return nil, fmt.Errorf("invalid --min-confidence %q: want low, medium or high", f.MinConfidence)
	}

	// Invert the host mapping so a concrete host finds the symbolic hosts that
	// stand for it.
	if len(f.HostMappings) > 0 {
		s.reverseHosts = map[string][]string{}
		for symbolic, concretes := range f.HostMappings {
			for _, c := range concretes {
				lc := strings.ToLower(c)
				s.reverseHosts[lc] = append(s.reverseHosts[lc], symbolic)
			}
		}
	}

	if f.Exclude != nil {
		ex := *f.Exclude
		ex.Exclude = nil
		// Exclusion is a pure predicate: lifecycle and confidence gates belong
		// to the include side only, or an exclusion would accidentally re-admit
		// removed calls.
		ex.IncludeRemoved, ex.IncludeTests = true, true
		ex.MinConfidence = ""
		ex.HostMappings = f.HostMappings
		sub, err := Compile(ex)
		if err != nil {
			return nil, err
		}
		s.exclude = sub
	}
	return s, nil
}

// Reason explains why a call did not match, for diagnostics.
type Reason string

// Match reports whether c passes the filter.
func (s *Selector) Match(c index.Call) (bool, Reason) {
	if s == nil {
		return true, ""
	}
	if !s.f.IncludeRemoved && c.Lifecycle.Status == index.StatusRemoved {
		return false, "removed"
	}
	if !s.f.IncludeTests && hasFlag(c.Flags, "test_file") {
		return false, "test_file"
	}
	if c.Score < s.minScoreBand {
		return false, "below_min_confidence"
	}
	if len(s.f.Hosts) > 0 && !s.matchHost(c) {
		return false, "host"
	}
	if len(s.vendors) > 0 && !s.vendors[strings.ToLower(c.Vendor)] {
		return false, "vendor"
	}
	if s.endpointSet != nil && !s.matchEndpoint(c) {
		return false, "endpoint"
	}
	if len(s.regexes) > 0 && !s.matchRegex(c) {
		return false, "regex"
	}
	if len(s.methods) > 0 && !s.methods[strings.ToUpper(c.Method)] {
		return false, "method"
	}
	if len(s.languages) > 0 && !s.languages[strings.ToLower(string(c.Language))] {
		return false, "language"
	}
	if len(s.clients) > 0 && !s.clients[strings.ToLower(c.Client)] {
		return false, "client"
	}
	if len(s.kinds) > 0 && !s.kinds[strings.ToLower(string(c.Kind))] {
		return false, "kind"
	}
	if len(s.f.PathGlobs) > 0 && !matchAnyGlob(c.Location.File, s.f.PathGlobs) {
		return false, "path_glob"
	}
	if s.exclude != nil {
		if ok, _ := s.exclude.Match(c); ok {
			return false, "excluded"
		}
	}
	return true, ""
}

// Apply returns the matching calls, preserving the index's canonical order.
func (s *Selector) Apply(calls []index.Call) []index.Call {
	out := make([]index.Call, 0, len(calls))
	for _, c := range calls {
		if ok, _ := s.Match(c); ok {
			out = append(out, c)
		}
	}
	return out
}

// Explain returns per-reason rejection counts, which is what makes "why did my
// filter match nothing?" answerable.
func (s *Selector) Explain(calls []index.Call) map[string]int {
	out := map[string]int{}
	for _, c := range calls {
		if ok, reason := s.Match(c); !ok {
			out[string(reason)]++
		}
	}
	return out
}

func (s *Selector) matchHost(c index.Call) bool {
	host := strings.ToLower(c.Host)
	for _, pat := range s.f.Hosts {
		p := strings.ToLower(pat)
		if p == host {
			return true
		}
		if ok, _ := path.Match(p, host); ok {
			return true
		}
		// A symbolic host matches a query for any concrete host it maps to.
		for _, symbolic := range s.reverseHosts[p] {
			if strings.EqualFold(symbolic, c.Host) {
				return true
			}
		}
		// Bare "${env:X}" style queries should also work without the wrapper.
		if c.HostKind != normalize.HostLiteral && strings.Contains(host, p) {
			return true
		}
	}
	return false
}

func (s *Selector) matchEndpoint(c index.Call) bool {
	tmpl := PathTemplate(c.Path)
	if s.endpointSet[tmpl] {
		return true
	}
	// A path recorded with a wide tail ("/api/**") covers any queried endpoint
	// beneath it: the call really does reach that endpoint, we just could not
	// see which one.
	if strings.HasSuffix(c.Path, "/**") {
		prefix := PathTemplate(strings.TrimSuffix(c.Path, "/**"))
		for e := range s.endpointSet {
			if e == prefix || strings.HasPrefix(e, prefix+"/") {
				return true
			}
		}
	}
	for _, pre := range s.endpointPre {
		if tmpl == pre || strings.HasPrefix(tmpl, pre+"/") {
			return true
		}
	}
	if s.f.EndpointMode == EndpointPrefix {
		for e := range s.endpointSet {
			if strings.HasPrefix(tmpl, e+"/") {
				return true
			}
		}
	}
	return false
}

func (s *Selector) matchRegex(c index.Call) bool {
	var subject string
	switch s.f.RegexTarget {
	case RegexPath:
		subject = c.Path
	case RegexRaw:
		subject = c.RawExpr
	case RegexFile:
		subject = c.Location.File
	default:
		scheme := c.Scheme
		if scheme == "" {
			scheme = "https"
		}
		subject = scheme + "://" + c.Host + c.Path
	}
	for _, re := range s.regexes {
		if re.MatchString(subject) {
			return true
		}
	}
	return false
}

// placeholderRe matches every placeholder spelling used by the frameworks people
// actually write: {id}, :id, <id>, <int:id>, [id], %s, ${id}, #{id}.
var placeholderRe = regexp.MustCompile(`\{[^/}]*\}|\$\{[^/}]*\}|#\{[^/}]*\}|:[A-Za-z_][A-Za-z0-9_]*|<[^/>]*>|\[[^/\]]*\]|%[sdvq]`)

// PathTemplate rewrites every placeholder to a bare "{}" so two spellings of the
// same route compare equal. It is the heart of template-insensitive matching.
func PathTemplate(p string) string {
	if p == "" {
		return "/"
	}
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	p = placeholderRe.ReplaceAllString(p, "{}")
	// Collapse duplicate slashes and drop a trailing one so "/x/" == "/x".
	for strings.Contains(p, "//") {
		p = strings.ReplaceAll(p, "//", "/")
	}
	if len(p) > 1 {
		p = strings.TrimSuffix(p, "/")
	}
	if p == "" {
		p = "/"
	}
	return p
}

func trimWildcardSuffix(e string) (string, bool) {
	for _, suf := range []string{"/**", "/*"} {
		if strings.HasSuffix(e, suf) {
			return strings.TrimSuffix(e, suf), true
		}
	}
	return e, false
}

func matchAnyGlob(rel string, globs []string) bool {
	for _, g := range globs {
		if ok, _ := path.Match(g, rel); ok {
			return true
		}
		trimmed := strings.TrimSuffix(strings.TrimSuffix(g, "/**"), "/")
		if trimmed != "" && (rel == trimmed || strings.HasPrefix(rel, trimmed+"/")) {
			return true
		}
	}
	return false
}

func upperSet(in []string) map[string]bool {
	if len(in) == 0 {
		return nil
	}
	m := make(map[string]bool, len(in))
	for _, s := range in {
		m[strings.ToUpper(strings.TrimSpace(s))] = true
	}
	return m
}

func lowerSet(in []string) map[string]bool {
	if len(in) == 0 {
		return nil
	}
	m := make(map[string]bool, len(in))
	for _, s := range in {
		m[strings.ToLower(strings.TrimSpace(s))] = true
	}
	return m
}

func hasFlag(flags []string, want string) bool {
	for _, f := range flags {
		if f == want {
			return true
		}
	}
	return false
}

// Languages returns the language names a filter mentions, for diagnostics.
func (f Filters) LanguageList() []detect.Language {
	out := make([]detect.Language, 0, len(f.Languages))
	for _, l := range f.Languages {
		out = append(out, detect.Language(strings.ToLower(l)))
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}
