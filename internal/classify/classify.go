// Package classify decides whether a detected call site belongs in the index,
// and how much to trust it.
//
// This is where precision is won or lost. Four gates run in order -- path
// exclusions, test files, route definitions, non-external destinations -- and
// every rejection is recorded with a reason rather than silently dropped. When
// a user says "you missed my call", `--explain-drops` has to be able to answer.
//
// Scoring is an explicit additive table rather than a learned or ad-hoc
// heuristic, so tuning it is a reviewable diff and its behaviour is asserted by
// a golden test.
package classify

import (
	"net"
	"path"
	"strings"

	"github.com/sfbee/api-integrity-tool/internal/detect"
	"github.com/sfbee/api-integrity-tool/internal/index"
	"github.com/sfbee/api-integrity-tool/internal/normalize"
	"github.com/sfbee/api-integrity-tool/internal/resolve"
)

// Drop reasons. These are stable strings: they appear in Stats.SitesDropped and
// in the drops golden file, so a change that starts swallowing real calls shows
// up as a test failure.
const (
	DropExcludedPath     = "excluded_path"
	DropTestFile         = "test_file"
	DropRoute            = "route_definition"
	DropSuspectedRoute   = "suspected_route"
	DropLocalHost        = "local_host"
	DropInternalService  = "internal_service"
	DropNonHTTPScheme    = "non_http_scheme"
	DropNoUsablePath     = "no_usable_path"
	DropUnverifiedNoHost = "unverified_receiver_no_host"
	DropIgnored          = "ignored_by_config"
)

// Options controls the gates. The zero value is the shipped default: exclude
// vendored and generated trees, exclude tests, drop route definitions, drop
// non-external destinations.
type Options struct {
	IncludeTests           bool
	IncludeSuspectedRoutes bool
	// IncludeInternal keeps localhost, RFC1918 and single-label hosts. Off by
	// default: an upstream repo cannot be monitored for a host that only exists
	// inside a developer's machine or cluster.
	IncludeInternal bool
	// ExcludePaths replaces the built-in exclusion list when non-empty.
	ExcludePaths []string
	// ExtraExcludePaths adds to whichever list is in effect.
	ExtraExcludePaths []string
	// IncludePaths re-includes paths that exclusions would have dropped, so a
	// user can deliberately scan a vendored SDK. It beats every exclusion.
	IncludePaths []string
}

// defaultExcludedDirs are directory names that hold code we did not write.
// Indexing them would report a dependency's API calls as our own.
var defaultExcludedDirs = []string{
	"vendor", "node_modules", "bower_components", ".venv", "venv", "virtualenv",
	"site-packages", ".bundle", "target", "build", "dist", "out", "obj",
	".next", ".nuxt", ".svelte-kit", "coverage", ".git", ".idea", ".vscode",
	".tox", ".mypy_cache", "__pycache__", ".gradle", ".m2", "Pods", "Carthage",
	"third_party", "3rdparty", "external", ".api-integrity",
}

// defaultExcludedSuffixes are generated or bundled files.
var defaultExcludedSuffixes = []string{
	".min.js", ".bundle.js", ".map", "_pb2.py", ".pb.go", ".pb.gw.go",
	"_generated.go", ".generated.cs", ".designer.cs", ".g.dart",
}

// testPathFragments and testFileMarkers identify test code across all seven
// languages. Test files legitimately talk to fake hosts, so indexing them
// pollutes the picture of what production code depends on.
var testPathFragments = []string{
	"/testdata/", "/tests/", "/test/", "/__tests__/", "/__mocks__/", "/mocks/",
	"/spec/", "/cypress/", "/e2e/", "/features/", "/fixtures/", "/t/",
}

var testFileMarkers = []string{
	"_test.go", "_test.py", "_test.rb", "_spec.rb", "_test.exs",
	".test.js", ".test.ts", ".test.jsx", ".test.tsx",
	".spec.js", ".spec.ts", ".spec.jsx", ".spec.tsx",
	"test.java", "tests.cs", "test.cs", ".t",
}

// ExcludedPath reports whether rel is excluded, and why. rel is repo-relative
// with forward slashes.
func ExcludedPath(rel string, opts Options) (string, bool) {
	slashed := "/" + strings.TrimPrefix(rel, "/")
	for _, inc := range opts.IncludePaths {
		if matchPathPattern(slashed, inc) {
			return "", false
		}
	}
	dirs := defaultExcludedDirs
	if len(opts.ExcludePaths) > 0 {
		dirs = opts.ExcludePaths
	}
	for _, d := range dirs {
		if strings.Contains(slashed, "/"+d+"/") || strings.HasPrefix(slashed, "/"+d+"/") {
			return DropExcludedPath, true
		}
	}
	for _, pat := range opts.ExtraExcludePaths {
		if matchPathPattern(slashed, pat) {
			return DropExcludedPath, true
		}
	}
	base := path.Base(rel)
	for _, suf := range defaultExcludedSuffixes {
		if strings.HasSuffix(base, suf) {
			return DropExcludedPath, true
		}
	}
	return "", false
}

// matchPathPattern matches a glob against a path, treating a pattern with no
// slash as a basename match and supporting a trailing "/**".
func matchPathPattern(slashed, pattern string) bool {
	if pattern == "" {
		return false
	}
	pattern = strings.TrimSuffix(pattern, "/**")
	if !strings.HasPrefix(pattern, "/") && !strings.Contains(pattern, "/") {
		if ok, _ := path.Match(pattern, path.Base(slashed)); ok {
			return true
		}
		return strings.Contains(slashed, "/"+pattern+"/")
	}
	if !strings.HasPrefix(pattern, "/") {
		pattern = "/" + pattern
	}
	if ok, _ := path.Match(pattern, slashed); ok {
		return true
	}
	return strings.HasPrefix(slashed, pattern+"/") || slashed == pattern
}

// IsTestFile reports whether rel looks like test code.
func IsTestFile(rel string) bool {
	slashed := strings.ToLower("/" + strings.TrimPrefix(rel, "/"))
	for _, frag := range testPathFragments {
		if strings.Contains(slashed, frag) {
			return true
		}
	}
	base := path.Base(slashed)
	for _, m := range testFileMarkers {
		if strings.HasSuffix(base, m) {
			return true
		}
	}
	return strings.HasPrefix(base, "test_") || strings.HasPrefix(base, "test-")
}

// routeFilePatterns are the canonical homes of server-side route definitions.
// A URL literal in one of these files is almost never an outbound call.
var routeFilePatterns = []string{
	"config/routes.rb", "urls.py", "web.php", "api.php",
}

// IsRouteFile reports whether rel is a known route-definition file.
func IsRouteFile(rel string) bool {
	lower := strings.ToLower("/" + strings.TrimPrefix(rel, "/"))
	for _, p := range routeFilePatterns {
		if strings.HasSuffix(lower, "/"+p) {
			return true
		}
	}
	base := path.Base(lower)
	switch {
	case strings.HasSuffix(base, "controller.java"), strings.HasSuffix(base, "controller.cs"),
		strings.HasSuffix(base, "controller.ts"), strings.HasSuffix(base, "controller.php"):
		return true
	case base == "route.ts" || base == "route.js":
		return true
	case strings.Contains(lower, "/pages/api/"), strings.Contains(lower, "/app/api/"):
		return true
	}
	return false
}

// Input is everything needed to classify one resolved call site.
type Input struct {
	File      string
	Generated bool
	Language  detect.Language
	Detector  string
	Site      detect.RawSite
	Res       resolve.Resolution
	Canon     normalize.Canonical
	// BaseScore comes from the signature that matched; see PatternBaseScore.
	BaseScore int
}

// Decision is the verdict for one site.
type Decision struct {
	Keep   bool
	Reason string
	Score  int
	Flags  []string
}

// PatternBaseScore returns the starting score for a signature. An exact AST
// match is trusted far more than a chained heuristic or an SDK-import guess.
func PatternBaseScore(pattern string) int {
	switch {
	case strings.HasSuffix(pattern, ".pkgfunc"),
		strings.Contains(pattern, "NewRequest"),
		strings.HasSuffix(pattern, ".client.method"):
		return 70
	case strings.HasSuffix(pattern, ".request"), strings.Contains(pattern, ".instance."):
		return 62
	case strings.HasPrefix(pattern, "go.receiver."):
		// A method call on a receiver we could not type-check. Lower than an
		// exact package-function match, but a literal absolute URL passed to
		// one of these still reaches "high" once its bonuses apply -- which is
		// correct, because such a line states its destination outright.
		return 55
	case strings.HasPrefix(pattern, "sdk."):
		return 40
	default:
		return 55
	}
}

// Classify applies the gates and computes the score.
func Classify(in Input, opts Options) Decision {
	d := Decision{Flags: append([]string{}, in.Canon.Flags...)}

	// Gate 1: excluded paths.
	if reason, ok := ExcludedPath(in.File, opts); ok {
		d.Reason = reason
		return d
	}

	// Gate 2: test files.
	isTest := IsTestFile(in.File)
	if isTest && !opts.IncludeTests {
		d.Reason = DropTestFile
		return d
	}
	if isTest {
		d.Flags = appendFlag(d.Flags, "test_file")
	}

	// Gate 3: route definitions. The detector's own suspicion is authoritative
	// when it saw a handler argument; a known route file is authoritative on
	// its own.
	if in.Site.RouteLike || IsRouteFile(in.File) {
		if !opts.IncludeSuspectedRoutes {
			d.Reason = DropRoute
			return d
		}
		d.Flags = appendFlag(d.Flags, "suspected_route")
	}

	// Gate 4: destinations we cannot or should not monitor.
	if in.Canon.Scheme != "" && !isHTTPish(in.Canon.Scheme) {
		d.Reason = DropNonHTTPScheme
		return d
	}
	if in.Canon.HostKind == normalize.HostLiteral {
		switch hostLocality(in.Canon.Host) {
		case localityLoopback, localityPrivate, localityReserved:
			if !opts.IncludeInternal {
				d.Reason = DropLocalHost
				return d
			}
			d.Flags = appendFlag(d.Flags, "local_host")
		case localitySingleLabel:
			if !opts.IncludeInternal {
				d.Reason = DropInternalService
				return d
			}
			d.Flags = appendFlag(d.Flags, "internal_service")
		}
	}

	// An unverified receiver with no recognizable host is almost certainly not
	// an HTTP call at all -- this is the gate that keeps cache.Get("key") and
	// map-like accessors out of the index.
	if hasNote(in.Site.Notes, "unverified_receiver") && in.Canon.HostKind != normalize.HostLiteral {
		d.Reason = DropUnverifiedNoHost
		return d
	}

	// Nothing usable at all: no host and no path.
	if in.Canon.HostKind == normalize.HostUnknown && (in.Canon.Path == "" || in.Canon.Path == "/") {
		d.Reason = DropNoUsablePath
		return d
	}

	d.Keep = true
	d.Score = score(in, isTest, &d.Flags)
	return d
}

func isHTTPish(scheme string) bool {
	switch scheme {
	case "http", "https", "ws", "wss", "":
		return true
	}
	return false
}

type locality int

const (
	localityExternal locality = iota
	localityLoopback
	localityPrivate
	localityReserved
	localitySingleLabel
)

// reservedSuffixes are TLDs that never resolve on the public internet. Note that
// "example.com" is NOT here: it is a real registered domain widely used in
// fixtures and documentation, and excluding it would gut the test corpus.
var reservedSuffixes = []string{".localhost", ".local", ".test", ".invalid", ".example", ".internal"}

var reservedHosts = map[string]bool{
	"localhost": true, "host.docker.internal": true,
	"metadata.google.internal": true, "kubernetes.default": true,
}

func hostLocality(host string) locality {
	h := strings.ToLower(strings.Trim(host, "[]"))
	if h == "" {
		return localityExternal
	}
	if reservedHosts[h] {
		return localityLoopback
	}
	for _, suf := range reservedSuffixes {
		if strings.HasSuffix(h, suf) {
			return localityReserved
		}
	}
	if ip := net.ParseIP(h); ip != nil {
		switch {
		case ip.IsLoopback(), ip.IsUnspecified():
			return localityLoopback
		case ip.IsPrivate(), ip.IsLinkLocalUnicast(), ip.IsLinkLocalMulticast():
			return localityPrivate
		default:
			return localityExternal
		}
	}
	// A hostname with no dot is a container or cluster service name, reachable
	// only from inside that network.
	if !strings.Contains(h, ".") {
		return localitySingleLabel
	}
	return localityExternal
}

// scoreAdjustment is one row of the confidence table. Keeping the table as data
// makes the whole scoring model readable at a glance and testable as a unit.
type scoreAdjustment struct {
	Flag  string
	Delta int
}

// Adjustments is the confidence table. Order does not matter: every applicable
// row is applied, then the result is clamped.
var Adjustments = []scoreAdjustment{
	{"fully_literal_url", +20},
	{"host_from_const", +12},
	{"host_from_binding", +10},
	{"inferred_from_constructor", +4},
	{"explicit_method", +5},
	{"symbolic_host", -15},
	{"param_host", -20},
	{"relative_host", -25},
	{"unknown_host", -25},
	{"wide_tail", -10},
	{"many_holes", -5},
	{"regex_detector", -20},
	{"multi_valued", -10},
	{"test_file", -10},
	{"generated", -5},
	{"suspected_route", -25},
	{"unparseable", -30},
	{"unverified_receiver", -15},
	{"partial_symbolic_host", -10},
}

var adjustmentByFlag = func() map[string]int {
	m := make(map[string]int, len(Adjustments))
	for _, a := range Adjustments {
		m[a.Flag] = a.Delta
	}
	return m
}()

// score computes the 0..100 confidence for a kept call.
func score(in Input, isTest bool, flags *[]string) int {
	base := in.BaseScore
	if base == 0 {
		base = PatternBaseScore(in.Site.Pattern)
	}

	// Derive the scoring flags from what resolution actually produced.
	if _, literal := in.Res.LiteralString(); literal && in.Canon.HostKind == normalize.HostLiteral {
		*flags = appendFlag(*flags, "fully_literal_url")
	}
	switch in.Canon.HostKind {
	case normalize.HostEnv, normalize.HostConfig, normalize.HostSymbol:
		*flags = appendFlag(*flags, "symbolic_host")
	case normalize.HostParam:
		*flags = appendFlag(*flags, "param_host")
	case normalize.HostRelative:
		*flags = appendFlag(*flags, "relative_host")
	case normalize.HostUnknown:
		*flags = appendFlag(*flags, "unknown_host")
	}
	// Only credit the client-instance binding when the call site did not state
	// the host itself. Otherwise "fully_literal_url" and "host_from_binding"
	// both fire and describe contradictory things.
	if in.Site.BaseHint != "" && in.Canon.HostKind == normalize.HostLiteral && !hasFlag(*flags, "fully_literal_url") {
		*flags = appendFlag(*flags, "host_from_binding")
	}
	if in.Site.MethodExpr != nil {
		*flags = appendFlag(*flags, "explicit_method")
	}
	if len(in.Canon.PathVars) >= 3 {
		*flags = appendFlag(*flags, "many_holes")
	}
	if in.Generated {
		*flags = appendFlag(*flags, "generated")
	}
	if isTest {
		*flags = appendFlag(*flags, "test_file")
	}
	for _, n := range in.Site.Notes {
		if _, ok := adjustmentByFlag[n]; !ok {
			continue
		}
		// An unproven receiver type is already priced into the lower base score
		// for go.receiver.* patterns. Charging for it again on a call whose URL
		// is a fully literal absolute URL is double-counting: whatever c.hc
		// turns out to be, "c.hc.Get(\"https://api.stripe.com/v1/health\")"
		// unambiguously targets api.stripe.com.
		if n == "unverified_receiver" && hasFlag(*flags, "fully_literal_url") {
			continue
		}
		*flags = appendFlag(*flags, n)
	}
	for _, f := range in.Res.Flags {
		if _, ok := adjustmentByFlag[f]; ok {
			*flags = appendFlag(*flags, f)
		}
	}

	total := base
	for _, f := range *flags {
		total += adjustmentByFlag[f]
	}
	return clamp(total, 0, 100)
}

func clamp(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

// Confidence is a convenience wrapper mapping a score to its bucket.
func Confidence(score int) index.Confidence { return index.ConfidenceFor(score) }

func appendFlag(flags []string, f string) []string {
	for _, e := range flags {
		if e == f {
			return flags
		}
	}
	return append(flags, f)
}

func hasNote(notes []string, want string) bool {
	for _, n := range notes {
		if n == want {
			return true
		}
	}
	return false
}

func hasFlag(flags []string, want string) bool {
	for _, f := range flags {
		if f == want {
			return true
		}
	}
	return false
}
