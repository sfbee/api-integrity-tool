// Package normalize turns a resolved segment list into a canonical URL: a
// scheme, a host (literal or symbolic), a port, a path with placeholder tokens
// in place of dynamic segments, and the set of query keys.
//
// Canonicalization is the difference between an index you can group, diff and
// query, and a pile of raw strings. Two call sites that hit the same endpoint
// with differently-named variables must produce the same normalized path, or
// they will not aggregate and the monitor will not match them against upstream
// changes.
//
// The rules here are applied in a fixed order and are covered case by case in
// url_test.go, so changing one is a visible, reviewable diff.
package normalize

import (
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode"

	"github.com/sfbee/api-integrity-tool/internal/resolve"
)

// HostKind classifies what we know about a call's destination host. Keeping
// unresolved hosts distinguishable by kind and name is what stops grouping from
// degenerating into one giant "unknown" bucket.
type HostKind string

const (
	// HostLiteral is a real hostname resolved from the source.
	HostLiteral HostKind = "literal"
	// HostEnv came from an environment variable.
	HostEnv HostKind = "env"
	// HostConfig came from a config lookup.
	HostConfig HostKind = "config"
	// HostSymbol came from an unresolved constant, variable or field.
	HostSymbol HostKind = "symbol"
	// HostParam came from a function parameter: the host is injected by a caller.
	HostParam HostKind = "param"
	// HostRelative is a path-only URL with no base, such as a browser
	// fetch('/api/x'). Kept rather than dropped because it may still leave the
	// machine through a gateway.
	HostRelative HostKind = "relative"
	// HostUnknown is everything else.
	HostUnknown HostKind = "unknown"
)

// SelfHost is the host recorded for relative URLs.
const SelfHost = "self"

// UnknownHost is the host recorded when nothing at all is known.
const UnknownHost = "${unknown}"

// PathVar records one placeholder token and the source expression it replaced.
type PathVar struct {
	Token  string `json:"token"`
	Source string `json:"source,omitempty"`
}

// Canonical is a normalized URL.
type Canonical struct {
	Scheme        string
	Host          string
	HostKind      HostKind
	Port          int
	Path          string
	PathVars      []PathVar
	QueryKeys     []string
	TrailingSlash bool
	Flags         []string
}

// Options tunes normalization.
type Options struct {
	// CollapseNumericIDs rewrites all-digit path segments to {id}. Off by
	// default: "/api/2/issue" and "/v1/2020-08-27" contain real digits, and
	// collapsing them loses the endpoint's identity.
	CollapseNumericIDs bool
	// DefaultHost is attributed to relative URLs when configured, so a SPA's
	// fetch('/api/x') can be tied to the gateway that actually serves it.
	DefaultHost string
}

// sentinel is substituted for holes before parsing. It must survive
// url.Parse and host lowercasing unchanged, so it is lowercase alphanumeric.
const sentinelPrefix = "aitxhole"

var sentinelRe = regexp.MustCompile(sentinelPrefix + `([0-9]+)`)

// Canonicalize applies every normalization rule to segs.
func Canonicalize(segs []resolve.Segment, opts Options) Canonical {
	c := Canonical{}
	segs = trimEmpty(segs)
	if len(segs) == 0 {
		c.Host, c.HostKind, c.Path = UnknownHost, HostUnknown, "/"
		return c
	}

	// An opaque head means the scheme and host live inside the unresolved
	// value, so the hole is the host rather than the first path segment.
	if segs[0].Kind == resolve.SegHole {
		c.Host, c.HostKind = symbolicHost(segs[0])
		rest := segs[1:]
		c.Path, c.PathVars, c.QueryKeys, c.TrailingSlash, c.Flags = buildPath(rest, opts, c.Flags)
		return c
	}

	head := segs[0].Text
	switch {
	case strings.HasPrefix(head, "/"):
		// Path-only: a relative call.
		c.HostKind = HostRelative
		c.Host = SelfHost
		if opts.DefaultHost != "" {
			c.Host = opts.DefaultHost
			c.HostKind = HostLiteral
			c.Flags = appendFlag(c.Flags, "default_host_applied")
		}
		c.Path, c.PathVars, c.QueryKeys, c.TrailingSlash, c.Flags = buildPath(segs, opts, c.Flags)
		return c
	case strings.HasPrefix(head, "//"):
		c.Flags = appendFlag(c.Flags, "scheme_relative")
	}

	masked, holes := mask(segs)
	u, err := url.Parse(masked)
	if err != nil || (u.Host == "" && !looksHostFirst(masked)) {
		if err != nil {
			c.Flags = appendFlag(c.Flags, "unparseable")
		}
		// Best effort: keep whatever we have rather than discarding a real call.
		c.Host, c.HostKind = UnknownHost, HostUnknown
		c.Path, c.PathVars, c.QueryKeys, c.TrailingSlash, c.Flags = buildPath(segs, opts, c.Flags)
		return c
	}
	if u.Host == "" {
		// "api.example.com/v1" with no scheme: url.Parse puts it all in Path.
		u, err = url.Parse("//" + masked)
		if err != nil || u.Host == "" {
			c.Host, c.HostKind = UnknownHost, HostUnknown
			c.Path, c.PathVars, c.QueryKeys, c.TrailingSlash, c.Flags = buildPath(segs, opts, c.Flags)
			return c
		}
		c.Flags = appendFlag(c.Flags, "scheme_relative")
	}

	c.Scheme = strings.ToLower(u.Scheme)
	if u.User != nil {
		// Never store credentials; only record that they were there.
		c.Flags = appendFlag(c.Flags, "embedded_credentials")
	}

	hostname, port := splitHostPort(u.Host)
	c.Port = normalizePort(c.Scheme, port, &c.Flags)
	c.Host, c.HostKind = classifyHost(hostname, holes, &c.Flags)

	// Rebuild the path from the masked URL so query and fragment handling
	// follows url.Parse rather than naive string splitting.
	pathSegs := unmaskToSegments(u.EscapedPath(), holes)
	c.Path, c.PathVars, _, c.TrailingSlash, c.Flags = buildPath(pathSegs, opts, c.Flags)
	c.QueryKeys = queryKeys(u.RawQuery)
	return c
}

// mask replaces holes with parseable sentinels and returns the sentinel table.
func mask(segs []resolve.Segment) (string, []resolve.Segment) {
	var b strings.Builder
	var holes []resolve.Segment
	for _, s := range segs {
		if s.Kind == resolve.SegLiteral {
			b.WriteString(s.Text)
			continue
		}
		b.WriteString(sentinelPrefix + strconv.Itoa(len(holes)))
		holes = append(holes, s)
	}
	return b.String(), holes
}

// unmaskToSegments turns a masked string back into a segment list.
func unmaskToSegments(masked string, holes []resolve.Segment) []resolve.Segment {
	var out []resolve.Segment
	last := 0
	for _, m := range sentinelRe.FindAllStringSubmatchIndex(masked, -1) {
		if m[0] > last {
			out = append(out, resolve.Literal(masked[last:m[0]]))
		}
		n, _ := strconv.Atoi(masked[m[2]:m[3]])
		if n < len(holes) {
			out = append(out, holes[n])
		} else {
			out = append(out, resolve.Hole("", "", ""))
		}
		last = m[1]
	}
	if last < len(masked) {
		out = append(out, resolve.Literal(masked[last:]))
	}
	return out
}

// classifyHost decides the host string and kind, handling a host that is
// entirely or partly a hole.
func classifyHost(hostname string, holes []resolve.Segment, flags *[]string) (string, HostKind) {
	ms := sentinelRe.FindAllStringSubmatchIndex(hostname, -1)
	if len(ms) == 0 {
		h := strings.ToLower(hostname)
		if h == "" {
			return UnknownHost, HostUnknown
		}
		return h, HostLiteral
	}
	// A host that is exactly one hole keeps that hole's identity, which is what
	// lets ${env:BILLING_URL} and ${env:SEARCH_URL} remain separate groups.
	if len(ms) == 1 && ms[0][0] == 0 && ms[0][1] == len(hostname) {
		n, _ := strconv.Atoi(hostname[ms[0][2]:ms[0][3]])
		if n < len(holes) {
			return symbolicHost(holes[n])
		}
		return UnknownHost, HostUnknown
	}
	// Mixed literal and hole, e.g. "aitxhole0.example.com": keep the shape.
	*flags = appendFlag(*flags, "partial_symbolic_host")
	out := sentinelRe.ReplaceAllStringFunc(hostname, func(s string) string {
		n, _ := strconv.Atoi(strings.TrimPrefix(s, sentinelPrefix))
		if n < len(holes) {
			h, _ := symbolicHost(holes[n])
			return h
		}
		return UnknownHost
	})
	return strings.ToLower(out), HostSymbol
}

// symbolicHost renders a hole as a stable symbolic host string plus its kind.
func symbolicHost(s resolve.Segment) (string, HostKind) {
	kind, name, ok := strings.Cut(s.Sym, ":")
	if !ok || name == "" {
		return UnknownHost, HostUnknown
	}
	switch kind {
	case "env":
		return "${env:" + name + "}", HostEnv
	case "cfg":
		return "${cfg:" + name + "}", HostConfig
	case "arg":
		return "${arg:" + name + "}", HostParam
	case "sym", "call":
		return "${sym:" + name + "}", HostSymbol
	default:
		return UnknownHost, HostUnknown
	}
}

// pathLikeNames are hole names that plausibly hold more than one path segment.
// A hole in the final position with one of these names, or with no name at all,
// widens the path to "/**" instead of becoming a single {token}.
var pathLikeNames = map[string]bool{
	"path": true, "endpoint": true, "route": true, "uri": true, "url": true,
	"suffix": true, "rest": true, "subpath": true, "resource": true,
	"pathname": true, "urlpath": true, "relative": true, "rel": true,
}

// buildPath assembles the normalized path, naming every hole.
func buildPath(segs []resolve.Segment, opts Options, flags []string) (string, []PathVar, []string, bool, []string) {
	// Strip query and fragment from the literal text; they are handled
	// separately and their values are frequently secrets.
	var qkeys []string
	segs, qkeys = splitQuery(segs)

	var b strings.Builder
	var vars []PathVar
	positional := 0
	for i, s := range segs {
		if s.Kind == resolve.SegLiteral {
			b.WriteString(s.Text)
			continue
		}
		isLast := i == len(segs)-1
		name := strings.TrimSpace(s.Name)
		switch {
		case isLast && (name == "" || pathLikeNames[strings.ToLower(lastIdent(name))]):
			// An opaque or path-shaped tail may contain slashes, so the path
			// becomes a prefix match rather than a single segment.
			cur := b.String()
			if !strings.HasSuffix(cur, "/") {
				b.WriteString("/")
			}
			b.WriteString("**")
			flags = appendFlag(flags, "wide_tail")
			if name != "" {
				vars = append(vars, PathVar{Token: "/**", Source: s.Name})
			}
		default:
			var tok string
			if name == "" {
				positional++
				tok = "{p" + strconv.Itoa(positional) + "}"
			} else if isPositionalVerb(name) {
				positional++
				tok = "{p" + strconv.Itoa(positional) + "}"
			} else {
				tok = "{" + toSnake(lastIdent(name)) + "}"
			}
			b.WriteString(tok)
			vars = append(vars, PathVar{Token: tok, Source: s.Name})
		}
	}

	p := b.String()
	hadHole := len(vars) > 0 || strings.Contains(p, "**")
	p, trailing := cleanPath(p, hadHole, &flags)
	// UUID and token-shaped segments are always collapsed; purely numeric
	// segments only when the caller opts in, since digits are often real route
	// components.
	p = collapseIDSegments(p, opts, &flags, &vars)
	return p, vars, qkeys, trailing, flags
}

// splitQuery removes everything from the first "?" or "#" onward, returning the
// query keys only. Values are dropped on purpose: they are noise at best and
// credentials at worst.
func splitQuery(segs []resolve.Segment) ([]resolve.Segment, []string) {
	for i, s := range segs {
		if s.Kind != resolve.SegLiteral {
			continue
		}
		if j := strings.IndexAny(s.Text, "?#"); j >= 0 {
			head := append([]resolve.Segment{}, segs[:i]...)
			if j > 0 {
				head = append(head, resolve.Literal(s.Text[:j]))
			}
			var raw string
			if s.Text[j] == '?' {
				raw = s.Text[j+1:]
				if k := strings.IndexByte(raw, '#'); k >= 0 {
					raw = raw[:k]
				}
			}
			return head, queryKeys(raw)
		}
	}
	return segs, nil
}

func queryKeys(raw string) []string {
	if raw == "" {
		return nil
	}
	seen := map[string]bool{}
	for _, kv := range strings.Split(raw, "&") {
		if kv == "" {
			continue
		}
		k, _, _ := strings.Cut(kv, "=")
		if k = strings.TrimSpace(k); k != "" && !sentinelRe.MatchString(k) {
			seen[k] = true
		}
	}
	if len(seen) == 0 {
		return nil
	}
	out := make([]string, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// cleanPath collapses duplicate slashes, uppercases percent escapes without
// decoding them, applies dot-segment cleaning only when no placeholder is
// involved, and reports whether the original had a trailing slash.
func cleanPath(p string, hadHole bool, flags *[]string) (string, bool) {
	if p == "" {
		return "/", false
	}
	p = upperPercentEscapes(p)
	for strings.Contains(p, "//") {
		p = strings.ReplaceAll(p, "//", "/")
	}
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	trailing := len(p) > 1 && strings.HasSuffix(p, "/")
	if !hadHole && (strings.Contains(p, "/./") || strings.Contains(p, "/../") ||
		strings.HasSuffix(p, "/.") || strings.HasSuffix(p, "/..")) {
		// Dot segments are only safe to resolve when no placeholder could be
		// standing in for the segment being cancelled.
		if cleaned := pathCleanKeepRoot(p); cleaned != p {
			*flags = appendFlag(*flags, "dot_segments_resolved")
			p = cleaned
		}
	}
	if trailing && len(p) > 1 {
		p = strings.TrimSuffix(p, "/")
		if p == "" {
			p = "/"
		}
	}
	return p, trailing
}

func pathCleanKeepRoot(p string) string {
	parts := strings.Split(p, "/")
	out := make([]string, 0, len(parts))
	for _, s := range parts {
		switch s {
		case ".", "":
			continue
		case "..":
			if len(out) > 0 {
				out = out[:len(out)-1]
			}
		default:
			out = append(out, s)
		}
	}
	return "/" + strings.Join(out, "/")
}

func upperPercentEscapes(s string) string {
	if !strings.Contains(s, "%") {
		return s
	}
	b := []byte(s)
	for i := 0; i+2 < len(b); i++ {
		if b[i] == '%' && isHex(b[i+1]) && isHex(b[i+2]) {
			b[i+1] = upperHex(b[i+1])
			b[i+2] = upperHex(b[i+2])
		}
	}
	return string(b)
}

func isHex(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'
}

func upperHex(c byte) byte {
	if c >= 'a' && c <= 'f' {
		return c - 'a' + 'A'
	}
	return c
}

var (
	uuidRe   = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	hexRe    = regexp.MustCompile(`^[0-9a-fA-F]{24,64}$`)
	base64Re = regexp.MustCompile(`^[A-Za-z0-9_-]{22,}$`)
	digitsRe = regexp.MustCompile(`^[0-9]+$`)
)

// collapseIDSegments rewrites literal segments that are obviously identifiers
// rather than route names. A hardcoded UUID in a URL is a specific record, not
// an endpoint, and leaving it in would fragment the index.
func collapseIDSegments(p string, opts Options, flags *[]string, vars *[]PathVar) string {
	if p == "/" || p == "" {
		return p
	}
	parts := strings.Split(p, "/")
	changed := false
	for i, s := range parts {
		if s == "" || strings.HasPrefix(s, "{") || s == "**" {
			continue
		}
		switch {
		case uuidRe.MatchString(s), hexRe.MatchString(s):
		case base64Re.MatchString(s) && !hasLetterAndSeparator(s):
		case opts.CollapseNumericIDs && digitsRe.MatchString(s):
		default:
			continue
		}
		parts[i] = "{id}"
		*vars = append(*vars, PathVar{Token: "{id}", Source: s})
		changed = true
	}
	if changed {
		*flags = appendFlag(*flags, "collapsed_literal_id")
	}
	return strings.Join(parts, "/")
}

// hasLetterAndSeparator keeps ordinary words like "subscriptions" from being
// mistaken for base64 tokens: real route names are lowercase words, often
// hyphenated, and lack the mixed-case entropy of a token.
func hasLetterAndSeparator(s string) bool {
	if strings.ContainsAny(s, "-_") {
		return true
	}
	var upper, lower, digit bool
	for _, r := range s {
		switch {
		case unicode.IsUpper(r):
			upper = true
		case unicode.IsLower(r):
			lower = true
		case unicode.IsDigit(r):
			digit = true
		}
	}
	// A pure lowercase word is a route name; mixed case with digits is a token.
	return lower && !upper && !digit
}

func splitHostPort(h string) (string, int) {
	if strings.HasPrefix(h, "[") {
		if i := strings.LastIndex(h, "]"); i >= 0 {
			host := h[:i+1]
			if rest := h[i+1:]; strings.HasPrefix(rest, ":") {
				n, _ := strconv.Atoi(rest[1:])
				return host, n
			}
			return host, 0
		}
	}
	if i := strings.LastIndex(h, ":"); i >= 0 {
		if n, err := strconv.Atoi(h[i+1:]); err == nil {
			return h[:i], n
		}
	}
	return h, 0
}

// normalizePort drops the default port for the scheme so
// "https://h:443/x" and "https://h/x" are the same endpoint.
func normalizePort(scheme string, port int, flags *[]string) int {
	switch {
	case port == 0:
		return 0
	case scheme == "http" && port == 80, scheme == "https" && port == 443,
		scheme == "ws" && port == 80, scheme == "wss" && port == 443:
		*flags = appendFlag(*flags, "default_port_stripped")
		return 0
	default:
		return port
	}
}

func isPositionalVerb(name string) bool {
	if name == "" {
		return false
	}
	switch name[0] {
	case '%', '{', '$':
		return true
	}
	return false
}

// toSnake converts an identifier to lower snake_case, handling acronyms:
// "userID" -> "user_id", "HTTPHost" -> "http_host", "user_id" -> "user_id".
func toSnake(s string) string {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "_")
	s = strings.Map(func(r rune) rune {
		if unicode.IsLetter(r) || unicode.IsDigit(r) || r == '_' {
			return r
		}
		return '_'
	}, s)
	rs := []rune(s)
	var b strings.Builder
	for i, r := range rs {
		if unicode.IsUpper(r) && i > 0 {
			prev := rs[i-1]
			nextLower := i+1 < len(rs) && unicode.IsLower(rs[i+1])
			if unicode.IsLower(prev) || unicode.IsDigit(prev) || (unicode.IsUpper(prev) && nextLower) {
				b.WriteByte('_')
			}
		}
		b.WriteRune(unicode.ToLower(r))
	}
	out := b.String()
	for strings.Contains(out, "__") {
		out = strings.ReplaceAll(out, "__", "_")
	}
	out = strings.Trim(out, "_")
	// Trailing noise words carry no information and only fragment tokens.
	for _, suf := range []string{"_str", "_string", "_param", "_value"} {
		if strings.HasSuffix(out, suf) && len(out) > len(suf) {
			out = strings.TrimSuffix(out, suf)
			break
		}
	}
	if out == "" {
		return "expr"
	}
	return out
}

func lastIdent(name string) string {
	name = strings.TrimSuffix(strings.TrimSpace(name), "()")
	if i := strings.LastIndexAny(name, ".:>[]"); i >= 0 && i+1 < len(name) {
		return name[i+1:]
	}
	return name
}

func looksHostFirst(s string) bool {
	i := strings.IndexAny(s, "/?#")
	head := s
	if i >= 0 {
		head = s[:i]
	}
	return strings.Contains(head, ".")
}

func trimEmpty(segs []resolve.Segment) []resolve.Segment {
	out := make([]resolve.Segment, 0, len(segs))
	for _, s := range segs {
		if s.Kind == resolve.SegLiteral && s.Text == "" {
			continue
		}
		out = append(out, s)
	}
	return out
}

func appendFlag(flags []string, f string) []string {
	for _, e := range flags {
		if e == f {
			return flags
		}
	}
	return append(flags, f)
}
