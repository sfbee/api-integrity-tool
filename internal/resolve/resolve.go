// Package resolve evaluates the detect.Expr trees produced by every language
// detector into a flat sequence of URL segments.
//
// This is where "client.Get(baseURL + \"/api/v1/user/add\")" becomes something
// a human recognises. Because it operates on the language-agnostic IR, the
// logic is written once for Go, JS/TS, Python, Perl, Ruby, Java and C#, and its
// tests are table-driven over hand-built Expr trees rather than over source
// code in seven languages.
//
// What it does: literal folding, intra-function variable propagation, file and
// module scope constants, format strings, template interpolation, path joining,
// environment variables, one-hop struct/field lookup, and fan-out when a name
// demonstrably holds more than one value.
//
// What it deliberately does not do: interprocedural dataflow, loops,
// conditionals beyond enumerating alternatives, container contents, reflection,
// or runtime service discovery. When resolution stalls, the value becomes a
// hole. A detected call is never dropped merely for being unresolvable --
// silently losing a real call is far worse than reporting one with a
// placeholder in it.
package resolve

import (
	"sort"
	"strconv"
	"strings"

	"github.com/stephen-bee/endpoint-monitor/internal/detect"
)

// Tunables. These are deliberately small: every one of them bounds work that
// would otherwise be unbounded on adversarial or merely unusual input.
const (
	// MaxDepth caps symbol substitution depth. Six is comfortably more than
	// real code uses (base -> host -> scheme+host is typically two).
	MaxDepth = 6
	// MaxAlternatives caps the fan-out when names hold several values. Beyond a
	// handful the results stop being useful and start being noise.
	MaxAlternatives = 4
	// MaxSegments bounds one resolution, guarding against a deeply nested
	// concat chain in generated code.
	MaxSegments = 128
)

// SegKind discriminates Segment.
type SegKind uint8

const (
	// SegLiteral is known text.
	SegLiteral SegKind = iota
	// SegHole is a value we could not determine.
	SegHole
)

// Segment is one piece of a resolved URL: either literal text or a hole.
type Segment struct {
	Kind SegKind
	// Text is the literal value when Kind is SegLiteral.
	Text string
	// Sym records where a hole came from, in "kind:name" form: "env:API_BASE",
	// "cfg:services.billing.url", "sym:Client.baseURL", "arg:baseURL",
	// "call:getBaseURL", or "" when nothing is known. normalize reads this to
	// classify symbolic hosts, which is what keeps two unresolved hosts from
	// collapsing into one meaningless group.
	Sym string
	// Name is the best human-readable name for the hole, used to derive
	// placeholder tokens such as {user_id}. Empty when fully opaque.
	Name string
	// Src is the verbatim source of the hole, for evidence.
	Src string
}

// Literal returns a literal segment.
func Literal(s string) Segment { return Segment{Kind: SegLiteral, Text: s} }

// Hole returns a hole segment.
func Hole(sym, name, src string) Segment {
	return Segment{Kind: SegHole, Sym: sym, Name: name, Src: detect.TrimSrc(src)}
}

// Resolution is one fully-evaluated alternative for a single call site.
type Resolution struct {
	Segments []Segment
	// Unresolved lists the symbolic names that blocked full resolution, sorted
	// and deduplicated. It drives the "17 calls have unresolved paths" summary
	// and the triage worklist.
	Unresolved []string
	// Flags records notable facts about how resolution went: "multi_valued",
	// "depth_exceeded", "inferred_from_constructor", "cycle".
	Flags []string
}

// HasHole reports whether any segment is a hole.
func (r Resolution) HasHole() bool {
	for _, s := range r.Segments {
		if s.Kind == SegHole {
			return true
		}
	}
	return false
}

// LiteralString returns the concatenated literal text, and whether the
// resolution was fully literal.
func (r Resolution) LiteralString() (string, bool) {
	var b strings.Builder
	for _, s := range r.Segments {
		if s.Kind != SegLiteral {
			return "", false
		}
		b.WriteString(s.Text)
	}
	return b.String(), true
}

// SymbolTable answers "what is this name bound to" with correct scope
// precedence: function locals, then enclosing type, then file, then module.
type SymbolTable struct {
	defs []detect.SymbolDef
}

// NewSymbolTable indexes defs. The slice is not copied; callers must not mutate
// it afterwards.
func NewSymbolTable(defs []detect.SymbolDef) *SymbolTable {
	return &SymbolTable{defs: defs}
}

// Lookup returns every value bound to name that is visible from function fn,
// narrowest scope first. Multiple returns mean the name genuinely holds
// different values, which the resolver turns into alternatives rather than
// guessing.
func (t *SymbolTable) Lookup(name, fn string) []*detect.Expr {
	if t == nil || name == "" {
		return nil
	}
	for _, scope := range []detect.ScopeKind{detect.ScopeFunc, detect.ScopeType, detect.ScopeFile, detect.ScopeModule} {
		var out []*detect.Expr
		for i := range t.defs {
			d := &t.defs[i]
			if d.Scope != scope || d.Name != name || d.Value == nil || d.Param {
				continue
			}
			// A function-scoped definition is only visible from its own
			// function. Two functions may each define "url".
			if scope == detect.ScopeFunc && fn != "" && d.Func != "" && d.Func != fn {
				continue
			}
			out = append(out, d.Value)
		}
		if len(out) > 0 {
			return dedupeExprs(out)
		}
	}
	// Fall back to a one-hop field lookup: a site referring to "c.baseURL"
	// matches a field definition recorded as "Client.baseURL", but only when
	// exactly one type declares that field. Ambiguity is left unresolved on
	// purpose -- picking one at random would attribute calls to the wrong host.
	if i := strings.LastIndex(name, "."); i >= 0 {
		suffix := "." + name[i+1:]
		var out []*detect.Expr
		for j := range t.defs {
			d := &t.defs[j]
			if d.Value != nil && d.Scope == detect.ScopeType && strings.HasSuffix(d.Name, suffix) {
				out = append(out, d.Value)
			}
		}
		if len(dedupeExprs(out)) == 1 {
			return dedupeExprs(out)
		}
	}
	return nil
}

// IsParam reports whether name is a parameter of function fn. A host that came
// from a parameter is recorded as ${arg:name} rather than ${sym:name}: both are
// unresolved, but the first says "the caller supplies this" while the second
// says "we could not find it", and that distinction matters when triaging.
func (t *SymbolTable) IsParam(name, fn string) bool {
	if t == nil || name == "" {
		return false
	}
	for i := range t.defs {
		d := &t.defs[i]
		if d.Param && d.Name == name && (fn == "" || d.Func == "" || d.Func == fn) {
			return true
		}
	}
	return false
}

func dedupeExprs(in []*detect.Expr) []*detect.Expr {
	seen := map[string]bool{}
	out := in[:0:0]
	for _, e := range in {
		k := e.String()
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, e)
	}
	return out
}

// Resolver evaluates expressions against a symbol table and client bindings.
type Resolver struct {
	Symbols  *SymbolTable
	Bindings map[string]*detect.Expr // client instance name -> base URL
	// Func is the enclosing function of the call site, scoping local lookups.
	Func string
}

// Resolve evaluates e and returns one Resolution per alternative value, capped
// at MaxAlternatives. It always returns at least one Resolution.
func (r *Resolver) Resolve(e *detect.Expr) []Resolution {
	st := &state{r: r, visiting: map[string]bool{}}
	alts := st.eval(e, 0)
	if len(alts) == 0 {
		alts = [][]Segment{{Hole("", "", "")}}
	}
	if len(alts) > 1 {
		st.flag("multi_valued")
	}
	out := make([]Resolution, 0, len(alts))
	for _, segs := range alts {
		out = append(out, Resolution{
			Segments:   coalesce(segs),
			Unresolved: sortedKeys(st.unresolved),
			Flags:      sortedKeys(st.flags),
		})
	}
	return out
}

// ResolveWithBase evaluates e and, when the result is a path-only value,
// prefixes the client instance's base URL. This is what connects
// axios.create({baseURL}) or HttpClient.BaseAddress to the relative paths its
// call sites use.
func (r *Resolver) ResolveWithBase(e *detect.Expr, instance string) []Resolution {
	res := r.Resolve(e)
	base, ok := r.Bindings[instance]
	if !ok {
		// Fall back to the file's default binding. Some clients declare their
		// base once for a whole file rather than per instance -- a Retrofit or
		// Refit interface, a Feign @FeignClient(url=...), an HTTParty
		// base_uri -- and those are recorded under the empty key. Without this
		// fallback every call from such a client resolves as a bare relative
		// path with no host.
		base, ok = r.Bindings[""]
	}
	if !ok || base == nil {
		return res
	}
	baseAlts := r.Resolve(base)
	if len(baseAlts) == 0 {
		return res
	}
	b := baseAlts[0]
	out := make([]Resolution, 0, len(res))
	for _, one := range res {
		// Only prefix when the value is genuinely relative. An absolute URL at
		// the call site overrides the instance base, matching how every one of
		// these client libraries actually behaves.
		if lit, ok := one.LiteralString(); ok && hasScheme(lit) {
			out = append(out, one)
			continue
		}
		merged := Resolution{
			Segments:   coalesce(append(append([]Segment{}, b.Segments...), one.Segments...)),
			Unresolved: mergeSorted(b.Unresolved, one.Unresolved),
			Flags:      mergeSorted(b.Flags, one.Flags),
		}
		out = append(out, merged)
	}
	return out
}

func hasScheme(s string) bool {
	i := strings.Index(s, "://")
	if i <= 0 {
		return false
	}
	for _, c := range s[:i] {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '+' || c == '-' || c == '.') {
			return false
		}
	}
	return true
}

// state carries per-resolution bookkeeping so Resolver stays reusable and
// concurrency-safe.
type state struct {
	r          *Resolver
	visiting   map[string]bool
	unresolved map[string]bool
	flags      map[string]bool
}

func (s *state) flag(f string) {
	if s.flags == nil {
		s.flags = map[string]bool{}
	}
	s.flags[f] = true
}

func (s *state) unresolve(name string) {
	if name == "" {
		return
	}
	if s.unresolved == nil {
		s.unresolved = map[string]bool{}
	}
	s.unresolved[name] = true
}

// eval returns the alternatives for e, each a segment list.
func (s *state) eval(e *detect.Expr, depth int) [][]Segment {
	if e == nil {
		return [][]Segment{{Hole("", "", "")}}
	}
	if depth > MaxDepth {
		s.flag("depth_exceeded")
		return [][]Segment{{Hole("", "", e.Src)}}
	}

	switch e.Kind {
	case detect.ExprLit:
		return [][]Segment{{Literal(e.Text)}}

	case detect.ExprConcat, detect.ExprTemplate:
		return s.sequence(e.Parts, depth, "")

	case detect.ExprJoin:
		return s.sequence(e.Parts, depth, "/")

	case detect.ExprCond:
		var out [][]Segment
		for _, p := range e.Parts {
			out = append(out, s.eval(p, depth+1)...)
			if len(out) >= MaxAlternatives {
				return out[:MaxAlternatives]
			}
		}
		return out

	case detect.ExprEnv:
		// An environment variable is recorded symbolically, never guessed. The
		// exact name is preserved so config can map it to a real host later.
		s.unresolve("env:" + e.Text)
		return [][]Segment{{Hole("env:"+e.Text, e.Text, e.Src)}}

	case detect.ExprIndex:
		name := indexName(e)
		s.unresolve("cfg:" + name)
		return [][]Segment{{Hole("cfg:"+name, lastIdent(name), e.Src)}}

	case detect.ExprCall:
		s.unresolve("call:" + e.Text)
		return [][]Segment{{Hole("call:"+e.Text, lastIdent(e.Text), e.Src)}}

	case detect.ExprSymbol:
		return s.evalSymbol(e, depth)

	case detect.ExprFormat:
		return s.evalFormat(e, depth)

	default: // ExprUnknown
		return [][]Segment{{Hole("", "", e.Src)}}
	}
}

func (s *state) evalSymbol(e *detect.Expr, depth int) [][]Segment {
	name := e.Text
	if s.visiting[name] {
		// Self-referential definition ("url = url + x"). Stop rather than
		// recurse forever.
		s.flag("cycle")
		s.unresolve("sym:" + name)
		return [][]Segment{{Hole("sym:"+name, lastIdent(name), e.Src)}}
	}
	vals := s.r.Symbols.Lookup(name, s.r.Func)
	if len(vals) == 0 {
		kind := "sym:"
		if s.r.Symbols.IsParam(name, s.r.Func) {
			kind = "arg:"
		}
		s.unresolve(kind + name)
		return [][]Segment{{Hole(kind+name, lastIdent(name), e.Src)}}
	}
	s.visiting[name] = true
	defer delete(s.visiting, name)

	var out [][]Segment
	for _, v := range vals {
		out = append(out, s.eval(v, depth+1)...)
		if len(out) >= MaxAlternatives {
			out = out[:MaxAlternatives]
			break
		}
	}
	// When a name resolves to a single unreadable value, the name itself is the
	// better placeholder. "$keyid = trimmed($cgi->param('keyid'))" should yield
	// /keys/{keyid}, not /keys/{trimmed}: the variable says what the segment
	// means, while the function that produced it says nothing about the endpoint.
	for i := range out {
		if len(out[i]) != 1 || out[i][0].Kind != SegHole {
			continue
		}
		h := &out[i][0]
		if h.Name == "" || strings.HasPrefix(h.Sym, "call:") {
			h.Name = lastIdent(name)
		}
	}
	return out
}

// sequence evaluates parts in order and returns the cartesian product of their
// alternatives, inserting sep between adjacent parts. The product is capped at
// MaxAlternatives, so a concat of several multi-valued names cannot explode.
func (s *state) sequence(parts []*detect.Expr, depth int, sep string) [][]Segment {
	acc := [][]Segment{{}}
	for i, p := range parts {
		alts := s.eval(p, depth+1)
		next := make([][]Segment, 0, len(acc))
		for _, prefix := range acc {
			for _, alt := range alts {
				combined := make([]Segment, 0, len(prefix)+len(alt)+1)
				combined = append(combined, prefix...)
				if i > 0 && sep != "" {
					combined = append(combined, Literal(sep))
				}
				combined = append(combined, alt...)
				if len(combined) > MaxSegments {
					combined = combined[:MaxSegments]
				}
				next = append(next, combined)
				if len(next) >= MaxAlternatives {
					break
				}
			}
			if len(next) >= MaxAlternatives {
				break
			}
		}
		acc = next
	}
	return acc
}

// evalFormat splits a format string into literals and holes, consuming
// arguments positionally. It understands both the C/Go/Perl/Ruby "%s" family
// and the Python/Java "{}" family, because the same code path serves all seven
// languages.
func (s *state) evalFormat(e *detect.Expr, depth int) [][]Segment {
	pieces := parseFormat(e.Text)
	// Resolve each argument once, taking only its first alternative: fanning
	// out every argument of a format string multiplies alternatives without
	// adding insight.
	args := make([][]Segment, len(e.Parts))
	for i, p := range e.Parts {
		alts := s.eval(p, depth+1)
		if len(alts) > 0 {
			args[i] = alts[0]
		}
	}

	var out []Segment
	next := 0
	for _, pc := range pieces {
		if pc.literal {
			out = append(out, Literal(pc.text))
			continue
		}
		idx := pc.argIndex
		if idx < 0 {
			idx = next
			next++
		}
		switch {
		case pc.name != "":
			// "{user_id}" names itself; no argument needed.
			out = append(out, Hole("", pc.name, pc.text))
		case idx < len(args) && args[idx] != nil:
			seg := args[idx]
			if len(seg) == 1 && seg[0].Kind == SegLiteral {
				out = append(out, seg[0])
			} else if len(seg) == 1 {
				// Carry the argument's own name through, so
				// Sprintf("%s/users/%s", base, userID) yields {user_id} rather
				// than an anonymous positional token.
				out = append(out, seg[0])
			} else {
				out = append(out, seg...)
			}
		default:
			// A verb with no corresponding argument: keep the verb text as the
			// name so normalize numbers it positionally ({p1}) instead of
			// treating it as a fully opaque tail.
			out = append(out, Hole("", pc.text, pc.text))
		}
	}
	if len(out) == 0 {
		return [][]Segment{{Hole("", "", e.Src)}}
	}
	return [][]Segment{out}
}

type formatPiece struct {
	literal  bool
	text     string
	argIndex int // -1 means "next positional"
	name     string
}

// parseFormat scans a format string into literal and verb pieces. It handles
// "%s"/"%d"/"%-10.2f"/"%%" and "{}"/"{0}"/"{name}"/"{{"/"}}" and "$1".
func parseFormat(f string) []formatPiece {
	var out []formatPiece
	var lit strings.Builder
	flush := func() {
		if lit.Len() > 0 {
			out = append(out, formatPiece{literal: true, text: lit.String()})
			lit.Reset()
		}
	}
	for i := 0; i < len(f); {
		c := f[i]
		switch c {
		case '%':
			if i+1 < len(f) && f[i+1] == '%' {
				lit.WriteByte('%')
				i += 2
				continue
			}
			j := i + 1
			for j < len(f) && strings.IndexByte("+-# 0123456789.*", f[j]) >= 0 {
				j++
			}
			if j < len(f) && isVerbLetter(f[j]) {
				flush()
				out = append(out, formatPiece{text: f[i : j+1], argIndex: -1})
				i = j + 1
				continue
			}
			lit.WriteByte(c)
			i++
		case '{':
			if i+1 < len(f) && f[i+1] == '{' {
				lit.WriteByte('{')
				i += 2
				continue
			}
			j := strings.IndexByte(f[i:], '}')
			if j < 0 {
				lit.WriteByte(c)
				i++
				continue
			}
			inner := f[i+1 : i+j]
			// Drop a format spec: "{0:>10}" or "{name!r}".
			if k := strings.IndexAny(inner, ":!"); k >= 0 {
				inner = inner[:k]
			}
			flush()
			pc := formatPiece{text: f[i : i+j+1], argIndex: -1}
			if inner == "" {
				// "{}" is the next positional argument.
			} else if n, err := strconv.Atoi(inner); err == nil {
				pc.argIndex = n
			} else {
				pc.name = inner
			}
			out = append(out, pc)
			i += j + 1
		case '}':
			if i+1 < len(f) && f[i+1] == '}' {
				lit.WriteByte('}')
				i += 2
				continue
			}
			lit.WriteByte(c)
			i++
		case '$':
			// "$1".."$9" as used by some templating and sprintf variants.
			if i+1 < len(f) && f[i+1] >= '1' && f[i+1] <= '9' {
				flush()
				n, _ := strconv.Atoi(f[i+1 : i+2])
				out = append(out, formatPiece{text: f[i : i+2], argIndex: n - 1})
				i += 2
				continue
			}
			lit.WriteByte(c)
			i++
		default:
			lit.WriteByte(c)
			i++
		}
	}
	flush()
	return out
}

func isVerbLetter(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}

// coalesce merges adjacent literal segments and drops empty ones, so
// resolutions compare equal regardless of how the detector chunked the source.
// Golden-file stability depends on this.
func coalesce(in []Segment) []Segment {
	out := make([]Segment, 0, len(in))
	for _, s := range in {
		if s.Kind == SegLiteral && s.Text == "" {
			continue
		}
		if n := len(out); n > 0 && s.Kind == SegLiteral && out[n-1].Kind == SegLiteral {
			out[n-1].Text += s.Text
			continue
		}
		out = append(out, s)
	}
	return out
}

// indexName renders an ExprIndex as a dotted config key: cfg["a"]["b"] becomes
// "a.b", which is what appears in host_mappings.
func indexName(e *detect.Expr) string {
	var parts []string
	var walk func(*detect.Expr)
	walk = func(n *detect.Expr) {
		if n == nil {
			return
		}
		switch n.Kind {
		case detect.ExprIndex:
			for _, p := range n.Parts {
				walk(p)
			}
		case detect.ExprLit:
			parts = append(parts, n.Text)
		case detect.ExprSymbol:
			parts = append(parts, n.Text)
		}
	}
	walk(e)
	// A config key written "Api:BaseUrl" is one key, not two levels.
	return strings.Join(parts, ".")
}

// lastIdent returns the final identifier component of a dotted or bracketed
// name, which is the best placeholder-name candidate: "u.Profile.ID" -> "ID".
func lastIdent(name string) string {
	name = strings.TrimSuffix(name, "()")
	if i := strings.LastIndexAny(name, ".:->[]"); i >= 0 && i+1 < len(name) {
		return name[i+1:]
	}
	return name
}

func sortedKeys(m map[string]bool) []string {
	if len(m) == 0 {
		return nil
	}
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func mergeSorted(a, b []string) []string {
	if len(a) == 0 {
		return b
	}
	if len(b) == 0 {
		return a
	}
	m := map[string]bool{}
	for _, s := range a {
		m[s] = true
	}
	for _, s := range b {
		m[s] = true
	}
	return sortedKeys(m)
}
