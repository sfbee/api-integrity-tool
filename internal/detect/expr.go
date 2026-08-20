// Package detect defines the contract that every language detector implements.
//
// The single most important idea in this program lives here: detectors know
// syntax and nothing about URLs, while the resolve and normalize packages know
// URLs and nothing about syntax. The two halves meet at Expr, a tiny
// language-agnostic expression tree.
//
// A Go AST detector and a Perl regex detector both emit Expr values, so
// everything downstream of this file -- constant folding, string concatenation,
// format strings, path joining, placeholder naming, host classification -- is
// written exactly once and tested exactly once. Adding a new language means
// adding a translator that produces Expr, not new URL logic.
//
// Detectors must not import internal/resolve, internal/normalize or
// internal/index. TestNoForbiddenImports enforces that.
package detect

import (
	"context"
	"sort"
	"strings"
)

// Language identifies a source language. Values are stable: they appear in the
// on-disk index and in golden files.
type Language string

const (
	LangGo     Language = "go"
	LangJS     Language = "javascript"
	LangTS     Language = "typescript"
	LangPython Language = "python"
	LangPerl   Language = "perl"
	LangRuby   Language = "ruby"
	LangJava   Language = "java"
	LangCSharp Language = "csharp"
)

// ExprKind discriminates Expr. The zero value is deliberately ExprUnknown so a
// half-built Expr degrades to "unresolvable" rather than to "empty literal",
// which would silently fabricate a URL.
type ExprKind uint8

const (
	// ExprUnknown is an opaque expression. Only Src is meaningful.
	ExprUnknown ExprKind = iota
	// ExprLit is a decoded string literal. Text holds the value with quotes
	// removed and escapes interpreted.
	ExprLit
	// ExprConcat joins Parts left to right ("+", ".", "<<", "&").
	ExprConcat
	// ExprSymbol names an identifier to look up: "baseURL", "cfg.Host",
	// "self.base_url", "pkg.BaseURL".
	ExprSymbol
	// ExprEnv reads an environment variable. Text is the variable name and
	// Parts[0], when present, is the default value.
	ExprEnv
	// ExprFormat is a format string in Text with arguments in Parts:
	// fmt.Sprintf, %-formatting, str.format, String.format, sprintf.
	ExprFormat
	// ExprTemplate interleaves literal and interpolated pieces, as produced by
	// template literals, f-strings, "#{}" and "$var" interpolation. Parts holds
	// the pieces in source order; literal pieces are ExprLit.
	ExprTemplate
	// ExprJoin concatenates Parts with exactly one "/" between them:
	// path.Join, url.JoinPath, urljoin, File.join, new URL(rel, base).
	ExprJoin
	// ExprCall is a function call we could not interpret. Text is the callee
	// name and Parts the arguments. Kept rather than discarded because the
	// callee name is often a useful placeholder name.
	ExprCall
	// ExprIndex is a subscript: Parts[0][Parts[1]]. Covers os.environ["X"],
	// config["url"], _config["Api:BaseUrl"].
	ExprIndex
	// ExprCond holds mutually exclusive alternatives (ternary, "a || b", or a
	// variable assigned different values on different paths). The resolver may
	// fan a single call site out into one call per alternative.
	ExprCond
)

// String renders the kind for test failures and debug output.
func (k ExprKind) String() string {
	switch k {
	case ExprLit:
		return "lit"
	case ExprConcat:
		return "concat"
	case ExprSymbol:
		return "symbol"
	case ExprEnv:
		return "env"
	case ExprFormat:
		return "format"
	case ExprTemplate:
		return "template"
	case ExprJoin:
		return "join"
	case ExprCall:
		return "call"
	case ExprIndex:
		return "index"
	case ExprCond:
		return "cond"
	default:
		return "unknown"
	}
}

// Pos is a 1-based source position. Col counts runes, not bytes, so positions
// are stable for non-ASCII source.
type Pos struct {
	Line int
	Col  int
}

// Expr is one node of the shared expression IR. Detectors build these; the
// resolver consumes them.
type Expr struct {
	Kind  ExprKind
	Text  string
	Parts []*Expr
	Pos   Pos
	// Src is the verbatim source slice with runs of whitespace collapsed,
	// truncated to MaxSrcRunes. It exists purely so findings and the index can
	// show a human what the code actually said.
	Src string
}

// MaxSrcRunes bounds Expr.Src and Call.RawExpr. Long enough to show a realistic
// URL-building expression, short enough that a pathological one-line file
// cannot bloat the index.
const MaxSrcRunes = 240

// Lit returns a string-literal expression.
func Lit(s string) *Expr { return &Expr{Kind: ExprLit, Text: s} }

// Sym returns a symbol reference.
func Sym(name string) *Expr { return &Expr{Kind: ExprSymbol, Text: name} }

// Env returns an environment-variable read. def may be nil.
func Env(name string, def *Expr) *Expr {
	e := &Expr{Kind: ExprEnv, Text: name}
	if def != nil {
		e.Parts = []*Expr{def}
	}
	return e
}

// Concat returns the left-to-right concatenation of parts. Nil parts are
// dropped; a single part is returned unwrapped so trees stay shallow.
func Concat(parts ...*Expr) *Expr { return fold(ExprConcat, parts) }

// Join returns parts joined with a single "/" between each.
func Join(parts ...*Expr) *Expr { return fold(ExprJoin, parts) }

// Template returns interleaved literal and interpolated pieces.
func Template(parts ...*Expr) *Expr { return fold(ExprTemplate, parts) }

// Cond returns a set of alternatives.
func Cond(parts ...*Expr) *Expr { return fold(ExprCond, parts) }

// Format returns a format string applied to args.
func Format(format string, args ...*Expr) *Expr {
	return &Expr{Kind: ExprFormat, Text: format, Parts: compact(args)}
}

// Call returns an uninterpreted call to name.
func Call(name string, args ...*Expr) *Expr {
	return &Expr{Kind: ExprCall, Text: name, Parts: compact(args)}
}

// Index returns a subscript expression.
func Index(base, key *Expr) *Expr {
	return &Expr{Kind: ExprIndex, Parts: compact([]*Expr{base, key})}
}

// Unknown returns an opaque expression carrying only its source text.
func Unknown(src string) *Expr { return &Expr{Kind: ExprUnknown, Src: TrimSrc(src)} }

func fold(kind ExprKind, parts []*Expr) *Expr {
	parts = compact(parts)
	switch len(parts) {
	case 0:
		return &Expr{Kind: ExprUnknown}
	case 1:
		// Collapsing a one-element Concat/Join/Template is safe and keeps the
		// resolver's recursion shallow. A one-element Cond is not a choice at
		// all, so the same applies.
		return parts[0]
	default:
		return &Expr{Kind: kind, Parts: parts}
	}
}

func compact(in []*Expr) []*Expr {
	out := make([]*Expr, 0, len(in))
	for _, e := range in {
		if e != nil {
			out = append(out, e)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// TrimSrc collapses whitespace runs and truncates to MaxSrcRunes. Used for
// every source snippet that reaches the index, so a minified line cannot blow
// up the output.
func TrimSrc(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	r := []rune(s)
	if len(r) <= MaxSrcRunes {
		return s
	}
	return string(r[:MaxSrcRunes-1]) + "…"
}

// String renders an Expr in a compact, deterministic form. Test failures read
// far better with this than with %+v on a pointer graph.
func (e *Expr) String() string {
	if e == nil {
		return "<nil>"
	}
	var b strings.Builder
	e.write(&b)
	return b.String()
}

func (e *Expr) write(b *strings.Builder) {
	switch e.Kind {
	case ExprLit:
		b.WriteByte('"')
		b.WriteString(e.Text)
		b.WriteByte('"')
		return
	case ExprSymbol:
		b.WriteString("sym(" + e.Text + ")")
		return
	case ExprEnv:
		b.WriteString("env(" + e.Text)
		if len(e.Parts) == 1 {
			b.WriteString(", ")
			e.Parts[0].write(b)
		}
		b.WriteByte(')')
		return
	case ExprUnknown:
		b.WriteString("?")
		return
	}
	b.WriteString(e.Kind.String())
	if e.Text != "" {
		b.WriteString("[" + e.Text + "]")
	}
	b.WriteByte('(')
	for i, p := range e.Parts {
		if i > 0 {
			b.WriteString(", ")
		}
		p.write(b)
	}
	b.WriteByte(')')
}

// SourceFile is one candidate file handed to a detector. Content is owned by
// the caller and must not be retained after Detect returns; detectors copy the
// slices they need into strings.
type SourceFile struct {
	// RelPath is repo-relative with forward slashes, always. Absolute paths
	// must never reach the index or a golden file.
	RelPath   string
	AbsPath   string
	Lang      Language
	Content   []byte
	Size      int64
	Hash      [32]byte
	Generated bool
}

// FileResult is everything a detector found in one file.
type FileResult struct {
	Sites      []RawSite
	Symbols    []SymbolDef
	Imports    []ImportDecl
	Frameworks []Framework
	Bindings   []ClientBinding
	// Errors collects non-fatal parse problems. A detector must never abort the
	// scan: a file it cannot understand contributes an error and zero sites.
	Errors []error
}

// RawSite is a detected call site, before URL resolution.
type RawSite struct {
	Client     string // "net/http", "axios", "requests", "LWP::UserAgent"
	Pattern    string // signature ID that matched, e.g. "axios.instance.method"
	MethodExpr *Expr  // nil means infer the method from Pattern
	URLExpr    *Expr
	// BaseHint names the client instance whose base URL applies, if any. The
	// resolver looks it up among the file's ClientBindings.
	BaseHint string
	Pos      Pos
	Src      string
	Func     string // enclosing function/method, for Location.Function
	// RouteLike records the detector's own suspicion that this is a server-side
	// route definition rather than an outbound call. classify makes the final
	// call, but the detector has syntax context that classify does not.
	RouteLike bool
	Notes     []string
}

// ScopeKind orders symbol lookup from narrowest to widest.
type ScopeKind uint8

const (
	ScopeFunc ScopeKind = iota
	ScopeType
	ScopeFile
	ScopeModule
)

// SymbolDef is a name bound to a value expression somewhere in the file.
type SymbolDef struct {
	Name     string
	Scope    ScopeKind
	Value    *Expr
	Pos      Pos
	Constant bool
	// Func scopes the definition when Scope is ScopeFunc. Two functions in one
	// file may each define "url" without colliding.
	Func string
	// Param marks a function parameter. A parameter's value is supplied by the
	// caller, so it never resolves to a literal -- but knowing that a host came
	// from a parameter rather than from an unknown global is useful, because it
	// says the host is injected rather than merely unread.
	Param bool
}

// ImportDecl records one import, used to gate ambiguous signatures. Knowing
// that a file imports express and not axios is what lets us classify
// "app.get('/x', handler)" as a route rather than an outbound call.
type ImportDecl struct {
	Path  string
	Alias string
	Pos   Pos
}

// Framework is a server-side framework detected in a file.
type Framework string

// ClientBinding is an HTTP client instance with a base URL: axios.create,
// HttpClient.BaseAddress, Faraday.new(url:), resty SetBaseURL, HTTParty
// base_uri, Retrofit/Refit baseUrl.
type ClientBinding struct {
	InstanceName   string
	BaseURL        *Expr
	DefaultHeaders map[string]string
	Pos            Pos
}

// Detector finds call sites in a single file.
//
// Detect must be pure and safe for concurrent use: the scanner runs one call
// per worker goroutine.
type Detector interface {
	Language() Language
	Extensions() []string
	Detect(ctx context.Context, f *SourceFile) (*FileResult, error)
}

// GroupDetector is implemented by detectors for languages with cross-file
// scope. Go is the motivating case: a const in one file of a package is visible
// to every other file in that package, so package-level symbols cannot be
// resolved until the whole directory has been parsed.
type GroupDetector interface {
	Detector
	// GroupKey buckets files that share a scope. For Go this is the directory.
	GroupKey(f *SourceFile) string
	// ResolveGroup returns the module-scope symbols visible across the group.
	ResolveGroup(ctx context.Context, files []*SourceFile, results []*FileResult) []SymbolDef
}

// Registry maps languages and file extensions to detectors.
type Registry struct {
	byLang map[Language]Detector
	byExt  map[string]Detector
}

// NewRegistry returns an empty registry.
func NewRegistry() *Registry {
	return &Registry{byLang: map[Language]Detector{}, byExt: map[string]Detector{}}
}

// Register adds d, overwriting any detector already claiming its language or
// extensions. Later registrations win so a caller can substitute a detector in
// tests.
func (r *Registry) Register(d Detector) {
	r.byLang[d.Language()] = d
	for _, ext := range d.Extensions() {
		r.byExt[strings.ToLower(ext)] = d
	}
}

// ForExt returns the detector claiming ext (which must include the leading
// dot), and whether one exists.
func (r *Registry) ForExt(ext string) (Detector, bool) {
	d, ok := r.byExt[strings.ToLower(ext)]
	return d, ok
}

// ForLang returns the detector for lang.
func (r *Registry) ForLang(l Language) (Detector, bool) {
	d, ok := r.byLang[l]
	return d, ok
}

// Languages returns the registered languages in sorted order.
func (r *Registry) Languages() []Language {
	out := make([]Language, 0, len(r.byLang))
	for l := range r.byLang {
		out = append(out, l)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// Extensions returns every claimed extension in sorted order. The walker uses
// this to decide which files are worth reading at all.
func (r *Registry) Extensions() []string {
	out := make([]string, 0, len(r.byExt))
	for e := range r.byExt {
		out = append(out, e)
	}
	sort.Strings(out)
	return out
}
