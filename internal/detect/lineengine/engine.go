// Package lineengine detects outbound HTTP calls in the six languages that do
// not get a real parser: JavaScript/TypeScript, Python, Perl, Ruby, Java and C#.
//
// Why not a parser? Because a correct one for six languages means either six
// toolchains at runtime or a CGO dependency on tree-sitter grammars, and this
// binary is meant to be a single static file you can drop on a machine. The
// trade is real and it is made explicitly: every call this package produces is
// tagged "regex_detector" and carries a confidence penalty, so weaker evidence
// is visible in the index rather than presented as equal to the Go AST results.
//
// The engine is shared and the languages are data. Each language supplies a
// Spec -- comment syntax, string syntax, import patterns, call signatures,
// symbol patterns -- and the engine does the rest:
//
//  1. blank out comments and documentation blocks, preserving byte offsets so
//     reported line numbers stay correct;
//  2. collect imports, which gate ambiguous signatures;
//  3. collect symbols and client base-URL bindings;
//  4. match call signatures, slicing real argument lists across newlines with a
//     quote- and bracket-aware scanner rather than a regex;
//  5. translate each URL argument into the shared detect.Expr IR.
//
// Step 4 is what makes this worth doing properly: a regex cannot tell that the
// second argument of app.get("/users", handler) is a function, and that single
// fact is what separates an outbound call from an inbound route definition.
package lineengine

import (
	"context"
	"regexp"
	"strings"

	"github.com/stephen-bee/endpoint-monitor/internal/detect"
)

// Signature describes one recognizable call shape.
type Signature struct {
	// ID is the stable pattern name recorded on each call, e.g. "axios.method".
	ID string
	// Client is the library name recorded on each call, e.g. "axios".
	Client string
	// Head matches the callee and must end immediately before the opening
	// parenthesis of the argument list. Submatch "recv" names the receiver when
	// the pattern has one; submatch "verb" supplies the HTTP method.
	Head *regexp.Regexp
	// Method is a fixed HTTP method. Empty means derive it from the "verb"
	// submatch, then from MethodArg.
	Method string
	// MethodArg is the argument index holding the method, or -1.
	MethodArg int
	// URLArg is the argument index holding the URL.
	URLArg int
	// URLOption names options-object keys that may hold the URL, as in
	// axios({url: "..."}). Several spellings are allowed because the same
	// library is often called both ways.
	URLOption []string
	// MethodOption names options-object keys that may hold the method.
	MethodOption []string
	// DefaultMethod is used when nothing else determines the method. It exists
	// for APIs with a documented default, such as fetch defaulting to GET.
	DefaultMethod string
	// RequireImport gates the signature: at least one of these tokens must
	// appear in the file's imports. This is the single most effective guard
	// against reading unrelated .get() calls as HTTP.
	RequireImport []string
	// RequireText gates the signature on a literal appearing anywhere in the
	// file. Some libraries are used without an import statement we can see --
	// XMLHttpRequest is a global, and a Java annotation is the only evidence a
	// class is a Feign client.
	RequireText []string
	// ForbidText suppresses the signature when a literal appears in the file.
	// This is how the same annotation is read as outbound on a Feign interface
	// and inbound on a Spring controller.
	ForbidText []string
	// RequireInstance restricts the signature to receivers that were bound to a
	// client base URL, which is how axios.create() instances are tracked.
	RequireInstance bool
	// RouteIfHandlerArg marks the site as a route definition when any argument
	// looks like a handler function.
	RouteIfHandlerArg bool
	// AlwaysRoute marks every match as a route definition. Used for server DSLs
	// that we detect only so they can be reported as deliberately excluded.
	AlwaysRoute bool
	// MinArgs skips matches with fewer arguments than this.
	MinArgs int
}

// SymbolPattern extracts a name/value binding.
type SymbolPattern struct {
	// Re must expose submatches "name" and "value".
	Re *regexp.Regexp
	// Scope is where the binding is visible.
	Scope detect.ScopeKind
	// Constant marks immutable bindings.
	Constant bool
}

// BindingPattern extracts a client instance's base URL.
type BindingPattern struct {
	// Re must expose submatches "name" and "value". When "name" is absent the
	// binding applies to the file's default instance.
	Re *regexp.Regexp
}

// InterpSyntax is one string-interpolation form, such as "${" ... "}".
type InterpSyntax struct {
	Open  string
	Close string
}

// StringSyntax describes one string literal form.
type StringSyntax struct {
	// Open and Close delimit the literal. For symmetric quotes they are equal.
	Open  string
	Close string
	// Prefix is a required prefix such as "f" for Python f-strings or "$" for
	// C# interpolated strings.
	Prefix string
	// Interp lists the interpolation forms active inside this literal. Empty
	// means the literal is inert.
	Interp []InterpSyntax
	// BareSigils are characters that introduce a bare interpolated variable,
	// as in Perl's "$base/path".
	BareSigils string
	// NoEscapes disables backslash escape processing, for raw and verbatim
	// strings.
	NoEscapes bool
	// DocString marks a literal that is blanked when it stands alone as a
	// statement. A Python docstring is a string, not a comment, so the scanner
	// would otherwise happily detect the example API calls inside it.
	DocString bool
}

// Spec is one language's configuration.
type Spec struct {
	Lang detect.Language
	Exts []string

	// LineComments and BlockComments are blanked before matching.
	LineComments  []string
	BlockComments [][2]string
	// SkipAfter truncates the file at a marker such as Perl's __END__.
	SkipAfter []string
	// PodBlocks strips Perl-style documentation blocks: lines from a line
	// starting with "=word" through a line starting with "=cut".
	PodBlocks bool

	Strings []StringSyntax

	// ImportRe extracts imported module tokens via submatch "path".
	ImportRe []*regexp.Regexp
	// ClientImports maps an import token substring to a client library name.
	ClientImports map[string]string
	// ServerImports maps an import token substring to a server framework.
	ServerImports map[string]detect.Framework

	Signatures []Signature
	Symbols    []SymbolPattern
	Bindings   []BindingPattern

	// EnvRe extracts environment variable reads via submatch "name".
	EnvRe []*regexp.Regexp
	// FormatCalls are function names whose first argument is a format string.
	FormatCalls []string
	// JoinCalls are function names that join path segments with "/".
	JoinCalls []string
	// ConcatOps are the top-level string concatenation operators.
	ConcatOps []string
	// HandlerHints appear in an argument that is a callback rather than data.
	HandlerHints []string
	// SelfNames are receiver names that refer to the enclosing object, so
	// "self.base_url" can be recorded as a type-scoped symbol.
	SelfNames []string
	// FuncRe locates the enclosing function via submatch "name".
	FuncRe *regexp.Regexp
}

// Detector adapts a Spec to detect.Detector.
type Detector struct{ spec *Spec }

// NewDetector returns a detector for spec.
func NewDetector(spec *Spec) Detector { return Detector{spec: spec} }

// Language implements detect.Detector.
func (d Detector) Language() detect.Language { return d.spec.Lang }

// Extensions implements detect.Detector.
func (d Detector) Extensions() []string { return d.spec.Exts }

// Spec exposes the language configuration, for tests and diagnostics.
func (d Detector) Spec() *Spec { return d.spec }

// Detect implements detect.Detector.
func (d Detector) Detect(ctx context.Context, f *detect.SourceFile) (*detect.FileResult, error) {
	res := &detect.FileResult{}
	src := string(f.Content)
	// Comments are blanked rather than removed so every offset still maps to the
	// original line, which is what keeps reported line numbers honest.
	code := blankNonCode(src, d.spec)

	imports := d.collectImports(code, res)
	d.collectSymbols(code, res)
	instances := d.collectBindings(code, res)
	funcs := d.functionRanges(code)

	for i := range d.spec.Signatures {
		if err := ctx.Err(); err != nil {
			return res, err
		}
		d.matchSignature(&d.spec.Signatures[i], code, imports, instances, funcs, res)
	}
	_ = src
	return res, nil
}

// importSet holds the file's import tokens plus the derived capability flags
// that gate ambiguous signatures.
type importSet struct {
	tokens    []string
	hasClient bool
	hasServer bool
}

func (s importSet) mentions(token string) bool {
	for _, t := range s.tokens {
		if strings.Contains(t, token) {
			return true
		}
	}
	return false
}

func (s importSet) mentionsAny(tokens []string) bool {
	for _, t := range tokens {
		if s.mentions(t) {
			return true
		}
	}
	return false
}

func (d Detector) collectImports(code string, res *detect.FileResult) importSet {
	var set importSet
	seenFramework := map[detect.Framework]bool{}
	for _, re := range d.spec.ImportRe {
		for _, m := range re.FindAllStringSubmatch(code, -1) {
			p := submatch(re, m, "path")
			if p == "" {
				continue
			}
			set.tokens = append(set.tokens, p)
			res.Imports = append(res.Imports, detect.ImportDecl{Path: p})
			for token, lib := range d.spec.ClientImports {
				if strings.Contains(p, token) {
					set.hasClient = true
					_ = lib
				}
			}
			for token, fw := range d.spec.ServerImports {
				if strings.Contains(p, token) && !seenFramework[fw] {
					seenFramework[fw] = true
					set.hasServer = true
					res.Frameworks = append(res.Frameworks, fw)
				}
			}
		}
	}
	return set
}

func (d Detector) collectSymbols(code string, res *detect.FileResult) {
	for _, sp := range d.spec.Symbols {
		for _, loc := range sp.Re.FindAllStringSubmatchIndex(code, -1) {
			name := submatchAt(sp.Re, code, loc, "name")
			value := submatchAt(sp.Re, code, loc, "value")
			if name == "" || value == "" {
				continue
			}
			scope, fn := sp.Scope, ""
			// A "self.x = y" assignment describes the type, not the function it
			// happens to sit in, so it is recorded at type scope.
			if d.isSelfQualified(name) {
				scope = detect.ScopeType
			} else if scope == detect.ScopeFunc {
				fn = d.enclosingFunc(code, loc[0])
			}
			res.Symbols = append(res.Symbols, detect.SymbolDef{
				Name:     name,
				Scope:    scope,
				Func:     fn,
				Value:    d.parseExpr(value),
				Pos:      posAt(code, loc[0]),
				Constant: sp.Constant,
			})
		}
	}
}

func (d Detector) isSelfQualified(name string) bool {
	for _, self := range d.spec.SelfNames {
		if strings.HasPrefix(name, self+".") || strings.HasPrefix(name, self+"->") {
			return true
		}
	}
	return false
}

func (d Detector) collectBindings(code string, res *detect.FileResult) map[string]bool {
	instances := map[string]bool{}
	for _, bp := range d.spec.Bindings {
		for _, loc := range bp.Re.FindAllStringSubmatchIndex(code, -1) {
			name := submatchAt(bp.Re, code, loc, "name")
			value := submatchAt(bp.Re, code, loc, "value")
			if value == "" {
				continue
			}
			res.Bindings = append(res.Bindings, detect.ClientBinding{
				InstanceName: name,
				BaseURL:      d.parseExpr(value),
				Pos:          posAt(code, loc[0]),
			})
			if name != "" {
				instances[name] = true
			}
		}
	}
	return instances
}

// funcRange records one function's extent, for attributing a call to it.
type funcRange struct {
	name  string
	start int
}

func (d Detector) functionRanges(code string) []funcRange {
	if d.spec.FuncRe == nil {
		return nil
	}
	var out []funcRange
	for _, loc := range d.spec.FuncRe.FindAllStringSubmatchIndex(code, -1) {
		name := submatchAt(d.spec.FuncRe, code, loc, "name")
		if name == "" {
			continue
		}
		out = append(out, funcRange{name: name, start: loc[0]})
	}
	return out
}

func (d Detector) enclosingFuncFrom(funcs []funcRange, off int) string {
	name := ""
	for _, f := range funcs {
		if f.start <= off {
			name = f.name
			continue
		}
		break
	}
	return name
}

func (d Detector) enclosingFunc(code string, off int) string {
	return d.enclosingFuncFrom(d.functionRanges(code), off)
}

func (d Detector) matchSignature(sig *Signature, code string, imports importSet, instances map[string]bool, funcs []funcRange, res *detect.FileResult) {
	if len(sig.RequireImport) > 0 && !imports.mentionsAny(sig.RequireImport) {
		return
	}
	if len(sig.RequireText) > 0 && !containsAny(code, sig.RequireText) {
		return
	}
	if len(sig.ForbidText) > 0 && containsAny(code, sig.ForbidText) {
		return
	}
	for _, loc := range sig.Head.FindAllStringSubmatchIndex(code, -1) {
		end := loc[1]
		recv := submatchAt(sig.Head, code, loc, "recv")
		if sig.RequireInstance && recv != "" && !instances[recv] {
			continue
		}
		// The head must be immediately followed by the argument list.
		open := skipSpace(code, end)
		if open >= len(code) || code[open] != '(' {
			continue
		}
		args, _, ok := sliceArgs(code, open, d.spec)
		if !ok || len(args) < sig.MinArgs {
			continue
		}

		site := detect.RawSite{
			Client:  sig.Client,
			Pattern: sig.ID,
			Pos:     posAt(code, loc[0]),
			Src:     detect.TrimSrc(code[loc[0]:min(len(code), open+argsSpan(args))]),
			Func:    d.enclosingFuncFrom(funcs, loc[0]),
			Notes:   []string{"regex_detector"},
		}
		if recv != "" {
			site.BaseHint = recv
		}

		site.URLExpr = d.urlFromArgs(sig, args)
		if site.URLExpr == nil {
			continue
		}
		site.MethodExpr = d.methodFromArgs(sig, code, loc, args)

		switch {
		case sig.AlwaysRoute:
			site.RouteLike = true
		case sig.RouteIfHandlerArg && d.hasHandlerArg(args):
			site.RouteLike = true
		case !imports.hasClient && imports.hasServer && sig.RequireInstance:
			// The file only knows about a server framework, so an ambiguous
			// receiver call is a route registration.
			site.RouteLike = true
		}
		res.Sites = append(res.Sites, site)
	}
}

func (d Detector) urlFromArgs(sig *Signature, args []string) *detect.Expr {
	// An options object can appear in any argument position, so search every
	// argument for the named keys before falling back to a positional read.
	keys := sig.URLOption
	if len(keys) == 0 {
		keys = []string{"url", "uri"}
	}
	for _, a := range args {
		if !isObjectLiteral(a) {
			continue
		}
		for _, key := range keys {
			if v, ok := objectValue(a, key, d.spec); ok {
				return d.parseExpr(v)
			}
		}
	}
	if sig.URLArg < 0 || sig.URLArg >= len(args) {
		return nil
	}
	return d.parseExpr(args[sig.URLArg])
}

func (d Detector) methodFromArgs(sig *Signature, code string, loc []int, args []string) *detect.Expr {
	if sig.Method != "" {
		return detect.Lit(sig.Method)
	}
	if verb := submatchAt(sig.Head, code, loc, "verb"); verb != "" {
		return detect.Lit(normalizeVerb(verb))
	}
	for _, key := range sig.MethodOption {
		for _, a := range args {
			if v, ok := objectValue(a, key, d.spec); ok {
				if lit := literalOf(v, d.spec); lit != "" {
					return detect.Lit(normalizeVerb(lit))
				}
				return d.parseExpr(v)
			}
		}
	}
	if sig.MethodArg >= 0 && sig.MethodArg < len(args) {
		arg := args[sig.MethodArg]
		// Method constants such as HttpMethod.Get or Method.Post are spelled
		// differently in every language but always end in the verb.
		if lit := literalOf(arg, d.spec); lit != "" {
			return detect.Lit(normalizeVerb(lit))
		}
		if v := constVerb(arg); v != "" {
			return detect.Lit(v)
		}
		return d.parseExpr(arg)
	}
	if sig.DefaultMethod != "" {
		return detect.Lit(sig.DefaultMethod)
	}
	return nil
}

// literalOf returns the value of arg when it is a plain string literal.
func literalOf(arg string, spec *Spec) string {
	t := strings.TrimSpace(arg)
	parts, _, end, ok := scanString(t, 0, spec)
	if !ok || end != len(t) || len(parts) != 1 || parts[0].isExpr {
		return ""
	}
	return parts[0].text
}

// constVerb recognizes a method constant such as HttpMethod.Get, Method.Post or
// :get and returns the HTTP verb it names.
func constVerb(arg string) string {
	t := strings.TrimSpace(arg)
	t = strings.TrimPrefix(t, ":")
	if i := strings.LastIndexAny(t, ".:"); i >= 0 {
		t = t[i+1:]
	}
	switch strings.ToUpper(t) {
	case "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS":
		return strings.ToUpper(t)
	}
	return ""
}

func containsAny(s string, needles []string) bool {
	for _, n := range needles {
		if strings.Contains(s, n) {
			return true
		}
	}
	return false
}

// hasHandlerArg reports whether any argument is a callback rather than data.
// This is the structural discriminator between a client call and a server route
// registration, and getting it right is the whole reason arguments are sliced
// properly instead of matched with a regex.
func (d Detector) hasHandlerArg(args []string) bool {
	for i, a := range args {
		if i == 0 {
			continue // the path
		}
		t := strings.TrimSpace(a)
		for _, hint := range d.spec.HandlerHints {
			if strings.Contains(t, hint) {
				return true
			}
		}
		// Structural fallback: a client call's extra arguments are data --
		// objects, literals, numbers. A route's extra arguments are handlers and
		// middleware, which are identifiers or calls. This catches
		// app.use("/static", express.static("public")), where no lambda arrow
		// appears anywhere.
		if !isDataArg(t, d.spec) {
			return true
		}
	}
	return false
}

// isDataArg reports whether an argument is plain data rather than a reference to
// executable code.
func isDataArg(t string, spec *Spec) bool {
	if t == "" {
		return true
	}
	if isObjectLiteral(t) {
		return true
	}
	if _, _, end, ok := scanString(t, 0, spec); ok && end == len(t) {
		return true
	}
	switch t {
	case "nil", "null", "None", "undefined", "true", "false", "True", "False":
		return true
	}
	if t[0] >= '0' && t[0] <= '9' {
		return true
	}
	// A keyword argument such as timeout=30 or json={} is data.
	if strings.Contains(t, "=") && !strings.Contains(t, "=>") && !strings.Contains(t, "==") {
		return true
	}
	return false
}

func normalizeVerb(v string) string {
	v = strings.TrimSpace(v)
	v = strings.TrimSuffix(v, "Async")
	v = strings.TrimPrefix(v, "@")
	v = strings.TrimPrefix(v, "[")
	v = strings.TrimSuffix(v, "]")
	switch strings.ToUpper(v) {
	case "GET", "GETJSON", "GETSTRING", "GETFROMJSON", "GETBYTEARRAY", "GETSTREAM", "DOWNLOADSTRING", "GETJSONASYNC":
		return "GET"
	case "POST", "POSTFORM", "POSTASJSON", "POSTFORMDATA", "POSTJSON", "UPLOADSTRING":
		return "POST"
	case "PUT", "PUTASJSON", "PUTJSON":
		return "PUT"
	case "PATCH", "PATCHJSON", "PATCHFORJSON":
		return "PATCH"
	case "DELETE", "DEL", "DELETEFROMJSON", "DELETEJSON":
		return "DELETE"
	case "HEAD":
		return "HEAD"
	case "OPTIONS":
		return "OPTIONS"
	default:
		return strings.ToUpper(v)
	}
}

func submatch(re *regexp.Regexp, m []string, name string) string {
	for i, n := range re.SubexpNames() {
		if n == name && i < len(m) {
			return m[i]
		}
	}
	return ""
}

func submatchAt(re *regexp.Regexp, src string, loc []int, name string) string {
	for i, n := range re.SubexpNames() {
		if n != name {
			continue
		}
		if 2*i+1 < len(loc) && loc[2*i] >= 0 {
			return src[loc[2*i]:loc[2*i+1]]
		}
	}
	return ""
}

// posAt converts a byte offset to a 1-based line and column.
func posAt(src string, off int) detect.Pos {
	if off > len(src) {
		off = len(src)
	}
	line := 1 + strings.Count(src[:off], "\n")
	col := off - (strings.LastIndex(src[:off], "\n") + 1) + 1
	return detect.Pos{Line: line, Col: col}
}

func skipSpace(s string, i int) int {
	for i < len(s) && (s[i] == ' ' || s[i] == '\t' || s[i] == '\n' || s[i] == '\r') {
		i++
	}
	return i
}

func argsSpan(args []string) int {
	n := 2
	for _, a := range args {
		n += len(a) + 2
	}
	return n
}
