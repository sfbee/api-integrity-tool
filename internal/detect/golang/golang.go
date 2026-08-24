// Package golang detects outbound HTTP calls in Go source using the standard
// go/parser and go/ast packages.
//
// This is the reference detector: it proves the detect.Expr contract before any
// other language is attempted, and it is the only detector that gets real
// syntax analysis rather than pattern matching.
//
// It parses without type checking. That is a deliberate trade: a large share of
// real repositories will not type-check in a scanning sandbox (missing
// dependencies, build tags, generated code), and refusing to scan them would
// make the tool useless exactly when it is most needed. Parse-only analysis
// resolves imports, package-level constants and single-assignment locals, which
// covers the overwhelming majority of URL construction. Where it cannot be
// certain -- notably whether an unknown receiver is really an *http.Client --
// it says so through a flag rather than guessing.
package golang

import (
	"context"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"path"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/sfbee/api-integrity-tool/internal/detect"
)

// Detector implements detect.Detector and detect.GroupDetector for Go.
type Detector struct{}

// New returns a Go detector.
func New() Detector { return Detector{} }

// Language implements detect.Detector.
func (Detector) Language() detect.Language { return detect.LangGo }

// Extensions implements detect.Detector.
func (Detector) Extensions() []string { return []string{".go"} }

// GroupKey buckets files by directory, which is a Go package: a constant
// declared in one file is visible to every other file beside it.
func (Detector) GroupKey(f *detect.SourceFile) string { return path.Dir(f.RelPath) }

// Client library import paths we recognize, mapped to the client name recorded
// on each call.
var clientPackages = map[string]string{
	"net/http":                              "net/http",
	"github.com/go-resty/resty/v2":          "resty",
	"github.com/go-resty/resty/v3":          "resty",
	"resty.dev/v3":                          "resty",
	"github.com/hashicorp/go-retryablehttp": "retryablehttp",
	"github.com/levigross/grequests":        "grequests",
	"github.com/imroc/req/v3":               "req",
}

// Server framework import paths. Their presence in a file is what lets us treat
// an ambiguous "r.Get(...)" as a route definition rather than an outbound call.
var serverFrameworks = map[string]detect.Framework{
	"net/http/httptest":                   "httptest",
	"github.com/gin-gonic/gin":            "gin",
	"github.com/labstack/echo":            "echo",
	"github.com/labstack/echo/v4":         "echo",
	"github.com/go-chi/chi":               "chi",
	"github.com/go-chi/chi/v5":            "chi",
	"github.com/gorilla/mux":              "gorilla/mux",
	"github.com/gofiber/fiber":            "fiber",
	"github.com/gofiber/fiber/v2":         "fiber",
	"github.com/julienschmidt/httprouter": "httprouter",
	"github.com/gofrs/http":               "generic",
}

// requestMethods maps net/http and resty accessor names to HTTP methods.
var requestMethods = map[string]string{
	"Get":      "GET",
	"Head":     "HEAD",
	"Post":     "POST",
	"PostForm": "POST",
	"Put":      "PUT",
	"Patch":    "PATCH",
	"Delete":   "DELETE",
	"Options":  "OPTIONS",
}

// allCapsMethods are router DSL method names. No Go HTTP client uses all-caps
// method names, so a call to one of these is always a route definition. This is
// the cheapest and most reliable of the route discriminators.
var allCapsMethods = map[string]bool{
	"GET": true, "HEAD": true, "POST": true, "PUT": true,
	"PATCH": true, "DELETE": true, "OPTIONS": true, "CONNECT": true, "TRACE": true,
}

// routeFuncs are names that always register a handler.
var routeFuncs = map[string]bool{
	"HandleFunc": true, "Handle": true, "PathPrefix": true, "Methods": true,
	"Mount": true, "Route": true, "Group": true, "Use": true,
	"MapGet": true, "MapPost": true, "RegisterService": true,
}

// Detect implements detect.Detector.
func (d Detector) Detect(ctx context.Context, f *detect.SourceFile) (*detect.FileResult, error) {
	res := &detect.FileResult{}
	fset := token.NewFileSet()
	// SkipObjectResolution: we build our own scope chain, and object resolution
	// costs time we would throw away. ParseComments so generated-code markers
	// and directives remain visible.
	file, err := parser.ParseFile(fset, f.RelPath, f.Content, parser.SkipObjectResolution|parser.ParseComments)
	if file == nil {
		// Unparseable beyond recovery. Report it and move on; one bad file must
		// never fail a scan.
		res.Errors = append(res.Errors, fmt.Errorf("parse %s: %w", f.RelPath, err))
		return res, nil
	}
	if err != nil {
		res.Errors = append(res.Errors, fmt.Errorf("parse %s (partial): %w", f.RelPath, err))
	}

	fc := &fileCtx{
		src:       f.Content,
		fset:      fset,
		rel:       f.RelPath,
		aliases:   map[string]string{},
		clients:   map[string]string{},
		receivers: map[string]string{},
	}
	fc.collectImports(file, res)

	// Two passes over declarations. The first records every symbol, so a
	// constant declared at the bottom of the file resolves for a call at the
	// top. The second matches call sites.
	for _, decl := range file.Decls {
		fc.collectDecl(decl, res)
	}
	for _, decl := range file.Decls {
		if err := ctx.Err(); err != nil {
			return res, err
		}
		fn, _ := decl.(*ast.FuncDecl)
		if fn == nil || fn.Body == nil {
			continue
		}
		fc.walkFunc(fn, res)
	}
	return res, nil
}

// ResolveGroup republishes each file's package-level symbols at module scope so
// they are visible to every other file in the same directory.
func (d Detector) ResolveGroup(ctx context.Context, files []*detect.SourceFile, results []*detect.FileResult) []detect.SymbolDef {
	var out []detect.SymbolDef
	for _, r := range results {
		if r == nil {
			continue
		}
		for _, s := range r.Symbols {
			switch s.Scope {
			case detect.ScopeFile, detect.ScopeType:
				promoted := s
				if s.Scope == detect.ScopeFile {
					promoted.Scope = detect.ScopeModule
				}
				out = append(out, promoted)
			}
		}
	}
	return out
}

// fileCtx carries per-file state through the walk.
type fileCtx struct {
	src  []byte
	fset *token.FileSet
	rel  string
	// aliases maps the local package name to its import path.
	aliases map[string]string
	// clients maps a local variable name to a client library, populated from
	// constructor calls such as "c := &http.Client{}" or "r := resty.New()".
	clients map[string]string
	// receivers maps a method receiver name to its type name, so "c.baseURL"
	// inside a method on *Client can be recorded as "Client.baseURL".
	receivers  map[string]string
	frameworks map[detect.Framework]bool
	hasClient  bool
}

func (fc *fileCtx) pos(p token.Pos) detect.Pos {
	pp := fc.fset.Position(p)
	return detect.Pos{Line: pp.Line, Col: pp.Column}
}

// text returns the verbatim source of n, whitespace-collapsed and truncated.
func (fc *fileCtx) text(n ast.Node) string {
	if n == nil {
		return ""
	}
	start := fc.fset.Position(n.Pos()).Offset
	end := fc.fset.Position(n.End()).Offset
	if start < 0 || end > len(fc.src) || start >= end {
		return ""
	}
	return detect.TrimSrc(string(fc.src[start:end]))
}

func (fc *fileCtx) collectImports(file *ast.File, res *detect.FileResult) {
	fc.frameworks = map[detect.Framework]bool{}
	for _, imp := range file.Imports {
		p, err := strconv.Unquote(imp.Path.Value)
		if err != nil {
			continue
		}
		alias := path.Base(p)
		if imp.Name != nil {
			alias = imp.Name.Name
		}
		// Version suffixes are not part of the package name.
		if strings.HasPrefix(alias, "v") && len(alias) <= 3 && imp.Name == nil {
			if parts := strings.Split(p, "/"); len(parts) >= 2 {
				alias = parts[len(parts)-2]
			}
		}
		fc.aliases[alias] = p
		res.Imports = append(res.Imports, detect.ImportDecl{Path: p, Alias: alias, Pos: fc.pos(imp.Pos())})
		if _, ok := clientPackages[p]; ok {
			fc.hasClient = true
		}
		if fw, ok := serverFrameworks[p]; ok {
			fc.frameworks[fw] = true
			res.Frameworks = append(res.Frameworks, fw)
		}
	}
}

// collectDecl records package-level constants, variables and struct field
// initialisations.
func (fc *fileCtx) collectDecl(decl ast.Decl, res *detect.FileResult) {
	switch d := decl.(type) {
	case *ast.GenDecl:
		if d.Tok == token.TYPE {
			// A struct field holding an *http.Client is how most real clients
			// are written. Recording the field's type here is what turns
			// "c.hc.Get(url)" into a verified outbound call rather than a guess.
			for _, spec := range d.Specs {
				ts, ok := spec.(*ast.TypeSpec)
				if !ok {
					continue
				}
				st, ok := ts.Type.(*ast.StructType)
				if !ok || st.Fields == nil {
					continue
				}
				for _, field := range st.Fields.List {
					pkg, sel := fc.qualified(field.Type)
					if sel != "Client" {
						continue
					}
					lib, ok := clientPackages[fc.aliases[pkg]]
					if !ok {
						continue
					}
					for _, fname := range field.Names {
						fc.clients[ts.Name.Name+"."+fname.Name] = lib
					}
				}
			}
			return
		}
		if d.Tok != token.CONST && d.Tok != token.VAR {
			return
		}
		for _, spec := range d.Specs {
			vs, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			for i, name := range vs.Names {
				if i >= len(vs.Values) {
					continue
				}
				res.Symbols = append(res.Symbols, detect.SymbolDef{
					Name:     name.Name,
					Scope:    detect.ScopeFile,
					Value:    fc.expr(vs.Values[i]),
					Pos:      fc.pos(name.Pos()),
					Constant: d.Tok == token.CONST,
				})
			}
		}
	case *ast.FuncDecl:
		// Record the receiver's type so field references inside the method can
		// be attributed to it.
		if d.Recv != nil && len(d.Recv.List) > 0 {
			rf := d.Recv.List[0]
			tn := typeName(rf.Type)
			if tn != "" && len(rf.Names) > 0 {
				fc.receivers[rf.Names[0].Name] = tn
			}
		}
		// Constructors assign struct fields; those assignments are how
		// "c.baseURL" gets a value.
		ast.Inspect(d, func(n ast.Node) bool {
			cl, ok := n.(*ast.CompositeLit)
			if !ok {
				return true
			}
			tn := typeName(cl.Type)
			if tn == "" {
				return true
			}
			for _, elt := range cl.Elts {
				kv, ok := elt.(*ast.KeyValueExpr)
				if !ok {
					continue
				}
				key, ok := kv.Key.(*ast.Ident)
				if !ok {
					continue
				}
				res.Symbols = append(res.Symbols, detect.SymbolDef{
					Name:  tn + "." + key.Name,
					Scope: detect.ScopeType,
					Value: fc.expr(kv.Value),
					Pos:   fc.pos(kv.Pos()),
				})
			}
			return true
		})
	}
}

// walkFunc records the function's parameters and locals, then matches calls.
func (fc *fileCtx) walkFunc(fn *ast.FuncDecl, res *detect.FileResult) {
	name := fn.Name.Name
	if fn.Recv != nil && len(fn.Recv.List) > 0 {
		if tn := typeName(fn.Recv.List[0].Type); tn != "" {
			name = tn + "." + name
		}
	}

	if fn.Type.Params != nil {
		for _, field := range fn.Type.Params.List {
			for _, id := range field.Names {
				res.Symbols = append(res.Symbols, detect.SymbolDef{
					Name: id.Name, Scope: detect.ScopeFunc, Func: name,
					Pos: fc.pos(id.Pos()), Param: true,
				})
			}
		}
	}

	// Locals first, so a variable assigned below its use still resolves. Go
	// forbids that for real, but generated code and closures blur the order.
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		switch s := n.(type) {
		case *ast.AssignStmt:
			fc.collectAssign(s, name, res)
		case *ast.DeclStmt:
			gd, ok := s.Decl.(*ast.GenDecl)
			if !ok || (gd.Tok != token.VAR && gd.Tok != token.CONST) {
				return true
			}
			for _, spec := range gd.Specs {
				vs, ok := spec.(*ast.ValueSpec)
				if !ok {
					continue
				}
				for i, id := range vs.Names {
					if i < len(vs.Values) {
						res.Symbols = append(res.Symbols, detect.SymbolDef{
							Name: id.Name, Scope: detect.ScopeFunc, Func: name,
							Value: fc.expr(vs.Values[i]), Pos: fc.pos(id.Pos()),
							Constant: gd.Tok == token.CONST,
						})
						fc.noteClientVar(id.Name, vs.Values[i])
					}
				}
			}
		}
		return true
	})

	ast.Inspect(fn.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		fc.matchCall(call, name, res)
		return true
	})
}

func (fc *fileCtx) collectAssign(s *ast.AssignStmt, fn string, res *detect.FileResult) {
	// Only simple positional assignment carries a usable value. A multi-value
	// call such as "req, err := http.NewRequest(...)" binds the request, not a
	// URL, and is handled by matchCall.
	if len(s.Lhs) == len(s.Rhs) {
		for i, lhs := range s.Lhs {
			id, ok := lhs.(*ast.Ident)
			if !ok || id.Name == "_" {
				continue
			}
			res.Symbols = append(res.Symbols, detect.SymbolDef{
				Name: id.Name, Scope: detect.ScopeFunc, Func: fn,
				Value: fc.expr(s.Rhs[i]), Pos: fc.pos(id.Pos()),
			})
			fc.noteClientVar(id.Name, s.Rhs[i])
		}
		return
	}
	// "v, err := f()" is the dominant Go idiom, and the value it binds is
	// frequently the URL itself: "u, _ := url.JoinPath(base, \"v2\", \"things\")".
	// Bind the first result to the call expression so the resolver can look
	// through it. Binding a non-URL value here is harmless: it simply resolves
	// to a hole that nothing asks about.
	if len(s.Rhs) == 1 && len(s.Lhs) > 1 {
		if id, ok := s.Lhs[0].(*ast.Ident); ok && id.Name != "_" {
			res.Symbols = append(res.Symbols, detect.SymbolDef{
				Name: id.Name, Scope: detect.ScopeFunc, Func: fn,
				Value: fc.expr(s.Rhs[0]), Pos: fc.pos(id.Pos()),
			})
			fc.noteClientVar(id.Name, s.Rhs[0])
		}
	}
}

// noteClientVar records that a variable holds an HTTP client, which is what
// makes "c.Get(url)" a verified outbound call rather than a guess.
func (fc *fileCtx) noteClientVar(name string, rhs ast.Expr) {
	switch v := rhs.(type) {
	case *ast.UnaryExpr:
		if v.Op == token.AND {
			fc.noteClientVar(name, v.X)
		}
	case *ast.CompositeLit:
		if pkg, sel := fc.qualified(v.Type); sel == "Client" {
			if lib, ok := clientPackages[fc.aliases[pkg]]; ok {
				fc.clients[name] = lib
			}
		}
	case *ast.SelectorExpr:
		// http.DefaultClient
		if pkg, sel := fc.qualified(v); sel == "DefaultClient" {
			if lib, ok := clientPackages[fc.aliases[pkg]]; ok {
				fc.clients[name] = lib
			}
		}
	case *ast.CallExpr:
		pkg, sel := fc.qualified(v.Fun)
		lib, ok := clientPackages[fc.aliases[pkg]]
		if !ok {
			return
		}
		switch sel {
		case "New", "NewClient", "NewRequest", "Client":
			fc.clients[name] = lib
		}
	}
}

// qualified splits "pkg.Sel" into its parts. It returns empty strings when e is
// not a package-qualified selector.
func (fc *fileCtx) qualified(e ast.Expr) (pkg, sel string) {
	e = unparen(e)
	if star, ok := e.(*ast.StarExpr); ok {
		e = unparen(star.X)
	}
	se, ok := e.(*ast.SelectorExpr)
	if !ok {
		return "", ""
	}
	id, ok := unparen(se.X).(*ast.Ident)
	if !ok {
		return "", ""
	}
	return id.Name, se.Sel.Name
}

// matchCall tests one call expression against every signature.
func (fc *fileCtx) matchCall(call *ast.CallExpr, fn string, res *detect.FileResult) {
	se, ok := unparen(call.Fun).(*ast.SelectorExpr)
	if !ok {
		return
	}
	sel := se.Sel.Name

	// Router DSLs first: an all-caps method name or a handler-registering
	// function is never an outbound call. These are recorded as route-like
	// sites rather than discarded, so classification counts them and
	// --explain-drops can answer "why didn't you find my call?".
	if allCapsMethods[sel] || routeFuncs[sel] {
		if len(call.Args) > 0 {
			res.Sites = append(res.Sites, detect.RawSite{
				Client: "route", Pattern: "go.route." + sel,
				MethodExpr: routeMethodExpr(sel),
				URLExpr:    fc.expr(call.Args[0]),
				Pos:        fc.pos(call.Pos()), Src: fc.text(call),
				Func: fn, RouteLike: true,
			})
		}
		return
	}

	recvPkg, _ := fc.qualified(call.Fun)
	importPath := fc.aliases[recvPkg]
	lib, isPkgCall := clientPackages[importPath]

	site := detect.RawSite{
		Pos:  fc.pos(call.Pos()),
		Src:  fc.text(call),
		Func: fn,
	}

	switch {
	case isPkgCall && lib == "net/http":
		switch sel {
		case "NewRequest":
			if len(call.Args) >= 2 {
				site.Client, site.Pattern = lib, "net/http.NewRequest"
				site.MethodExpr, site.URLExpr = fc.expr(call.Args[0]), fc.expr(call.Args[1])
				res.Sites = append(res.Sites, site)
			}
			return
		case "NewRequestWithContext":
			if len(call.Args) >= 3 {
				site.Client, site.Pattern = lib, "net/http.NewRequestWithContext"
				site.MethodExpr, site.URLExpr = fc.expr(call.Args[1]), fc.expr(call.Args[2])
				res.Sites = append(res.Sites, site)
			}
			return
		case "Get", "Head", "Post", "PostForm":
			if len(call.Args) >= 1 {
				site.Client, site.Pattern = lib, "net/http.pkgfunc"
				site.MethodExpr = detect.Lit(requestMethods[sel])
				site.URLExpr = fc.expr(call.Args[0])
				res.Sites = append(res.Sites, site)
			}
			return
		}
		return

	case isPkgCall && lib != "":
		// Package-level helpers on a third-party client: resty.New() is handled
		// by noteClientVar, but retryablehttp.Get and grequests.Get are direct.
		if m, ok := requestMethods[sel]; ok && len(call.Args) >= 1 {
			site.Client, site.Pattern = lib, lib+".pkgfunc"
			site.MethodExpr = detect.Lit(m)
			site.URLExpr = fc.expr(call.Args[0])
			res.Sites = append(res.Sites, site)
		}
		if sel == "NewRequest" && len(call.Args) >= 2 {
			site.Client, site.Pattern = lib, lib+".NewRequest"
			site.MethodExpr, site.URLExpr = fc.expr(call.Args[0]), fc.expr(call.Args[1])
			res.Sites = append(res.Sites, site)
		}
		return
	}

	// A method call on some receiver. Resty's fluent chain and a plain
	// *http.Client both land here.
	m, isMethod := requestMethods[sel]
	if !isMethod && sel != "Execute" && sel != "SetBaseURL" && sel != "SetHostURL" {
		return
	}

	recvName := fc.receiverKey(se.X)

	if sel == "SetBaseURL" || sel == "SetHostURL" {
		if len(call.Args) >= 1 {
			res.Bindings = append(res.Bindings, detect.ClientBinding{
				InstanceName: recvName,
				BaseURL:      fc.expr(call.Args[0]),
				Pos:          fc.pos(call.Pos()),
			})
		}
		return
	}

	restyChain := chainHasR(se.X)
	clientLib := fc.clients[recvName]

	switch {
	case restyChain:
		site.Client = "resty"
		site.Pattern = "resty.request"
		site.BaseHint = rootIdent(se.X)
	case clientLib != "":
		site.Client = clientLib
		site.Pattern = clientLib + ".client.method"
		site.BaseHint = recvName
	case fc.hasClient:
		// The receiver is unverified: we cannot prove it is an HTTP client
		// without type information. The file does import a client library, so
		// this is plausible -- record it, mark it, and let classification and
		// scoring decide. Files with no client import at all are skipped
		// entirely, which is what keeps cache.Get("key") out of the index.
		site.Client = "unknown"
		site.Pattern = "go.receiver.method"
		site.BaseHint = recvName
		site.Notes = append(site.Notes, "unverified_receiver")
	default:
		return
	}

	if sel == "Execute" {
		if len(call.Args) >= 2 {
			site.MethodExpr, site.URLExpr = fc.expr(call.Args[0]), fc.expr(call.Args[1])
			res.Sites = append(res.Sites, site)
		}
		return
	}
	if len(call.Args) == 0 {
		return
	}
	site.MethodExpr = detect.Lit(m)
	site.URLExpr = fc.expr(call.Args[0])

	// A handler-shaped trailing argument means this is a route registration
	// that slipped past the name checks (chi and fiber use title-case verbs).
	if hasHandlerArg(call) {
		site.RouteLike = true
	}
	res.Sites = append(res.Sites, site)
}

// chainHasR reports whether a selector chain contains a ".R()" call, the
// signature of a resty request.
func chainHasR(e ast.Expr) bool {
	for {
		switch v := unparen(e).(type) {
		case *ast.CallExpr:
			if se, ok := unparen(v.Fun).(*ast.SelectorExpr); ok {
				if se.Sel.Name == "R" {
					return true
				}
				e = se.X
				continue
			}
			return false
		case *ast.SelectorExpr:
			e = v.X
		default:
			return false
		}
	}
}

// receiverKey names the receiver of a method call, rewriting a method's own
// receiver variable to its type. Inside a method on *Client, "c.hc" becomes
// "Client.hc", which is the key the struct-field pass recorded.
func (fc *fileCtx) receiverKey(e ast.Expr) string {
	if se, ok := unparen(e).(*ast.SelectorExpr); ok {
		if id, ok := unparen(se.X).(*ast.Ident); ok {
			if tn, ok := fc.receivers[id.Name]; ok {
				return tn + "." + se.Sel.Name
			}
		}
	}
	return receiverIdent(e)
}

// routeMethodExpr recovers the HTTP method a router DSL name implies.
func routeMethodExpr(sel string) *detect.Expr {
	if allCapsMethods[sel] {
		return detect.Lit(sel)
	}
	if m, ok := requestMethods[sel]; ok {
		return detect.Lit(m)
	}
	return nil
}

// receiverIdent names the immediate receiver of a method call.
func receiverIdent(e ast.Expr) string {
	switch v := unparen(e).(type) {
	case *ast.Ident:
		return v.Name
	case *ast.SelectorExpr:
		if id, ok := unparen(v.X).(*ast.Ident); ok {
			return id.Name + "." + v.Sel.Name
		}
		return v.Sel.Name
	case *ast.CallExpr:
		return receiverIdent(v.Fun)
	}
	return ""
}

// rootIdent walks to the base of a chain: for "c.R().SetBody(x)" it returns "c".
func rootIdent(e ast.Expr) string {
	for {
		switch v := unparen(e).(type) {
		case *ast.Ident:
			return v.Name
		case *ast.SelectorExpr:
			e = v.X
		case *ast.CallExpr:
			e = v.Fun
		default:
			return ""
		}
	}
}

// hasHandlerArg reports whether any argument is a function literal, which marks
// a route registration.
func hasHandlerArg(call *ast.CallExpr) bool {
	for _, a := range call.Args {
		switch unparen(a).(type) {
		case *ast.FuncLit:
			return true
		}
	}
	return false
}

func typeName(e ast.Expr) string {
	switch v := unparen(e).(type) {
	case *ast.Ident:
		return v.Name
	case *ast.StarExpr:
		return typeName(v.X)
	case *ast.SelectorExpr:
		return v.Sel.Name
	case *ast.IndexExpr: // generic instantiation
		return typeName(v.X)
	}
	return ""
}

func unparen(e ast.Expr) ast.Expr {
	for {
		p, ok := e.(*ast.ParenExpr)
		if !ok {
			return e
		}
		e = p.X
	}
}

// ensure filepath stays referenced if the build tags change; GroupKey uses path
// because index paths are always slash-separated.
var _ = filepath.Separator
