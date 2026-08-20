package golang

import (
	"go/ast"
	"go/token"
	"strconv"
	"strings"

	"github.com/stephen-bee/endpoint-monitor/internal/detect"
)

// expr translates a Go expression into the shared IR.
//
// Only the constructs that actually build URLs are interpreted. Everything else
// becomes an opaque node carrying its source text, which the resolver reports as
// a hole -- an honest "we could not read this" rather than a guess.
func (fc *fileCtx) expr(e ast.Expr) *detect.Expr {
	if e == nil {
		return nil
	}
	e = unparen(e)
	var out *detect.Expr

	switch v := e.(type) {
	case *ast.BasicLit:
		switch v.Kind {
		case token.STRING:
			s, err := strconv.Unquote(v.Value)
			if err != nil {
				// A raw string with an odd escape still has usable content.
				s = strings.Trim(v.Value, "`\"")
			}
			out = detect.Lit(s)
		case token.INT, token.FLOAT:
			out = detect.Lit(v.Value)
		default:
			out = detect.Unknown(fc.text(v))
		}

	case *ast.BinaryExpr:
		if v.Op == token.ADD {
			out = detect.Concat(fc.expr(v.X), fc.expr(v.Y))
		} else {
			out = detect.Unknown(fc.text(v))
		}

	case *ast.Ident:
		switch v.Name {
		case "nil", "true", "false":
			out = detect.Unknown(v.Name)
		default:
			out = detect.Sym(v.Name)
		}

	case *ast.SelectorExpr:
		out = fc.selectorExpr(v)

	case *ast.IndexExpr:
		out = detect.Index(fc.expr(v.X), fc.expr(v.Index))

	case *ast.CallExpr:
		out = fc.callExpr(v)

	case *ast.CompositeLit:
		out = fc.compositeExpr(v)

	case *ast.UnaryExpr:
		if v.Op == token.AND {
			out = fc.expr(v.X)
		} else {
			out = detect.Unknown(fc.text(v))
		}

	case *ast.StarExpr:
		out = fc.expr(v.X)

	default:
		out = detect.Unknown(fc.text(e))
	}

	if out != nil {
		out.Pos = fc.pos(e.Pos())
		if out.Src == "" {
			out.Src = fc.text(e)
		}
	}
	return out
}

// selectorExpr renders a field or qualified reference as a dotted symbol name.
// A method receiver is rewritten to its type, so "c.baseURL" inside a method on
// *Client becomes "Client.baseURL" and matches the field assignment recorded by
// the constructor.
func (fc *fileCtx) selectorExpr(v *ast.SelectorExpr) *detect.Expr {
	if id, ok := unparen(v.X).(*ast.Ident); ok {
		if tn, ok := fc.receivers[id.Name]; ok {
			return detect.Sym(tn + "." + v.Sel.Name)
		}
		return detect.Sym(id.Name + "." + v.Sel.Name)
	}
	return detect.Sym(flattenSelector(v))
}

func flattenSelector(e ast.Expr) string {
	switch v := unparen(e).(type) {
	case *ast.Ident:
		return v.Name
	case *ast.SelectorExpr:
		if base := flattenSelector(v.X); base != "" {
			return base + "." + v.Sel.Name
		}
		return v.Sel.Name
	case *ast.CallExpr:
		return flattenSelector(v.Fun)
	case *ast.IndexExpr:
		return flattenSelector(v.X)
	}
	return ""
}

// callExpr interprets the small set of calls that build URLs.
func (fc *fileCtx) callExpr(v *ast.CallExpr) *detect.Expr {
	pkg, sel := fc.qualified(v.Fun)
	imported := fc.aliases[pkg]

	switch {
	case imported == "fmt" && (sel == "Sprintf" || sel == "Sprint"):
		if sel == "Sprint" {
			return detect.Concat(fc.exprs(v.Args)...)
		}
		if len(v.Args) >= 1 {
			if f, ok := stringLit(v.Args[0]); ok {
				return detect.Format(f, fc.exprs(v.Args[1:])...)
			}
		}
		return detect.Call("fmt.Sprintf", fc.exprs(v.Args)...)

	case (imported == "path" || imported == "path/filepath") && sel == "Join":
		return detect.Join(fc.exprs(v.Args)...)

	case imported == "net/url" && sel == "JoinPath":
		return detect.Join(fc.exprs(v.Args)...)

	case imported == "os" && (sel == "Getenv" || sel == "LookupEnv"):
		if len(v.Args) >= 1 {
			if name, ok := stringLit(v.Args[0]); ok {
				return detect.Env(name, nil)
			}
		}
		return detect.Call("os.Getenv", fc.exprs(v.Args)...)

	case imported == "os" && sel == "ExpandEnv":
		if len(v.Args) == 1 {
			return fc.expr(v.Args[0])
		}

	case imported == "strings" && sel == "Join":
		// strings.Join(parts, "/") is a path join; any other separator is not.
		if len(v.Args) == 2 {
			if sep, ok := stringLit(v.Args[1]); ok && sep == "/" {
				return detect.Join(fc.expr(v.Args[0]))
			}
		}

	case imported == "strings" && (sel == "TrimSuffix" || sel == "TrimRight" || sel == "TrimSpace"):
		// Trimming a trailing slash does not change the endpoint; normalization
		// handles slashes, so pass the subject through.
		if len(v.Args) >= 1 {
			return fc.expr(v.Args[0])
		}

	case imported == "net/url" && (sel == "PathEscape" || sel == "QueryEscape"):
		if len(v.Args) == 1 {
			return fc.expr(v.Args[0])
		}
	}

	// Method calls on a value: "u.String()", "u.JoinPath(x)", "b.String()".
	if se, ok := unparen(v.Fun).(*ast.SelectorExpr); ok {
		switch se.Sel.Name {
		case "String":
			return fc.expr(se.X)
		case "JoinPath":
			return detect.Join(append([]*detect.Expr{fc.expr(se.X)}, fc.exprs(v.Args)...)...)
		}
	}

	name := flattenSelector(v.Fun)
	if name == "" {
		name = "call"
	}
	return detect.Call(name, fc.exprs(v.Args)...)
}

// compositeExpr handles url.URL literals, which are a common way to build a
// request target without ever writing a full URL string.
func (fc *fileCtx) compositeExpr(v *ast.CompositeLit) *detect.Expr {
	pkg, sel := fc.qualified(v.Type)
	if fc.aliases[pkg] != "net/url" || sel != "URL" {
		return detect.Unknown(fc.text(v))
	}
	fields := map[string]*detect.Expr{}
	for _, elt := range v.Elts {
		kv, ok := elt.(*ast.KeyValueExpr)
		if !ok {
			continue
		}
		key, ok := kv.Key.(*ast.Ident)
		if !ok {
			continue
		}
		fields[key.Name] = fc.expr(kv.Value)
	}
	var parts []*detect.Expr
	if s, ok := fields["Scheme"]; ok {
		parts = append(parts, s, detect.Lit("://"))
	}
	if h, ok := fields["Host"]; ok {
		parts = append(parts, h)
	}
	if p, ok := fields["Path"]; ok {
		parts = append(parts, p)
	}
	if len(parts) == 0 {
		return detect.Unknown(fc.text(v))
	}
	return detect.Concat(parts...)
}

func (fc *fileCtx) exprs(in []ast.Expr) []*detect.Expr {
	out := make([]*detect.Expr, 0, len(in))
	for _, e := range in {
		out = append(out, fc.expr(e))
	}
	return out
}

func stringLit(e ast.Expr) (string, bool) {
	bl, ok := unparen(e).(*ast.BasicLit)
	if !ok || bl.Kind != token.STRING {
		return "", false
	}
	s, err := strconv.Unquote(bl.Value)
	if err != nil {
		return strings.Trim(bl.Value, "`\""), true
	}
	return s, true
}
