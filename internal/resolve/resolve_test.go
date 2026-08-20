package resolve

import (
	"strings"
	"testing"

	"github.com/stephen-bee/endpoint-monitor/internal/detect"
)

// render turns a Resolution into a compact comparable string: literals as-is,
// holes as <sym|name>. Reading a diff of these is much easier than comparing
// segment structs field by field.
func render(r Resolution) string {
	var b strings.Builder
	for _, s := range r.Segments {
		if s.Kind == SegLiteral {
			b.WriteString(s.Text)
			continue
		}
		b.WriteString("<" + s.Sym + "|" + s.Name + ">")
	}
	return b.String()
}

func TestResolveLiteralsAndConcat(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		expr *detect.Expr
		want string
	}{
		{"plain literal", detect.Lit("https://api.example.com/v1/users"), "https://api.example.com/v1/users"},
		{"concat of literals", detect.Concat(detect.Lit("https://api.example.com"), detect.Lit("/v1/users")), "https://api.example.com/v1/users"},
		{"nested concat folds", detect.Concat(detect.Concat(detect.Lit("https://"), detect.Lit("api.example.com")), detect.Lit("/v1")), "https://api.example.com/v1"},
		{"join inserts one slash", detect.Join(detect.Lit("https://api.example.com"), detect.Lit("v1"), detect.Lit("users")), "https://api.example.com/v1/users"},
		{"single part unwraps", detect.Concat(detect.Lit("/only")), "/only"},
		{"empty literals dropped", detect.Concat(detect.Lit(""), detect.Lit("/x"), detect.Lit("")), "/x"},
		{"template of literals", detect.Template(detect.Lit("https://h"), detect.Lit("/p")), "https://h/p"},
		{"nil expr is a hole", nil, "<|>"},
		{"unknown is a hole", detect.Unknown("mystery()"), "<|>"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			r := &Resolver{}
			got := r.Resolve(tc.expr)
			if len(got) != 1 {
				t.Fatalf("want 1 resolution, got %d", len(got))
			}
			if s := render(got[0]); s != tc.want {
				t.Errorf("render = %q, want %q", s, tc.want)
			}
		})
	}
}

func TestResolveSymbols(t *testing.T) {
	t.Parallel()
	syms := NewSymbolTable([]detect.SymbolDef{
		{Name: "baseURL", Scope: detect.ScopeFile, Value: detect.Lit("https://api.example.com"), Constant: true},
		{Name: "apiRoot", Scope: detect.ScopeModule, Value: detect.Concat(detect.Sym("baseURL"), detect.Lit("/api"))},
		{Name: "local", Scope: detect.ScopeFunc, Func: "doThing", Value: detect.Lit("https://local.example.com")},
		{Name: "local", Scope: detect.ScopeFunc, Func: "other", Value: detect.Lit("https://other.example.com")},
		{Name: "Client.baseURL", Scope: detect.ScopeType, Value: detect.Lit("https://field.example.com")},
		{Name: "cycle", Scope: detect.ScopeFile, Value: detect.Concat(detect.Sym("cycle"), detect.Lit("/x"))},
	})

	t.Run("file scope const", func(t *testing.T) {
		t.Parallel()
		r := &Resolver{Symbols: syms}
		got := r.Resolve(detect.Concat(detect.Sym("baseURL"), detect.Lit("/v1/user/add")))
		if want := "https://api.example.com/v1/user/add"; render(got[0]) != want {
			t.Errorf("got %q, want %q", render(got[0]), want)
		}
	})

	t.Run("transitive symbol", func(t *testing.T) {
		t.Parallel()
		r := &Resolver{Symbols: syms}
		got := r.Resolve(detect.Concat(detect.Sym("apiRoot"), detect.Lit("/v1")))
		if want := "https://api.example.com/api/v1"; render(got[0]) != want {
			t.Errorf("got %q, want %q", render(got[0]), want)
		}
	})

	t.Run("function scope is not shared", func(t *testing.T) {
		t.Parallel()
		r := &Resolver{Symbols: syms, Func: "doThing"}
		got := r.Resolve(detect.Sym("local"))
		if want := "https://local.example.com"; render(got[0]) != want {
			t.Errorf("got %q, want %q", render(got[0]), want)
		}
	})

	t.Run("field one hop by suffix", func(t *testing.T) {
		t.Parallel()
		r := &Resolver{Symbols: syms}
		got := r.Resolve(detect.Concat(detect.Sym("c.baseURL"), detect.Lit("/api/v1/user/add")))
		if want := "https://field.example.com/api/v1/user/add"; render(got[0]) != want {
			t.Errorf("got %q, want %q", render(got[0]), want)
		}
	})

	t.Run("unknown symbol becomes a named hole", func(t *testing.T) {
		t.Parallel()
		r := &Resolver{Symbols: syms}
		got := r.Resolve(detect.Concat(detect.Sym("mystery"), detect.Lit("/v1")))
		if want := "<sym:mystery|mystery>/v1"; render(got[0]) != want {
			t.Errorf("got %q, want %q", render(got[0]), want)
		}
		if len(got[0].Unresolved) != 1 || got[0].Unresolved[0] != "sym:mystery" {
			t.Errorf("Unresolved = %v, want [sym:mystery]", got[0].Unresolved)
		}
	})

	t.Run("self reference terminates", func(t *testing.T) {
		t.Parallel()
		r := &Resolver{Symbols: syms}
		got := r.Resolve(detect.Sym("cycle"))
		if len(got) == 0 {
			t.Fatal("no resolution")
		}
		if !hasFlag(got[0].Flags, "cycle") {
			t.Errorf("Flags = %v, want to contain cycle", got[0].Flags)
		}
	})
}

func TestResolveMultiValuedFansOut(t *testing.T) {
	t.Parallel()
	syms := NewSymbolTable([]detect.SymbolDef{
		{Name: "host", Scope: detect.ScopeFile, Value: detect.Lit("https://a.example.com")},
		{Name: "host", Scope: detect.ScopeFile, Value: detect.Lit("https://b.example.com")},
	})
	r := &Resolver{Symbols: syms}
	got := r.Resolve(detect.Concat(detect.Sym("host"), detect.Lit("/v1")))
	if len(got) != 2 {
		t.Fatalf("want 2 alternatives, got %d", len(got))
	}
	want := map[string]bool{"https://a.example.com/v1": false, "https://b.example.com/v1": false}
	for _, one := range got {
		s := render(one)
		if _, ok := want[s]; !ok {
			t.Errorf("unexpected alternative %q", s)
		}
		want[s] = true
		if !hasFlag(one.Flags, "multi_valued") {
			t.Errorf("alternative %q missing multi_valued flag: %v", s, one.Flags)
		}
	}
	for s, seen := range want {
		if !seen {
			t.Errorf("missing alternative %q", s)
		}
	}
}

func TestResolveAlternativesAreCapped(t *testing.T) {
	t.Parallel()
	var defs []detect.SymbolDef
	for _, h := range []string{"a", "b", "c", "d", "e", "f", "g"} {
		defs = append(defs, detect.SymbolDef{Name: "host", Scope: detect.ScopeFile, Value: detect.Lit("https://" + h)})
	}
	r := &Resolver{Symbols: NewSymbolTable(defs)}
	got := r.Resolve(detect.Sym("host"))
	if len(got) > MaxAlternatives {
		t.Fatalf("got %d alternatives, want at most %d", len(got), MaxAlternatives)
	}
}

func TestResolveEnvAndConfig(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name           string
		expr           *detect.Expr
		want           string
		wantUnresolved string
	}{
		{
			"env var keeps its exact name",
			detect.Concat(detect.Env("API_BASE_URL", nil), detect.Lit("/v1/users")),
			"<env:API_BASE_URL|API_BASE_URL>/v1/users",
			"env:API_BASE_URL",
		},
		{
			"config subscript becomes a dotted key",
			detect.Concat(detect.Index(detect.Sym("cfg"), detect.Lit("services.billing.url")), detect.Lit("/charge")),
			"<cfg:cfg.services.billing.url|url>/charge",
			"cfg:cfg.services.billing.url",
		},
		{
			"opaque call keeps the callee name",
			detect.Concat(detect.Call("getBaseURL"), detect.Lit("/x")),
			"<call:getBaseURL|getBaseURL>/x",
			"call:getBaseURL",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			r := &Resolver{}
			got := r.Resolve(tc.expr)
			if s := render(got[0]); s != tc.want {
				t.Errorf("render = %q, want %q", s, tc.want)
			}
			if len(got[0].Unresolved) != 1 || got[0].Unresolved[0] != tc.wantUnresolved {
				t.Errorf("Unresolved = %v, want [%s]", got[0].Unresolved, tc.wantUnresolved)
			}
		})
	}
}

// Two different unresolved env vars must stay distinguishable. If they
// collapsed into one anonymous hole, grouping calls by host would merge
// unrelated vendors, which is the whole point of keeping the symbolic name.
func TestDistinctSymbolicHostsStayDistinct(t *testing.T) {
	t.Parallel()
	r := &Resolver{}
	a := render(r.Resolve(detect.Concat(detect.Env("BILLING_URL", nil), detect.Lit("/charge")))[0])
	b := render(r.Resolve(detect.Concat(detect.Env("SEARCH_URL", nil), detect.Lit("/charge")))[0])
	if a == b {
		t.Fatalf("distinct env hosts collapsed: both rendered %q", a)
	}
}

func TestResolveFormat(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		expr *detect.Expr
		want string
	}{
		{
			"sprintf host and id",
			detect.Format("%s/api/v1/users/%s", detect.Lit("https://api.example.com"), detect.Sym("userID")),
			"https://api.example.com/api/v1/users/<sym:userID|userID>",
		},
		{
			"percent literal",
			detect.Format("https://h/100%%/x"),
			"https://h/100%/x",
		},
		{
			"width and precision verbs",
			detect.Format("https://h/%-10s/%.2f", detect.Sym("a"), detect.Sym("b")),
			"https://h/<sym:a|a>/<sym:b|b>",
		},
		{
			"python positional braces",
			detect.Format("{}/api/{}", detect.Lit("https://api.example.com"), detect.Sym("id")),
			"https://api.example.com/api/<sym:id|id>",
		},
		{
			"python indexed braces reuse args",
			detect.Format("{0}/api/{0}", detect.Lit("https://h")),
			"https://h/api/https://h",
		},
		{
			"named braces name themselves",
			detect.Format("https://h/users/{user_id}/posts"),
			"https://h/users/<|user_id>/posts",
		},
		{
			"brace format spec is dropped",
			detect.Format("https://h/{id:>4}"),
			"https://h/<|id>",
		},
		{
			"escaped braces are literal",
			detect.Format("https://h/{{literal}}"),
			"https://h/{literal}",
		},
		{
			"dollar positional",
			detect.Format("$1/api", detect.Lit("https://h")),
			"https://h/api",
		},
		{
			// The verb text becomes the hole's name so normalize can number it
			// positionally instead of treating it as an opaque tail.
			"verb without an argument keeps its text as its name",
			detect.Format("https://h/%s"),
			"https://h/<|%s>",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			r := &Resolver{}
			got := r.Resolve(tc.expr)
			if s := render(got[0]); s != tc.want {
				t.Errorf("render = %q, want %q", s, tc.want)
			}
		})
	}
}

func TestResolveWithBase(t *testing.T) {
	t.Parallel()
	r := &Resolver{
		Bindings: map[string]*detect.Expr{
			"api": detect.Lit("https://api.example.com/v2"),
		},
	}
	t.Run("relative path gets the instance base", func(t *testing.T) {
		t.Parallel()
		got := r.ResolveWithBase(detect.Lit("/users/add"), "api")
		if want := "https://api.example.com/v2/users/add"; render(got[0]) != want {
			t.Errorf("got %q, want %q", render(got[0]), want)
		}
	})
	t.Run("absolute url overrides the instance base", func(t *testing.T) {
		t.Parallel()
		got := r.ResolveWithBase(detect.Lit("https://other.example.com/x"), "api")
		if want := "https://other.example.com/x"; render(got[0]) != want {
			t.Errorf("got %q, want %q", render(got[0]), want)
		}
	})
	t.Run("unknown instance is a no-op", func(t *testing.T) {
		t.Parallel()
		got := r.ResolveWithBase(detect.Lit("/users"), "nope")
		if want := "/users"; render(got[0]) != want {
			t.Errorf("got %q, want %q", render(got[0]), want)
		}
	})
}

func TestDepthIsBounded(t *testing.T) {
	t.Parallel()
	// A chain longer than MaxDepth must terminate and say so, not recurse away.
	var defs []detect.SymbolDef
	for i := 0; i < MaxDepth+4; i++ {
		defs = append(defs, detect.SymbolDef{
			Name:  "s" + string(rune('0'+i)),
			Scope: detect.ScopeFile,
			Value: detect.Sym("s" + string(rune('0'+i+1))),
		})
	}
	r := &Resolver{Symbols: NewSymbolTable(defs)}
	got := r.Resolve(detect.Sym("s0"))
	if len(got) == 0 {
		t.Fatal("no resolution")
	}
	if !hasFlag(got[0].Flags, "depth_exceeded") {
		t.Errorf("Flags = %v, want depth_exceeded", got[0].Flags)
	}
}

func TestLiteralString(t *testing.T) {
	t.Parallel()
	r := &Resolver{}
	got := r.Resolve(detect.Concat(detect.Lit("https://h"), detect.Lit("/p")))
	if s, ok := got[0].LiteralString(); !ok || s != "https://h/p" {
		t.Errorf("LiteralString() = %q, %v", s, ok)
	}
	got = r.Resolve(detect.Concat(detect.Sym("x"), detect.Lit("/p")))
	if s, ok := got[0].LiteralString(); ok {
		t.Errorf("LiteralString() = %q, true; want not-literal", s)
	}
	if !got[0].HasHole() {
		t.Error("HasHole() = false, want true")
	}
}

func hasFlag(flags []string, want string) bool {
	for _, f := range flags {
		if f == want {
			return true
		}
	}
	return false
}

// A host injected by a caller is reported as ${arg:...} rather than ${sym:...}:
// both are unresolved, but only the first tells the reader where to look.
func TestParameterHostsAreDistinguishedFromUnknownSymbols(t *testing.T) {
	t.Parallel()
	syms := NewSymbolTable([]detect.SymbolDef{
		{Name: "baseURL", Scope: detect.ScopeFunc, Func: "fetch", Param: true},
	})
	r := &Resolver{Symbols: syms, Func: "fetch"}
	got := r.Resolve(detect.Concat(detect.Sym("baseURL"), detect.Lit("/v1")))
	if want := "<arg:baseURL|baseURL>/v1"; render(got[0]) != want {
		t.Errorf("got %q, want %q", render(got[0]), want)
	}
	other := &Resolver{Symbols: syms, Func: "elsewhere"}
	got = other.Resolve(detect.Sym("mystery"))
	if want := "<sym:mystery|mystery>"; render(got[0]) != want {
		t.Errorf("got %q, want %q", render(got[0]), want)
	}
}
