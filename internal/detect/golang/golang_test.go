package golang

import (
	"context"
	"crypto/sha256"
	"strings"
	"testing"

	"github.com/stephen-bee/endpoint-monitor/internal/detect"
	"github.com/stephen-bee/endpoint-monitor/internal/normalize"
	"github.com/stephen-bee/endpoint-monitor/internal/resolve"
)

// run parses src and returns the detector's findings.
func run(t *testing.T, src string) *detect.FileResult {
	t.Helper()
	f := &detect.SourceFile{
		RelPath: "client.go",
		Lang:    detect.LangGo,
		Content: []byte(src),
		Size:    int64(len(src)),
		Hash:    sha256.Sum256([]byte(src)),
	}
	res, err := New().Detect(context.Background(), f)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	return res
}

// endpoints runs the full detect -> resolve -> normalize pipeline and returns
// "METHOD host path" strings. Testing through the whole pipeline is what proves
// the IR contract actually holds end to end.
func endpoints(t *testing.T, src string) []string {
	t.Helper()
	res := run(t, src)
	syms := resolve.NewSymbolTable(res.Symbols)
	bindings := map[string]*detect.Expr{}
	for _, b := range res.Bindings {
		bindings[b.InstanceName] = b.BaseURL
	}
	var out []string
	for _, s := range res.Sites {
		if s.RouteLike {
			continue
		}
		r := &resolve.Resolver{Symbols: syms, Bindings: bindings, Func: s.Func}
		for _, one := range r.ResolveWithBase(s.URLExpr, s.BaseHint) {
			c := normalize.Canonicalize(one.Segments, normalize.Options{})
			method := "ANY"
			if s.MethodExpr != nil {
				for _, m := range r.Resolve(s.MethodExpr) {
					if lit, ok := m.LiteralString(); ok && lit != "" {
						method = strings.ToUpper(lit)
					}
				}
			}
			out = append(out, method+" "+c.Host+c.Path)
		}
	}
	return out
}

func assertEndpoints(t *testing.T, src string, want ...string) {
	t.Helper()
	got := endpoints(t, src)
	if len(got) != len(want) {
		t.Fatalf("got %d endpoints %v, want %d %v", len(got), got, len(want), want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("endpoint %d = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestNetHTTPPackageFunctions(t *testing.T) {
	t.Parallel()
	assertEndpoints(t, `
package main

import "net/http"

func f() {
	http.Get("https://api.example.com/api/v1/user/list")
	http.Post("https://api.example.com/api/v1/user/add", "application/json", nil)
	http.Head("https://api.example.com/ping")
	http.PostForm("https://api.example.com/form", nil)
}
`,
		"GET api.example.com/api/v1/user/list",
		"POST api.example.com/api/v1/user/add",
		"HEAD api.example.com/ping",
		"POST api.example.com/form",
	)
}

func TestNetHTTPNewRequest(t *testing.T) {
	t.Parallel()
	assertEndpoints(t, `
package main

import (
	"context"
	"net/http"
)

func f(ctx context.Context) {
	req, _ := http.NewRequest("DELETE", "https://api.example.com/v1/user/9")
	_ = req
	r2, _ := http.NewRequestWithContext(ctx, "PATCH", "https://api.example.com/v1/user/9")
	_ = r2
}
`,
		"DELETE api.example.com/v1/user/9",
		"PATCH api.example.com/v1/user/9",
	)
}

// The URL lives at NewRequest, so that is where the site is recorded. Emitting a
// second site for client.Do(req) would double-count the same endpoint.
func TestClientDoIsNotDoubleCounted(t *testing.T) {
	t.Parallel()
	assertEndpoints(t, `
package main

import "net/http"

func f() {
	c := &http.Client{}
	req, _ := http.NewRequest("PUT", "https://api.example.com/v1/thing")
	c.Do(req)
}
`,
		"PUT api.example.com/v1/thing",
	)
}

func TestVerifiedClientReceiver(t *testing.T) {
	t.Parallel()
	assertEndpoints(t, `
package main

import "net/http"

func f() {
	c := &http.Client{}
	c.Get("https://api.example.com/v1/a")
	http.DefaultClient.Get("https://api.example.com/v1/b")
}
`,
		"GET api.example.com/v1/a",
		"GET api.example.com/v1/b",
	)
}

func TestConstantAndConcatenation(t *testing.T) {
	t.Parallel()
	assertEndpoints(t, `
package main

import "net/http"

const baseURL = "https://api.example.com"

func f() {
	http.Get(baseURL + "/api/v1/user/add")
}
`,
		"GET api.example.com/api/v1/user/add",
	)
}

func TestSprintfAndJoin(t *testing.T) {
	t.Parallel()
	assertEndpoints(t, `
package main

import (
	"fmt"
	"net/http"
	"net/url"
)

const host = "https://api.example.com"

func f(userID string) {
	http.Get(fmt.Sprintf("%s/api/v1/users/%s/posts", host, userID))
	u, _ := url.JoinPath(host, "api", "v2", "things")
	http.Get(u)
}
`,
		"GET api.example.com/api/v1/users/{user_id}/posts",
		"GET api.example.com/api/v2/things",
	)
}

func TestEnvironmentHostStaysSymbolic(t *testing.T) {
	t.Parallel()
	assertEndpoints(t, `
package main

import (
	"net/http"
	"os"
)

func f() {
	http.Get(os.Getenv("BILLING_BASE_URL") + "/v1/charge")
}
`,
		"GET ${env:BILLING_BASE_URL}/v1/charge",
	)
}

// The single most valuable resolution case: a client struct holding its base URL.
func TestStructFieldOneHop(t *testing.T) {
	t.Parallel()
	assertEndpoints(t, `
package main

import "net/http"

type Client struct {
	hc      *http.Client
	baseURL string
}

func New() *Client {
	return &Client{hc: &http.Client{}, baseURL: "https://api.example.com"}
}

func (c *Client) AddUser() {
	c.hc.Get(c.baseURL + "/api/v1/user/add")
}
`,
		"GET api.example.com/api/v1/user/add",
	)
}

func TestParameterHostIsReportedAsInjected(t *testing.T) {
	t.Parallel()
	assertEndpoints(t, `
package main

import "net/http"

func fetch(base string) {
	http.Get(base + "/v1/items")
}
`,
		"GET ${arg:base}/v1/items",
	)
}

func TestURLStructLiteral(t *testing.T) {
	t.Parallel()
	assertEndpoints(t, `
package main

import (
	"net/http"
	"net/url"
)

func f() {
	u := url.URL{Scheme: "https", Host: "api.example.com", Path: "/v1/built"}
	http.Get(u.String())
}
`,
		"GET api.example.com/v1/built",
	)
}

func TestRestyChainAndBaseURL(t *testing.T) {
	t.Parallel()
	assertEndpoints(t, `
package main

import "github.com/go-resty/resty/v2"

func f() {
	c := resty.New()
	c.SetBaseURL("https://api.example.com/v3")
	c.R().Get("/users/list")
	c.R().SetBody("x").Post("/users/create")
}
`,
		"GET api.example.com/v3/users/list",
		"POST api.example.com/v3/users/create",
	)
}

func TestRetryableHTTPAndGrequests(t *testing.T) {
	t.Parallel()
	assertEndpoints(t, `
package main

import (
	"github.com/hashicorp/go-retryablehttp"
	"github.com/levigross/grequests"
)

func f() {
	retryablehttp.Get("https://api.example.com/retry")
	grequests.Post("https://api.example.com/greq", nil)
}
`,
		"GET api.example.com/retry",
		"POST api.example.com/greq",
	)
}

// Router DSLs are syntactically indistinguishable from client calls in Go. These
// must all be classified as route definitions, or the index fills up with the
// repo's own inbound routes.
func TestServerRoutesAreNotOutboundCalls(t *testing.T) {
	t.Parallel()
	src := `
package main

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/go-chi/chi/v5"
	"github.com/gorilla/mux"
)

func routes() {
	http.HandleFunc("/api/v1/inbound", nil)

	m := mux.NewRouter()
	m.HandleFunc("/api/v1/mux", nil)
	m.PathPrefix("/static/")

	g := gin.New()
	g.GET("/api/v1/gin", nil)
	g.POST("/api/v1/gin", nil)

	r := chi.NewRouter()
	r.Get("/api/v1/chi", func(w http.ResponseWriter, req *http.Request) {})
	r.Mount("/sub", nil)
}
`
	res := run(t, src)
	for _, s := range res.Sites {
		if !s.RouteLike {
			t.Errorf("route definition at line %d recorded as an outbound call: %s", s.Pos.Line, s.Src)
		}
	}
	if got := endpoints(t, src); len(got) != 0 {
		t.Errorf("router file produced endpoints: %v", got)
	}
}

// A file with no HTTP client import must not have arbitrary .Get calls read as
// HTTP. This import gate is what keeps cache.Get("key") out of the index.
func TestNonHTTPGetIsIgnoredWithoutAClientImport(t *testing.T) {
	t.Parallel()
	res := run(t, `
package main

type cache struct{}

func (c cache) Get(k string) string { return "" }

func f() {
	var c cache
	c.Get("some-cache-key")
}
`)
	if len(res.Sites) != 0 {
		t.Errorf("got %d sites, want 0: %+v", len(res.Sites), res.Sites)
	}
}

func TestUnverifiedReceiverIsFlagged(t *testing.T) {
	t.Parallel()
	res := run(t, `
package main

import "net/http"

var _ = http.DefaultClient

type wrapper struct{}

func (w wrapper) Get(u string) {}

func f(w wrapper) {
	w.Get("https://api.example.com/v1/maybe")
}
`)
	if len(res.Sites) != 1 {
		t.Fatalf("got %d sites, want 1", len(res.Sites))
	}
	if !hasNote(res.Sites[0].Notes, "unverified_receiver") {
		t.Errorf("Notes = %v, want unverified_receiver", res.Sites[0].Notes)
	}
}

func TestImportAliasesAreHonoured(t *testing.T) {
	t.Parallel()
	assertEndpoints(t, `
package main

import nh "net/http"

func f() {
	nh.Get("https://api.example.com/aliased")
}
`,
		"GET api.example.com/aliased",
	)
}

func TestUnparseableFileIsReportedNotFatal(t *testing.T) {
	t.Parallel()
	f := &detect.SourceFile{RelPath: "broken.go", Lang: detect.LangGo, Content: []byte("package main\nfunc ( {{{")}
	res, err := New().Detect(context.Background(), f)
	if err != nil {
		t.Fatalf("a syntax error must not fail the scan: %v", err)
	}
	if len(res.Errors) == 0 {
		t.Error("want a recorded parse error")
	}
}

func TestCrossFilePackageConstants(t *testing.T) {
	t.Parallel()
	consts := &detect.SourceFile{RelPath: "pkg/consts.go", Lang: detect.LangGo, Content: []byte(`
package pkg

const APIRoot = "https://api.example.com/api"
`)}
	client := &detect.SourceFile{RelPath: "pkg/client.go", Lang: detect.LangGo, Content: []byte(`
package pkg

import "net/http"

func f() {
	http.Get(APIRoot + "/v1/cross")
}
`)}
	d := New()
	ctx := context.Background()
	r1, _ := d.Detect(ctx, consts)
	r2, _ := d.Detect(ctx, client)

	if got, want := d.GroupKey(consts), d.GroupKey(client); got != want {
		t.Fatalf("files in one package grouped differently: %q vs %q", got, want)
	}
	group := d.ResolveGroup(ctx, []*detect.SourceFile{consts, client}, []*detect.FileResult{r1, r2})

	// The client file alone cannot resolve APIRoot; with the group's symbols it can.
	syms := resolve.NewSymbolTable(append(r2.Symbols, group...))
	r := &resolve.Resolver{Symbols: syms, Func: r2.Sites[0].Func}
	res := r.Resolve(r2.Sites[0].URLExpr)
	c := normalize.Canonicalize(res[0].Segments, normalize.Options{})
	if c.Host != "api.example.com" || c.Path != "/api/v1/cross" {
		t.Errorf("got %s%s, want api.example.com/api/v1/cross", c.Host, c.Path)
	}
}

func TestRawStringsAndTrailingSlashHelpers(t *testing.T) {
	t.Parallel()
	assertEndpoints(t, "package main\n\nimport (\n\t\"net/http\"\n\t\"strings\"\n)\n\nfunc f() {\n\thttp.Get(strings.TrimSuffix(`https://api.example.com/v1/`, \"/\") + \"/x\")\n}\n",
		"GET api.example.com/v1/x",
	)
}

func hasNote(notes []string, want string) bool {
	for _, n := range notes {
		if n == want {
			return true
		}
	}
	return false
}
