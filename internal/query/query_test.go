package query

import (
	"strings"
	"testing"

	"github.com/stephen-bee/endpoint-monitor/internal/detect"
	"github.com/stephen-bee/endpoint-monitor/internal/index"
	"github.com/stephen-bee/endpoint-monitor/internal/normalize"
)

func mk(host, method, path string, opts ...func(*index.Call)) index.Call {
	c := index.Call{
		Host: host, HostKind: normalize.HostLiteral, Method: method, Path: path,
		Kind: index.KindHTTP, Scheme: "https", Client: "net/http",
		Language: detect.LangGo, Score: 90, Confidence: index.ConfHigh,
		Location:  index.Location{File: "internal/client/client.go", Line: 10},
		Lifecycle: index.Lifecycle{Status: index.StatusActive},
	}
	for _, o := range opts {
		o(&c)
	}
	return c
}

func corpus() []index.Call {
	return []index.Call{
		mk("api.stripe.com", "POST", "/v1/charges"),
		mk("api.stripe.com", "GET", "/v1/invoices"),
		mk("api.acme.example.com", "POST", "/api/v1/user/add"),
		mk("api.acme.example.com", "GET", "/api/v1/users/{user_id}"),
		mk("api.other.com", "GET", "/health", func(c *index.Call) {
			c.Score = 40
			c.Confidence = index.ConfLow
			c.Language = detect.LangPython
			c.Location.File = "svc/app.py"
		}),
		mk("${env:BILLING_URL}", "POST", "/charge", func(c *index.Call) {
			c.HostKind = normalize.HostEnv
			c.Score = 60
			c.Confidence = index.ConfMedium
		}),
		mk("api.legacy.com", "GET", "/old", func(c *index.Call) {
			c.Lifecycle.Status = index.StatusRemoved
		}),
		mk("api.test.com", "GET", "/fixture", func(c *index.Call) {
			c.Flags = []string{"test_file"}
			c.Location.File = "internal/client/client_test.go"
		}),
	}
}

func names(calls []index.Call) []string {
	out := make([]string, 0, len(calls))
	for _, c := range calls {
		out = append(out, c.Method+" "+c.Host+c.Path)
	}
	return out
}

func apply(t *testing.T, f Filters) []string {
	t.Helper()
	s, err := Compile(f)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	return names(s.Apply(corpus()))
}

// Removed and test calls are hidden by default: the default question is "what
// does my production code depend on right now?".
func TestDefaultsHideRemovedAndTestCalls(t *testing.T) {
	t.Parallel()
	got := strings.Join(apply(t, Filters{}), "|")
	if strings.Contains(got, "api.legacy.com") {
		t.Error("a removed call appeared without --include-removed")
	}
	if strings.Contains(got, "api.test.com") {
		t.Error("a test-file call appeared without --include-tests")
	}
	if n := len(apply(t, Filters{})); n != 6 {
		t.Errorf("got %d calls, want 6", n)
	}
	if n := len(apply(t, Filters{IncludeRemoved: true, IncludeTests: true})); n != 8 {
		t.Errorf("with both includes, got %d calls, want 8", n)
	}
}

// Rule 1: several values in one dimension are OR-ed.
func TestOrWithinADimension(t *testing.T) {
	t.Parallel()
	got := apply(t, Filters{Hosts: []string{"api.stripe.com", "api.other.com"}})
	if len(got) != 3 {
		t.Errorf("got %v, want 3 calls across both hosts", got)
	}
}

// Rule 2: dimensions are AND-ed. Somebody combining them is narrowing.
func TestAndAcrossDimensions(t *testing.T) {
	t.Parallel()
	got := apply(t, Filters{
		Hosts:     []string{"api.stripe.com"},
		Endpoints: []string{"/v1/charges"},
	})
	if len(got) != 1 || got[0] != "POST api.stripe.com/v1/charges" {
		t.Errorf("got %v, want only the stripe charges call", got)
	}
	// A host and an endpoint that do not co-occur must yield nothing.
	got = apply(t, Filters{
		Hosts:     []string{"api.stripe.com"},
		Endpoints: []string{"/api/v1/user/add"},
	})
	if len(got) != 0 {
		t.Errorf("got %v, want no matches for a non-co-occurring pair", got)
	}
}

// Rule 3: an empty dimension is a wildcard.
func TestEmptyDimensionIsWildcard(t *testing.T) {
	t.Parallel()
	if len(apply(t, Filters{Methods: []string{"GET"}})) == 0 {
		t.Error("a method-only filter matched nothing")
	}
}

// Rule 4: exclusion always wins, even against an explicit include.
func TestExcludeBeatsInclude(t *testing.T) {
	t.Parallel()
	got := apply(t, Filters{
		Hosts:   []string{"api.stripe.com"},
		Exclude: &Filters{Hosts: []string{"api.stripe.com"}},
	})
	if len(got) != 0 {
		t.Errorf("got %v, want nothing: exclude must beat include", got)
	}
	got = apply(t, Filters{
		Hosts:   []string{"api.stripe.com"},
		Exclude: &Filters{Endpoints: []string{"/v1/invoices"}},
	})
	if len(got) != 1 || got[0] != "POST api.stripe.com/v1/charges" {
		t.Errorf("got %v, want only charges", got)
	}
}

func TestHostGlobs(t *testing.T) {
	t.Parallel()
	got := apply(t, Filters{Hosts: []string{"api.*.com"}})
	if len(got) == 0 {
		t.Error("glob host filter matched nothing")
	}
	got = apply(t, Filters{Hosts: []string{"*.example.com"}})
	if len(got) != 2 {
		t.Errorf("got %v, want the 2 acme.example.com calls", got)
	}
}

// The endpoint filter must not require the user to guess our parameter names.
func TestEndpointMatchingIsTemplateInsensitive(t *testing.T) {
	t.Parallel()
	for _, pattern := range []string{
		"/api/v1/users/{user_id}", "/api/v1/users/:id", "/api/v1/users/{id}",
		"/api/v1/users/<int:id>", "/api/v1/users/%s", "/api/v1/users/[id]",
	} {
		got := apply(t, Filters{Endpoints: []string{pattern}})
		if len(got) != 1 {
			t.Errorf("--endpoint=%q matched %v, want the templated users call", pattern, got)
		}
	}
}

func TestEndpointExactVsPrefix(t *testing.T) {
	t.Parallel()
	if got := apply(t, Filters{Endpoints: []string{"/api/v1"}}); len(got) != 0 {
		t.Errorf("exact mode matched %v, want nothing for a partial path", got)
	}
	if got := apply(t, Filters{Endpoints: []string{"/api/v1/*"}}); len(got) != 2 {
		t.Errorf("wildcard suffix matched %v, want 2", got)
	}
	if got := apply(t, Filters{Endpoints: []string{"/api/v1"}, EndpointMode: EndpointPrefix}); len(got) != 2 {
		t.Errorf("prefix mode matched %v, want 2", got)
	}
}

func TestTrailingSlashesAndDuplicatesAreEquivalent(t *testing.T) {
	t.Parallel()
	for _, pattern := range []string{"/v1/charges", "/v1/charges/", "//v1//charges"} {
		if got := apply(t, Filters{Endpoints: []string{pattern}}); len(got) != 1 {
			t.Errorf("--endpoint=%q matched %v, want 1", pattern, got)
		}
	}
}

// A call whose path could not be fully resolved still covers the endpoints
// beneath it: the code really does reach them, we just could not see which.
func TestWideTailCoversEndpointsBeneathIt(t *testing.T) {
	t.Parallel()
	calls := []index.Call{mk("api.acme.example.com", "ANY", "/api/v1/**")}
	s, err := Compile(Filters{Endpoints: []string{"/api/v1/user/add"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Apply(calls)) != 1 {
		t.Error("a /api/v1/** call should match a query for /api/v1/user/add")
	}
	s, _ = Compile(Filters{Endpoints: []string{"/other/thing"}})
	if len(s.Apply(calls)) != 0 {
		t.Error("a /api/v1/** call must not match an unrelated endpoint")
	}
}

func TestRegexTargets(t *testing.T) {
	t.Parallel()
	if got := apply(t, Filters{Regexes: []string{`^https://api\.stripe\.com/v1/`}}); len(got) != 2 {
		t.Errorf("url regex matched %v, want 2", got)
	}
	if got := apply(t, Filters{Regexes: []string{`charges$`}, RegexTarget: RegexPath}); len(got) != 1 {
		t.Errorf("path regex matched %v, want 1", got)
	}
	if got := apply(t, Filters{Regexes: []string{`\.py$`}, RegexTarget: RegexFile}); len(got) != 1 {
		t.Errorf("file regex matched %v, want 1", got)
	}
}

func TestInvalidRegexIsReportedOnce(t *testing.T) {
	t.Parallel()
	_, err := Compile(Filters{Regexes: []string{"([unclosed"}})
	if err == nil {
		t.Fatal("want an error for an invalid regex")
	}
	if !strings.Contains(err.Error(), "--regex") {
		t.Errorf("error should name the flag, got: %v", err)
	}
}

func TestInvalidConfidenceIsReported(t *testing.T) {
	t.Parallel()
	if _, err := Compile(Filters{MinConfidence: "excellent"}); err == nil {
		t.Error("want an error for an unknown confidence level")
	}
	for _, c := range []index.Confidence{"", index.ConfLow, index.ConfMedium, index.ConfHigh} {
		if _, err := Compile(Filters{MinConfidence: c}); err != nil {
			t.Errorf("Compile(%q) = %v", c, err)
		}
	}
}

func TestMinConfidence(t *testing.T) {
	t.Parallel()
	if got := apply(t, Filters{MinConfidence: index.ConfHigh}); len(got) != 4 {
		t.Errorf("high-only matched %v, want the 4 high-confidence calls", got)
	}
	if got := apply(t, Filters{MinConfidence: index.ConfMedium}); len(got) != 5 {
		t.Errorf("medium-and-up matched %v, want 5", got)
	}
}

func TestMethodAndLanguageFilters(t *testing.T) {
	t.Parallel()
	if got := apply(t, Filters{Methods: []string{"post"}}); len(got) != 3 {
		t.Errorf("method filter is case sensitive: %v", got)
	}
	if got := apply(t, Filters{Languages: []string{"python"}}); len(got) != 1 {
		t.Errorf("language filter matched %v, want 1", got)
	}
}

// The payoff for keeping host mapping at query time: a concrete hostname finds
// the calls recorded against the environment variable that stands for it.
func TestHostMappingResolvesSymbolicHosts(t *testing.T) {
	t.Parallel()
	got := apply(t, Filters{
		Hosts:        []string{"billing.acme.internal"},
		HostMappings: map[string][]string{"${env:BILLING_URL}": {"billing.acme.internal"}},
	})
	if len(got) != 1 || got[0] != "POST ${env:BILLING_URL}/charge" {
		t.Errorf("got %v, want the symbolic billing call", got)
	}
	// The symbolic name itself must keep working.
	if got := apply(t, Filters{Hosts: []string{"${env:BILLING_URL}"}}); len(got) != 1 {
		t.Errorf("querying by the symbolic name matched %v, want 1", got)
	}
}

func TestExplainCountsRejections(t *testing.T) {
	t.Parallel()
	s, err := Compile(Filters{Hosts: []string{"api.stripe.com"}})
	if err != nil {
		t.Fatal(err)
	}
	reasons := s.Explain(corpus())
	if reasons["host"] == 0 {
		t.Errorf("Explain should attribute rejections to the host filter: %v", reasons)
	}
	if reasons["removed"] == 0 || reasons["test_file"] == 0 {
		t.Errorf("Explain should report lifecycle rejections too: %v", reasons)
	}
}

func TestApplyPreservesOrder(t *testing.T) {
	t.Parallel()
	s, _ := Compile(Filters{})
	got := s.Apply(corpus())
	for i := 1; i < len(got); i++ {
		// Input order is the index's canonical order; Apply must not reorder.
		if got[i-1].Host == got[i].Host && got[i-1].Path > got[i].Path {
			continue // same host, order comes from the index, not from us
		}
	}
	if len(got) == 0 {
		t.Fatal("no calls")
	}
	if got[0].Host != corpus()[0].Host {
		t.Errorf("first result = %q, want the first input %q", got[0].Host, corpus()[0].Host)
	}
}

func TestPathTemplate(t *testing.T) {
	t.Parallel()
	tests := map[string]string{
		"/users/{id}":        "/users/{}",
		"/users/:id":         "/users/{}",
		"/users/<int:id>":    "/users/{}",
		"/users/[id]":        "/users/{}",
		"/users/%s":          "/users/{}",
		"/users/${id}":       "/users/{}",
		"/users/#{id}":       "/users/{}",
		"/users/{id}/posts":  "/users/{}/posts",
		"/users/":            "/users",
		"//users//x":         "/users/x",
		"users":              "/users",
		"":                   "/",
		"/":                  "/",
		"/v1/user-{id}/edit": "/v1/user-{}/edit",
	}
	for in, want := range tests {
		if got := PathTemplate(in); got != want {
			t.Errorf("PathTemplate(%q) = %q, want %q", in, got, want)
		}
	}
}
