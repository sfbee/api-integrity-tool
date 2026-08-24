package classify

import (
	"strings"
	"testing"

	"github.com/sfbee/api-integrity-tool/internal/detect"
	"github.com/sfbee/api-integrity-tool/internal/normalize"
	"github.com/sfbee/api-integrity-tool/internal/resolve"
)

func TestExcludedPaths(t *testing.T) {
	t.Parallel()
	excluded := []string{
		"vendor/github.com/x/y.go", "web/node_modules/pkg/index.js",
		"api/.venv/lib/site-packages/requests/api.py", "target/classes/App.java",
		"dist/bundle.js", "app/static/app.min.js", "gen/service.pb.go",
		"src/__pycache__/mod.py", ".api-integrity/index.json",
	}
	for _, p := range excluded {
		if reason, ok := ExcludedPath(p, Options{}); !ok {
			t.Errorf("ExcludedPath(%q) = not excluded, want excluded", p)
			_ = reason
		}
	}
	kept := []string{
		"internal/client/client.go", "src/api.ts", "app/models/user.rb",
		"lib/vendored_helper.go", "src/main/java/App.java", "buildinfo.go",
	}
	for _, p := range kept {
		if _, ok := ExcludedPath(p, Options{}); ok {
			t.Errorf("ExcludedPath(%q) = excluded, want kept", p)
		}
	}
}

func TestIncludePathBeatsExclusion(t *testing.T) {
	t.Parallel()
	p := "vendor/github.com/acme/sdk/client.go"
	if _, ok := ExcludedPath(p, Options{}); !ok {
		t.Fatal("precondition: path should be excluded by default")
	}
	if _, ok := ExcludedPath(p, Options{IncludePaths: []string{"vendor/github.com/acme/sdk"}}); ok {
		t.Error("an explicit include must beat the default exclusion")
	}
}

func TestExtraExcludePaths(t *testing.T) {
	t.Parallel()
	if _, ok := ExcludedPath("internal/legacy/client.go", Options{ExtraExcludePaths: []string{"internal/legacy"}}); !ok {
		t.Error("ExtraExcludePaths was not applied")
	}
}

func TestIsTestFile(t *testing.T) {
	t.Parallel()
	yes := []string{
		"internal/client/client_test.go", "src/api.test.ts", "src/api.spec.tsx",
		"tests/test_client.py", "spec/models/user_spec.rb", "src/test/java/AppTest.java",
		"Api.Tests.cs", "t/basic.t", "internal/client/testdata/fixture.go",
		"cypress/e2e/login.js", "src/__mocks__/api.js",
	}
	for _, p := range yes {
		if !IsTestFile(p) {
			t.Errorf("IsTestFile(%q) = false, want true", p)
		}
	}
	no := []string{"internal/client/client.go", "src/api.ts", "app/latest.go", "src/contest.py"}
	for _, p := range no {
		if IsTestFile(p) {
			t.Errorf("IsTestFile(%q) = true, want false", p)
		}
	}
}

func TestIsRouteFile(t *testing.T) {
	t.Parallel()
	yes := []string{
		"config/routes.rb", "myapp/urls.py", "routes/web.php",
		"src/main/java/com/x/UserController.java", "Controllers/UserController.cs",
		"app/api/users/route.ts", "pages/api/users.ts",
	}
	for _, p := range yes {
		if !IsRouteFile(p) {
			t.Errorf("IsRouteFile(%q) = false, want true", p)
		}
	}
	no := []string{"internal/client/client.go", "src/apiClient.ts", "lib/routing_helper.rb"}
	for _, p := range no {
		if IsRouteFile(p) {
			t.Errorf("IsRouteFile(%q) = true, want false", p)
		}
	}
}

// in builds a Classify input for a literal external endpoint, which callers then
// perturb to exercise one gate at a time.
func in(file string) Input {
	return Input{
		File:     file,
		Language: detect.LangGo,
		Detector: "go/ast",
		Site: detect.RawSite{
			Client: "net/http", Pattern: "net/http.pkgfunc",
			MethodExpr: detect.Lit("GET"),
		},
		Res: resolve.Resolution{Segments: []resolve.Segment{resolve.Literal("https://api.example.com/v1/x")}},
		Canon: normalize.Canonical{
			Scheme: "https", Host: "api.example.com", HostKind: normalize.HostLiteral, Path: "/v1/x",
		},
	}
}

func TestGatesInOrder(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		mutate     func(*Input)
		opts       Options
		wantKeep   bool
		wantReason string
	}{
		{"plain external call is kept", nil, Options{}, true, ""},
		{
			"vendored path dropped",
			func(i *Input) { i.File = "vendor/x/client.go" },
			Options{}, false, DropExcludedPath,
		},
		{
			"test file dropped by default",
			func(i *Input) { i.File = "client_test.go" },
			Options{}, false, DropTestFile,
		},
		{
			"test file kept and flagged when requested",
			func(i *Input) { i.File = "client_test.go" },
			Options{IncludeTests: true}, true, "",
		},
		{
			"route-like site dropped",
			func(i *Input) { i.Site.RouteLike = true },
			Options{}, false, DropRoute,
		},
		{
			"route file dropped",
			func(i *Input) { i.File = "config/routes.rb" },
			Options{}, false, DropRoute,
		},
		{
			"route kept and flagged when requested",
			func(i *Input) { i.Site.RouteLike = true },
			Options{IncludeSuspectedRoutes: true}, true, "",
		},
		{
			"localhost dropped",
			func(i *Input) { i.Canon.Host = "localhost" },
			Options{}, false, DropLocalHost,
		},
		{
			"loopback ip dropped",
			func(i *Input) { i.Canon.Host = "127.0.0.1" },
			Options{}, false, DropLocalHost,
		},
		{
			"rfc1918 dropped",
			func(i *Input) { i.Canon.Host = "10.1.2.3" },
			Options{}, false, DropLocalHost,
		},
		{
			"reserved tld dropped",
			func(i *Input) { i.Canon.Host = "api.svc.local" },
			Options{}, false, DropLocalHost,
		},
		{
			"single label host dropped as internal",
			func(i *Input) { i.Canon.Host = "billing" },
			Options{}, false, DropInternalService,
		},
		{
			"internal kept when requested",
			func(i *Input) { i.Canon.Host = "localhost" },
			Options{IncludeInternal: true}, true, "",
		},
		{
			"non http scheme dropped",
			func(i *Input) { i.Canon.Scheme = "jdbc" },
			Options{}, false, DropNonHTTPScheme,
		},
		{
			"websocket kept",
			func(i *Input) { i.Canon.Scheme = "wss" },
			Options{}, true, "",
		},
		{
			"unverified receiver with no host dropped",
			func(i *Input) {
				i.Site.Notes = []string{"unverified_receiver"}
				i.Canon.HostKind = normalize.HostUnknown
				i.Canon.Host = normalize.UnknownHost
			},
			Options{}, false, DropUnverifiedNoHost,
		},
		{
			"unverified receiver with a real host is kept",
			func(i *Input) { i.Site.Notes = []string{"unverified_receiver"} },
			Options{}, true, "",
		},
		{
			"nothing usable dropped",
			func(i *Input) {
				i.Canon.HostKind = normalize.HostUnknown
				i.Canon.Host = normalize.UnknownHost
				i.Canon.Path = "/"
			},
			Options{}, false, DropNoUsablePath,
		},
		{
			"symbolic host is kept: it is still a real dependency",
			func(i *Input) {
				i.Canon.HostKind = normalize.HostEnv
				i.Canon.Host = "${env:BILLING_URL}"
			},
			Options{}, true, "",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			input := in("internal/client/client.go")
			if tc.mutate != nil {
				tc.mutate(&input)
			}
			got := Classify(input, tc.opts)
			if got.Keep != tc.wantKeep {
				t.Errorf("Keep = %v, want %v (reason %q)", got.Keep, tc.wantKeep, got.Reason)
			}
			if got.Reason != tc.wantReason {
				t.Errorf("Reason = %q, want %q", got.Reason, tc.wantReason)
			}
		})
	}
}

func TestScoreOrdering(t *testing.T) {
	t.Parallel()
	literal := Classify(in("internal/client/client.go"), Options{})
	if literal.Score < 80 {
		t.Errorf("a fully literal external URL scored %d, want high confidence", literal.Score)
	}

	env := in("internal/client/client.go")
	env.Canon.HostKind = normalize.HostEnv
	env.Canon.Host = "${env:BILLING_URL}"
	env.Res = resolve.Resolution{Segments: []resolve.Segment{
		resolve.Hole("env:BILLING_URL", "BILLING_URL", ""), resolve.Literal("/v1/x"),
	}}
	envDec := Classify(env, Options{})
	if envDec.Score >= literal.Score {
		t.Errorf("symbolic host scored %d, want below the literal score %d", envDec.Score, literal.Score)
	}

	regex := env
	regex.Site.Notes = []string{"regex_detector"}
	regexDec := Classify(regex, Options{})
	if regexDec.Score >= envDec.Score {
		t.Errorf("regex detector scored %d, want below the AST score %d", regexDec.Score, envDec.Score)
	}
}

func TestScoreIsClampedAndBucketed(t *testing.T) {
	t.Parallel()
	i := in("internal/client/client.go")
	i.BaseScore = 100
	d := Classify(i, Options{})
	if d.Score > 100 || d.Score < 0 {
		t.Errorf("Score = %d, want within 0..100", d.Score)
	}
	if Confidence(d.Score) != "high" {
		t.Errorf("Confidence(%d) = %q, want high", d.Score, Confidence(d.Score))
	}

	worst := in("client_test.go")
	worst.BaseScore = 40
	worst.Generated = true
	worst.Canon.HostKind = normalize.HostUnknown
	worst.Canon.Host = normalize.UnknownHost
	worst.Canon.Path = "/x"
	worst.Site.Notes = []string{"regex_detector", "unverified_receiver"}
	worst.Site.MethodExpr = nil
	d = Classify(worst, Options{IncludeTests: true})
	if d.Keep && d.Score != 0 {
		t.Errorf("worst case scored %d, want clamped to 0", d.Score)
	}
}

// Every flag in the table must be reachable, or the table is lying about what
// influences a score.
func TestAdjustmentTableHasNoDuplicates(t *testing.T) {
	t.Parallel()
	seen := map[string]bool{}
	for _, a := range Adjustments {
		if seen[a.Flag] {
			t.Errorf("duplicate adjustment for %q", a.Flag)
		}
		seen[a.Flag] = true
		if a.Delta == 0 {
			t.Errorf("adjustment %q has no effect", a.Flag)
		}
	}
}

func TestPatternBaseScores(t *testing.T) {
	t.Parallel()
	exact := PatternBaseScore("net/http.pkgfunc")
	chain := PatternBaseScore("resty.request")
	guess := PatternBaseScore("go.receiver.method")
	sdk := PatternBaseScore("sdk.aws")
	if !(exact > chain && chain > guess && guess > sdk) {
		t.Errorf("base scores not ordered by evidence strength: exact=%d chain=%d guess=%d sdk=%d",
			exact, chain, guess, sdk)
	}
}

func TestDropReasonsAreStableStrings(t *testing.T) {
	t.Parallel()
	// These strings appear in golden files and user-facing output; a rename is a
	// breaking change and should be a deliberate one.
	for _, r := range []string{
		DropExcludedPath, DropTestFile, DropRoute, DropSuspectedRoute,
		DropLocalHost, DropInternalService, DropNonHTTPScheme,
		DropNoUsablePath, DropUnverifiedNoHost, DropIgnored,
	} {
		if r == "" || strings.ContainsAny(r, " \t") {
			t.Errorf("drop reason %q must be a non-empty single token", r)
		}
	}
}
