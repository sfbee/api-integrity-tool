package normalize

import (
	"strings"
	"testing"

	"github.com/stephen-bee/endpoint-monitor/internal/resolve"
)

func lit(s string) resolve.Segment { return resolve.Literal(s) }

func hole(sym, name string) resolve.Segment { return resolve.Hole(sym, name, name) }

func TestCanonicalizeLiteralURLs(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name         string
		segs         []resolve.Segment
		wantScheme   string
		wantHost     string
		wantKind     HostKind
		wantPort     int
		wantPath     string
		wantQuery    []string
		wantTrailing bool
		wantFlag     string
	}{
		{
			name: "plain absolute url", segs: []resolve.Segment{lit("https://api.example.com/api/v1/user/add")},
			wantScheme: "https", wantHost: "api.example.com", wantKind: HostLiteral, wantPath: "/api/v1/user/add",
		},
		{
			name: "host is lowercased", segs: []resolve.Segment{lit("https://API.Example.COM/v1")},
			wantScheme: "https", wantHost: "api.example.com", wantKind: HostLiteral, wantPath: "/v1",
		},
		{
			name: "default https port stripped", segs: []resolve.Segment{lit("https://api.example.com:443/v1")},
			wantScheme: "https", wantHost: "api.example.com", wantKind: HostLiteral, wantPath: "/v1",
			wantFlag: "default_port_stripped",
		},
		{
			name: "non default port kept", segs: []resolve.Segment{lit("http://api.example.com:8080/v1")},
			wantScheme: "http", wantHost: "api.example.com", wantKind: HostLiteral, wantPort: 8080, wantPath: "/v1",
		},
		{
			name: "query keys only sorted and deduped", segs: []resolve.Segment{lit("https://h.example.com/s?b=2&a=1&a=3&token=secret")},
			wantScheme: "https", wantHost: "h.example.com", wantKind: HostLiteral, wantPath: "/s",
			wantQuery: []string{"a", "b", "token"},
		},
		{
			name: "fragment dropped", segs: []resolve.Segment{lit("https://h.example.com/s#frag")},
			wantScheme: "https", wantHost: "h.example.com", wantKind: HostLiteral, wantPath: "/s",
		},
		{
			name: "trailing slash recorded then stripped", segs: []resolve.Segment{lit("https://h.example.com/users/")},
			wantScheme: "https", wantHost: "h.example.com", wantKind: HostLiteral, wantPath: "/users", wantTrailing: true,
		},
		{
			name: "duplicate slashes collapsed", segs: []resolve.Segment{lit("https://h.example.com//api///v1")},
			wantScheme: "https", wantHost: "h.example.com", wantKind: HostLiteral, wantPath: "/api/v1",
		},
		{
			name: "root path", segs: []resolve.Segment{lit("https://h.example.com")},
			wantScheme: "https", wantHost: "h.example.com", wantKind: HostLiteral, wantPath: "/",
		},
		{
			name: "credentials flagged not stored", segs: []resolve.Segment{lit("https://user:pass@h.example.com/v1")},
			wantScheme: "https", wantHost: "h.example.com", wantKind: HostLiteral, wantPath: "/v1",
			wantFlag: "embedded_credentials",
		},
		{
			name: "scheme relative host", segs: []resolve.Segment{lit("api.example.com/v1/x")},
			wantHost: "api.example.com", wantKind: HostLiteral, wantPath: "/v1/x", wantFlag: "scheme_relative",
		},
		{
			name: "websocket scheme", segs: []resolve.Segment{lit("wss://ws.example.com:443/socket")},
			wantScheme: "wss", wantHost: "ws.example.com", wantKind: HostLiteral, wantPath: "/socket",
			wantFlag: "default_port_stripped",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := Canonicalize(tc.segs, Options{})
			if got.Scheme != tc.wantScheme {
				t.Errorf("Scheme = %q, want %q", got.Scheme, tc.wantScheme)
			}
			if got.Host != tc.wantHost {
				t.Errorf("Host = %q, want %q", got.Host, tc.wantHost)
			}
			if got.HostKind != tc.wantKind {
				t.Errorf("HostKind = %q, want %q", got.HostKind, tc.wantKind)
			}
			if got.Port != tc.wantPort {
				t.Errorf("Port = %d, want %d", got.Port, tc.wantPort)
			}
			if got.Path != tc.wantPath {
				t.Errorf("Path = %q, want %q", got.Path, tc.wantPath)
			}
			if tc.wantQuery != nil && strings.Join(got.QueryKeys, ",") != strings.Join(tc.wantQuery, ",") {
				t.Errorf("QueryKeys = %v, want %v", got.QueryKeys, tc.wantQuery)
			}
			if got.TrailingSlash != tc.wantTrailing {
				t.Errorf("TrailingSlash = %v, want %v", got.TrailingSlash, tc.wantTrailing)
			}
			if tc.wantFlag != "" && !hasFlag(got.Flags, tc.wantFlag) {
				t.Errorf("Flags = %v, want to contain %q", got.Flags, tc.wantFlag)
			}
		})
	}
}

func TestPercentEscapesUppercasedNotDecoded(t *testing.T) {
	t.Parallel()
	// Escapes are case-normalized so two spellings of the same path compare
	// equal, but never decoded: %2F is not a path separator.
	got := Canonicalize([]resolve.Segment{lit("https://h.example.com/a%2fb%20c")}, Options{})
	if want := "/a%2Fb%20c"; got.Path != want {
		t.Errorf("Path = %q, want %q", got.Path, want)
	}
}

func TestSymbolicHosts(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		segs     []resolve.Segment
		wantHost string
		wantKind HostKind
		wantPath string
	}{
		{
			"env var host", []resolve.Segment{hole("env:API_BASE_URL", "API_BASE_URL"), lit("/api/v1/user/add")},
			"${env:API_BASE_URL}", HostEnv, "/api/v1/user/add",
		},
		{
			"config host", []resolve.Segment{hole("cfg:services.billing.url", "url"), lit("/charge")},
			"${cfg:services.billing.url}", HostConfig, "/charge",
		},
		{
			"unresolved symbol host", []resolve.Segment{hole("sym:Client.baseURL", "baseURL"), lit("/v1")},
			"${sym:Client.baseURL}", HostSymbol, "/v1",
		},
		{
			"parameter host", []resolve.Segment{hole("arg:baseURL", "baseURL"), lit("/v1")},
			"${arg:baseURL}", HostParam, "/v1",
		},
		{
			"fully opaque host", []resolve.Segment{hole("", ""), lit("/v1")},
			UnknownHost, HostUnknown, "/v1",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := Canonicalize(tc.segs, Options{})
			if got.Host != tc.wantHost || got.HostKind != tc.wantKind {
				t.Errorf("Host/Kind = %q/%q, want %q/%q", got.Host, got.HostKind, tc.wantHost, tc.wantKind)
			}
			if got.Path != tc.wantPath {
				t.Errorf("Path = %q, want %q", got.Path, tc.wantPath)
			}
		})
	}
}

// Grouping by host is only useful if unresolved hosts keep their identity.
func TestDistinctSymbolicHostsDoNotCollapse(t *testing.T) {
	t.Parallel()
	a := Canonicalize([]resolve.Segment{hole("env:BILLING_URL", "BILLING_URL"), lit("/charge")}, Options{})
	b := Canonicalize([]resolve.Segment{hole("env:SEARCH_URL", "SEARCH_URL"), lit("/charge")}, Options{})
	if a.Host == b.Host {
		t.Fatalf("distinct env hosts collapsed to %q", a.Host)
	}
	if a.HostKind != HostEnv || b.HostKind != HostEnv {
		t.Errorf("kinds = %q, %q; want both env", a.HostKind, b.HostKind)
	}
}

func TestRelativeURLs(t *testing.T) {
	t.Parallel()
	got := Canonicalize([]resolve.Segment{lit("/api/v1/user/add")}, Options{})
	if got.Host != SelfHost || got.HostKind != HostRelative {
		t.Errorf("Host/Kind = %q/%q, want %q/relative", got.Host, got.HostKind, SelfHost)
	}
	if got.Path != "/api/v1/user/add" {
		t.Errorf("Path = %q", got.Path)
	}

	got = Canonicalize([]resolve.Segment{lit("/api/v1/user/add")}, Options{DefaultHost: "app.example.com"})
	if got.Host != "app.example.com" || got.HostKind != HostLiteral {
		t.Errorf("with DefaultHost: Host/Kind = %q/%q", got.Host, got.HostKind)
	}
	if !hasFlag(got.Flags, "default_host_applied") {
		t.Errorf("Flags = %v, want default_host_applied", got.Flags)
	}
}

func TestPlaceholderNaming(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		segs     []resolve.Segment
		wantPath string
	}{
		{
			"camelCase identifier becomes snake_case",
			[]resolve.Segment{lit("https://h.example.com/users/"), hole("sym:userID", "userID"), lit("/posts")},
			"/users/{user_id}/posts",
		},
		{
			"dotted name uses its last component",
			[]resolve.Segment{lit("https://h.example.com/users/"), hole("sym:u.Profile.ID", "ID"), lit("/x")},
			"/users/{id}/x",
		},
		{
			"acronym runs split correctly",
			[]resolve.Segment{lit("https://h.example.com/"), hole("sym:HTTPHost", "HTTPHost")},
			"/{http_host}",
		},
		{
			"noise suffix trimmed",
			[]resolve.Segment{lit("https://h.example.com/u/"), hole("sym:idStr", "idStr"), lit("/x")},
			"/u/{id}/x",
		},
		{
			"positional verbs numbered in path order",
			[]resolve.Segment{lit("https://h.example.com/a/"), hole("", "%s"), lit("/b/"), hole("", "%d"), lit("/c")},
			"/a/{p1}/b/{p2}/c",
		},
		{
			"hole inside a segment keeps its literal neighbours",
			[]resolve.Segment{lit("https://h.example.com/v1/user-"), hole("sym:id", "id"), lit("/avatar")},
			"/v1/user-{id}/avatar",
		},
		{
			"path-like tail widens to a prefix match",
			[]resolve.Segment{lit("https://h.example.com/api/"), hole("arg:path", "path")},
			"/api/**",
		},
		{
			"opaque tail widens to a prefix match",
			[]resolve.Segment{lit("https://h.example.com/api/"), hole("", "")},
			"/api/**",
		},
		{
			"named non-path tail stays a single segment",
			[]resolve.Segment{lit("https://h.example.com/users/"), hole("sym:userID", "userID")},
			"/users/{user_id}",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := Canonicalize(tc.segs, Options{})
			if got.Path != tc.wantPath {
				t.Errorf("Path = %q, want %q", got.Path, tc.wantPath)
			}
		})
	}
}

func TestPathVarsRecordTheirSource(t *testing.T) {
	t.Parallel()
	got := Canonicalize([]resolve.Segment{
		lit("https://h.example.com/users/"), hole("sym:userID", "userID"), lit("/posts"),
	}, Options{})
	if len(got.PathVars) != 1 {
		t.Fatalf("PathVars = %+v, want 1 entry", got.PathVars)
	}
	if got.PathVars[0].Token != "{user_id}" || got.PathVars[0].Source != "userID" {
		t.Errorf("PathVars[0] = %+v", got.PathVars[0])
	}
}

func TestIDShapedSegmentCollapsing(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		raw      string
		opts     Options
		wantPath string
	}{
		{"uuid collapsed", "https://h.example.com/users/3f2504e0-4f89-11d3-9a0c-0305e82c3301/posts", Options{}, "/users/{id}/posts"},
		{"long hex collapsed", "https://h.example.com/objects/9f86d081884c7d659a2feaa0c55ad015a3bf4f1b", Options{}, "/objects/{id}"},
		{"route word not collapsed", "https://h.example.com/api/v1/subscriptions", Options{}, "/api/v1/subscriptions"},
		{"hyphenated route word not collapsed", "https://h.example.com/api/user-profiles", Options{}, "/api/user-profiles"},
		{"digits kept by default", "https://h.example.com/api/2/issue", Options{}, "/api/2/issue"},
		{"digits collapsed when requested", "https://h.example.com/api/2/issue", Options{CollapseNumericIDs: true}, "/api/{id}/issue"},
		{"version segment kept", "https://h.example.com/v1/users", Options{}, "/v1/users"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := Canonicalize([]resolve.Segment{lit(tc.raw)}, tc.opts)
			if got.Path != tc.wantPath {
				t.Errorf("Path = %q, want %q", got.Path, tc.wantPath)
			}
		})
	}
}

func TestEmptyInput(t *testing.T) {
	t.Parallel()
	got := Canonicalize(nil, Options{})
	if got.Host != UnknownHost || got.HostKind != HostUnknown || got.Path != "/" {
		t.Errorf("got %+v, want unknown host and root path", got)
	}
}

func TestToSnake(t *testing.T) {
	t.Parallel()
	tests := map[string]string{
		"userID": "user_id", "UserID": "user_id", "user_id": "user_id",
		"HTTPHost": "http_host", "ID": "id", "id": "id",
		"_private": "private", "orgSlug": "org_slug",
		"customerNumber2": "customer_number2", "": "expr",
	}
	for in, want := range tests {
		if got := toSnake(in); got != want {
			t.Errorf("toSnake(%q) = %q, want %q", in, got, want)
		}
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
