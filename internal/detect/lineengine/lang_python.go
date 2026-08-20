package lineengine

import (
	"regexp"

	"github.com/stephen-bee/endpoint-monitor/internal/detect"
)

// pythonStrings lists f-strings and triple-quoted forms before the plain ones,
// because scanString takes the first syntax that matches and the longer
// delimiters must win.
var pythonStrings = []StringSyntax{
	{Prefix: "f", Open: `"""`, Close: `"""`, Interp: []InterpSyntax{{Open: "{", Close: "}"}}},
	{Prefix: "f", Open: `'''`, Close: `'''`, Interp: []InterpSyntax{{Open: "{", Close: "}"}}},
	{Prefix: "f", Open: `"`, Close: `"`, Interp: []InterpSyntax{{Open: "{", Close: "}"}}},
	{Prefix: "f", Open: "'", Close: "'", Interp: []InterpSyntax{{Open: "{", Close: "}"}}},
	{Prefix: "r", Open: `"`, Close: `"`, NoEscapes: true},
	{Prefix: "r", Open: "'", Close: "'", NoEscapes: true},
	{Open: `"""`, Close: `"""`, DocString: true},
	{Open: `'''`, Close: `'''`, DocString: true},
	{Open: `"`, Close: `"`},
	{Open: "'", Close: "'"},
}

func pythonSpec() *Spec {
	verbs := `get|post|put|patch|delete|head|options`
	return &Spec{
		Lang:         detect.LangPython,
		Exts:         []string{".py", ".pyi"},
		LineComments: []string{"#"},
		Strings:      pythonStrings,
		ImportRe: []*regexp.Regexp{
			regexp.MustCompile(`(?m)^\s*import\s+(?P<path>[\w.]+)`),
			regexp.MustCompile(`(?m)^\s*from\s+(?P<path>[\w.]+)\s+import`),
		},
		ClientImports: map[string]string{
			"requests": "requests", "httpx": "httpx", "aiohttp": "aiohttp",
			"urllib": "urllib", "http.client": "http.client", "urllib3": "urllib3",
			"treq": "treq", "niquests": "niquests",
		},
		ServerImports: map[string]detect.Framework{
			"flask": "flask", "fastapi": "fastapi", "django": "django",
			"rest_framework": "drf", "responses": "responses", "requests_mock": "requests_mock",
			"aioresponses": "aioresponses", "starlette": "starlette",
		},
		ConcatOps:    []string{"+"},
		FormatCalls:  []string{"format"},
		JoinCalls:    []string{"urljoin", "join", "urlunsplit"},
		HandlerHints: []string{"lambda"},
		SelfNames:    []string{"self", "cls"},
		FuncRe:       regexp.MustCompile(`(?m)^\s*(?:async\s+)?def\s+(?P<name>\w+)`),
		EnvRe: []*regexp.Regexp{
			regexp.MustCompile(`^os\.environ\[\s*['"](?P<name>\w+)['"]\s*\]$`),
			regexp.MustCompile(`^os\.environ\.get\(\s*['"](?P<name>\w+)['"].*\)$`),
			regexp.MustCompile(`^os\.getenv\(\s*['"](?P<name>\w+)['"].*\)$`),
		},
		Symbols: []SymbolPattern{
			{Re: regexp.MustCompile(`(?m)^(?P<name>[A-Za-z_]\w*)\s*(?::\s*[\w\[\], .]+\s*)?=\s*(?P<value>[^\n#]+)`), Scope: detect.ScopeFile},
			{Re: regexp.MustCompile(`(?P<name>self\.\w+)\s*=\s*(?P<value>[^\n#]+)`), Scope: detect.ScopeType},
		},
		Bindings: []BindingPattern{
			// httpx.Client(base_url=...) and aiohttp.ClientSession(base_url=...)
			{Re: regexp.MustCompile(`(?P<name>\w+)\s*=\s*(?:httpx\.(?:Async)?Client|aiohttp\.ClientSession)\(\s*base_url\s*=\s*(?P<value>[^,)\n]+)`)},
			{Re: regexp.MustCompile(`(?P<name>self\.\w+)\s*=\s*(?:httpx\.(?:Async)?Client|aiohttp\.ClientSession)\(\s*base_url\s*=\s*(?P<value>[^,)\n]+)`)},
		},
		Signatures: []Signature{
			{
				ID: "requests.method", Client: "requests",
				Head:   regexp.MustCompile(`\b(?:requests|httpx|treq|niquests)\.(?P<verb>` + verbs + `)`),
				URLArg: 0, MethodArg: -1, MinArgs: 1,
			},
			{
				ID: "requests.request", Client: "requests",
				Head:      regexp.MustCompile(`\b(?:requests|httpx)\.request`),
				MethodArg: 0, URLArg: 1, MinArgs: 2,
			},
			{
				ID: "requests.session", Client: "requests",
				Head:   regexp.MustCompile(`\b(?P<recv>[\w.]+)\.(?P<verb>` + verbs + `)`),
				URLArg: 0, MethodArg: -1, MinArgs: 1,
				RequireInstance: true,
			},
			{
				ID: "urllib.urlopen", Client: "urllib",
				Head:   regexp.MustCompile(`\b(?:urllib\.request\.)?urlopen`),
				URLArg: 0, MethodArg: -1, DefaultMethod: "GET", MinArgs: 1,
				RequireImport: []string{"urllib"},
			},
			{
				ID: "urllib.Request", Client: "urllib",
				Head:   regexp.MustCompile(`\b(?:urllib\.request\.)?Request`),
				URLArg: 0, MethodArg: -1, MethodOption: []string{"method"},
				DefaultMethod: "GET", MinArgs: 1,
				RequireImport: []string{"urllib"},
			},
			{
				// Recorded so route decorators show up as deliberate exclusions
				// rather than vanishing.
				ID: "python.route", Client: "route",
				Head:   regexp.MustCompile(`@\s*(?:app|router|bp|blueprint)\.(?P<verb>route|` + verbs + `)`),
				URLArg: 0, MethodArg: -1, MinArgs: 1,
				AlwaysRoute: true,
			},
			{
				ID: "django.route", Client: "route",
				Head:   regexp.MustCompile(`\b(?:path|re_path)`),
				URLArg: 0, MethodArg: -1, MinArgs: 1,
				AlwaysRoute: true,
				RequireText: []string{"urlpatterns"},
			},
		},
	}
}

// NewPython returns a detector for Python sources.
func NewPython() Detector { return NewDetector(pythonSpec()) }
