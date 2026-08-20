package lineengine

import (
	"regexp"

	"github.com/stephen-bee/endpoint-monitor/internal/detect"
)

// jsStrings covers the three JavaScript literal forms. The template literal is
// listed first because its interpolation is what most modern URL building uses.
var jsStrings = []StringSyntax{
	{Open: "`", Close: "`", Interp: []InterpSyntax{{Open: "${", Close: "}"}}},
	{Open: `"`, Close: `"`},
	{Open: "'", Close: "'"},
}

// jsHandlerHints identify a callback argument. An arrow function or the word
// "function" in a later argument means the call registers a route rather than
// making one, which is the single most important discrimination in this file.
var jsHandlerHints = []string{"=>", "function", "async(", "async ("}

func jsSpec(lang detect.Language, exts []string) *Spec {
	verbs := `get|post|put|patch|delete|head|options`
	return &Spec{
		Lang:          lang,
		Exts:          exts,
		LineComments:  []string{"//"},
		BlockComments: [][2]string{{"/*", "*/"}},
		Strings:       jsStrings,
		ImportRe: []*regexp.Regexp{
			regexp.MustCompile(`(?m)^\s*import\s[^'"\n]*['"](?P<path>[^'"]+)['"]`),
			regexp.MustCompile(`require\(\s*['"](?P<path>[^'"]+)['"]\s*\)`),
		},
		ClientImports: map[string]string{
			"axios": "axios", "got": "got", "ky": "ky", "node-fetch": "fetch",
			"superagent": "superagent", "undici": "undici", "graphql-request": "graphql-request",
		},
		ServerImports: map[string]detect.Framework{
			"express": "express", "fastify": "fastify", "koa": "koa",
			"@nestjs/common": "nest", "hapi": "hapi", "msw": "msw",
		},
		ConcatOps:    []string{"+"},
		JoinCalls:    []string{"join", "posix.join"},
		HandlerHints: jsHandlerHints,
		SelfNames:    []string{"this"},
		FuncRe:       regexp.MustCompile(`(?m)^\s*(?:export\s+)?(?:async\s+)?function\s+(?P<name>\w+)`),
		EnvRe: []*regexp.Regexp{
			regexp.MustCompile(`^process\.env\.(?P<name>\w+)$`),
			regexp.MustCompile(`^process\.env\[\s*['"](?P<name>\w+)['"]\s*\]$`),
			regexp.MustCompile(`^import\.meta\.env\.(?P<name>\w+)$`),
		},
		Symbols: []SymbolPattern{
			{Re: regexp.MustCompile(`(?m)^\s*(?:export\s+)?(?:const|let|var)\s+(?P<name>\w+)\s*(?::\s*[\w<>\[\]|]+\s*)?=\s*(?P<value>[^;\n]+)`), Scope: detect.ScopeFile},
			{Re: regexp.MustCompile(`(?P<name>this\.\w+)\s*=\s*(?P<value>[^;\n]+)`), Scope: detect.ScopeType},
		},
		Bindings: []BindingPattern{
			// axios.create({baseURL}) and got.extend({prefixUrl}) bind an
			// instance, whose call sites then use bare paths.
			{Re: regexp.MustCompile(`(?:const|let|var)\s+(?P<name>\w+)\s*=\s*axios\.create\(\s*\{[^}]*?base(?:URL|Url)\s*:\s*(?P<value>[^,}\n]+)`)},
			{Re: regexp.MustCompile(`(?:const|let|var)\s+(?P<name>\w+)\s*=\s*(?:got|ky)\.(?:extend|create)\(\s*\{[^}]*?prefixUrl\s*:\s*(?P<value>[^,}\n]+)`)},
			{Re: regexp.MustCompile(`(?:const|let|var)\s+(?P<name>\w+)\s*=\s*createClient\(\s*\{[^}]*?base(?:URL|Url)\s*:\s*(?P<value>[^,}\n]+)`)},
			{Re: regexp.MustCompile(`(?P<name>\w+)\.defaults\.baseURL\s*=\s*(?P<value>[^;\n]+)`)},
		},
		Signatures: []Signature{
			{
				ID: "js.fetch", Client: "fetch",
				Head:          regexp.MustCompile(`\bfetch`),
				URLArg:        0,
				MethodArg:     -1,
				MethodOption:  []string{"method"},
				DefaultMethod: "GET",
				MinArgs:       1,
			},
			{
				ID: "axios.method", Client: "axios",
				Head:   regexp.MustCompile(`\baxios\.(?P<verb>` + verbs + `)`),
				URLArg: 0, MethodArg: -1, MinArgs: 1,
			},
			{
				ID: "axios.request", Client: "axios",
				Head:   regexp.MustCompile(`\baxios(?:\.request)?`),
				URLArg: 0, MethodArg: -1,
				URLOption: []string{"url", "uri"}, MethodOption: []string{"method"},
				DefaultMethod: "GET", MinArgs: 1,
			},
			{
				ID: "axios.instance", Client: "axios",
				Head:   regexp.MustCompile(`\b(?P<recv>\w+)\.(?P<verb>` + verbs + `)`),
				URLArg: 0, MethodArg: -1, MinArgs: 1,
				RequireInstance: true,
			},
			{
				ID: "got.method", Client: "got",
				Head:   regexp.MustCompile(`\b(?:got|ky)\.(?P<verb>` + verbs + `)`),
				URLArg: 0, MethodArg: -1, MinArgs: 1,
				RequireImport: []string{"got", "ky"},
			},
			{
				ID: "superagent.method", Client: "superagent",
				Head:   regexp.MustCompile(`\b(?:superagent|request)\.(?P<verb>` + verbs + `)`),
				URLArg: 0, MethodArg: -1, MinArgs: 1,
				RequireImport: []string{"superagent", "request"},
			},
			{
				ID: "jquery.ajax", Client: "jquery",
				Head:   regexp.MustCompile(`\$\.ajax`),
				URLArg: 0, MethodArg: -1,
				URLOption: []string{"url"}, MethodOption: []string{"type", "method"},
				DefaultMethod: "GET", MinArgs: 1,
			},
			{
				ID: "jquery.method", Client: "jquery",
				Head:   regexp.MustCompile(`\$\.(?P<verb>get|post|getJSON)`),
				URLArg: 0, MethodArg: -1, MinArgs: 1,
			},
			{
				// XMLHttpRequest is a global, so there is no import to gate on;
				// the type name appearing anywhere in the file is the evidence.
				ID: "xhr.open", Client: "XMLHttpRequest",
				Head:      regexp.MustCompile(`\b\w+\.open`),
				MethodArg: 0, URLArg: 1, MinArgs: 2,
				RequireText: []string{"XMLHttpRequest"},
			},
			{
				// Recorded only so it can be reported as a deliberate exclusion.
				ID: "js.route", Client: "route",
				Head:   regexp.MustCompile(`\b(?:app|router|server|fastify)\.(?P<verb>` + verbs + `|all|use)`),
				URLArg: 0, MethodArg: -1, MinArgs: 1,
				RouteIfHandlerArg: true,
			},
		},
	}
}

// NewJavaScript returns a detector for .js and friends.
func NewJavaScript() Detector {
	return NewDetector(jsSpec(detect.LangJS, []string{".js", ".jsx", ".mjs", ".cjs"}))
}

// NewTypeScript returns a detector for .ts and .tsx. TypeScript shares
// JavaScript's call syntax entirely; only the file extension differs.
func NewTypeScript() Detector {
	return NewDetector(jsSpec(detect.LangTS, []string{".ts", ".tsx", ".mts", ".cts"}))
}
