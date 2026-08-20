package lineengine

import (
	"regexp"

	"github.com/stephen-bee/endpoint-monitor/internal/detect"
)

// Verbatim (@"...") and interpolated ($"...") forms are listed before the plain
// quote so their prefixes are recognised. $@"..." combines both.
var csharpStrings = []StringSyntax{
	{Open: `"`, Close: `"`, Prefix: `$@`, NoEscapes: true, Interp: []InterpSyntax{{Open: "{", Close: "}"}}},
	{Open: `"`, Close: `"`, Prefix: `@$`, NoEscapes: true, Interp: []InterpSyntax{{Open: "{", Close: "}"}}},
	{Open: `"`, Close: `"`, Prefix: `$`, Interp: []InterpSyntax{{Open: "{", Close: "}"}}},
	{Open: `"`, Close: `"`, Prefix: `@`, NoEscapes: true},
	{Open: `"`, Close: `"`},
}

func csharpSpec() *Spec {
	return &Spec{
		Lang:          detect.LangCSharp,
		Exts:          []string{".cs"},
		LineComments:  []string{"//"},
		BlockComments: [][2]string{{"/*", "*/"}},
		Strings:       csharpStrings,
		ImportRe: []*regexp.Regexp{
			regexp.MustCompile(`(?m)^\s*(?:global\s+)?using\s+(?:static\s+)?(?P<path>[\w.]+)`),
		},
		ClientImports: map[string]string{
			"System.Net.Http": "HttpClient",
			"System.Net":      "System.Net",
			"RestSharp":       "RestSharp",
			"Refit":           "Refit",
			"Flurl":           "Flurl",
		},
		ServerImports: map[string]detect.Framework{
			"Microsoft.AspNetCore.Mvc": "aspnet-mvc",
			"Microsoft.AspNetCore":     "aspnet",
			"WireMock":                 "wiremock",
		},
		ConcatOps:    []string{"+"},
		FormatCalls:  []string{"string.Format", "String.Format", "Format"},
		JoinCalls:    []string{"Path.Combine", "AppendPathSegment"},
		HandlerHints: []string{"=>", "delegate"},
		SelfNames:    []string{"this"},
		FuncRe:       regexp.MustCompile(`(?m)^\s*(?:public|private|protected|internal|static|async|override|virtual|\s)*[\w<>\[\],.\s?]+\s+(?P<name>\w+)\s*\([^)]*\)`),
		EnvRe: []*regexp.Regexp{
			regexp.MustCompile(`Environment\.GetEnvironmentVariable\(\s*"(?P<name>[^"]+)"\s*\)`),
		},
		Symbols: []SymbolPattern{
			{Re: regexp.MustCompile(`(?m)^\s*(?:public|private|protected|internal)?\s*(?:const|static\s+readonly)\s+string\s+(?P<name>\w+)\s*=\s*(?P<value>[^;\n]+)`),
				Scope: detect.ScopeFile, Constant: true},
			{Re: regexp.MustCompile(`(?m)^\s*(?:var|string)\s+(?P<name>\w+)\s*=\s*(?P<value>[^;\n]+)`),
				Scope: detect.ScopeFile},
			{Re: regexp.MustCompile(`this\.(?P<name>\w+)\s*=\s*(?P<value>[^;\n]+)`),
				Scope: detect.ScopeType},
		},
		Bindings: []BindingPattern{
			// client.BaseAddress = new Uri("https://...")
			{Re: regexp.MustCompile(`(?P<name>\w+)\.BaseAddress\s*=\s*new\s+Uri\(\s*(?P<value>[^,)\n]+)`)},
			// A typed or named client configured at registration. The base
			// applies file-wide because the consumer resolves it by name
			// elsewhere, which we cannot follow.
			{Re: regexp.MustCompile(`c\.BaseAddress\s*=\s*new\s+Uri\(\s*(?P<value>[^,)\n]+)`)},
			{Re: regexp.MustCompile(`(?:var|RestClient)\s+(?P<name>\w+)\s*=\s*new\s+RestClient\(\s*(?P<value>"[^"]*")`)},
		},
		Signatures: []Signature{
			{
				// GetAsync, PostAsync, PutAsync, PatchAsync, DeleteAsync
				ID: "csharp.httpclient.verbasync", Client: "HttpClient",
				Head:   regexp.MustCompile(`\b(?P<recv>[\w_]+)\.(?P<verb>Get|Post|Put|Patch|Delete)Async`),
				URLArg: 0, MethodArg: -1, MinArgs: 1,
			},
			{
				// GetStringAsync, GetByteArrayAsync, GetStreamAsync
				ID: "csharp.httpclient.getcontent", Client: "HttpClient",
				Head:   regexp.MustCompile(`\b(?P<recv>[\w_]+)\.Get(?:String|ByteArray|Stream)Async`),
				URLArg: 0, MethodArg: -1, Method: "GET", MinArgs: 1,
			},
			{
				// System.Net.Http.Json: GetFromJsonAsync, PostAsJsonAsync...
				ID: "csharp.httpclient.json", Client: "System.Net.Http.Json",
				Head:   regexp.MustCompile(`\b(?P<recv>[\w_]+)\.(?P<verb>Get|Post|Put|Patch|Delete)(?:From|As)JsonAsync(?:<[^>]*>)?`),
				URLArg: 0, MethodArg: -1, MinArgs: 1,
			},
			{
				ID: "csharp.httprequestmessage", Client: "HttpClient",
				Head:      regexp.MustCompile(`new\s+HttpRequestMessage`),
				MethodArg: 0, URLArg: 1, MinArgs: 2,
			},
			{
				ID: "csharp.webrequest", Client: "System.Net",
				Head:   regexp.MustCompile(`\bWebRequest\.Create`),
				URLArg: 0, MethodArg: -1, MinArgs: 1,
			},
			{
				ID: "csharp.restsharp.request", Client: "RestSharp",
				Head:   regexp.MustCompile(`new\s+RestRequest`),
				URLArg: 0, MethodArg: 1, MinArgs: 1,
			},
			{
				// A declarative Refit client: the attribute is the call. The
				// pattern requires "[" immediately before the verb, so it cannot
				// match ASP.NET's [HttpGet(...)].
				ID: "csharp.refit.attribute", Client: "Refit",
				Head:   regexp.MustCompile(`\[(?P<verb>Get|Post|Put|Patch|Delete|Head|Options)`),
				URLArg: 0, MethodArg: -1, MinArgs: 1,
				RequireText: []string{"Refit", "RestService", "AddRefitClient"},
			},
			{
				// ASP.NET route registrations, recorded so they are reported as
				// deliberate exclusions.
				ID: "csharp.aspnet.attribute", Client: "route",
				Head:   regexp.MustCompile(`\[Http(?:Get|Post|Put|Patch|Delete|Head|Options)`),
				URLArg: 0, MethodArg: -1, MinArgs: 1,
				AlwaysRoute: true,
			},
			{
				ID: "csharp.aspnet.minimal", Client: "route",
				Head:   regexp.MustCompile(`\.Map(?:Get|Post|Put|Patch|Delete)`),
				URLArg: 0, MethodArg: -1, MinArgs: 1,
				AlwaysRoute: true,
			},
		},
	}
}

// NewCSharp returns a detector for C# sources.
func NewCSharp() Detector { return NewDetector(csharpSpec()) }
