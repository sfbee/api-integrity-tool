package lineengine

import (
	"regexp"

	"github.com/sfbee/api-integrity-tool/internal/detect"
)

// Text blocks must be listed before the plain quote so the longer delimiter
// wins when both could start at the same offset.
var javaStrings = []StringSyntax{
	{Open: `"""`, Close: `"""`, NoEscapes: true},
	{Open: `"`, Close: `"`},
}

func javaSpec() *Spec {
	verbs := `GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS`
	return &Spec{
		Lang:          detect.LangJava,
		Exts:          []string{".java"},
		LineComments:  []string{"//"},
		BlockComments: [][2]string{{"/*", "*/"}},
		Strings:       javaStrings,
		ImportRe: []*regexp.Regexp{
			regexp.MustCompile(`(?m)^\s*import\s+(?:static\s+)?(?P<path>[\w.]+)`),
		},
		ClientImports: map[string]string{
			"java.net.http":      "java.net.http",
			"okhttp3":            "okhttp",
			"org.apache.http":    "apache-httpclient",
			"org.apache.hc":      "apache-httpclient",
			"web.client":         "spring-web",
			"retrofit2":          "retrofit",
			"feign":              "feign",
			"kong.unirest":       "unirest",
			"javax.ws.rs.client": "jaxrs",
		},
		ServerImports: map[string]detect.Framework{
			"web.bind.annotation":             "spring-mvc",
			"javax.ws.rs":                     "jaxrs-server",
			"jakarta.ws.rs":                   "jaxrs-server",
			"javax.servlet":                   "servlet",
			"com.github.tomakehurst.wiremock": "wiremock",
		},
		ConcatOps: []string{"+"},
		// String.join puts the delimiter first, so it is not a path join and is
		// deliberately absent: mapping it to Join would emit a reversed URL.
		FormatCalls:  []string{"String.format", "format", "formatted"},
		JoinCalls:    []string{"Paths.get"},
		HandlerHints: []string{"->", "new Handler", "::"},
		SelfNames:    []string{"this"},
		FuncRe:       regexp.MustCompile(`(?m)^\s*(?:public|private|protected|static|final|\s)*[\w<>\[\],.\s]+\s+(?P<name>\w+)\s*\([^)]*\)\s*(?:throws [\w,.\s]+)?\{`),
		EnvRe: []*regexp.Regexp{
			regexp.MustCompile(`System\.getenv\(\s*"(?P<name>[^"]+)"\s*\)`),
			// @Value("${api.base}") resolves from configuration, not the
			// environment, but it is symbolic in exactly the same way.
			regexp.MustCompile(`@Value\(\s*"\$\{(?P<name>[^:}]+)`),
		},
		Symbols: []SymbolPattern{
			{Re: regexp.MustCompile(`(?m)^\s*(?:public|private|protected)?\s*static\s+final\s+String\s+(?P<name>\w+)\s*=\s*(?P<value>[^;\n]+)`),
				Scope: detect.ScopeFile, Constant: true},
			{Re: regexp.MustCompile(`(?m)^\s*(?:final\s+)?String\s+(?P<name>\w+)\s*=\s*(?P<value>[^;\n]+)`),
				Scope: detect.ScopeFile},
			{Re: regexp.MustCompile(`this\.(?P<name>\w+)\s*=\s*(?P<value>[^;\n]+)`),
				Scope: detect.ScopeType},
		},
		Bindings: []BindingPattern{
			// WebClient.create(base) / builder().baseUrl(base)
			{Re: regexp.MustCompile(`(?:WebClient|RestClient)\s+(?P<name>\w+)\s*=\s*(?:WebClient|RestClient)\.(?:create|builder\(\)\.baseUrl)\(\s*(?P<value>[^,)\n]+)`)},
			{Re: regexp.MustCompile(`(?P<name>\w+)\s*=\s*(?:WebClient|RestClient)\.builder\(\)[^;]*?\.baseUrl\(\s*(?P<value>[^,)\n]+)`)},
			// Retrofit and Feign declare the base once for a whole interface, so
			// the binding has no instance name and applies file-wide.
			{Re: regexp.MustCompile(`\.baseUrl\(\s*(?P<value>[^,)\n]+)`)},
			{Re: regexp.MustCompile(`@FeignClient\([^)]*url\s*=\s*(?P<value>"[^"]*")`)},
		},
		Signatures: []Signature{
			{
				// HttpRequest.newBuilder().uri(URI.create(url)); the method is
				// set elsewhere in the chain, so it stays undetermined.
				ID: "java.httpclient.uri", Client: "java.net.http",
				Head:   regexp.MustCompile(`\bURI\.create`),
				URLArg: 0, MethodArg: -1, MinArgs: 1,
				RequireText: []string{"HttpRequest", "HttpClient"},
			},
			{
				ID: "java.okhttp.url", Client: "okhttp",
				Head:   regexp.MustCompile(`\.url`),
				URLArg: 0, MethodArg: -1, MinArgs: 1,
				RequireText: []string{"Request.Builder", "OkHttpClient"},
			},
			{
				ID: "java.apache.request", Client: "apache-httpclient",
				Head:   regexp.MustCompile(`new\s+Http(?P<verb>Get|Post|Put|Patch|Delete|Head|Options)`),
				URLArg: 0, MethodArg: -1, MinArgs: 1,
			},
			{
				// getForObject, postForEntity, patchForObject, headForHeaders...
				ID: "java.resttemplate.forx", Client: "spring-resttemplate",
				Head:   regexp.MustCompile(`\b(?P<recv>\w+)\.(?P<verb>get|post|put|patch|delete|head|options)For\w+`),
				URLArg: 0, MethodArg: -1, MinArgs: 1,
			},
			{
				// exchange(url, HttpMethod.POST, ...) and execute(...)
				ID: "java.resttemplate.exchange", Client: "spring-resttemplate",
				Head:   regexp.MustCompile(`\.(?:exchange|execute)`),
				URLArg: 0, MethodArg: 1, MinArgs: 2,
				RequireText: []string{"RestTemplate"},
			},
			{
				ID: "java.webclient.uri", Client: "spring-webclient",
				Head:   regexp.MustCompile(`\b(?P<recv>\w+)\.uri`),
				URLArg: 0, MethodArg: -1, MinArgs: 1,
				RequireText: []string{"WebClient", "RestClient"},
			},
			{
				ID: "java.unirest", Client: "unirest",
				Head:   regexp.MustCompile(`\bUnirest\.(?P<verb>get|post|put|patch|delete|head|options)`),
				URLArg: 0, MethodArg: -1, MinArgs: 1,
			},
			{
				// A declarative client: the annotation IS the call. Retrofit and
				// Feign both spell it this way.
				ID: "java.retrofit.annotation", Client: "retrofit",
				Head:   regexp.MustCompile(`@(?P<verb>` + verbs + `)`),
				URLArg: 0, MethodArg: -1, MinArgs: 1,
				RequireText: []string{"retrofit2", "Retrofit", "@FeignClient", "@HttpExchange", "RequestLine"},
			},
			{
				// The sharpest trap in Java: @GetMapping("/x") is OUTBOUND on a
				// Feign interface and INBOUND on a Spring controller. The two
				// readings are separated by requiring, and forbidding, the
				// @FeignClient annotation.
				ID: "java.feign.mapping", Client: "feign",
				Head:   regexp.MustCompile(`@(?P<verb>Get|Post|Put|Patch|Delete|Head|Options)Mapping`),
				URLArg: 0, MethodArg: -1, MinArgs: 1,
				URLOption:   []string{"value", "path"},
				RequireText: []string{"@FeignClient", "@HttpExchange"},
			},
			{
				// Spring MVC route registrations, recorded so they are reported
				// as deliberate exclusions rather than silently ignored.
				ID: "java.spring.route", Client: "route",
				Head:   regexp.MustCompile(`@(?:(?:Get|Post|Put|Patch|Delete|Head|Options)Mapping|RequestMapping)`),
				URLArg: 0, MethodArg: -1, MinArgs: 1,
				URLOption:   []string{"value", "path"},
				ForbidText:  []string{"@FeignClient", "@HttpExchange"},
				AlwaysRoute: true,
			},
			{
				ID: "java.jaxrs.route", Client: "route",
				Head:   regexp.MustCompile(`@Path`),
				URLArg: 0, MethodArg: -1, MinArgs: 1,
				ForbidText:  []string{"@FeignClient", "@RegisterRestClient"},
				AlwaysRoute: true,
			},
		},
	}
}

// NewJava returns a detector for Java sources.
func NewJava() Detector { return NewDetector(javaSpec()) }
