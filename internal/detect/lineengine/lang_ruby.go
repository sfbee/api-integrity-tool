package lineengine

import (
	"regexp"

	"github.com/stephen-bee/endpoint-monitor/internal/detect"
)

var rubyStrings = []StringSyntax{
	{Open: `"`, Close: `"`, Interp: []InterpSyntax{{Open: "#{", Close: "}"}}},
	{Open: "'", Close: "'"},
	{Open: "%{", Close: "}", Interp: []InterpSyntax{{Open: "#{", Close: "}"}}},
}

func rubySpec() *Spec {
	verbs := `get|post|put|patch|delete|head|options`
	return &Spec{
		Lang:          detect.LangRuby,
		Exts:          []string{".rb", ".rake", ".gemspec"},
		LineComments:  []string{"#"},
		BlockComments: [][2]string{{"=begin", "=end"}},
		Strings:       rubyStrings,
		ImportRe: []*regexp.Regexp{
			regexp.MustCompile(`(?m)^\s*require(?:_relative)?\s+['"](?P<path>[^'"]+)['"]`),
			regexp.MustCompile(`(?m)^\s*(?:include|extend)\s+(?P<path>[\w:]+)`),
		},
		ClientImports: map[string]string{
			"net/http": "net/http", "faraday": "faraday", "httparty": "httparty",
			"rest-client": "rest-client", "excon": "excon", "typhoeus": "typhoeus",
			"open-uri": "open-uri", "http": "http.rb", "HTTParty": "httparty",
		},
		ServerImports: map[string]detect.Framework{
			"sinatra": "sinatra", "rails": "rails", "webmock": "webmock", "vcr": "vcr",
		},
		ConcatOps:    []string{"+", "<<"},
		FormatCalls:  []string{"format", "sprintf"},
		JoinCalls:    []string{"join"},
		HandlerHints: []string{"do |", "->", "lambda", "proc", "to:"},
		SelfNames:    []string{"self", "@"},
		FuncRe:       regexp.MustCompile(`(?m)^\s*def\s+(?P<name>[\w.?!=]+)`),
		PackageRe:    regexp.MustCompile(`(?m)^\s*(?:class|module)\s+(?P<name>[\w:]+)`),
		EnvRe: []*regexp.Regexp{
			regexp.MustCompile(`^ENV\[\s*['"](?P<name>\w+)['"]\s*\]$`),
			regexp.MustCompile(`^ENV\.fetch\(\s*['"](?P<name>\w+)['"].*\)$`),
		},
		Symbols: []SymbolPattern{
			{Re: regexp.MustCompile(`(?m)^\s*(?P<name>[A-Z][A-Z0-9_]*)\s*=\s*(?P<value>[^\n#]+)`), Scope: detect.ScopeFile, Constant: true},
			{Re: regexp.MustCompile(`(?m)^\s*(?P<name>@?\w+)\s*=\s*(?P<value>[^\n#]+)`), Scope: detect.ScopeFile},
		},
		Bindings: []BindingPattern{
			{Re: regexp.MustCompile(`(?P<name>@?\w+)\s*=\s*Faraday\.new\(\s*(?:url:\s*)?(?P<value>['"][^'"]+['"])`)},
			{Re: regexp.MustCompile(`(?P<name>@?\w+)\s*=\s*Excon\.new\(\s*(?P<value>['"][^'"]+['"])`)},
			// "base_uri" is a class-level declaration with no receiver, so the
			// binding has no instance name and applies file-wide.
			{Re: regexp.MustCompile(`(?m)^\s*base_uri\s+(?P<value>['"][^'"]+['"])`)},
		},
		Signatures: []Signature{
			{
				ID: "ruby.nethttp", Client: "net/http",
				Head:   regexp.MustCompile(`\bNet::HTTP\.(?P<verb>get_response|post_form|get|post)`),
				URLArg: 0, MethodArg: -1, MinArgs: 1,
			},
			{
				ID: "ruby.library.method", Client: "ruby-http",
				Head:   regexp.MustCompile(`\b(?:HTTParty|RestClient|Faraday|Excon|Typhoeus|HTTP)\.(?P<verb>` + verbs + `)`),
				URLArg: 0, MethodArg: -1, MinArgs: 1,
			},
			{
				ID: "ruby.restclient.execute", Client: "rest-client",
				Head:   regexp.MustCompile(`\bRestClient::Request\.execute`),
				URLArg: 0, MethodArg: -1,
				URLOption: []string{"url"}, MethodOption: []string{"method"}, MinArgs: 1,
			},
			{
				ID: "ruby.instance.method", Client: "ruby-http",
				Head:   regexp.MustCompile(`\b(?P<recv>@?\w+)\.(?P<verb>` + verbs + `)`),
				URLArg: 0, MethodArg: -1, MinArgs: 1,
				RequireInstance: true,
			},
			{
				// "self.class.get('/x')" is the HTTParty class-method idiom.
				ID: "ruby.httparty.selfclass", Client: "httparty",
				Head:   regexp.MustCompile(`\bself\.class\.(?P<verb>` + verbs + `)`),
				URLArg: 0, MethodArg: -1, MinArgs: 1,
				RequireText: []string{"HTTParty"},
			},
			{
				// Rails route DSL. Recorded so it is reported as excluded rather
				// than silently ignored.
				ID: "ruby.route", Client: "route",
				Head:   regexp.MustCompile(`(?m)(?:^|[;\s])(?:` + verbs + `|resources|resource|root|match)`),
				URLArg: 0, MethodArg: -1, MinArgs: 1,
				AlwaysRoute: true,
				RequireText: []string{"Rails.application.routes", "routes.draw"},
			},
		},
	}
}

// NewRuby returns a detector for Ruby sources.
func NewRuby() Detector { return NewDetector(rubySpec()) }
