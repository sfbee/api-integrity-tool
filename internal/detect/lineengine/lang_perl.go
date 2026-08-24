package lineengine

import (
	"regexp"

	"github.com/sfbee/api-integrity-tool/internal/detect"
)

// perlStrings covers interpolating and non-interpolating literals plus the qq
// and q quoting operators. Perl interpolates bare sigil variables, so a URL is
// commonly written "$base/api/v1/thing" with no braces at all.
var perlStrings = []StringSyntax{
	{Open: "qq{", Close: "}", Interp: []InterpSyntax{{Open: "${", Close: "}"}}, BareSigils: "$@"},
	{Open: "q{", Close: "}"},
	{Open: `"`, Close: `"`, Interp: []InterpSyntax{{Open: "${", Close: "}"}}, BareSigils: "$@"},
	{Open: "'", Close: "'"},
}

func perlSpec() *Spec {
	clients := []string{"LWP::UserAgent", "HTTP::Tiny", "Mojo::UserAgent", "REST::Client", "Furl", "WWW::Mechanize", "HTTP::Request"}
	return &Spec{
		Lang:         detect.LangPerl,
		Exts:         []string{".pl", ".pm", ".t", ".cgi", ".psgi"},
		LineComments: []string{"#"},
		// Perl documentation lives in POD blocks and anything after __END__ is
		// data, not code. Both are full of example calls.
		PodBlocks: true,
		SkipAfter: []string{"__END__", "__DATA__"},
		Strings:   perlStrings,
		ImportRe: []*regexp.Regexp{
			regexp.MustCompile(`(?m)^\s*use\s+(?P<path>[\w:]+)`),
			regexp.MustCompile(`(?m)^\s*require\s+(?P<path>[\w:]+)`),
		},
		ClientImports: map[string]string{
			"LWP": "LWP::UserAgent", "HTTP::Tiny": "HTTP::Tiny",
			"Mojo::UserAgent": "Mojo::UserAgent", "REST::Client": "REST::Client",
			"Furl": "Furl", "WWW::Mechanize": "WWW::Mechanize",
		},
		ServerImports: map[string]detect.Framework{
			"Mojolicious": "mojolicious", "Dancer": "dancer", "Catalyst": "catalyst", "Plack": "plack",
		},
		FatComma:     true,
		ConcatOps:    []string{"."},
		FormatCalls:  []string{"sprintf"},
		JoinCalls:    []string{"join"},
		HandlerHints: []string{"sub {", "sub{", "=> sub"},
		SelfNames:    []string{"$self", "self"},
		FuncRe:       regexp.MustCompile(`(?m)^\s*sub\s+(?P<name>\w+)`),
		PackageRe:    regexp.MustCompile(`(?m)^\s*package\s+(?P<name>[\w:]+)`),
		EnvRe: []*regexp.Regexp{
			regexp.MustCompile(`^\$ENV\{\s*['"]?(?P<name>\w+)['"]?\s*\}$`),
		},
		Symbols: []SymbolPattern{
			{Re: regexp.MustCompile(`\bmy\s+\$(?P<name>\w+)\s*=\s*(?:my\s+\$\w+\s*=\s*)*(?P<value>[^;\n]+)`), Scope: detect.ScopeFile},
			{Re: regexp.MustCompile(`\bour\s+\$(?P<name>\w+)\s*=\s*(?:our\s+\$\w+\s*=\s*)*(?P<value>[^;\n]+)`), Scope: detect.ScopeFile},
			{Re: regexp.MustCompile(`\buse\s+constant\s+(?P<name>\w+)\s*=>\s*(?P<value>[^;\n]+)`), Scope: detect.ScopeFile, Constant: true},
			{Re: regexp.MustCompile(`(?P<name>\$self->\{\s*\w+\s*\})\s*=\s*(?P<value>[^;\n]+)`), Scope: detect.ScopeType},
		},
		Bindings: []BindingPattern{
			{Re: regexp.MustCompile(`(?P<name>\$\w+)\s*->\s*setHost\(\s*(?P<value>[^)\n]+)\)`)},
			{Re: regexp.MustCompile(`(?P<name>\$\w+)\s*=\s*REST::Client->new\(\s*\{[^}]*?host\s*=>\s*(?P<value>[^,}\n]+)`)},
		},
		Signatures: []Signature{
			{
				ID: "perl.ua.method", Client: "LWP::UserAgent",
				Head:   regexp.MustCompile(`(?P<recv>\$\w+)\s*->\s*(?P<verb>get|post|put|delete|head|patch|options)`),
				URLArg: 0, MethodArg: -1, MinArgs: 1,
				RequireText: clients,
			},
			{
				// "$ua->request(GET => $url)" and its simple_request variant.
				// LWP's own request() takes an HTTP::Request object rather than a
				// method and URL, but the two-argument form is the dominant
				// convention in wrapper classes built on top of it.
				ID: "perl.ua.request", Client: "perl-http",
				Head:      regexp.MustCompile(`(?P<recv>\$\w+(?:->\{\s*\w+\s*\})?)\s*->\s*(?:simple_)?request`),
				MethodArg: 0, URLArg: 1, MinArgs: 2,
				RequireVerbArg: true,
			},
			{
				ID: "perl.request.new", Client: "HTTP::Request",
				Head:      regexp.MustCompile(`\bHTTP::Request\s*->\s*new`),
				MethodArg: 0, URLArg: 1, MinArgs: 2,
				RequireText: []string{"HTTP::Request"},
			},
			{
				ID: "perl.mojo.build", Client: "Mojo::UserAgent",
				Head:      regexp.MustCompile(`(?P<recv>\$\w+)\s*->\s*build_tx`),
				MethodArg: 0, URLArg: 1, MinArgs: 2,
				RequireText: []string{"Mojo::UserAgent"},
			},
			{
				// LWP::Simple exports a bare get(); the "use" line is the only
				// thing distinguishing it from any other function named get.
				ID: "perl.simple.get", Client: "LWP::Simple",
				Head:   regexp.MustCompile(`(?m)(?:^|[;{}\s=(])(?:get|head|getstore|mirror)`),
				URLArg: 0, MethodArg: -1, Method: "GET", MinArgs: 1,
				RequireText: []string{"LWP::Simple"},
			},
		},
	}
}

// NewPerl returns a detector for Perl sources.
func NewPerl() Detector { return NewDetector(perlSpec()) }
