package lineengine

import (
	"context"
	"strings"
	"testing"

	"github.com/sfbee/api-integrity-tool/internal/detect"
	"github.com/sfbee/api-integrity-tool/internal/normalize"
	"github.com/sfbee/api-integrity-tool/internal/resolve"
)

// endpoints runs the full detect -> resolve -> normalize pipeline and returns
// "METHOD host path" strings, so tests assert the user-visible result rather
// than the shape of an intermediate tree.
func endpoints(t *testing.T, d Detector, name, src string) []string {
	t.Helper()
	f := &detect.SourceFile{RelPath: name, Lang: d.Language(), Content: []byte(src), Size: int64(len(src))}
	res, err := d.Detect(context.Background(), f)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
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

// has asserts that want appears among the detected endpoints. Signatures can
// legitimately overlap (axios.get also matches the generic instance pattern),
// so membership is the right assertion for most cases.
func has(t *testing.T, got []string, want ...string) {
	t.Helper()
	set := map[string]bool{}
	for _, g := range got {
		set[g] = true
	}
	for _, w := range want {
		if !set[w] {
			t.Errorf("missing endpoint %q\ngot: %v", w, got)
		}
	}
}

func hasNot(t *testing.T, got []string, unwanted ...string) {
	t.Helper()
	for _, g := range got {
		for _, u := range unwanted {
			if strings.Contains(g, u) {
				t.Errorf("unwanted endpoint %q matched %q\ngot: %v", g, u, got)
			}
		}
	}
}

func TestJavaScriptFetchAndAxios(t *testing.T) {
	t.Parallel()
	got := endpoints(t, NewJavaScript(), "src/api.js", `
import axios from "axios";

const BASE = "https://api.example.com";

export async function load(userId) {
  await fetch("https://api.example.com/api/v1/user/list");
  await fetch(BASE + "/api/v1/user/add", { method: "POST" });
  await fetch(`+"`${BASE}/api/v1/users/${userId}/posts`"+`);
  await axios.get("https://api.example.com/v2/things");
  await axios.post("https://api.example.com/v2/things", { name: "x" });
  await axios({ url: "https://api.example.com/v2/custom", method: "PUT" });
}
`)
	has(t, got,
		"GET api.example.com/api/v1/user/list",
		"POST api.example.com/api/v1/user/add",
		"GET api.example.com/api/v1/users/{user_id}/posts",
		"GET api.example.com/v2/things",
		"POST api.example.com/v2/things",
		"PUT api.example.com/v2/custom",
	)
}

// An axios.create instance's base URL must be joined onto its bare paths, or
// every call from a configured client is reported as a relative path.
func TestJavaScriptAxiosInstance(t *testing.T) {
	t.Parallel()
	got := endpoints(t, NewJavaScript(), "src/client.ts", `
import axios from "axios";

const api = axios.create({ baseURL: "https://api.example.com/v3", timeout: 100 });

export function addUser() {
  return api.post("/users/create");
}
export function getUser(id) {
  return api.get(`+"`/users/${id}`"+`);
}
`)
	has(t, got, "POST api.example.com/v3/users/create", "GET api.example.com/v3/users/{id}")
}

// Express routes and axios calls are syntactically identical. If this test ever
// fails, the index is being polluted with the repo's own inbound API surface.
func TestJavaScriptRoutesAreNotOutboundCalls(t *testing.T) {
	t.Parallel()
	got := endpoints(t, NewJavaScript(), "src/server.js", `
import express from "express";

const app = express();
app.get("/api/v1/inbound", (req, res) => res.send("ok"));
app.post("/api/v1/inbound", function (req, res) { res.send("ok"); });
app.use("/static", express.static("public"));

const router = express.Router();
router.delete("/api/v1/items/:id", async (req, res) => {});
`)
	hasNot(t, got, "inbound", "static", "items")
	if len(got) != 0 {
		t.Errorf("a pure route file produced endpoints: %v", got)
	}
}

func TestJavaScriptXHRAndJQuery(t *testing.T) {
	t.Parallel()
	got := endpoints(t, NewJavaScript(), "src/legacy.js", `
var xhr = new XMLHttpRequest();
xhr.open("PATCH", "https://api.example.com/v1/legacy");
$.ajax({ url: "https://api.example.com/v1/ajax", type: "DELETE" });
$.get("https://api.example.com/v1/jq");
`)
	has(t, got,
		"PATCH api.example.com/v1/legacy",
		"DELETE api.example.com/v1/ajax",
		"GET api.example.com/v1/jq",
	)
}

// A .open() call in a file that never mentions XMLHttpRequest must not be read
// as HTTP: this is the import/text gate doing its job.
func TestJavaScriptOpenWithoutXHRIsIgnored(t *testing.T) {
	t.Parallel()
	got := endpoints(t, NewJavaScript(), "src/fs.js", `
const db = require("./db");
db.open("GET", "not-a-url");
`)
	if len(got) != 0 {
		t.Errorf("got %v, want nothing", got)
	}
}

func TestJavaScriptEnvHostStaysSymbolic(t *testing.T) {
	t.Parallel()
	got := endpoints(t, NewJavaScript(), "src/api.js", `
await fetch(process.env.BILLING_URL + "/v1/charge");
`)
	has(t, got, "GET ${env:BILLING_URL}/v1/charge")
}

func TestPythonRequestsAndHttpx(t *testing.T) {
	t.Parallel()
	got := endpoints(t, NewPython(), "svc/client.py", `
import os
import requests
import httpx

BASE = "https://api.example.com"

def list_users():
    return requests.get(BASE + "/api/v1/user/list")

def add_user():
    return requests.post(f"{BASE}/api/v1/user/add", json={})

def get_user(user_id):
    return httpx.get(f"{BASE}/api/v1/users/{user_id}")

def custom():
    return requests.request("PATCH", BASE + "/api/v1/custom")

def search(q):
    return requests.get(os.environ["SEARCH_URL"] + "/search")

def formatted(org):
    return requests.get("{}/api/v1/orgs/{}".format(BASE, org))
`)
	has(t, got,
		"GET api.example.com/api/v1/user/list",
		"POST api.example.com/api/v1/user/add",
		"GET api.example.com/api/v1/users/{user_id}",
		"PATCH api.example.com/api/v1/custom",
		"GET ${env:SEARCH_URL}/search",
		// The format argument's own name is recovered, which is more useful
		// than a positional {p1} token.
		"GET api.example.com/api/v1/orgs/{org}",
	)
}

func TestPythonSelfFieldAndClientBinding(t *testing.T) {
	t.Parallel()
	got := endpoints(t, NewPython(), "svc/client.py", `
import httpx

class Client:
    def __init__(self):
        self.base = "https://api.example.com"
        self.http = httpx.Client(base_url="https://api.other.com/v2")

    def add(self):
        return httpx.post(self.base + "/api/v1/user/add")

    def fetch(self):
        return self.http.get("/things")
`)
	has(t, got, "POST api.example.com/api/v1/user/add", "GET api.other.com/v2/things")
}

func TestPythonRoutesAreNotOutboundCalls(t *testing.T) {
	t.Parallel()
	got := endpoints(t, NewPython(), "svc/routes.py", `
from flask import Flask

app = Flask(__name__)

@app.route("/api/v1/inbound", methods=["GET"])
def inbound():
    return "ok"

@app.get("/api/v1/typed")
def typed():
    return "ok"
`)
	if len(got) != 0 {
		t.Errorf("route decorators produced endpoints: %v", got)
	}
}

func TestPythonCommentsAndStringsAreDistinguished(t *testing.T) {
	t.Parallel()
	got := endpoints(t, NewPython(), "svc/client.py", `
import requests

# requests.get("https://api.commented-out.example.com/never")
def f():
    """requests.get("https://api.docstring.example.com/never")"""
    return requests.get("https://api.example.com/v1/real#fragment")
`)
	has(t, got, "GET api.example.com/v1/real")
	hasNot(t, got, "commented-out", "docstring")
}

// A "#" inside a URL is data, not a comment. Getting this wrong truncates real
// URLs, so it is worth an explicit test.
func TestHashInsideStringIsNotAComment(t *testing.T) {
	t.Parallel()
	got := endpoints(t, NewPython(), "svc/client.py", `
import requests
requests.get("https://api.example.com/v1/thing#anchor")
`)
	has(t, got, "GET api.example.com/v1/thing")
}

func TestMultiLineArgumentsAreSliced(t *testing.T) {
	t.Parallel()
	got := endpoints(t, NewPython(), "svc/client.py", `
import requests

requests.post(
    "https://api.example.com/api/v1/user/add",
    json={"name": "x", "tags": [1, 2, 3]},
    timeout=30,
)
`)
	has(t, got, "POST api.example.com/api/v1/user/add")
}

func TestEveryLineEngineCallIsFlaggedAsWeakerEvidence(t *testing.T) {
	t.Parallel()
	d := NewPython()
	f := &detect.SourceFile{
		RelPath: "svc/client.py", Lang: d.Language(),
		Content: []byte("import requests\nrequests.get(\"https://api.example.com/v1/x\")\n"),
	}
	res, err := d.Detect(context.Background(), f)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Sites) == 0 {
		t.Fatal("no sites")
	}
	for _, s := range res.Sites {
		found := false
		for _, n := range s.Notes {
			if n == "regex_detector" {
				found = true
			}
		}
		if !found {
			t.Errorf("site %q lacks the regex_detector note: %v", s.Src, s.Notes)
		}
	}
}

func TestLineNumbersSurviveCommentBlanking(t *testing.T) {
	t.Parallel()
	d := NewPython()
	src := "import requests\n" + // 1
		"# a comment\n" + // 2
		"'''\na docstring spanning lines\n'''\n" + // 3-5
		"requests.get(\"https://api.example.com/v1/x\")\n" // 6
	f := &detect.SourceFile{RelPath: "a.py", Lang: d.Language(), Content: []byte(src)}
	res, err := d.Detect(context.Background(), f)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Sites) != 1 {
		t.Fatalf("got %d sites, want 1", len(res.Sites))
	}
	if res.Sites[0].Pos.Line != 6 {
		t.Errorf("Pos.Line = %d, want 6", res.Sites[0].Pos.Line)
	}
}

// One call site must produce exactly one endpoint. Several signatures can match
// the same text -- "api.get('/users')" is an axios instance call and also fits
// the generic route-registration shape -- and before dedupeSites this emitted
// two entries: the correct one plus a phantom relative-host copy. The phantom
// then showed up as its own host and would have prompted for an upstream repo
// URL that does not exist.
func TestOneCallSiteProducesOneEndpoint(t *testing.T) {
	t.Parallel()
	src := `
import axios from 'axios';
const api = axios.create({ baseURL: 'https://api.acme.com/v2' });
export const load = (id) => api.get('/users/' + id);
`
	got := endpoints(t, NewJavaScript(), "api.ts", src)
	if len(got) != 1 {
		t.Fatalf("want exactly 1 endpoint, got %d: %v", len(got), got)
	}
	has(t, got, "GET api.acme.com/v2/users/{id}")
	hasNot(t, got, "GET self/users/{id}")
}

// "api" reads as a client instance, not a server router. Naming a receiver
// "api" is overwhelmingly an HTTP client in real code, and treating it as an
// express app silently dropped genuine calls.
func TestJavaScriptApiReceiverIsAClientNotARoute(t *testing.T) {
	t.Parallel()
	src := `
import axios from 'axios';
const api = axios.create({ baseURL: 'https://api.acme.com' });
api.post('/v1/charge', {});
`
	has(t, endpoints(t, NewJavaScript(), "charge.js", src), "POST api.acme.com/v1/charge")
}

func TestPerlUserAgentCalls(t *testing.T) {
	t.Parallel()
	src := `
use LWP::UserAgent;
my $ua = LWP::UserAgent->new;
my $base = "https://api.example.com";
my $r1 = $ua->get("$base/api/v1/things");
my $r2 = $ua->post($base . "/api/v1/things/create");
my $r3 = $ua->delete("https://api.example.com/api/v1/things/42");
`
	got := endpoints(t, NewPerl(), "client.pl", src)
	has(t, got,
		"GET api.example.com/api/v1/things",
		"POST api.example.com/api/v1/things/create",
		// "42" stays literal: purely numeric segments are not collapsed to
		// {id} by default, because digits are frequently a real part of the
		// route ("/api/2/issue", "/v1/2020-08-27").
		"DELETE api.example.com/api/v1/things/42",
	)
}

func TestPerlHTTPTinyAndMojo(t *testing.T) {
	t.Parallel()
	src := `
use HTTP::Tiny;
use Mojo::UserAgent;
my $http = HTTP::Tiny->new;
my $res = $http->get("https://api.example.com/tiny/status");
my $ua = Mojo::UserAgent->new;
my $tx = $ua->post("https://api.example.com/mojo/publish");
`
	has(t, endpoints(t, NewPerl(), "mixed.pl", src),
		"GET api.example.com/tiny/status",
		"POST api.example.com/mojo/publish",
	)
}

// Perl's POD blocks and __END__ section are prose. Example calls inside them are
// documentation, not code, and indexing them invents endpoints the program never
// calls.
func TestPerlPodAndEndAreNotCode(t *testing.T) {
	t.Parallel()
	src := `
use LWP::UserAgent;
my $ua = LWP::UserAgent->new;
my $real = $ua->get("https://api.example.com/real/call");

=head1 SYNOPSIS

  $ua->get("https://api.example.com/pod/example");

=cut

my $also_real = $ua->get("https://api.example.com/after/pod");

__END__
$ua->get("https://api.example.com/after/end");
`
	got := endpoints(t, NewPerl(), "doc.pl", src)
	has(t, got, "GET api.example.com/real/call", "GET api.example.com/after/pod")
	hasNot(t, got, "GET api.example.com/pod/example", "GET api.example.com/after/end")
}

func TestRubyFaradayAndNetHTTP(t *testing.T) {
	t.Parallel()
	src := `
require 'faraday'
require 'net/http'

BASE = 'https://api.example.com'

def fetch_user(id)
  Faraday.get("#{BASE}/api/v1/users/#{id}")
end

def post_event
  Faraday.post(BASE + '/api/v1/events')
end

def legacy
  Net::HTTP.get(URI('https://api.example.com/legacy/ping'))
end
`
	got := endpoints(t, NewRuby(), "client.rb", src)
	has(t, got,
		"GET api.example.com/api/v1/users/{id}",
		"POST api.example.com/api/v1/events",
	)
}

// A Faraday connection built with a url: option supplies the base for its bare
// paths, the same way axios.create does in JavaScript.
func TestRubyFaradayConnectionBinding(t *testing.T) {
	t.Parallel()
	src := `
require 'faraday'
conn = Faraday.new(url: 'https://api.acme.com/v3')
def call(conn)
  conn.get('/widgets')
end
`
	has(t, endpoints(t, NewRuby(), "conn.rb", src), "GET api.acme.com/v3/widgets")
}

// Rails routes use the same verb names as HTTParty with an implicit receiver.
// This is Ruby's version of the express/axios collision, and getting it wrong
// fills the index with the application's own inbound routes.
func TestRubyRailsRoutesAreNotOutboundCalls(t *testing.T) {
	t.Parallel()
	src := `
Rails.application.routes.draw do
  get '/api/v1/users', to: 'users#index'
  post '/api/v1/users', to: 'users#create'
  delete '/api/v1/users/:id', to: 'users#destroy'
end
`
	got := endpoints(t, NewRuby(), "config/routes.rb", src)
	hasNot(t, got,
		"GET self/api/v1/users",
		"POST self/api/v1/users",
		"GET api.example.com/api/v1/users",
	)
}

func TestJavaHttpClientsAndRestTemplate(t *testing.T) {
	t.Parallel()
	src := `
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import org.springframework.web.client.RestTemplate;

public class Client {
    private static final String BASE = "https://api.example.com";

    public void fetch() {
        HttpRequest req = HttpRequest.newBuilder()
            .uri(URI.create(BASE + "/api/v1/things"))
            .build();
    }

    public void viaTemplate(RestTemplate rt) {
        rt.getForObject(BASE + "/api/v1/users", String.class);
        rt.postForEntity("https://api.example.com/api/v1/orders", body, String.class);
    }
}
`
	got := endpoints(t, NewJava(), "Client.java", src)
	has(t, got,
		"GET api.example.com/api/v1/users",
		"POST api.example.com/api/v1/orders",
	)
	// The builder chain sets the method elsewhere, so the URI call itself has
	// no determinable verb. What matters is that the endpoint is found.
	has(t, got, "ANY api.example.com/api/v1/things")
}

func TestJavaApacheAndRetrofit(t *testing.T) {
	t.Parallel()
	src := `
import org.apache.http.client.methods.HttpGet;
import retrofit2.http.GET;
import retrofit2.Retrofit;

public class Mixed {
    void apache() {
        HttpGet g = new HttpGet("https://api.example.com/apache/thing");
    }
}

interface Service {
    @GET("/api/v1/retrofit/users")
    Call<List<User>> listUsers();

    @POST("/api/v1/retrofit/users")
    Call<User> create(@Body User u);
}
`
	got := endpoints(t, NewJava(), "Mixed.java", src)
	has(t, got,
		"GET api.example.com/apache/thing",
		// This interface declares no baseUrl, so the host is genuinely unknown
		// from this file alone and the path stays relative. Retrofit supplies
		// the base at Retrofit.Builder() call sites elsewhere.
		"GET self/api/v1/retrofit/users",
		"POST self/api/v1/retrofit/users",
	)
}

// The sharpest discrimination in Java: @GetMapping("/users") is an OUTBOUND
// call on a Feign interface and an INBOUND route on a Spring controller. The
// syntax is identical; only the surrounding annotation distinguishes them.
func TestJavaFeignIsOutboundSpringControllerIsNot(t *testing.T) {
	t.Parallel()
	feign := `
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.GetMapping;

@FeignClient(name = "billing", url = "https://api.acme.com")
public interface BillingClient {
    @GetMapping("/api/v1/invoices")
    List<Invoice> listInvoices();
}
`
	has(t, endpoints(t, NewJava(), "BillingClient.java", feign),
		"GET api.acme.com/api/v1/invoices")

	controller := `
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class UserController {
    @GetMapping("/api/v1/users")
    public List<User> list() { return users; }

    @PostMapping("/api/v1/users")
    public User create(@RequestBody User u) { return u; }
}
`
	got := endpoints(t, NewJava(), "UserController.java", controller)
	if len(got) != 0 {
		t.Errorf("Spring controller routes read as outbound calls: %v", got)
	}
}

func TestCSharpHttpClient(t *testing.T) {
	t.Parallel()
	src := `
using System.Net.Http;
using System.Net.Http.Json;

public class Client {
    private const string Base = "https://api.example.com";
    private readonly HttpClient _http;

    public async Task Fetch(string id) {
        await _http.GetAsync(Base + "/api/v1/things");
        await _http.PostAsync("https://api.example.com/api/v1/orders", content);
        await _http.GetStringAsync(Base + "/api/v1/raw");
        await _http.GetFromJsonAsync<Thing>($"{Base}/api/v1/things/{id}");
    }
}
`
	got := endpoints(t, NewCSharp(), "Client.cs", src)
	has(t, got,
		"GET api.example.com/api/v1/things",
		"POST api.example.com/api/v1/orders",
		"GET api.example.com/api/v1/raw",
		"GET api.example.com/api/v1/things/{id}",
	)
}

// A BaseAddress supplies the host for every relative path on that client, the
// same role axios.create plays in JavaScript.
func TestCSharpBaseAddressBinding(t *testing.T) {
	t.Parallel()
	src := `
using System.Net.Http;

public class Api {
    private readonly HttpClient client = new HttpClient();

    public Api() {
        client.BaseAddress = new Uri("https://api.acme.com/v2/");
    }

    public async Task Add() {
        await client.PostAsync("/users/add", null);
    }
}
`
	has(t, endpoints(t, NewCSharp(), "Api.cs", src), "POST api.acme.com/v2/users/add")
}

// Refit's [Get("/x")] is outbound; ASP.NET's [HttpGet("/x")] is a route. The
// Refit pattern requires "[" immediately before the verb so it cannot match
// [HttpGet(...)].
func TestCSharpRefitIsOutboundControllerIsNot(t *testing.T) {
	t.Parallel()
	refit := `
using Refit;

public interface IBillingApi {
    [Get("/api/v1/invoices")]
    Task<List<Invoice>> ListInvoices();

    [Post("/api/v1/invoices")]
    Task<Invoice> Create([Body] Invoice i);
}
`
	// No base is registered in this file, so the paths stay relative; the host
	// arrives from AddRefitClient configuration elsewhere.
	has(t, endpoints(t, NewCSharp(), "IBillingApi.cs", refit),
		"GET self/api/v1/invoices", "POST self/api/v1/invoices")

	controller := `
using Microsoft.AspNetCore.Mvc;

[ApiController]
public class UsersController : ControllerBase {
    [HttpGet("/api/v1/users")]
    public IActionResult List() => Ok(users);

    [HttpPost("/api/v1/users")]
    public IActionResult Create(User u) => Ok(u);
}
`
	got := endpoints(t, NewCSharp(), "UsersController.cs", controller)
	if len(got) != 0 {
		t.Errorf("ASP.NET controller routes read as outbound calls: %v", got)
	}
}

func TestCSharpVerbatimAndInterpolatedStrings(t *testing.T) {
	t.Parallel()
	src := `
using System.Net.Http;
public class C {
    public async Task F(HttpClient h, string id) {
        await h.GetAsync(@"https://api.example.com/verbatim/path");
        await h.GetAsync($"https://api.example.com/interp/{id}");
    }
}
`
	has(t, endpoints(t, NewCSharp(), "C.cs", src),
		"GET api.example.com/verbatim/path",
		"GET api.example.com/interp/{id}",
	)
}

// Perl's "=>" is a synonym for a comma. Without treating it as an argument
// separator the whole list collapses into one string and every positional
// signature silently fails to match.
func TestPerlFatCommaAndRequest(t *testing.T) {
	t.Parallel()
	got := endpoints(t, NewPerl(), "lib/Acme/LicenseAPI.pm", `
package Acme::LicenseAPI;
use LWP::UserAgent ();

sub retrieve_license_key {
    my ($self, $id) = @_;
    my $response = $self->request(GET => "$self->{base}/keys/$id");
    return $response;
}

sub create_license_key {
    my ($self) = @_;
    return $self->request(
       POST => "$self->{base}/keys?return-key-state=yes", [
          'Content-Type' => 'application/json',
       ]
    );
}

sub terminate_license_key {
    my ($self, $key) = @_;
    return $self->request(DELETE => "$self->{base}/keys/$key");
}
`)
	// The host is qualified by the declared package, so another class's
	// $self->{base} is a different host rather than the same one.
	has(t, got,
		"GET ${sym:Acme::LicenseAPI.base}/keys/{id}",
		"POST ${sym:Acme::LicenseAPI.base}/keys",
		"DELETE ${sym:Acme::LicenseAPI.base}/keys/{key}",
	)
}

// The two-argument HTTP::Request->new form depends on the same fat comma.
func TestPerlHTTPRequestNewFatComma(t *testing.T) {
	t.Parallel()
	got := endpoints(t, NewPerl(), "lib/Client.pm", `
package Client;
use HTTP::Request ();
my $url = "https://api.example.com/v1/thing";
my $req = HTTP::Request->new(GET => $url);
`)
	has(t, got, "GET api.example.com/v1/thing")
}

// The verb gate is what lets a project-local wrapper class be recognised without
// hard-coding its name -- and what keeps a non-HTTP ->request out of the index.
func TestPerlRequestRequiresAnHTTPVerb(t *testing.T) {
	t.Parallel()
	got := endpoints(t, NewPerl(), "lib/Db.pm", `
package Db;
my $sql = $db->request(SELECT => "users/all");
my $job = $queue->request(ENQUEUE => "jobs/run");
`)
	if len(got) != 0 {
		t.Errorf("got %v, want nothing: SELECT and ENQUEUE are not HTTP verbs", got)
	}
}

func TestPerlLocalWrapperClassIsRecognised(t *testing.T) {
	t.Parallel()
	// No recognisable CPAN client is imported; the HTTP verb is the only
	// evidence, and it is enough.
	got := endpoints(t, NewPerl(), "public_html/tools/get_ka_license.cgi", `
my $client = Acme::LicenseAPI->connect( section => "production" );
my $response = $client->request(GET => $client->{base}."/keys/$keyid");
`)
	has(t, got, "GET ${sym:client.base}/keys/{keyid}")
}

// Perl allows chained declarations. The captured value must skip the inner
// declarations, or it parses as an opaque call and yields a nonsense token.
func TestPerlChainedDeclaration(t *testing.T) {
	t.Parallel()
	got := endpoints(t, NewPerl(), "t.cgi", `
my $base = my $base_in = "https://api.example.com";
my $r = $ua->request(GET => "$base/v1/x");
`)
	has(t, got, "GET api.example.com/v1/x")
}

// "$self->{base}" is a generic Perl idiom. Two classes using it are two
// different services, and collapsing them would attribute one service's
// endpoints to another -- which is exactly what happens in shared-client, where five
// unrelated clients all spell their base URL that way.
func TestPerlSelfBaseIsQualifiedByPackage(t *testing.T) {
	t.Parallel()
	lic := endpoints(t, NewPerl(), "lib/Acme/LicenseAPI.pm", `
package Acme::LicenseAPI;
use LWP::UserAgent ();
my $r = $self->request(GET => "$self->{base}/keys");
`)
	other := endpoints(t, NewPerl(), "lib/Acme/BillingAPI.pm", `
package Acme::BillingAPI;
use LWP::UserAgent ();
my $r = $self->request(GET => "$self->{base}/keys");
`)
	has(t, lic, "GET ${sym:Acme::LicenseAPI.base}/keys")
	has(t, other, "GET ${sym:Acme::BillingAPI.base}/keys")
	if lic[0] == other[0] {
		t.Fatalf("two packages collapsed to the same host: %q", lic[0])
	}
}

// With no package declaration the file name still disambiguates.
func TestSelfQualifierFallsBackToTheFileName(t *testing.T) {
	t.Parallel()
	got := endpoints(t, NewPerl(), "public_html/tools/thing.cgi", `
use LWP::UserAgent ();
my $r = $self->request(GET => "$self->{base}/keys");
`)
	has(t, got, "GET ${sym:thing.base}/keys")
}
