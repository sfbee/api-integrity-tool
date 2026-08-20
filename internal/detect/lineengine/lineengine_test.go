package lineengine

import (
	"context"
	"strings"
	"testing"

	"github.com/stephen-bee/endpoint-monitor/internal/detect"
	"github.com/stephen-bee/endpoint-monitor/internal/normalize"
	"github.com/stephen-bee/endpoint-monitor/internal/resolve"
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
