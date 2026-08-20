# api-integrity-tool

Builds an index of every outbound API call your repository makes, so you can see
what your code depends on — and, eventually, get told when an upstream change is
about to break it.

The problem it exists to solve: your code calls other people's APIs, nothing
tells you when those APIs change, and you find out in production.

> **Status: in development.** Scanning, indexing and querying work today across
> seven languages. Upstream monitoring, the MCP server and the results dashboard
> are not built yet — see [Status](#status) for exactly what does and doesn't
> work, so you know what you're getting.

## Install

Requires Go 1.27 or newer (as declared in `go.mod`). Pure Go: no CGO, and
no third-party dependencies.

```sh
git clone https://github.com/stephen-bee/endpoint-monitor
cd endpoint-monitor
go build -o api-integrity-tool ./cmd/api-integrity-tool
```

Put it somewhere on your `PATH`:

```sh
install -m 0755 api-integrity-tool ~/.local/bin/
```

## Quick start

From inside any repository:

```sh
api-integrity-tool scan
api-integrity-tool list
```

`scan` walks the repo, finds outbound HTTP calls, and writes
`.api-integrity/index.json`. `list` queries what it found.

```
==> Scanned 10 files (1 skipped) in 70ms
    16 outbound calls across 5 hosts
    16 new, 0 removed, 0 moved, 0 unchanged
    5 call sites rejected: local_host=1 route_definition=4
    (re-run with --explain-drops to see each one)
```

```
METHOD  HOST                     PATH                     CONF    LANG        LOCATION
GET     api.stripe.com           /v1/health               high    go          internal/client/client.go:19
DELETE  api.stripe.com           /v1/users/{id}/profile   medium  go          internal/client/client.go:27
GET     ${env:BILLING_BASE_URL}  /charge                  medium  go          internal/client/client.go:33
GET     api.acme.com             /api/v1/invoices         medium  java        java/BillingClient.java:6
GET     api.acme.com             /v4/things/{id}          medium  csharp      cs/Client.cs:6
GET     api.example.com          /api/v1/users/{user_id}  low     python      py/client.py:7
```

Group the same data by upstream host:

```sh
api-integrity-tool hosts
```

```
HOST                     KIND     CALLS  PATHS  METHODS          CONF
${env:BILLING_BASE_URL}  env      1      1      GET              medium
api.acme.com             literal  3      3      GET              medium
api.stripe.com           literal  3      3      DELETE,GET,POST  high
```

## Commands

| Command | What it does |
|---|---|
| `scan` | Index the outbound API calls in a repository |
| `list` | Query the indexed calls |
| `hosts` | Show API hosts, grouped, with call and path counts |
| `version` | Print the build version |

Run `api-integrity-tool <command> -h` for the full flag list.

### Scanning another repository

```sh
api-integrity-tool scan --repo-path ~/src/some-other-repo
```

### Narrowing what gets scanned

Only these flags actually make a scan faster, because they decide which files
are opened at all:

```sh
api-integrity-tool scan --lang go --lang python
api-integrity-tool scan --path-glob 'internal/**'
api-integrity-tool scan --exclude-path 'legacy/**'
```

### Understanding what was rejected

The scanner deliberately refuses to index some call sites. It always tells you
how many and why, and `--explain-drops` shows each one:

```sh
api-integrity-tool scan --explain-drops
```

```
    rejected sites:
    LOCATION                      REASON            EXPRESSION
    internal/client/client.go:37  local_host        http.Get("http://127.0.0.1:9000/debug")
    java/UserController.java:6    route_definition  @GetMapping("/api/v1/users")
    web/server.js:3               route_definition  app.get('/api/v1/user/add', (req, res) => res.send('ok'));
```

This matters more than it sounds. "Why didn't it find my call?" should always
have an answer, so nothing is dropped silently. If you disagree with a
rejection, override it:

```sh
api-integrity-tool scan --include-internal            # keep localhost and private IPs
api-integrity-tool scan --include-tests               # keep calls in test files
api-integrity-tool scan --include-suspected-routes    # keep ambiguous route-shaped sites
api-integrity-tool scan --include-path 'vendor/sdk/**'  # beats every exclusion
```

## Filtering the index

Filters apply at query time, so you index once and slice it many ways.

```sh
api-integrity-tool list --host api.stripe.com
api-integrity-tool list --host 'api.*'                    # glob
api-integrity-tool list --endpoint /api/v1/user/add
api-integrity-tool list --regex 'v[12]/users'              # RE2
api-integrity-tool list --method POST --method DELETE
api-integrity-tool list --lang python
api-integrity-tool list --min-confidence high
api-integrity-tool list --exclude-host api.internal.example.com
```

Four rules govern how filters combine. They're worth knowing, because the
second one surprises people:

1. **OR within a dimension.** `--host a.com --host b.com` matches either.
2. **AND across dimensions.** `--host a.com --endpoint /v1/x` requires both.
3. **An empty dimension is a wildcard.** No `--host` means all hosts.
4. **Exclude always beats include.** If a call matches both `--host x` and
   `--exclude-host x`, it is excluded.

Endpoint matching ignores placeholder naming, so `--endpoint /users/:id` matches
an indexed `/users/{user_id}`. You don't have to know how the tool named the
variable.

## Output formats

```sh
api-integrity-tool list --format json     # full records, for scripting
api-integrity-tool list --format csv      # spreadsheet-friendly
api-integrity-tool scan --format json     # machine-readable scan summary
```

## Using it in CI

`scan --check` exits 1 if the committed index is out of date, without writing
anything:

```sh
api-integrity-tool scan --check
```

Commit `.api-integrity/index.json` and this becomes a review gate: a pull
request that starts calling a new third-party host shows up as a diff in the
index, and CI fails until it's regenerated deliberately. That is the main reason
the index is a committed, human-readable file rather than a cache.

## What it understands

| Language | Detection | Libraries |
|---|---|---|
| Go | Full AST (`go/ast`) | `net/http`, resty, retryablehttp, grequests |
| JavaScript / TypeScript | Line engine | `fetch`, axios (incl. `create`), got, ky, superagent, XHR, jQuery |
| Python | Line engine | requests, httpx, aiohttp, urllib, http.client |
| Java | Line engine | `java.net.http`, OkHttp, Apache HttpClient, RestTemplate, WebClient, Retrofit, Feign |
| C# | Line engine | HttpClient (+ `Http.Json`), HttpRequestMessage, WebRequest, RestSharp, Refit |
| Ruby | Line engine | Net::HTTP, Faraday, HTTParty, RestClient, Excon |
| Perl | Line engine | LWP::UserAgent, HTTP::Tiny, Mojo::UserAgent, REST::Client |

Go gets real AST analysis. The others share a line-oriented engine, which is
weaker — so every call it finds is scored lower and flagged, rather than being
presented as equally reliable. Confidence is visible in every output.

Beyond finding call sites, it resolves how the URL was built: package
constants, struct fields, `Sprintf`/f-strings/template literals, `path.Join`,
and client base URLs (`axios.create`, `HttpClient.BaseAddress`,
`Faraday.new(url:)`, Feign's `url=`, HTTParty's `base_uri`). Dynamic segments
become named placeholders, so `/v1/users/{user_id}` aggregates across every call
site that hits it.

Two behaviours worth understanding:

**Unresolved hosts keep their identity.** A host read from an environment
variable is recorded as `${env:BILLING_URL}`, not discarded and not guessed.
`${env:BILLING_URL}` and `${env:SEARCH_URL}` stay separate hosts, because
collapsing them into one anonymous bucket would merge unrelated vendors.

**Your own routes are not API calls.** In JavaScript, Ruby, Java and C#,
registering a route and making a request are the same syntax —
`app.get('/users', handler)` versus `api.get('/users')`. The scanner separates
them by whether an argument is a function, whether a base-URL binding proves the
receiver is a client, and what the file imports. Java's
`@GetMapping("/invoices")` is read as outbound on a `@FeignClient` interface and
as an inbound route on a `@RestController`.

## What it can't see

Being explicit about this, because a scanner that quietly misses things is worse
than one whose limits you know:

- **Calls behind your own wrapper.** If your code calls an internal
  `apiFetch(path)` in 300 places, the scanner finds the one call inside the
  wrapper, not the 300 endpoints. One-hop wrapper inference is planned; a
  `wrappers:` config escape hatch is not built yet.
- **Hosts that only exist at runtime**, from Helm values, service discovery or
  Kubernetes config. These show up as `${env:...}` or `${cfg:...}` — visible and
  countable, but not resolved to a hostname.
- **Genuinely dynamic URLs** assembled through loops, maps or reflection.
- **Cross-file resolution outside Go.** Go resolves package-level constants
  across files. The other six languages resolve within a file.
- **`new URL(path, base)` in JavaScript**, whose arguments are the reverse of a
  path join, so it is left unresolved rather than emitted backwards.

Use `hosts --unresolved` to see the triage list:

```sh
api-integrity-tool hosts --unresolved
```

## Status

Working today:

- Scanning and indexing across all seven languages
- URL resolution, placeholder normalization, confidence scoring
- Route-definition and localhost exclusion, with `--explain-drops`
- Query filters, `list`/`hosts`, table/JSON/CSV output
- Index merge that tracks when a call first and last appeared
- `scan --check` as a CI drift gate

Not built yet:

- **Upstream repo linking** — mapping `api.stripe.com` to the GitHub repo behind it
- **Breaking-change monitoring** — watching those repos for changes that break your calls
- **MCP server** — so an agent can drive all of this
- **Results dashboard** on `:6969` with `--view-results`
- **Config file** (`.api-integrity.yml`) — including endpoint lists and `host_mappings`
- **Integration test suite** and `install.sh`

Anything in that second list is not implemented, however plausible it may look
in the plan.

## Development

```sh
go build ./...
go vet ./...
go test ./...
```

Tests are golden-file based where output shape matters. Regenerate after an
intentional behaviour change, and read the diff:

```sh
go test ./internal/scan -update
```

Two invariants the tests enforce, both of which have already caught real bugs:

- **Output is byte-identical across worker counts.** A worker pool is the
  classic source of nondeterministic output, and goldens are worthless without
  this.
- **No filename may end in a GOOS or GOARCH token.** A file named `lang_js.go`
  carries an implicit `GOOS=js` build constraint, so it compiles and vets
  cleanly while being excluded from every build — and `go test` reports "no test
  files" rather than an error. That silently hid a language spec and its whole
  test file here once.
