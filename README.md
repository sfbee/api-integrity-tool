# api-integrity-tool

Indexes every outbound API call your repository makes, links each API host to
the upstream repository behind it, and tells you when an upstream change is
about to break one of those calls.

The problem it exists to solve: your code calls other people's APIs, nothing
tells you when those APIs change, and you find out in production.

```
$ api-integrity-tool check

==> Checked 4 upstream(s), skipped 2, 11 API call(s)
    GitHub rate limit: 4913/5000 remaining

3 new finding(s): 1 breaking, 1 risky, 1 info

[BREAKING] New required parameter on GET /api/v1/invoices
    openapi.required_param_added  confidence 0.86  acme/billing
    a new required query parameter "tenant" was added
    affects GET /api/v1/invoices  (internal/billing/client.go:31)
```

## Install

Requires Go 1.27 or newer (as declared in `go.mod`). Pure Go: no CGO, and no
dependencies beyond the MCP SDK and `yaml.v3`.

```sh
git clone https://github.com/sfbee/api-integrity-tool
cd api-integrity-tool
./install.sh
```

The installer verifies your Go version, builds with `CGO_ENABLED=0`, **runs the
test suite and refuses to install if it fails**, then installs to
`/usr/local/bin` (falling back to `~/.local/bin`). Interactively it also offers
to register the MCP server with Claude Code and to schedule periodic checks.

```sh
./install.sh --prefix ~/.local/bin --mcp     # explicit
./install.sh --schedule ~/src/myrepo         # launchd job every 6 hours
./install.sh --uninstall                     # remove binary, job and MCP entry
```

Non-interactively (a pipe, or CI) it installs the binary only, rather than
hanging on a prompt.

## The workflow

Four steps, from inside any repository:

```sh
api-integrity-tool scan          # 1. find the outbound API calls
api-integrity-tool link-hosts    # 2. link each API host to its upstream repo
api-integrity-tool check         # 3. look for breaking upstream changes
api-integrity-tool --view-results  # 4. review findings in a browser
```

### 1. Scan

```
$ api-integrity-tool scan
==> Scanned 10 files (1 skipped) in 70ms
    16 outbound calls across 5 hosts
    16 new, 0 removed, 0 moved, 0 unchanged
    5 call sites rejected: local_host=1 route_definition=4
    (re-run with --explain-drops to see each one)
```

```
$ api-integrity-tool list
METHOD  HOST                     PATH                     CONF    LANG        LOCATION
GET     api.stripe.com           /v1/health               high    go          internal/client.go:19
DELETE  api.stripe.com           /v1/users/{id}/profile   medium  go          internal/client.go:27
GET     ${env:BILLING_BASE_URL}  /charge                  medium  go          internal/client.go:33
GET     api.acme.com             /api/v1/invoices         medium  java        java/BillingClient.java:6
GET     api.acme.com             /v4/things/{id}          medium  csharp      cs/Client.cs:6
```

The scanner deliberately refuses to index some call sites, and always says how
many. `--explain-drops` shows each one:

```
    LOCATION                      REASON            EXPRESSION
    internal/client.go:37         local_host        http.Get("http://127.0.0.1:9000/debug")
    java/UserController.java:6    route_definition  @GetMapping("/api/v1/users")
    web/server.js:3               route_definition  app.get('/api/v1/user/add', (req, res) => ...)
```

"Why didn't it find my call?" should always have an answer, so nothing is
dropped silently. Override with `--include-internal`, `--include-tests`,
`--include-suspected-routes` or `--include-path GLOB`.

### 2. Link hosts to upstream repositories

```
$ api-integrity-tool link-hosts
==> Linked 1 host(s) automatically
    api.stripe.com -> https://github.com/stripe/openapi (spec_only)

2 host(s) still need an upstream repository:

  api.acme.com — 3 call(s)
      GET /api/v1/invoices
      suggestion: https://github.com/acme/acme (derived from the hostname)
  ${env:BILLING_BASE_URL} — 1 call(s)
      this host came from a variable; consider a host_mappings entry
```

A curated table of 50 well-known API hosts links itself with no interaction.
For the rest:

```sh
api-integrity-tool link api.acme.com --repo github.com/acme/billing
api-integrity-tool link api.acme.com --repo github.com/acme/monorepo//services/billing --path-prefix /billing/
api-integrity-tool unmonitor api.internal.corp --reason internal
api-integrity-tool upstreams        # show links and decisions
```

**`--role` matters.** Most third-party APIs are closed source but publish an
OpenAPI description: `api.stripe.com` cannot be monitored, but
`stripe/openapi` can. `--role spec_only` says the repository holds only a
specification, so the checker runs the high-signal structural diff and skips
route analysis it would never match.

Declining is first class. `unmonitor` records a reason and the tool stops
asking. A softer "not now" expires after a week, so dismissing a prompt once
does not silence a host permanently.

### 3. Check for breaking changes

```sh
api-integrity-tool check                       # all linked upstreams
api-integrity-tool check --host api.acme.com   # just one
api-integrity-tool check --fail-on breaking    # exit 1 for CI
api-integrity-tool findings -v                 # re-read with evidence
api-integrity-tool ack <id> --note "known"     # stop being told
api-integrity-tool mute <id> --for 720h
```

Needs a GitHub token: `GITHUB_TOKEN`, `GH_TOKEN`, or `gh auth login`. Run
`api-integrity-tool doctor` to see what it found.

**The first check of an upstream records a baseline and reports nothing.** That
is deliberate: emitting a repository's whole history on day one is noise, and
none of it is actionable.

### 4. Review in a browser

```
$ api-integrity-tool --view-results
==> Results dashboard listening on 127.0.0.1:6969
    Open: http://127.0.0.1:6969/login?t=KQ_QGaPwH9iXunGW1dmI7Jxfc…
    This link is valid only while this process runs. Ctrl-C to stop.
```

Findings sorted breaking-first, with the affected call sites, the upstream diff
hunk, and buttons to acknowledge, mute or resolve. Plus endpoint, host and run
views.

It is authenticated, and not because localhost is hostile: any web page you
visit can issue requests to `127.0.0.1:6969`, and this dashboard exposes your
internal hostnames, source paths and upstream diffs. So there is a per-process
capability token, a session cookie, a Host-header allowlist (the
DNS-rebinding defence), CSRF protection on mutations, login throttling and a
strict CSP. Binding anywhere but loopback is refused outright.

## Commands

| Command | Purpose |
|---|---|
| `scan` | Index the outbound API calls in a repository |
| `list` | Query the indexed calls |
| `hosts` | Show API hosts and call counts |
| `link-hosts` | Link everything it can; report what it cannot |
| `link` / `unlink` | Link one host to a repository, or remove it |
| `unmonitor` | Record that a host is deliberately not watched |
| `upstreams` | Show current links and decisions |
| `check` | Look for upstream changes that break your calls |
| `findings` | List what previous checks found |
| `ack` / `mute` | Triage a finding |
| `serve` | Run the dashboard (alias: `--view-results`) |
| `mcp` | Serve the Model Context Protocol over stdio |
| `config init` / `config show` | Manage `.api-integrity.yml` |
| `doctor` | Report configuration, credentials and rate limits |
| `version` | Print the build version |

`api-integrity-tool <command> -h` lists a command's flags.

**Stream convention:** human-readable summaries go to **stderr**; stdout carries
only machine-readable output (`--format json`, `list`, `hosts`). That is what
makes `scan --format json | jq` safe.

## Filtering

Filters apply at query time, so you index once and slice it many ways.

```sh
api-integrity-tool list --host api.stripe.com
api-integrity-tool list --host 'api.*'                 # glob
api-integrity-tool list --endpoint /api/v1/user/add
api-integrity-tool list --regex 'v[12]/users'           # RE2
api-integrity-tool list --method POST --method DELETE
api-integrity-tool list --min-confidence high
api-integrity-tool list --exclude-host api.legacy.example.com
```

Four rules govern how filters combine. The second one surprises people:

1. **OR within a dimension.** `--host a.com --host b.com` matches either.
2. **AND across dimensions.** `--host a.com --endpoint /v1/x` requires both.
3. **An empty dimension is a wildcard.** No `--host` means all hosts.
4. **Exclude always beats include.**

Endpoint matching ignores placeholder naming, so `--endpoint /users/:id` matches
an indexed `/users/{user_id}`.

## Configuration

`api-integrity-tool config init` writes a documented `.api-integrity.yml`.
Commit it: it is the team's shared answer to "which repository is behind this
API host?".

```yaml
version: 1

upstreams:
  api.stripe.com: github.com/stripe/openapi
  api.acme.com:
    - repo: github.com/acme/monorepo//services/billing
      path_prefix: /billing/
      role: implementation
    - repo: github.com/acme/api-specs
      role: spec_only
      priority: 50

unmonitored:
  - host: api.internal.corp
    reason: internal

# The scanner records a host read from an environment variable as
# ${env:NAME} rather than guessing. This is where you tell it the answer.
host_mappings:
  "${env:BILLING_BASE_URL}": ["billing.acme.internal"]

filters:
  endpoints:
    - /api/v1/user/add

github:
  min_remaining: 100
```

Unknown keys are rejected rather than ignored, so a typo fails loudly instead of
silently doing nothing. Command-line filters are **unioned** with the config's,
never replacing them.

## Use from Claude Code

```sh
claude mcp add api-integrity -- api-integrity-tool mcp
```

Tools: `scan_repo`, `list_endpoints`, `list_hosts`, `link_upstream`,
`check_upstreams`, `list_findings`, `update_finding`, `index_stats`. Read-only
tools are annotated as such.

`scan_repo` returns any hosts that need an upstream repository as a
`needs_linking` payload, with an instruction to satisfy them via `link_upstream`.
There is no interactive prompt: MCP protocol 2026-07-28 forbids a server from
eliciting while serving a request, so the structured payload is the contract.

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
weaker — so every call it finds is scored lower and flagged, rather than
presented as equally reliable.

It resolves how the URL was built: package constants, struct fields,
`Sprintf`/f-strings/template literals, `path.Join`, and client base URLs
(`axios.create`, `HttpClient.BaseAddress`, `Faraday.new(url:)`, Feign's `url=`,
HTTParty's `base_uri`). Dynamic segments become named placeholders, so
`/v1/users/{user_id}` aggregates across every call site that hits it.

Two behaviours worth understanding:

**Unresolved hosts keep their identity.** A host from an environment variable is
recorded as `${env:BILLING_URL}`, not discarded and not guessed.
`${env:BILLING_URL}` and `${env:SEARCH_URL}` stay separate, because collapsing
them would merge unrelated vendors.

**Your own routes are not API calls.** In JavaScript, Ruby, Java and C#,
registering a route and making a request are the same syntax —
`app.get('/users', handler)` versus `api.get('/users')`. They are separated by
whether an argument is a function, whether a base-URL binding proves the
receiver is a client, and what the file imports. Java's
`@GetMapping("/invoices")` is outbound on a `@FeignClient` interface and an
inbound route on a `@RestController`.

## How findings are judged

Three severities, because a scale with more gradations invites arguing about the
middle instead of acting.

| Severity | Meaning |
|---|---|
| `breaking` | An existing call will fail |
| `risky` | Something a caller may depend on changed |
| `info` | Worth knowing, not actionable |

Signals, in descending order of how much they are believed:

- **`openapi.*`** — structural specification diff. Compares *parsed documents*,
  not diff text, because GitHub omits patches for large files and a textual diff
  cannot express "this parameter became required".
- **`route.*` / `diff.*`** — route declarations and path literals on removed
  lines. Line-level diff scanning is **capped at RISKY** by design: the same text
  appears in tests, logs and client code, so only structural analysis may claim
  an endpoint is gone.
- **`release.*` / `changelog.*`** — major version bumps and breaking-change
  markers, RISKY only when they also name one of your endpoints.

Confidence is the product of four factors (signal prior × match quality × file
class × scanner confidence) and may only **lower** a severity, never raise it.
Corroboration by a second signal sorts a finding first without changing what it
claims — automatic promotion is how these tools become noisy and get ignored.

Noise control that matters more than any single signal: specification changes
that do not touch an endpoint you call collapse into one informational line, and
a path literal removed in one place but added in another becomes `route_moved` at
info, because renames are the dominant false positive.

## In CI

```sh
api-integrity-tool scan --check              # exit 1 if the committed index is stale
api-integrity-tool check --fail-on breaking  # exit 1 on a breaking finding
```

Commit `.api-integrity/index.json` and the first becomes a review gate: a pull
request that starts calling a new third-party host shows up as a diff.

## What it can't see

Being explicit, because a scanner whose blind spots you know is worth more than
one that quietly misses things:

- **Calls behind your own wrapper.** If your code calls an internal
  `apiFetch(path)` in 300 places, the scanner finds the call inside the wrapper,
  not the 300 endpoints. One-hop inference exists for the same file; a
  `wrappers:` config escape hatch does not yet.
- **Hosts that only exist at runtime** (Helm values, service discovery). These
  appear as `${env:...}`, visible and countable but unresolved. Use
  `host_mappings`.
- **Genuinely dynamic URLs** built through loops, maps or reflection.
- **Cross-file resolution outside Go.** Go resolves package constants across
  files; the other six resolve within a file.
- **`new URL(path, base)` in JavaScript**, whose arguments are the reverse of a
  path join, so it is left unresolved rather than emitted backwards.
- **Upstreams with no public repository.** Record them with
  `unmonitor --reason closed_source`.

`api-integrity-tool hosts --unresolved` lists the triage set.

## Status

Working: scanning and indexing in seven languages; URL resolution and
normalization; confidence scoring; route-definition and localhost exclusion with
`--explain-drops`; query filters; the config file; upstream linking with the
well-known table; the GitHub client with conditional requests and rate-limit
budgeting; the OpenAPI/route/diff/release analyzers; findings with triage;
the MCP server; the `:6969` dashboard; `scan --check` and `check --fail-on` as
CI gates; `install.sh` with scheduling and uninstall.

Not built: a `wrappers:` config escape hatch for cross-module wrappers;
`InputRequests`-based interactive prompting over MCP; GitLab support (repository
URLs parse, but only the GitHub API is implemented).

## Development

```sh
go build ./... && go vet ./... && go test ./...
go test ./test/integration/ -v     # builds the binary and drives it
go test ./internal/scan -update    # regenerate golden files
```

Three invariants the tests enforce, each of which has already caught a real bug:

- **Output is byte-identical across worker counts.** A worker pool is the classic
  source of nondeterministic output, and goldens are worthless without it.
- **No filename may end in a GOOS or GOARCH token.** A file named `lang_js.go`
  carries an implicit `GOOS=js` constraint, so it compiles and vets cleanly while
  being excluded from every build — and `go test` reports "no test files" rather
  than an error. That silently hid a language spec and its whole test file.
- **In `mcp` mode, stdout carries JSON-RPC and nothing else.** A single stray
  line corrupts the stream and the session dies with an unhelpful parse error.

Tests never reach the network: the GitHub client is always pointed at a fake
`httptest` server that speaks the real API, including ETags, `Link` pagination
and secondary rate limits.
