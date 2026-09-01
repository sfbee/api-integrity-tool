# Local demo — no GitHub, no token, no network

Watch the tool catch a breaking upstream change, end to end, entirely offline.

Every step is a script. Run them in order, or run `./demo.sh` for all of them.
Nothing outside this directory is touched, and `./99-reset.sh` removes
everything the demo created.

```bash
./demo.sh              # the whole thing, pausing between steps
./demo.sh --no-pause   # straight through
```

## Why there is a fake upstream

The tool reads an upstream repository through a handful of read-only GitHub
endpoints. `bin/fake-upstream.py` serves exactly those on `127.0.0.1`, and the
consumer's config points at it:

```yaml
github:
  base_url: http://127.0.0.1:8788
```

So the demo needs no network, no token and no write access to anyone's
repository — and, more usefully, you author the exact upstream change worth
demonstrating instead of waiting for a real one.

**Open <http://127.0.0.1:8788/> while it runs.** It shows which revision is
currently being served, the head SHA, and every endpoint it implements. Anything
else returns a 404 that says so — the stand-in implements only the paths the tool
asks for, so a 404 on some other path is correct behaviour, not a fault.
`/healthz` returns the same state as JSON.

## The scripts

| | |
|---|---|
| `01-setup.sh` | Create the consumer repo, start the local upstream at API 1.4.0 |
| `02-scan.sh` | Index the consumer's outbound calls |
| `03-link.sh` | Attach the host to the repository behind it |
| `04-baseline.sh` | Record where the upstream is now |
| `05-break.sh` | The vendor publishes a breaking 2.0.0 |
| `06-check.sh` | Detect and grade the change |
| `07-explain.sh` | Why each finding got the severity it did |
| `99-reset.sh` | Stop the upstream, delete everything |

`demo.sh` runs 01–07 in order.

## The cast

**Consumer** — `fixture/app.go`, a Go "storefront" service calling
`https://api.acmepay.io` from six places, deliberately at different evidence
strengths so one change produces the whole severity ladder.

**Vendor** — `fixture/specs/v1.yml` and `v2.yml`, two revisions of the published
contract. Which one is served is decided by a state file, so the upstream flips
mid-demo without a restart.

The 2.0.0 change does four things:

| Change | Consequence |
|---|---|
| `/v1/balance` → `/v1/balances` | **breaking** — `path_removed` on a high-confidence call |
| `POST /v1/charges` gains required `idempotency_key` | **breaking** — `required_param_added` |
| `PUT /v1/customers/{id}` withdrawn | **risky** — `operation_removed` |
| `/v1/refunds` becomes documented | a previously recorded finding is **retracted** |

`GET /v1/charges/{id}` and `GET /v1/customers/{id}` are unchanged: the control.

## What you should see

```
5 new finding(s): 2 breaking, 2 risky, 1 info

[BREAKING] Path removed: /v1/balance
    openapi.path_removed  confidence 0.90  acmepay/api-spec
    affects GET /v1/balance  (app.go:25)

[BREAKING] New required parameter on POST /v1/charges
    openapi.required_param_added  confidence 0.90  acmepay/api-spec
    a new required query parameter "idempotency_key" was added
    affects POST /v1/charges  (app.go:20)

[RISKY]    version_major_bump on the specification          confidence 0.40
[RISKY]    Operation removed: PUT /v1/customers/{customerId} confidence 0.64
[info]     specs/payments.yml changed in 2 other places      confidence 0.90

2 finding(s) at breaking or above
```

Every finding names a line of your code — `app.go:25`, not "the API changed".
The control endpoints appear only in the major-version rollup, which genuinely
does affect everything. Two unrelated edits are one info line rather than two
findings.

Coverage moves in both directions at once:

```
MISSING  GET  /v1/balance   -                   app.go:25
ok       GET  /v1/refunds   specs/payments.yml  app.go:42

1 previously recorded finding(s) no longer apply and were resolved
```

## `scan` is not `check`

The commonest way to conclude the tool is broken:

- **`scan`** indexes the calls your code makes. It never looks at the upstream
  and never reports a change. `0 new, 0 removed, 62 unchanged` means the scan
  worked and nothing in *your* code moved.
- **`check`** compares the upstream against what was recorded last time. This is
  the one that finds breaking changes.
- **`coverage`** asks a different question again — which of your calls any
  published specification actually documents. It is state-based, so it reports
  every run, not only when the upstream moves.

## Two traps worth knowing

**`--fail-on` gates on newly discovered findings, not standing ones.** Re-running
`06-check.sh` exits 0, because the findings are no longer new. A CI job that
clones fresh every time therefore never fails — its first check is always a
baseline. Use `--force` to re-analyse, or gate on state:

```bash
api-integrity-tool findings --format json \
  | jq -e '[.[]|select(.status=="open" and .severity=="breaking")]|length==0'
```

**`check` skips an upstream that has not been pushed.** That is the change-driven
gate working, and it is why `05-break.sh` moves `pushed_at` as well as the spec
content. `Checked 0, skipped 1` is not a failure.

## A real limitation this demo shows

`app.go:49` calls `PUT /v1/customers/{id}` via
`http.NewRequest(http.MethodPut, …)`, and it is indexed as **`ANY`**, not `PUT` —
the method is a constant rather than a string literal, and the detector loses it.
Consequences you can see in the output:

- The withdrawn `PUT` matches on path but not method, so it lands at `0.64`
  risky instead of a clean breaking.
- `coverage` reports `ANY /v1/customers/{id}` as `ok`, because `ANY` matches the
  `get` that still exists. **A withdrawn operation looks covered.**

`http.Get` and `http.Post` carry the method in the function name and are fine.
It is the explicit-request form that loses it. Not yet fixed.

## Overrides

| Variable | Default |
|---|---|
| `AIT` | installed `api-integrity-tool`, else built from this checkout into `.work/` |
| `AIT_DEMO_PORT` | `8788` |
| `AIT_DEMO_WORK` | `.work/` in this directory |
