# The same demo, one command at a time

`README.md` runs this as scripts. This is every command those scripts issue, to
copy and paste yourself — useful for demonstrating to someone, or for adapting
the flow to a real repository.

All output below is a transcript of running exactly these commands.

**Two shells.** The upstream stand-in runs in the foreground in one, everything
else happens in the other.

---

## Setup

```bash
DEMO=~/personal-projects/endpoint-monitor/demos/local-no-github
WORK=$DEMO/.work
mkdir -p "$WORK"
```

### The consumer repository

```bash
mkdir -p "$WORK/storefront"
cp "$DEMO/fixture/app.go" "$DEMO/fixture/go.mod" "$WORK/storefront/"
cd "$WORK/storefront"

git init -q .
git config user.email demo@localhost
git config user.name Demo

cat > .api-integrity.yml <<'EOF'
version: 1

github:
  # Point at the local stand-in instead of api.github.com.
  base_url: http://127.0.0.1:8788
EOF

# A scan writes an untracked .api-integrity/ into the working tree. Excluding it
# keeps `git status` honest and stops a stray `git add -A` committing it.
printf '.api-integrity/\n' >> .git/info/exclude

git add -A
git commit -qm "Storefront service calling the AcmePay API"
```

### The upstream stand-in — second shell

```bash
DEMO=~/personal-projects/endpoint-monitor/demos/local-no-github
echo before > "$DEMO/.work/upstream-state"

python3 "$DEMO/bin/fake-upstream.py" --port 8788 \
  --owner acmepay --name api-spec --spec-path specs/payments.yml \
  --before "$DEMO/fixture/specs/v1.yml" \
  --after  "$DEMO/fixture/specs/v2.yml" \
  --state  "$DEMO/.work/upstream-state"
```

Confirm, and see what it is serving:

```bash
curl -s http://127.0.0.1:8788/healthz          # {"ok": true, "revision": "before"}
open http://127.0.0.1:8788/                    # live status page
```

### The token

```bash
export GITHUB_TOKEN=local-demo-no-auth
```

Nothing authenticates against the stand-in, so the value is irrelevant — but the
tool requires the variable to be set.

If `api-integrity-tool` is not on your `PATH`:

```bash
cd ~/personal-projects/endpoint-monitor && go build -o /tmp/ait ./cmd/api-integrity-tool
alias api-integrity-tool=/tmp/ait
```

---

## Step 1 — index the calls

```bash
api-integrity-tool scan
```
```
==> Scanned 1 files (3 skipped) in 78ms
    6 outbound calls across 1 hosts
    6 new, 0 removed, 0 moved, 0 unchanged
    unresolved symbols blocking full resolution: arg:id
```

```bash
api-integrity-tool list
```
```
METHOD  HOST            PATH                CONF    LANG  LOCATION
POST    api.acmepay.io  /v1/charges         high    go    app.go:20
GET     api.acmepay.io  /v1/balance         high    go    app.go:25
GET     api.acmepay.io  /v1/charges/{id}    medium  go    app.go:30
GET     api.acmepay.io  /v1/customers/{id}  medium  go    app.go:36
GET     api.acmepay.io  /v1/refunds         high    go    app.go:42
ANY     api.acmepay.io  /v1/customers/{id}  medium  go    app.go:49
```

Unparameterised paths score `high`, templated ones `medium`. That difference
decides severity in step 4. `app.go:49` shows as `ANY` rather than `PUT` — a real
detector limitation, see the README.

**`scan` never reports an upstream change.** It indexes your calls and stops
there. `0 new, 0 removed, N unchanged` on a second run means the scan worked and
nothing in *your* code moved.

Useful variants:

```bash
api-integrity-tool list --format json
api-integrity-tool list --method POST
api-integrity-tool list --min-confidence high
api-integrity-tool scan --explain-drops        # why a call site was rejected
```

---

## Step 2 — link the host to a repository

A scan finds hosts. Which repository is behind one is a judgement only you can
make.

```bash
api-integrity-tool hosts
```
```
HOST            KIND     CALLS  PATHS  METHODS       CONF
api.acmepay.io  literal  6      5      ANY,GET,POST  high
```

```bash
api-integrity-tool link-hosts
```
```
1 host(s) still need an upstream repository:

  api.acmepay.io — 6 call(s)
      POST /v1/charges
      GET /v1/balance
      GET /v1/refunds
      GET /v1/charges/{id}
      GET /v1/customers/{id}
      suggestion: https://github.com/acmepay/acmepay (derived from the hostname)

Link one with:
  api-integrity-tool link <host> --repo <url>
Or record a deliberate decision not to:
  api-integrity-tool unmonitor <host> --reason internal
```

The suggestion is guessed from the hostname and is wrong here, which is the
normal case — a vendor's API rarely lives at a repository named after its domain.

```bash
api-integrity-tool link api.acmepay.io \
  --repo github.com/acmepay/api-spec \
  --ref main \
  --role spec_only \
  --note "vendor publishes the contract here"
```
```
linked api.acmepay.io -> https://github.com/acmepay/api-spec@main (spec_only)
```

`--role spec_only` says this repository publishes a contract but is not the
running implementation, so a specification diff is weighted heavily and no route
handlers are looked for. `implementation` is the default; `gateway` sits in front
of one.

```bash
api-integrity-tool upstreams
```
```
HOST            REPOSITORY                                ROLE       PREFIX  SOURCE
api.acmepay.io  https://github.com/acmepay/api-spec@main  spec_only  -       cli
```

`SOURCE: cli` means the link lives in local state. Declaring it under
`upstreams:` in `.api-integrity.yml` instead shows `config` — use that when the
decision should be shared with the team through version control.

Interactive alternative, which walks every unlinked host:

```bash
api-integrity-tool link-hosts --interactive
```

---

## Step 3 — record a baseline

```bash
api-integrity-tool check
```
```
(a first check records the current state and reports nothing)
No new findings.
```

Correct — there is nothing to compare against yet.

```bash
api-integrity-tool coverage
```
```
==> api.acmepay.io (https://github.com/acmepay/api-spec@main)
    1 specification(s): specs/payments.yml
    6 endpoint(s) called, 1 undocumented
    STATUS   METHOD  PATH                DOCUMENTED BY       CALL SITE
    MISSING  GET     /v1/refunds         -                   app.go:42
    ok       GET     /v1/balance         specs/payments.yml  app.go:25
    ok       POST    /v1/charges         specs/payments.yml  app.go:20
    ok       GET     /v1/charges/{id}    specs/payments.yml  app.go:30
    ok       ANY     /v1/customers/{id}  specs/payments.yml  app.go:49
    ok       GET     /v1/customers/{id}  specs/payments.yml  app.go:36
```

`coverage` has something to say immediately, because it is state-based rather
than change-based: `/v1/refunds` works today but no specification promises it
will keep working.

Add `--record=false` for a look that does not write findings to state.

---

## Step 4 — break the API

```bash
echo after > "$DEMO/.work/upstream-state"
curl -s http://127.0.0.1:8788/healthz          # {"ok": true, "revision": "after"}
```

The stand-in now serves 2.0.0, which changes four things:

| Change | Consequence |
|---|---|
| `/v1/balance` → `/v1/balances` | breaking `path_removed` |
| `POST /v1/charges` gains required `idempotency_key` | breaking `required_param_added` |
| `PUT /v1/customers/{id}` withdrawn | risky `operation_removed` |
| `/v1/refunds` becomes documented | a finding is retracted |

`pushed_at` moves at the same time. Without that, `check` would skip the upstream
as unchanged — and the demo would prove only that the skip gate works.

---

## Step 5 — detect it

```bash
api-integrity-tool check --fail-on breaking
echo "exit=$?"
```
```
==> Checked 1 upstream(s), skipped 0, 5 API call(s)

5 new finding(s): 2 breaking, 2 risky, 1 info

[BREAKING] Path removed: /v1/balance
    openapi.path_removed  confidence 0.90  acmepay/api-spec
    the path no longer exists in the specification
    affects GET /v1/balance  (app.go:25)

[BREAKING] New required parameter on POST /v1/charges
    openapi.required_param_added  confidence 0.90  acmepay/api-spec
    a new required query parameter "idempotency_key" was added
    affects POST /v1/charges  (app.go:20)

[RISKY]    version_major_bump on the specification
    openapi.version_major_bump  confidence 0.40  acmepay/api-spec
    affects all six endpoints

[RISKY]    Operation removed: PUT /v1/customers/{customerId}
    openapi.operation_removed  confidence 0.64  acmepay/api-spec
    affects ANY /v1/customers/{id}  (app.go:49)

[info]     specs/payments.yml changed in 2 other places
    openapi.unrelated_rollup  confidence 0.90  acmepay/api-spec
    2 specification changes did not affect any of the 6 endpoints this repository calls.

2 finding(s) at breaking or above
exit=1
```

Every finding names a line of your code. The two control endpoints appear only in
the major-version rollup, which genuinely does affect everything, and two
unrelated edits are one info line rather than two findings.

```bash
api-integrity-tool coverage
```
```
    MISSING  GET  /v1/balance   -                   app.go:25
    ok       GET  /v1/refunds   specs/payments.yml  app.go:42

1 undocumented endpoint(s) recorded as findings
1 previously recorded finding(s) no longer apply and were resolved
```

Both directions at once: `/v1/refunds` became documented so its finding was
retracted, `/v1/balance` was renamed away so it is now undocumented.

---

## Step 6 — inspect

```bash
api-integrity-tool findings                       # all of them, with evidence
api-integrity-tool findings --format json | jq .
api-integrity-tool check --force -v               # re-analyse, verbose evidence
api-integrity-tool ack <fingerprint> --note "migrating next sprint"
api-integrity-tool mute <fingerprint> --for 720h   # a duration, not a date
```

Dashboard on :6969, single-use token exchanged for an HttpOnly cookie:

```bash
api-integrity-tool --view-results
```

---

## Re-running, and the `--fail-on` trap

`--fail-on` gates on findings **this run discovered**, not on findings standing
in state. So:

```bash
api-integrity-tool check --fail-on breaking   # exit 1  (first time)
api-integrity-tool check --fail-on breaking   # exit 0  (nothing new)
api-integrity-tool check --force --fail-on breaking   # exit 0 — still nothing new
```

**`--force` is not enough.** It re-analyses the window, but the findings already
exist, so they are updated rather than discovered and the gate stays quiet. Only
rolling the recorded baseline back makes them new again:

```bash
python3 - <<'PY'
import json, pathlib
p = pathlib.Path(".api-integrity/state.json"); s = json.loads(p.read_text())
s["findings"] = []
for c in s["checks"].values():
    c["last_head_sha"] = "1" * 40      # the stand-in's "before" SHA
p.write_text(json.dumps(s, indent=1))
PY
api-integrity-tool check --force --fail-on breaking   # exit 1
```

The practical consequence for CI: **a job that clones fresh every time never
fails**, because its first check is always a baseline. To gate on standing state
instead, ask the findings directly:

```bash
api-integrity-tool findings --format json \
  | jq -e '[.[]|select(.status=="open" and .severity=="breaking")]|length==0'
# exit 1 while any open breaking finding exists
```

---

## Clean up

Second shell: `Ctrl-C`. Then:

```bash
rm -rf ~/personal-projects/endpoint-monitor/demos/local-no-github/.work
```

Or just `./99-reset.sh`.
