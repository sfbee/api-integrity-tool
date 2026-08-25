# Worked example: monitoring a dependency you do not control

An end-to-end walkthrough of pointing this tool at a real upstream: indexing the
endpoints your code calls, watching the upstream repository for changes that
would break them, and reporting the calls no published specification covers.

Names here are placeholders — upstream `acme/billing-service` serving
`api.acme.com`, your application `myapp`, and a shared client library
`shared-client`. Output is illustrative; the numbers you see will be your own.

The observations in [§7](#7-reading-the-results) and
[§11](#11-known-limits) are not hypothetical. They are the things that actually
went wrong when this was first run against a live private upstream, which is why
they are worth reading before you trust a green result.

---

## 1. Prerequisites

| Need | Why |
|---|---|
| Go 1.22+ | to build the tool |
| `gh` authenticated with read access to the upstream | the monitor reads it through the GitHub API |
| A clone of the repository that depends on the upstream | the dependent |
| A clone of whatever *builds the requests* | usually not the same repo — see [§3](#3-clone-the-repository-that-builds-the-request) |

```bash
gh auth status                                  # needs 'repo' scope for a private upstream
export GITHUB_TOKEN="$(gh auth token --user <account>)"
```

**Name the account.** Bare `gh auth token` returns whichever account is
*currently active*. If you use `gh` with more than one account, switching hands
the tool a credential that may have no access to the upstream at all — and the
failure is quiet. See [§11](#11-known-limits).

The tool never writes a token to disk; it reads `GITHUB_TOKEN` or `GH_TOKEN`
from the environment at run time.

---

## 2. Install

```bash
./install.sh
```

Builds a single static binary and installs it to
`~/.local/bin/api-integrity-tool`. Then confirm the environment:

```bash
api-integrity-tool doctor --repo-path /path/to/myapp
```

`doctor` reports whether a token was found, whether the path is a git checkout,
and which language detectors are registered.

---

## 3. Clone the repository that builds the request

This is the step that decides whether the whole exercise is worth anything.

Scanning the application alone can find almost nothing, and that is not a tool
failure — it is how the code is arranged:

```perl
# myapp calls named methods, not URLs:
$client->get_record($id);

# shared-client is where the request is actually built:
$self->{ua}->request(GET => $self->{base} . "/records/$id");
```

If a dependency is wrapped in a client library, the repository that *wants the
data* and the repository that *constructs the URL* are different repositories.
Index both, or you will monitor a fraction of your real surface and believe you
have covered it.

```bash
gh repo clone acme/shared-client ~/src/shared-client
```

---

## 4. Configure each repository

Two indexes, one upstream. The application records the dependency; the client
library records the endpoints.

`~/src/shared-client/.api-integrity.yml`:

```yaml
version: 1

upstreams:
  api.acme.com:
    - repo: github.com/acme/billing-service
      ref: main
      role: implementation

# The base URL is read from a config file at runtime, so no scan can resolve it.
# These are the symbols that stand for it. They are qualified by package on
# purpose: several clients in this repository spell their base URL
# $self->{base}, and mapping the bare symbol would attribute their endpoints to
# whichever one you happened to name.
host_mappings:
  "${sym:Acme::BillingAPI.base}": ["api.acme.com"]
```

### Why `host_mappings` is not optional

When a base URL is a runtime value — an environment variable, an INI key, a
constructor argument — static analysis cannot see it, so the scanner records the
*symbol* rather than inventing a hostname. The mapping is where you assert what
that symbol really is. It is a hand-maintained claim: if someone adds a new
config section, the mapping needs updating and the tool cannot tell you it went
stale.

Package qualification matters more than it looks. Five clients in one library
sharing `$self->{base}` will collapse into one symbol, and a single mapping then
files four unrelated services under the fifth.

---

## 5. Keep the scan output out of git

`scan` writes its index to `.api-integrity/` **inside the repository working
tree**. It does not touch git history, and it does not modify any tracked file —
the directory simply appears as untracked:

```
$ api-integrity-tool scan --repo-path .
$ git status --porcelain
?? .api-integrity/
```

Two reasons that matters in a shared repository. It makes `git status` noisy for
whatever else you are working on, and a routine `git add -A` will happily stage
it:

```
$ git add -A && git status --porcelain
A  .api-integrity/index.json
```

That is the only route by which monitoring reaches history — you putting it
there. Closing it takes one line per repository. Use `.git/info/exclude`, which
is local and untracked, rather than `.gitignore`, which is a committed file and
so is itself a change to the shared repository:

```bash
for r in ~/src/myapp ~/src/shared-client; do
  printf '.api-integrity/\n.api-integrity.yml\n' >> "$r/.git/info/exclude"
done

# verify: git no longer sees it, even with everything staged
git -C ~/src/myapp        status --porcelain | grep api-integrity   # expect nothing
git -C ~/src/shared-client status --porcelain | grep api-integrity  # expect nothing
```

If you would rather the index *were* committed — it is a useful artefact to
review in a pull request, and the tool is designed for that — skip this step.
The exclusion is for repositories where you want no footprint at all.

---

## 6. Index, link, check

```bash
export GITHUB_TOKEN="$(gh auth token --user <account>)"

for r in ~/src/myapp ~/src/shared-client; do
  api-integrity-tool scan     --repo-path "$r"
  api-integrity-tool link     --repo-path "$r" api.acme.com \
      --repo github.com/acme/billing-service --ref main
  api-integrity-tool check    --repo-path "$r"
  api-integrity-tool coverage --repo-path "$r"
done
```

- `scan` builds the endpoint index from source.
- `link` binds a host to an upstream repository (the `upstreams:` block does the
  same; either is enough).
- `check` diffs the upstream since the last recorded commit and reports changes
  that would break an indexed call.
- `coverage` compares every indexed endpoint against the upstream's OpenAPI
  specifications.

`check` and `coverage` answer different questions and neither replaces the other.
`check` is **change-driven**: it skips an upstream whose `pushed_at` has not
moved, so on a quiet day it correctly reports nothing. `coverage` is
**state-driven**: it re-evaluates the current contract every run, and therefore
deliberately runs outside that skip gate. If it did not, an undocumented
endpoint would only ever be reported on days the upstream happened to be pushed.

---

## 7. Reading the results

```
==> api.acme.com (https://github.com/acme/billing-service@main)
    4 specification(s): openapi/partner-v3.yml, openapi/portal-v1.yml, ...
    12 endpoint(s) called, 5 undocumented
    STATUS   METHOD  PATH                         DOCUMENTED BY              CALL SITE
    MISSING  POST    /                            -                          lib/Acme/BillingAPI.pm:113
    MISSING  GET     /records/{id}/history        -                          lib/Acme/BillingAPI.pm:189
    MISSING  GET     /records/{key}/usage         -                          lib/Acme/BillingAPI.pm:241
    ok       GET     /records                     openapi/portal-v1.yml      lib/Acme/BillingAPI.pm:77
    ok       POST    /records                     openapi/partner-v3.yml     lib/Acme/BillingAPI.pm:95
    ok       GET     /records/{id}                openapi/partner-v3.yml     lib/Acme/BillingAPI.pm:196
```

Path templates are compared after normalisation, so a caller's `/records/{id}`
matches a specification's `/records/{recordNumberOrExternalRef}` — parameter
naming never causes a false MISSING. The specification's `servers:` base path is
stripped before comparison for the same reason.

### What `spec.undocumented` means

Recorded at **info** severity. It is not a defect in your code. It means you
depend on behaviour no specification promises, so the upstream can change it
without breaking any documented contract and without tripping any of the signals
`check` watches.

The category worth your attention is **implemented but undocumented**: the
endpoint demonstrably works — you can find the handler in the upstream — yet no
specification declares it. It works today, so nobody notices it carries no
promise. Two callers reaching the same endpoint with different parameter
spellings is another useful smell.

A `POST /` on an RPC-style entry point is expected to be absent from an OpenAPI
document and is usually not interesting.

---

## 8. Viewing the results

```bash
api-integrity-tool --view-results --repo-path ~/src/shared-client
```

Prints a URL containing a single-use capability token and opens the dashboard on
:6969. The token is exchanged for an `HttpOnly` session cookie via a 303
redirect, so the secret does not linger in the URL bar or in browser history.

Verified behaviour:

| Request | Response |
|---|---|
| `GET /api/findings` with no session | `401` |
| `GET /healthz` | `200` |
| Any request with an unexpected `Host` header | `421` (DNS-rebinding defence) |
| `GET /login?t=<token>` | `303` to `/`, sets `aitk_session` (HttpOnly) + `aitk_csrf` (readable, double-submit CSRF) |

The dashboard serves one repository's state at a time. Use `--port 6970` for a
second, or view them in turn.

---

## 9. Scheduling

`install.sh` schedules one repository per launchd label, which is enough for a
single checkout. When a dependency spans two — an application plus its client
library — one label per repository would have each overwrite the other. Use
`scripts/scheduled-check.sh`, which takes a list:

```bash
cp scripts/scheduled-check.sh ~/.local/bin/scheduled-check
chmod +x ~/.local/bin/scheduled-check
```

Keep the machine-specific values in a small shim so no internal name is
committed:

```bash
#!/bin/bash
export AIT_REPOS="$HOME/src/myapp $HOME/src/shared-client"
export AIT_ACCOUNT="work-account"          # pins the token; see §11
export AIT_UPSTREAM="acme/billing-service" # verified before any check runs
exec "$HOME/src/api-integrity-tool/scripts/scheduled-check.sh" "$@"
```

Then a launchd plist with `StartInterval` and that shim as `ProgramArguments`:

```bash
launchctl bootstrap "gui/$(id -u)" ~/Library/LaunchAgents/<label>.plist
launchctl kickstart -p "gui/$(id -u)/<label>"    # run once now
```

The script re-indexes before checking, so a newly added call is caught on the
same pass.

---

## 10. Reproducing a real change detection

A quiet check proves nothing. To watch the monitor catch an actual change, roll
the recorded baseline back behind a commit that edited a specification and
re-check:

```bash
cd ~/src/shared-client
python3 - <<'PY'
import json, pathlib
p = pathlib.Path(".api-integrity/state.json")
s = json.loads(p.read_text())
for c in s["checks"].values():
    c["last_head_sha"] = "<a commit before the change>"
p.write_text(json.dumps(s, indent=1))
PY
api-integrity-tool check --repo-path . --force
```

Restore afterwards with a normal `check`, or set `last_head_sha` back to the
current head.

### Two false positives this exercise exposed

Running against real history rather than fixtures is what found these. Both are
fixed, with regression tests:

1. **`openapi.path_removed` on an endpoint that still existed.** The differ
   compared raw path strings, so renaming a path parameter looked like one path
   disappearing and an unrelated one appearing. Templates are now normalised
   before diffing and the rename is reported as `openapi.path_param_renamed`.
2. **`openapi.required_param_added` — a *breaking* signal — on that same
   rename.** Once operations were matched through the rename, the old and new
   parameter names looked like a removal plus a new required addition.
   Path-parameter add/remove is now skipped when two operations were matched
   *through* a rename.

A companion test asserts a genuine path removal is still breaking, so neither
fix can mask real breakage.

---

## 11. Known limits

- **A wrong-account token is the failure mode to watch for.** Found the hard
  way: switching the active `gh` account made `gh auth token` return a
  credential with no access to the upstream. Every specification fetch 404'd and
  coverage reported *all* endpoints as undocumented — false findings written
  straight into monitoring state. Note the shape of it: being unable to read the
  contract looked exactly like the contract not existing. Two fixes followed —
  coverage now reports `coverage undetermined` and emits nothing when it cannot
  fetch a specification, and findings it no longer produces are retracted rather
  than left open forever. `scripts/scheduled-check.sh` pins `--user` and refuses
  to run when the token cannot read the upstream.
- **Use `--record=false` for ad-hoc checks.** `coverage` records findings by
  default, so a casual smoke test writes to real monitoring state.
- **Inbound routes are not indexed.** If the upstream also calls *you*, this
  tool covers only your outbound direction. Route tables expressed as a
  data-driven DSL — a dispatch table rather than a call expression — cannot be
  read by a positional signature at all; that needs a bespoke extractor and a
  notion of endpoint direction in the index model. Neither exists yet, so
  compare that direction by hand.
- **`host_mappings` is a hand-maintained assertion** ([§4](#4-configure-each-repository)).
- **Regex-based detectors score low, by design and to a fault.** For every
  language except Go, detection is regex-based (−20 confidence) and a symbolic
  host costs a further −15. That honesty is correct in principle, but it means a
  *genuine* breaking change on such a call is demoted as readily as a cosmetic
  one. Worth revisiting whether a user-declared `host_mappings` entry should
  count as resolving the symbol.
- **No PHP detector.**
