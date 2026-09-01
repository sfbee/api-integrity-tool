#!/usr/bin/env python3
"""A stand-in for the GitHub API, so an upstream change can be demonstrated
offline.

The tool reads an upstream through a handful of read-only endpoints. Serving
those locally means the demo needs no network, no token and no write access to
anyone's repository -- and, more usefully, lets you author the exact upstream
change you want to show instead of waiting for a real one.

Which of two specification revisions is served is decided by the contents of the
state file, so the upstream can be flipped mid-demo without a restart. The
repository's pushed_at moves at the same time, because `check` deliberately
skips an upstream that has not been pushed: without that, flipping the spec
would prove only that the skip gate works.
"""
import argparse
import base64
import json
import os
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs

BEFORE_SHA = "1" * 40
AFTER_SHA = "2" * 40
EPOCH = datetime(2026, 1, 1, tzinfo=timezone.utc)


class Upstream:
    def __init__(self, owner, name, branch, spec_path, before, after, state_file):
        self.owner, self.name, self.branch = owner, name, branch
        self.spec_path, self.state_file = spec_path, state_file
        self.before, self.after = before, after

    @property
    def flipped(self):
        try:
            with open(self.state_file) as fh:
                return fh.read().strip() == "after"
        except FileNotFoundError:
            return False

    @property
    def head_sha(self):
        return AFTER_SHA if self.flipped else BEFORE_SHA

    @property
    def pushed_at(self):
        return EPOCH + (timedelta(days=1) if self.flipped else timedelta())

    def stamp(self):
        return self.pushed_at.strftime("%Y-%m-%dT%H:%M:%SZ")


def make_handler(up):
    prefix = f"/repos/{up.owner}/{up.name}"

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass  # quiet: the demo's own output is the point

        def _send(self, body, code=200):
            raw = json.dumps(body).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            # Generous, so a demo never looks like a throttled run.
            self.send_header("X-RateLimit-Remaining", "4999")
            self.send_header("X-RateLimit-Limit", "5000")
            self.end_headers()
            self.wfile.write(raw)

        def _send_html(self, body, code=200):
            raw = body.encode()
            self.send_response(code)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def _status_page(self):
            rev = "2.0.0 (after the change)" if up.flipped else "1.4.0 (before the change)"
            other = "before" if up.flipped else "after"
            rows = "".join(
                f"<tr><td><a href='{path}'>{path}</a></td><td>{what}</td></tr>"
                for path, what in [
                    (prefix, "repository metadata, including pushed_at"),
                    (f"{prefix}/commits", "commit list"),
                    (f"{prefix}/git/trees/{up.branch}", "file tree"),
                    (f"{prefix}/contents/{up.spec_path}", "the specification at the current head"),
                    (f"{prefix}/compare/{BEFORE_SHA[:7]}...{AFTER_SHA[:7]}", "the diff between revisions"),
                    (f"{prefix}/releases", "releases (always empty here)"),
                ])
            return f"""<!doctype html>
<meta charset=utf-8><title>local upstream stand-in</title>
<style>
 body{{font:14px/1.6 ui-monospace,SFMono-Regular,Menlo,monospace;max-width:52rem;
      margin:3rem auto;padding:0 1.5rem;color:#1a1a1a;background:#fafafa}}
 h1{{font-size:1.1rem}} h2{{font-size:.95rem;margin-top:2rem}}
 table{{border-collapse:collapse;width:100%}}
 td{{padding:.3rem .6rem;border-bottom:1px solid #e5e5e5;vertical-align:top}}
 td:first-child{{white-space:nowrap;width:1%}}
 code,a{{color:#0645ad}} .now{{background:#fff;border:1px solid #ddd;
      border-radius:4px;padding:.8rem 1rem;margin:1rem 0}}
 .hint{{color:#666}}
</style>
<h1>Local upstream stand-in &mdash; not GitHub</h1>
<p>This serves the handful of read-only GitHub API endpoints
   <code>api-integrity-tool</code> reads, so the demo runs with no network, no
   token and no real repository. It is <strong>working correctly</strong>; only
   the paths below are implemented, so anything else returns 404.</p>
<div class=now>
  <strong>Standing in for:</strong> github.com/{up.owner}/{up.name} (branch {up.branch})<br>
  <strong>Currently serving:</strong> API {rev}<br>
  <strong>Head commit:</strong> <code>{up.head_sha[:12]}</code>
  &middot; <strong>pushed_at:</strong> <code>{up.stamp()}</code>
</div>
<p class=hint>Flip the revision without restarting:<br>
   <code>echo {other} &gt; {up.state_file}</code><br>
   Then re-run <code>./06-check.sh</code>. The demo scripts do this for you.</p>
<h2>Implemented endpoints</h2>
<table>{rows}</table>
<h2>What it does not do</h2>
<p class=hint>No authentication, pagination, retries, ETag revalidation or real
   rate limiting. It is a fixture, not a GitHub emulator.</p>
"""

        def do_GET(self):
            u = urlparse(self.path)
            p, q = u.path, parse_qs(u.query)

            # A browser hitting the root should learn what this is, not get a
            # 404 that looks like a broken server.
            if p in ("/", "/index.html"):
                return self._send_html(self._status_page())

            if p == "/healthz":
                return self._send({"ok": True, "revision": "after" if up.flipped else "before"})

            if p == prefix:
                return self._send({
                    "full_name": f"{up.owner}/{up.name}",
                    "html_url": f"https://github.com/{up.owner}/{up.name}",
                    "default_branch": up.branch,
                    "pushed_at": up.stamp(),
                })

            if p == f"{prefix}/commits":
                msg = "Publish API 2.0.0" if up.flipped else "Publish API 1.4.0"
                return self._send([{
                    "sha": up.head_sha,
                    "html_url": f"https://github.com/{up.owner}/{up.name}/commit/{up.head_sha}",
                    "commit": {"message": msg,
                               "author": {"name": "Vendor", "date": up.stamp()}},
                }])

            if p.startswith(f"{prefix}/git/trees/"):
                return self._send({"tree": [{"path": up.spec_path, "type": "blob"}]})

            if p.startswith(f"{prefix}/contents/"):
                if p[len(f"{prefix}/contents/"):] != up.spec_path:
                    return self._send({"message": "Not Found"}, 404)
                # A diff asks for both sides explicitly, so BEFORE_SHA must
                # always serve the old revision. Everything else -- a branch
                # name, the current head -- is asking "what is there now", and
                # must follow the flip. Serving `before` for those made coverage
                # read a stale contract while check read a fresh one.
                ref = q.get("ref", [""])[0]
                if ref == BEFORE_SHA:
                    body = up.before
                else:
                    body = up.after if up.flipped else up.before
                return self._send({
                    "path": up.spec_path, "sha": "blob-" + (ref or "x"),
                    "encoding": "base64", "size": len(body),
                    "content": base64.b64encode(body.encode()).decode(),
                })

            if p.startswith(f"{prefix}/compare/"):
                return self._send({
                    "status": "ahead", "ahead_by": 1, "total_commits": 1,
                    "html_url": f"https://github.com/{up.owner}/{up.name}/compare/{BEFORE_SHA}...{AFTER_SHA}",
                    "base_commit": {"sha": BEFORE_SHA},
                    "commits": [{
                        "sha": AFTER_SHA,
                        "html_url": f"https://github.com/{up.owner}/{up.name}/commit/{AFTER_SHA}",
                        "commit": {"message": "Publish API 2.0.0",
                                   "author": {"name": "Vendor", "date": up.stamp()}},
                    }],
                    "files": [{
                        "filename": up.spec_path, "status": "modified",
                        "sha": "blob-" + AFTER_SHA,
                        "blob_url": f"https://github.com/{up.owner}/{up.name}/blob/{AFTER_SHA}/{up.spec_path}",
                        "changes": 8,
                        "patch": "@@ -1 +1 @@\n-  /v1/balance:\n+  /v1/balances:\n",
                    }],
                })

            if p in (f"{prefix}/releases", f"{prefix}/tags"):
                return self._send([])

            return self._send({
                "message": "Not Found",
                "note": (f"this stand-in only implements a few {prefix}/... paths; "
                         "see http://127.0.0.1:%d/ for the list" % self.server.server_address[1]),
            }, 404)

    return Handler


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8788)
    ap.add_argument("--owner", default="acmepay")
    ap.add_argument("--name", default="api-spec")
    ap.add_argument("--branch", default="main")
    ap.add_argument("--spec-path", default="specs/payments.yml")
    ap.add_argument("--before", required=True)
    ap.add_argument("--after", required=True)
    ap.add_argument("--state", required=True)
    args = ap.parse_args()

    with open(args.before) as fh:
        before = fh.read()
    with open(args.after) as fh:
        after = fh.read()
    if not os.path.exists(args.state):
        with open(args.state, "w") as fh:
            fh.write("before\n")

    up = Upstream(args.owner, args.name, args.branch, args.spec_path,
                  before, after, args.state)
    HTTPServer(("127.0.0.1", args.port), make_handler(up)).serve_forever()


if __name__ == "__main__":
    main()
