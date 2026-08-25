#!/usr/bin/env python3
"""A minimal stand-in for the GitHub API, so a breaking change can be
demonstrated without touching a real upstream.

The tool talks to GitHub through a handful of read-only endpoints. Serving
those locally means a demo needs no network, no token, no write access to
anyone's repository, and -- most usefully -- lets you author the exact upstream
change you want to show rather than waiting for one to happen.

Point the tool at it with, in .api-integrity.yml:

    github:
      base_url: http://127.0.0.1:8787

Two revisions of the specification are served: the one named in --before, and
the one in --after. Which is current is decided by the contents of the state
file (--state), so you can flip the upstream mid-demo without a restart:

    echo after > /tmp/demo-state

The repository's pushed_at moves when the state flips, because `check` skips an
upstream that has not been pushed -- a demo where nothing appears to have
changed would prove only that the skip logic works.
"""
import argparse
import base64
import json
import os
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs

BEFORE_SHA = "a" * 40
AFTER_SHA = "b" * 40
EPOCH = datetime(2026, 1, 1, tzinfo=timezone.utc)


class Upstream:
    def __init__(self, owner, name, branch, spec_path, before, after, state_file):
        self.owner, self.name, self.branch = owner, name, branch
        self.spec_path = spec_path
        self.before, self.after = before, after
        self.state_file = state_file

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
    def spec(self):
        return self.after if self.flipped else self.before

    @property
    def pushed_at(self):
        # Must move when the upstream moves, or check correctly skips it.
        return EPOCH + (timedelta(days=1) if self.flipped else timedelta())


def make_handler(up: Upstream):
    prefix = f"/repos/{up.owner}/{up.name}"

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass  # quiet; the demo's own output is the point

        def _send(self, body, code=200):
            raw = json.dumps(body).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            # Generous limits: a demo should never look like a throttled run.
            self.send_header("X-RateLimit-Remaining", "4999")
            self.send_header("X-RateLimit-Limit", "5000")
            self.end_headers()
            self.wfile.write(raw)

        def do_GET(self):
            u = urlparse(self.path)
            p, q = u.path, parse_qs(u.query)
            sha = up.head_sha

            if p == prefix:
                return self._send({
                    "full_name": f"{up.owner}/{up.name}",
                    "html_url": f"https://github.com/{up.owner}/{up.name}",
                    "default_branch": up.branch,
                    "pushed_at": up.pushed_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
                })

            if p == f"{prefix}/commits":
                return self._send([{
                    "sha": sha,
                    "html_url": f"https://github.com/{up.owner}/{up.name}/commit/{sha}",
                    "commit": {
                        "message": "Retire the v1 key lookup" if up.flipped else "Initial specification",
                        "author": {"name": "Upstream", "date": up.pushed_at.strftime("%Y-%m-%dT%H:%M:%SZ")},
                    },
                }])

            if p.startswith(f"{prefix}/git/trees/"):
                return self._send({"tree": [{"path": up.spec_path, "type": "blob"}]})

            if p.startswith(f"{prefix}/contents/"):
                path = p[len(f"{prefix}/contents/"):]
                if path != up.spec_path:
                    return self._send({"message": "Not Found"}, 404)
                # The ref decides which revision, so a diff sees both sides.
                body = up.after if q.get("ref", [""])[0] == AFTER_SHA else up.before
                return self._send({
                    "path": path, "sha": "blob-" + q.get("ref", ["x"])[0],
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
                        "commit": {"message": "Retire the v1 key lookup",
                                   "author": {"name": "Upstream",
                                              "date": up.pushed_at.strftime("%Y-%m-%dT%H:%M:%SZ")}},
                    }],
                    "files": [{
                        "filename": up.spec_path, "status": "modified",
                        "sha": "blob-" + AFTER_SHA,
                        "blob_url": f"https://github.com/{up.owner}/{up.name}/blob/{AFTER_SHA}/{up.spec_path}",
                        "changes": 4,
                        "patch": "@@ -1 +1 @@\n-  /keys/{id}:\n+  /v2/keys/{id}:\n",
                    }],
                })

            if p in (f"{prefix}/releases", f"{prefix}/tags"):
                return self._send([])

            return self._send({"message": "Not Found"}, 404)

    return Handler


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8787)
    ap.add_argument("--owner", default="acme")
    ap.add_argument("--name", default="billing-service")
    ap.add_argument("--branch", default="main")
    ap.add_argument("--spec-path", default="openapi/api.yml")
    ap.add_argument("--before", required=True, help="specification file for the current state")
    ap.add_argument("--after", required=True, help="specification file after the change")
    ap.add_argument("--state", default="/tmp/api-integrity-demo-state")
    args = ap.parse_args()

    with open(args.before) as fh:
        before = fh.read()
    with open(args.after) as fh:
        after = fh.read()
    if not os.path.exists(args.state):
        with open(args.state, "w") as fh:
            fh.write("before\n")

    up = Upstream(args.owner, args.name, args.branch, args.spec_path, before, after, args.state)
    srv = HTTPServer(("127.0.0.1", args.port), make_handler(up))
    print(f"fake upstream {args.owner}/{args.name} on http://127.0.0.1:{args.port}")
    print(f"  flip with: echo after > {args.state}")
    srv.serve_forever()


if __name__ == "__main__":
    main()
