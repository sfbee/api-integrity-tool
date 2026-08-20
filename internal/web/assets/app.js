// Dashboard front end. Deliberately dependency-free and served from the binary,
// so the strict Content-Security-Policy holds and there is no supply chain.
(function () {
  "use strict";

  var state = { view: "findings", summary: null, error: null };

  function csrf() {
    var m = document.cookie.match(/(?:^|;\s*)aitk_csrf=([^;]+)/);
    return m ? decodeURIComponent(m[1]) : "";
  }

  function get(path) {
    return fetch(path, { credentials: "same-origin" }).then(function (r) {
      if (r.status === 401) { window.location = "/login"; return null; }
      if (!r.ok) throw new Error(path + " returned " + r.status);
      return r.json();
    });
  }

  function post(path, body) {
    return fetch(path, {
      method: "POST",
      credentials: "same-origin",
      headers: { "Content-Type": "application/json", "X-CSRF-Token": csrf() },
      body: JSON.stringify(body || {}),
    }).then(function (r) {
      if (!r.ok) throw new Error(path + " returned " + r.status);
      return r.json();
    });
  }

  function el(tag, attrs, kids) {
    var n = document.createElement(tag);
    Object.keys(attrs || {}).forEach(function (k) {
      if (k === "class") n.className = attrs[k];
      else if (k === "text") n.textContent = attrs[k];
      else n.setAttribute(k, attrs[k]);
    });
    (kids || []).forEach(function (c) { if (c) n.appendChild(c); });
    return n;
  }

  function tile(kind, n, label) {
    return el("div", { class: "tile " + kind }, [
      el("div", { class: "n", text: String(n) }),
      el("div", { class: "k", text: label }),
    ]);
  }

  function renderTiles(s) {
    var t = el("div", { class: "tiles" }, [
      tile("breaking", s.counts.breaking, "breaking"),
      tile("risky", s.counts.risky, "risky"),
      tile("info", s.counts.info, "info"),
      tile("", s.endpoint_count, "endpoints"),
      tile("", s.host_count, "hosts"),
      tile("", s.unlinked_hosts, "unlinked"),
    ]);
    return t;
  }

  // Diff hunks are the one place upstream text is rendered, and it is inserted
  // as text nodes only: never as HTML.
  function hunk(text) {
    var pre = el("pre");
    text.split("\n").forEach(function (line) {
      var cls = line.charAt(0) === "+" ? "add" : line.charAt(0) === "-" ? "del" : "";
      var span = el("span", cls ? { class: cls } : {});
      span.textContent = line + "\n";
      pre.appendChild(span);
    });
    return pre;
  }

  function findingCard(f) {
    var kids = [
      el("h3", { text: f.title }),
      el("div", { class: "row" }, [
        el("span", { class: "sev " + f.severity, text: f.severity }),
        el("span", { class: "mono", text: f.signal }),
        el("span", { class: "mono", text: "confidence " + f.confidence.toFixed(2) }),
        el("span", { class: "mono", text: f.repo }),
      ]),
    ];
    if (f.detail) kids.push(el("p", { class: "detail", text: f.detail }));
    if (f.endpoints && f.endpoints.length) {
      var ul = el("ul");
      f.endpoints.forEach(function (e) {
        ul.appendChild(el("li", { class: "mono", text: e.method + " " + e.path + "  " + (e.call_site || "") }));
      });
      kids.push(el("div", {}, [el("div", { class: "k", text: "affected calls" }), ul]));
    }
    if (f.suggestion) kids.push(el("p", { class: "detail", text: "Suggestion: " + f.suggestion }));
    (f.evidence || []).forEach(function (ev) {
      if (ev.json_pointer) kids.push(el("div", { class: "mono", text: (ev.file || "") + " " + ev.json_pointer }));
      if (ev.hunk) kids.push(hunk(ev.hunk));
      if (ev.permalink_url) {
        var a = el("a", { href: ev.permalink_url, rel: "noreferrer noopener", target: "_blank" });
        a.textContent = "view upstream";
        kids.push(el("div", {}, [a]));
      }
    });

    var acts = el("div", { class: "actions" });
    [["ack", "Acknowledge"], ["mute", "Mute 30 days"], ["resolve", "Resolve"]].forEach(function (pair) {
      var b = el("button", { class: "act", text: pair[1] });
      b.addEventListener("click", function () {
        post("/api/findings/" + encodeURIComponent(f.id) + "/status", { action: pair[0] })
          .then(load)
          .catch(showError);
      });
      acts.appendChild(b);
    });
    kids.push(acts);
    return el("div", { class: "finding" }, kids);
  }

  function table(headers, rows) {
    var thead = el("thead", {}, [el("tr", {}, headers.map(function (h) { return el("th", { text: h }); }))]);
    var tbody = el("tbody", {}, rows.map(function (cells) {
      return el("tr", {}, cells.map(function (c) { return el("td", { class: "mono", text: String(c) }); }));
    }));
    return el("table", {}, [thead, tbody]);
  }

  function render() {
    var main = document.getElementById("main");
    main.textContent = "";
    if (state.error) main.appendChild(el("div", { class: "err", text: state.error }));
    var s = state.summary;
    if (!s) return;

    main.appendChild(renderTiles(s));

    if (state.view === "findings") {
      if (!s.findings.length) {
        main.appendChild(el("div", { class: "empty", text: "No open findings." }));
      } else {
        s.findings.forEach(function (f) { main.appendChild(findingCard(f)); });
      }
    } else if (state.view === "endpoints") {
      main.appendChild(table(
        ["method", "host", "path", "confidence", "language", "location"],
        s.endpoints.map(function (e) {
          return [e.method, e.host, e.path, e.confidence, e.language, e.file + ":" + e.line];
        })));
    } else if (state.view === "hosts") {
      main.appendChild(table(
        ["host", "calls", "paths", "upstream", "role"],
        s.hosts.map(function (h) {
          return [h.host, h.calls, h.paths, h.repo || "not linked", h.role || "-"];
        })));
    } else if (state.view === "runs") {
      main.appendChild(table(
        ["started", "checked", "skipped", "new", "breaking", "risky", "info"],
        s.runs.map(function (r) {
          return [r.started_at, r.upstreams_checked, r.upstreams_skipped,
                  r.findings_new, r.counts.breaking, r.counts.risky, r.counts.info];
        })));
    }
  }

  function showError(e) {
    state.error = String(e && e.message ? e.message : e);
    render();
  }

  function load() {
    return get("/api/summary").then(function (s) {
      if (!s) return;
      state.summary = s;
      state.error = null;
      var m = document.getElementById("meta");
      m.textContent = s.repo + " · " + (s.commit ? s.commit.slice(0, 8) : "no commit") +
        (s.last_check ? " · last check " + s.last_check : " · never checked");
      render();
    }).catch(showError);
  }

  document.addEventListener("DOMContentLoaded", function () {
    Array.prototype.forEach.call(document.querySelectorAll("nav button"), function (b) {
      b.addEventListener("click", function () {
        state.view = b.getAttribute("data-view");
        Array.prototype.forEach.call(document.querySelectorAll("nav button"), function (o) {
          o.setAttribute("aria-selected", o === b ? "true" : "false");
        });
        render();
      });
    });
    document.getElementById("logout").addEventListener("click", function () {
      post("/logout", {}).then(function () { window.location = "/login"; }).catch(showError);
    });
    document.getElementById("check").addEventListener("click", function () {
      state.error = null;
      post("/api/checks", {}).then(load).catch(showError);
    });
    load();
  });
})();
