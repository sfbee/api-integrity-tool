package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/sfbee/api-integrity-tool/internal/model"
)

func write(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, ".api-integrity.yml"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestLoadMissingFileIsNotAnError(t *testing.T) {
	t.Parallel()
	f, err := Load(t.TempDir())
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if f.Path != "" || len(f.Upstreams) != 0 {
		t.Errorf("expected an empty config, got %+v", f)
	}
}

// An empty or comment-only file must load cleanly; yaml decodes it to io.EOF.
func TestLoadEmptyFile(t *testing.T) {
	t.Parallel()
	for _, body := range []string{"", "# just a comment\n", "\n\n"} {
		if _, err := Load(write(t, body)); err != nil {
			t.Errorf("Load(%q): %v", body, err)
		}
	}
}

// The shorthand form is what people actually write for the common case.
func TestUpstreamShorthandAndListForms(t *testing.T) {
	t.Parallel()
	dir := write(t, `
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
`)
	f, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	ups, err := f.ConfiguredUpstreams()
	if err != nil {
		t.Fatal(err)
	}
	if len(ups) != 3 {
		t.Fatalf("want 3 upstreams, got %d: %+v", len(ups), ups)
	}
	byHost := map[string][]model.Upstream{}
	for _, u := range ups {
		byHost[u.Host] = append(byHost[u.Host], u)
	}
	if got := byHost["api.stripe.com"]; len(got) != 1 || got[0].Repo.Slug() != "stripe/openapi" {
		t.Errorf("stripe = %+v", got)
	}
	if got := byHost["api.acme.com"]; len(got) != 2 {
		t.Fatalf("acme = %+v", got)
	}
	var sawSubpath, sawSpecOnly bool
	for _, u := range byHost["api.acme.com"] {
		if u.Repo.Subpath == "services/billing" && u.PathPrefix == "/billing/" {
			sawSubpath = true
		}
		if u.Role == model.RoleSpecOnly && u.Priority == 50 {
			sawSpecOnly = true
		}
	}
	if !sawSubpath || !sawSpecOnly {
		t.Errorf("monorepo subpath or spec_only entry lost: %+v", byHost["api.acme.com"])
	}
}

// A typo in a key must fail loudly. Silently ignoring unknown fields is how a
// team discovers months later that their config never took effect.
func TestUnknownKeysAreRejected(t *testing.T) {
	t.Parallel()
	_, err := Load(write(t, "version: 1\nupstreems:\n  api.x.com: org/repo\n"))
	if err == nil {
		t.Fatal("expected an error for a misspelled key")
	}
}

func TestValidationErrors(t *testing.T) {
	t.Parallel()
	tests := map[string]string{
		"bad role":          "upstreams:\n  api.x.com:\n    - repo: org/repo\n      role: nonsense\n",
		"missing repo":      "upstreams:\n  api.x.com:\n    - path_prefix: /v1/\n",
		"unparseable repo":  "upstreams:\n  api.x.com: file:///tmp/x\n",
		"bad confidence":    "filters:\n  min_confidence: enormous\n",
		"unmonitored empty": "unmonitored:\n  - reason: internal\n",
		"future version":    "version: 99\n",
	}
	for name, body := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, err := Load(write(t, body)); err == nil {
				t.Errorf("expected an error for %s", name)
			}
		})
	}
}

func TestHostMappingsAndDecisions(t *testing.T) {
	t.Parallel()
	f, err := Load(write(t, `
host_mappings:
  "${env:BILLING_BASE_URL}": ["billing.acme.internal", "billing-staging.acme.internal"]
unmonitored:
  - host: api.internal.corp
    reason: internal
  - host: api.vendor.example
`))
	if err != nil {
		t.Fatal(err)
	}
	got := f.ResolveHost("${env:BILLING_BASE_URL}")
	if len(got) != 2 || got[0] != "billing.acme.internal" {
		t.Errorf("ResolveHost = %v", got)
	}
	if got := f.ResolveHost("api.other.com"); len(got) != 1 || got[0] != "api.other.com" {
		t.Errorf("unmapped host should pass through, got %v", got)
	}
	ds := f.ConfiguredDecisions()
	if len(ds) != 2 {
		t.Fatalf("want 2 decisions, got %+v", ds)
	}
	// A decision with no stated reason still records one, so the "why" column
	// is never blank.
	for _, d := range ds {
		if d.Reason == "" || d.Kind != model.DecisionUnmonitored {
			t.Errorf("decision = %+v", d)
		}
	}
	if !ds[0].Sticky() && ds[0].Host == "api.internal.corp" {
		t.Error("an internal host should be a sticky decision")
	}
}

// The documented example must itself be valid, or the first thing a user copies
// fails to load.
func TestExampleConfigIsValid(t *testing.T) {
	t.Parallel()
	f, err := Load(write(t, Example))
	if err != nil {
		t.Fatalf("the embedded example config does not load: %v", err)
	}
	if _, err := f.ConfiguredUpstreams(); err != nil {
		t.Errorf("example upstreams: %v", err)
	}
}
