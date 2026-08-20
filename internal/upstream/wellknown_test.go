package upstream

import "testing"

func TestWellKnownLookup(t *testing.T) {
	t.Parallel()
	if wk, ok := LookupWellKnown("api.stripe.com"); !ok || wk.Repo != "github.com/stripe/openapi" {
		t.Errorf("stripe = %+v, %v", wk, ok)
	}
	// A wildcard entry must match a subdomain.
	if wk, ok := LookupWellKnown("compute.googleapis.com"); !ok || wk.Vendor != "Google" {
		t.Errorf("googleapis = %+v, %v", wk, ok)
	}
	if _, ok := LookupWellKnown("api.totally-unknown-vendor.example"); ok {
		t.Error("unknown host should not match")
	}
	// Every entry must parse, or the table silently degrades.
	table, err := WellKnownTable()
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range table {
		if _, err := ParseRepoRef(e.Repo); err != nil {
			t.Errorf("well-known %s: repo %q does not parse: %v", e.Host, e.Repo, err)
		}
		if !e.Role.Valid() {
			t.Errorf("well-known %s: invalid role %q", e.Host, e.Role)
		}
	}
}

func TestGuessRepo(t *testing.T) {
	t.Parallel()
	g := GuessRepo("api.stripe.com", "")
	if len(g) != 1 || g[0].Confidence != 1.0 {
		t.Fatalf("well-known host should yield one confident guess, got %+v", g)
	}
	// Symbolic hosts cannot be guessed at all.
	if g := GuessRepo("${env:BILLING_URL}", "github.com/acme/web"); len(g) != 0 {
		t.Errorf("symbolic host produced guesses: %+v", g)
	}
	// Same-organisation inference.
	g = GuessRepo("api.acme.com", "github.com/acme/web")
	if len(g) == 0 || g[0].Repo.Owner != "acme" {
		t.Errorf("same-org guess missing: %+v", g)
	}
}

func TestHostLabel(t *testing.T) {
	t.Parallel()
	for in, want := range map[string]string{
		"api.acme.com": "acme", "acme.io": "acme", "www.acme.co.uk": "acme",
		"graph.microsoft.com": "microsoft", "self": "", "${env:X}": "",
	} {
		if got := hostLabel(in); got != want {
			t.Errorf("hostLabel(%q) = %q, want %q", in, got, want)
		}
	}
}
