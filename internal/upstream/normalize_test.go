package upstream

import "testing"

func TestParseRepoRefAcceptedForms(t *testing.T) {
	t.Parallel()
	tests := []struct {
		in            string
		wantCanonical string
		wantSubpath   string
		wantRef       string
	}{
		{"https://github.com/Org/Repo", "https://github.com/Org/Repo", "", ""},
		{"https://github.com/Org/Repo.git", "https://github.com/Org/Repo", "", ""},
		{"https://github.com/Org/Repo/", "https://github.com/Org/Repo", "", ""},
		{"http://github.com/org/repo", "https://github.com/org/repo", "", ""},
		{"git@github.com:org/repo.git", "https://github.com/org/repo", "", ""},
		{"ssh://git@github.com/org/repo", "https://github.com/org/repo", "", ""},
		{"git://github.com/org/repo", "https://github.com/org/repo", "", ""},
		{"github.com/org/repo", "https://github.com/org/repo", "", ""},
		{"org/repo", "https://github.com/org/repo", "", ""},
		{"gh:org/repo", "https://github.com/org/repo", "", ""},
		{"github.com/org/repo//services/api", "https://github.com/org/repo//services/api", "services/api", ""},
		{"org/repo//svc/billing", "https://github.com/org/repo//svc/billing", "svc/billing", ""},
		{"github.com/org/repo@v2", "https://github.com/org/repo@v2", "", "v2"},
		{"github.com/org/repo#release-2", "https://github.com/org/repo@release-2", "", "release-2"},
		{"https://github.com/org/repo/tree/main/services/api", "https://github.com/org/repo//services/api@main", "services/api", "main"},
		{"https://gitlab.com/group/project", "https://gitlab.com/group/project", "", ""},
	}
	for _, tc := range tests {
		t.Run(tc.in, func(t *testing.T) {
			t.Parallel()
			got, err := ParseRepoRef(tc.in)
			if err != nil {
				t.Fatalf("ParseRepoRef(%q): %v", tc.in, err)
			}
			if got.Canonical() != tc.wantCanonical {
				t.Errorf("Canonical() = %q, want %q", got.Canonical(), tc.wantCanonical)
			}
			if got.Subpath != tc.wantSubpath {
				t.Errorf("Subpath = %q, want %q", got.Subpath, tc.wantSubpath)
			}
			if got.Ref != tc.wantRef {
				t.Errorf("Ref = %q, want %q", got.Ref, tc.wantRef)
			}
		})
	}
}

// A pull-request or issue URL is what someone actually has in their clipboard.
// Recovering the repository is far friendlier than rejecting it.
func TestParseRepoRefRecoversRepoFromDeepURLs(t *testing.T) {
	t.Parallel()
	for _, in := range []string{
		"https://github.com/org/repo/pull/123",
		"https://github.com/org/repo/issues/9",
		"https://github.com/org/repo/commit/deadbeef",
		"https://github.com/org/repo/releases/tag/v1.2.3",
	} {
		got, err := ParseRepoRef(in)
		if err != nil {
			t.Errorf("ParseRepoRef(%q): %v", in, err)
			continue
		}
		if got.Canonical() != "https://github.com/org/repo" {
			t.Errorf("ParseRepoRef(%q) = %q, want the plain repository", in, got.Canonical())
		}
	}
}

func TestParseRepoRefRejections(t *testing.T) {
	t.Parallel()
	tests := []struct{ in, wantSubstr string }{
		{"", "empty"},
		{"file:///tmp/repo", "local paths"},
		{"https://github.com/org", "owner but not a repository"},
		{"https://user:secret@github.com/org/repo", "embedded credentials"},
		{"ftp://github.com/org/repo", "unsupported scheme"},
		{"github.com/org/repo//../etc", `".."`},
	}
	for _, tc := range tests {
		t.Run(tc.in, func(t *testing.T) {
			t.Parallel()
			_, err := ParseRepoRef(tc.in)
			if err == nil {
				t.Fatalf("ParseRepoRef(%q) succeeded, want an error", tc.in)
			}
			if !contains(err.Error(), tc.wantSubstr) {
				t.Errorf("error = %q, want it to mention %q", err, tc.wantSubstr)
			}
		})
	}
}

// GitHub owners and repositories are case-insensitive, so two spellings of the
// same repository must collapse to one key or the same upstream gets linked and
// checked twice.
func TestRepoKeyIsCaseInsensitive(t *testing.T) {
	t.Parallel()
	a, err := ParseRepoRef("https://github.com/Org/Repo")
	if err != nil {
		t.Fatal(err)
	}
	b, err := ParseRepoRef("https://github.com/org/repo")
	if err != nil {
		t.Fatal(err)
	}
	if a.Key() != b.Key() {
		t.Errorf("keys differ: %q vs %q", a.Key(), b.Key())
	}
	// Display case is preserved even though identity is folded.
	if a.Canonical() == b.Canonical() {
		t.Errorf("display form should preserve case: both %q", a.Canonical())
	}
}

// A subpath is part of the identity: two services in one monorepo are distinct
// upstreams with distinct check state.
func TestSubpathIsPartOfIdentity(t *testing.T) {
	t.Parallel()
	a, _ := ParseRepoRef("org/repo//services/billing")
	b, _ := ParseRepoRef("org/repo//services/identity")
	if a.Key() == b.Key() {
		t.Errorf("monorepo subpaths collapsed to one key: %q", a.Key())
	}
}

func TestBlobURLIsPinnedToCommit(t *testing.T) {
	t.Parallel()
	r, _ := ParseRepoRef("github.com/org/repo")
	got := r.BlobURL("abc123", "openapi.yaml", 42)
	want := "https://github.com/org/repo/blob/abc123/openapi.yaml#L42"
	if got != want {
		t.Errorf("BlobURL = %q, want %q", got, want)
	}
}

func contains(s, sub string) bool {
	return len(sub) == 0 || (len(s) >= len(sub) && indexOf(s, sub) >= 0)
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
