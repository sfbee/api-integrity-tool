package analyze

import "testing"

func TestClassify(t *testing.T) {
	t.Parallel()
	tests := map[string]Class{
		"openapi.yaml":                        ClassSpec,
		"spec/openapi/billing.yaml":           ClassSpec,
		"api/swagger.json":                    ClassSpec,
		"schema.proto":                        ClassSpec,
		"config/routes.rb":                    ClassRoutes,
		"app/controllers/users_controller.rb": ClassRoutes,
		"src/urls.py":                         ClassRoutes,
		"internal/server/handler.go":          ClassRoutes,
		"internal/billing/charge.go":          ClassSource,
		"main_test.go":                        ClassTest,
		"spec/models/user_spec.rb":            ClassTest,
		"testdata/fixture.yaml":               ClassTest,
		"docs/api/guide.md":                   ClassDoc,
		"README.md":                           ClassDoc,
		"vendor/github.com/x/y/z.go":          ClassVendor,
		"node_modules/pkg/index.js":           ClassVendor,
		"api.pb.go":                           ClassGenerated,
		"go.sum":                              ClassLock,
		"logo.png":                            ClassBinary,
		"config/settings.yml":                 ClassConfig,
	}
	for path, want := range tests {
		if got := Classify(path); got != want {
			t.Errorf("Classify(%q) = %q, want %q", path, got, want)
		}
	}
}

// A Ruby "spec/" directory holds tests, not an API specification. Getting this
// backwards would treat every Ruby test edit as high-signal evidence.
func TestRubySpecDirectoryIsTestsNotSpecification(t *testing.T) {
	t.Parallel()
	if got := Classify("spec/requests/users_spec.rb"); got != ClassTest {
		t.Errorf("Classify = %q, want test", got)
	}
}

// Only classes that can plausibly define an interface may justify a breaking
// verdict.
func TestOnlyRealSourceCanBreak(t *testing.T) {
	t.Parallel()
	for _, c := range []Class{ClassSpec, ClassRoutes, ClassSource, ClassConfig} {
		if !c.CanBreak() {
			t.Errorf("%q should be able to break", c)
		}
	}
	for _, c := range []Class{ClassTest, ClassDoc, ClassVendor, ClassGenerated, ClassLock, ClassBinary} {
		if c.CanBreak() {
			t.Errorf("%q must never justify a breaking verdict", c)
		}
	}
}

func TestParseHunksTracksLineNumbers(t *testing.T) {
	t.Parallel()
	patch := "@@ -10,4 +10,4 @@ func handler() {\n" +
		" context line\n" +
		"-\tmux.Get(\"/api/v1/users\", h)\n" +
		"+\tmux.Get(\"/api/v2/users\", h)\n" +
		" another context\n"
	hunks := ParseHunks(patch)
	if len(hunks) != 1 {
		t.Fatalf("hunks = %d, want 1", len(hunks))
	}
	h := hunks[0]
	if h.OldStart != 10 || h.NewStart != 10 {
		t.Errorf("starts = %d/%d", h.OldStart, h.NewStart)
	}
	var removed, added Line
	for _, l := range h.Lines {
		if l.Removed() {
			removed = l
		}
		if l.Added() {
			added = l
		}
	}
	// The removed line is the eleventh: one context line precedes it.
	if removed.OldLine != 11 {
		t.Errorf("removed line number = %d, want 11", removed.OldLine)
	}
	if added.NewLine != 11 {
		t.Errorf("added line number = %d, want 11", added.NewLine)
	}
}

func TestParseHunksHandlesMultipleHunks(t *testing.T) {
	t.Parallel()
	patch := "@@ -1,2 +1,2 @@\n-a\n+b\n@@ -50,2 +50,2 @@\n-c\n+d\n"
	hunks := ParseHunks(patch)
	if len(hunks) != 2 {
		t.Fatalf("hunks = %d, want 2", len(hunks))
	}
	if hunks[1].OldStart != 50 {
		t.Errorf("second hunk starts at %d, want 50", hunks[1].OldStart)
	}
}

func TestParseHunksOnEmptyPatch(t *testing.T) {
	t.Parallel()
	if got := ParseHunks(""); got != nil {
		t.Errorf("want nil for an empty patch, got %+v", got)
	}
}

func TestIsCommentLine(t *testing.T) {
	t.Parallel()
	for _, s := range []string{"// old: /api/v1/users", "# GET /api/v1/users", "-- sql comment", "* javadoc"} {
		if !IsCommentLine(s) {
			t.Errorf("IsCommentLine(%q) = false, want true", s)
		}
	}
	for _, s := range []string{`mux.Get("/api/v1/users", h)`, "", "   "} {
		if IsCommentLine(s) {
			t.Errorf("IsCommentLine(%q) = true, want false", s)
		}
	}
}

func TestMentionsBreakingChange(t *testing.T) {
	t.Parallel()
	for _, s := range []string{
		"BREAKING CHANGE: removed /v1",
		"feat!: drop legacy endpoint",
		"The /users endpoint has been removed",
		"clients must now send a tenant header",
	} {
		if !MentionsBreakingChange(s) {
			t.Errorf("MentionsBreakingChange(%q) = false, want true", s)
		}
	}
	for _, s := range []string{"fix: typo in docs", "chore: bump deps"} {
		if MentionsBreakingChange(s) {
			t.Errorf("MentionsBreakingChange(%q) = true, want false", s)
		}
	}
}
