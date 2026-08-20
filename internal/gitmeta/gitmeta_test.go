package gitmeta

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestFindRootWalksUp(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	deep := filepath.Join(root, "a", "b", "c")
	if err := os.MkdirAll(deep, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	got := FindRoot(deep)
	want, _ := filepath.EvalSymlinks(root)
	gotEval, _ := filepath.EvalSymlinks(got)
	if gotEval != want {
		t.Errorf("FindRoot = %q, want %q", gotEval, want)
	}
}

// Scanning a plain directory is legitimate, so a missing .git is not an error.
func TestFindRootWithoutGitReturnsTheDirectory(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	if got := FindRoot(dir); got == "" {
		t.Error("FindRoot returned empty for a non-repo directory")
	}
}

func TestStaticProvider(t *testing.T) {
	t.Parallel()
	want := Info{Root: "/x", Commit: "abc", Dirty: true, HasCommits: true}
	got, err := Static{I: want}.Info(context.Background(), "anywhere")
	if err != nil || got != want {
		t.Errorf("Static.Info = %+v, %v", got, err)
	}
}

func TestNormalizeRemote(t *testing.T) {
	t.Parallel()
	tests := map[string]string{
		"git@github.com:org/repo.git":       "https://github.com/org/repo",
		"https://github.com/org/repo.git":   "https://github.com/org/repo",
		"http://github.com/org/repo":        "https://github.com/org/repo",
		"ssh://git@github.com/org/repo.git": "github.com/org/repo",
		"https://github.com/org/repo":       "https://github.com/org/repo",
	}
	for in, want := range tests {
		if got := normalizeRemote(in); got != want {
			t.Errorf("normalizeRemote(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestGitInfoOnARealRepo(t *testing.T) {
	t.Parallel()
	// Exercises the real provider without asserting values that vary by machine.
	info, err := Git{}.Info(context.Background(), ".")
	if err != nil {
		t.Fatalf("Info: %v", err)
	}
	if info.Root == "" {
		t.Error("Root is empty")
	}
}
