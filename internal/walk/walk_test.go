package walk

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// tree writes a map of repo-relative paths to contents into a temp dir.
func tree(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for rel, content := range files {
		p := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func paths(cs []Candidate) []string {
	out := make([]string, 0, len(cs))
	for _, c := range cs {
		out = append(out, c.RelPath)
	}
	return out
}

func TestFindIsSortedAndDeterministic(t *testing.T) {
	t.Parallel()
	root := tree(t, map[string]string{
		"z.go": "package main", "a.go": "package main", "m/b.go": "package main",
	})
	opts := Options{Root: root, Extensions: map[string]bool{".go": true}}
	first, _, err := Find(context.Background(), opts)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"a.go", "m/b.go", "z.go"}
	if got := strings.Join(paths(first), ","); got != strings.Join(want, ",") {
		t.Errorf("paths = %v, want %v", paths(first), want)
	}
	for range 5 {
		again, _, err := Find(context.Background(), opts)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Join(paths(again), ",") != strings.Join(paths(first), ",") {
			t.Fatal("Find order varied between runs")
		}
	}
}

func TestFindFiltersByExtension(t *testing.T) {
	t.Parallel()
	root := tree(t, map[string]string{"a.go": "package main", "b.md": "# doc", "c.py": "x = 1"})
	got, stats, err := Find(context.Background(), Options{Root: root, Extensions: map[string]bool{".go": true}})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].RelPath != "a.go" {
		t.Errorf("paths = %v, want [a.go]", paths(got))
	}
	if stats.Skipped[SkipUnknownExt] != 2 {
		t.Errorf("skipped unknown_extension = %d, want 2", stats.Skipped[SkipUnknownExt])
	}
}

func TestExcludeDirsArePrunedNotDescended(t *testing.T) {
	t.Parallel()
	root := tree(t, map[string]string{
		"src/a.go":                   "package main",
		"node_modules/pkg/index.js":  "x",
		"node_modules/pkg/deep/n.js": "x",
		"vendor/x/y.go":              "package x",
	})
	got, _, err := Find(context.Background(), Options{
		Root:        root,
		Extensions:  map[string]bool{".go": true, ".js": true},
		ExcludeDirs: []string{"node_modules", "vendor"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].RelPath != "src/a.go" {
		t.Errorf("paths = %v, want [src/a.go]", paths(got))
	}
}

func TestGitignoreIsHonoured(t *testing.T) {
	t.Parallel()
	root := tree(t, map[string]string{
		".gitignore":     "build/\n*.gen.go\n!keep.gen.go\n",
		"a.go":           "package main",
		"keep.gen.go":    "package main",
		"skip.gen.go":    "package main",
		"build/out.go":   "package main",
		"sub/.gitignore": "local.go\n",
		"sub/local.go":   "package sub",
		"sub/shared.go":  "package sub",
	})
	got, stats, err := Find(context.Background(), Options{
		Root: root, Extensions: map[string]bool{".go": true}, RespectGitignore: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	want := "a.go,keep.gen.go,sub/shared.go"
	if g := strings.Join(paths(got), ","); g != want {
		t.Errorf("paths = %q, want %q", g, want)
	}
	if stats.Skipped[SkipIgnored] == 0 {
		t.Error("no files recorded as gitignored")
	}
}

func TestGitignoreCanBeDisabled(t *testing.T) {
	t.Parallel()
	root := tree(t, map[string]string{".gitignore": "*.go\n", "a.go": "package main"})
	got, _, err := Find(context.Background(), Options{Root: root, Extensions: map[string]bool{".go": true}})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Errorf("paths = %v, want a.go included when gitignore is off", paths(got))
	}
}

func TestIncludeGlobBeatsExcludeAndIgnore(t *testing.T) {
	t.Parallel()
	root := tree(t, map[string]string{
		".gitignore":    "sdk/\n",
		"sdk/client.go": "package sdk",
		"app/main.go":   "package main",
	})
	got, _, err := Find(context.Background(), Options{
		Root: root, Extensions: map[string]bool{".go": true},
		RespectGitignore: true, IncludeGlobs: []string{"sdk"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(paths(got), ",") != "app/main.go,sdk/client.go" {
		t.Errorf("paths = %v, want the explicitly included sdk dir back", paths(got))
	}
}

func TestPathGlobsNarrowTraversal(t *testing.T) {
	t.Parallel()
	root := tree(t, map[string]string{"api/a.go": "package api", "web/b.go": "package web"})
	got, _, err := Find(context.Background(), Options{
		Root: root, Extensions: map[string]bool{".go": true}, PathGlobs: []string{"api/**"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].RelPath != "api/a.go" {
		t.Errorf("paths = %v, want [api/a.go]", paths(got))
	}
}

func TestMaxFileSize(t *testing.T) {
	t.Parallel()
	root := tree(t, map[string]string{"big.go": strings.Repeat("x", 500), "small.go": "package main"})
	got, stats, err := Find(context.Background(), Options{
		Root: root, Extensions: map[string]bool{".go": true}, MaxFileSize: 100,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].RelPath != "small.go" {
		t.Errorf("paths = %v, want [small.go]", paths(got))
	}
	if stats.Skipped[SkipTooLarge] != 1 {
		t.Errorf("too_large = %d, want 1", stats.Skipped[SkipTooLarge])
	}
}

func TestSymlinksNotFollowedByDefault(t *testing.T) {
	t.Parallel()
	root := tree(t, map[string]string{"real.go": "package main"})
	if err := os.Symlink(filepath.Join(root, "real.go"), filepath.Join(root, "link.go")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	got, stats, err := Find(context.Background(), Options{Root: root, Extensions: map[string]bool{".go": true}})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].RelPath != "real.go" {
		t.Errorf("paths = %v, want only the real file", paths(got))
	}
	if stats.Skipped[SkipSymlink] != 1 {
		t.Errorf("symlink skips = %d, want 1", stats.Skipped[SkipSymlink])
	}
}

func TestFindRespectsContextCancellation(t *testing.T) {
	t.Parallel()
	root := tree(t, map[string]string{"a.go": "package main"})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := Find(ctx, Options{Root: root}); err == nil {
		t.Error("want an error from a cancelled context")
	}
}

func TestContentSkipReason(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		content []byte
		want    string
	}{
		{"plain source", []byte("package main\n\nfunc main() {}\n"), ""},
		{"nul byte", []byte("abc\x00def"), SkipBinary},
		{"elf magic", []byte("\x7fELF\x02\x01"), SkipBinary},
		{"png magic", []byte("\x89PNG\r\n\x1a\n"), SkipBinary},
		{"minified", []byte(strings.Repeat("a", maxLineLength+1)), SkipMinified},
		{"long file short lines", []byte(strings.Repeat("abc\n", 5000)), ""},
		{"utf8 is fine", []byte("// héllo wörld\n"), ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := ContentSkipReason(tc.content); got != tc.want {
				t.Errorf("ContentSkipReason = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestIsGenerated(t *testing.T) {
	t.Parallel()
	if !IsGenerated([]byte("// Code generated by protoc-gen-go. DO NOT EDIT.\npackage x")) {
		t.Error("want generated for a protoc header")
	}
	if !IsGenerated([]byte("// <auto-generated />\nnamespace X {}")) {
		t.Error("want generated for a C# auto-generated header")
	}
	if IsGenerated([]byte("package main\n// this code was written by hand\n")) {
		t.Error("hand-written file reported as generated")
	}
}

func TestIgnoreStackPatterns(t *testing.T) {
	t.Parallel()
	tests := []struct {
		pattern string
		base    string
		path    string
		isDir   bool
		want    bool
	}{
		{"*.log", "", "app.log", false, true},
		{"*.log", "", "sub/app.log", false, true},
		{"/*.log", "", "sub/app.log", false, false},
		{"/root.log", "", "root.log", false, true},
		{"build/", "", "build", true, true},
		{"build/", "", "build", false, false},
		{"build/", "", "build/out.txt", false, true},
		{"a/b", "", "a/b/c.txt", false, true},
		{"a/b", "", "x/a/b", false, false},
		{"**/gen", "", "src/deep/gen/x.go", false, true},
		{"src/**/gen.go", "", "src/a/b/gen.go", false, true},
		{"src/**/gen.go", "", "src/gen.go", false, true},
		{"file?.txt", "", "file1.txt", false, true},
		{"file[0-9].txt", "", "file7.txt", false, true},
		{"file[0-9].txt", "", "filex.txt", false, false},
		{"nested.go", "sub", "sub/nested.go", false, true},
		{"nested.go", "sub", "other/nested.go", false, false},
	}
	for _, tc := range tests {
		s := &IgnoreStack{}
		s.AddLine(tc.pattern, tc.base)
		if got := s.Match(tc.path, tc.isDir); got != tc.want {
			t.Errorf("pattern %q base %q vs %q (dir=%v) = %v, want %v",
				tc.pattern, tc.base, tc.path, tc.isDir, got, tc.want)
		}
	}
}

func TestIgnoreNegationLastMatchWins(t *testing.T) {
	t.Parallel()
	s := &IgnoreStack{}
	s.AddLine("*.gen.go", "")
	s.AddLine("!keep.gen.go", "")
	if !s.Match("a.gen.go", false) {
		t.Error("a.gen.go should be ignored")
	}
	if s.Match("keep.gen.go", false) {
		t.Error("keep.gen.go should be re-included by the negation")
	}
}

func TestIgnoreCommentsAndBlanks(t *testing.T) {
	t.Parallel()
	s := &IgnoreStack{}
	s.AddLine("# a comment", "")
	s.AddLine("", "")
	s.AddLine("   ", "")
	if s.Len() != 0 {
		t.Errorf("Len = %d, want 0", s.Len())
	}
}
