package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Go treats a trailing _GOOS or _GOARCH in a filename as an implicit build
// constraint. A file named lang_js.go is silently excluded from every build
// that is not GOOS=js, so it compiles, vets and formats cleanly while never
// running -- and `go test` reports "no test files" rather than an error.
//
// That cost real debugging time on this project: a JS language spec and its
// tests were both invisible for an hour. This test makes the trap impossible to
// fall into twice.
func TestNoAccidentalBuildConstraintFilenames(t *testing.T) {
	t.Parallel()

	// The full set Go recognises, from go/build. "js" and "windows" are the
	// ones that plausibly collide with a domain word; the rest are here so the
	// list does not have to be revisited.
	reserved := map[string]bool{}
	for _, s := range []string{
		// GOOS
		"aix", "android", "darwin", "dragonfly", "freebsd", "hurd", "illumos",
		"ios", "js", "linux", "nacl", "netbsd", "openbsd", "plan9", "solaris",
		"wasip1", "windows", "zos",
		// GOARCH
		"386", "amd64", "amd64p32", "arm", "arm64", "arm64be", "armbe",
		"loong64", "mips", "mips64", "mips64le", "mips64p32", "mips64p32le",
		"mipsle", "ppc", "ppc64", "ppc64le", "riscv", "riscv64", "s390",
		"s390x", "sparc", "sparc64", "wasm",
		// Also constraint-bearing
		"unix",
	} {
		reserved[s] = true
	}

	root := moduleRoot(t)
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "testdata", "node_modules", "vendor":
				return filepath.SkipDir
			}
			return nil
		}
		name := d.Name()
		if !strings.HasSuffix(name, ".go") {
			return nil
		}
		stem := strings.TrimSuffix(name, ".go")
		stem = strings.TrimSuffix(stem, "_test")
		if i := strings.LastIndex(stem, "_"); i >= 0 {
			if suffix := stem[i+1:]; reserved[suffix] {
				rel, _ := filepath.Rel(root, path)
				t.Errorf("%s: filename suffix %q is an implicit GOOS/GOARCH build constraint, "+
					"so this file is excluded from normal builds and its tests never run; rename it "+
					"(for example lang_js.go -> lang_javascript.go)", rel, "_"+suffix)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
}

// moduleRoot walks up from the test's working directory to the directory
// holding go.mod.
func moduleRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("could not locate go.mod above the test working directory")
		}
		dir = parent
	}
}
