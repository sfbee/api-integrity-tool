package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sfbee/api-integrity-tool/internal/index"
)

// writeRepo lays out the two files `list` reads: the index, and the config that
// says what a symbolic host really is.
func writeRepo(t *testing.T, configYAML string) string {
	t.Helper()
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, ".api-integrity"), 0o755); err != nil {
		t.Fatal(err)
	}
	idx := index.Index{
		SchemaVersion: 1,
		Calls: []index.Call{{
			ID: "c1", Method: "GET", Host: "${sym:Acme::LicenseAPI.base}", Path: "/records/{id}",
			HostKind: "symbol", Language: "perl", Confidence: index.ConfLow,
			Location: index.Location{File: "lib/Acme/LicenseAPI.pm", Line: 77},
		}},
	}
	b, err := json.Marshal(idx)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, ".api-integrity", "index.json"), b, 0o644); err != nil {
		t.Fatal(err)
	}
	if configYAML != "" {
		if err := os.WriteFile(filepath.Join(root, ".api-integrity.yml"), []byte(configYAML), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func runListIn(t *testing.T, root string, args ...string) string {
	t.Helper()
	var out, errOut bytes.Buffer
	env := Env{Stdout: &out, Stderr: &errOut, Cwd: root, Getenv: func(string) string { return "" }}
	if err := runList(env, append([]string{"--repo-path", root}, args...)); err != nil {
		t.Fatalf("runList: %v", err)
	}
	return out.String() + errOut.String()
}

// The reason this is worth a test of its own: query.Filters knew how to invert a
// host mapping and matchHost knew how to use it, but nothing ever populated the
// field from config -- so the whole feature was unreachable from the CLI.
// Filtering by the host you actually linked silently returned nothing, which
// reads as "no calls to that API" rather than "this flag is not wired up".
func TestListResolvesAMappedHostToItsSymbol(t *testing.T) {
	t.Parallel()
	root := writeRepo(t, `
version: 1
host_mappings:
  "${sym:Acme::LicenseAPI.base}": ["api.acme.com"]
`)
	got := runListIn(t, root, "--host", "api.acme.com")
	if !strings.Contains(got, "/records/{id}") {
		t.Errorf("filtering by the mapped host found nothing:\n%s", got)
	}
}

// The symbolic form must keep working, so the mapping is an addition rather
// than a replacement.
func TestListStillMatchesTheSymbolicHost(t *testing.T) {
	t.Parallel()
	root := writeRepo(t, `
version: 1
host_mappings:
  "${sym:Acme::LicenseAPI.base}": ["api.acme.com"]
`)
	got := runListIn(t, root, "--host", "${sym:Acme::LicenseAPI.base}")
	if !strings.Contains(got, "/records/{id}") {
		t.Errorf("the symbolic host stopped matching:\n%s", got)
	}
}

// An unmapped host must not match, or the filter would be useless.
func TestListDoesNotMatchAnUnrelatedHost(t *testing.T) {
	t.Parallel()
	root := writeRepo(t, `
version: 1
host_mappings:
  "${sym:Acme::LicenseAPI.base}": ["api.acme.com"]
`)
	got := runListIn(t, root, "--host", "api.unrelated.com")
	if strings.Contains(got, "/records/{id}") {
		t.Errorf("an unrelated host matched:\n%s", got)
	}
}

// With no config at all the command must still work rather than fail to load.
func TestListWorksWithoutAConfigFile(t *testing.T) {
	t.Parallel()
	root := writeRepo(t, "")
	got := runListIn(t, root)
	if !strings.Contains(got, "/records/{id}") {
		t.Errorf("listing without a config found nothing:\n%s", got)
	}
}
