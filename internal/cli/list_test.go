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
func writeRepo(t *testing.T, configYAML string, extra ...index.Call) string {
	t.Helper()
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, ".api-integrity"), 0o755); err != nil {
		t.Fatal(err)
	}
	calls := []index.Call{{
		ID: "c1", Method: "GET", Host: "${sym:Acme::LicenseAPI.base}", Path: "/records/{id}",
		HostKind: "symbol", Language: "perl", Confidence: index.ConfLow,
		Location: index.Location{File: "lib/Acme/LicenseAPI.pm", Line: 77},
	}}
	calls = append(calls, extra...)
	idx := index.Index{SchemaVersion: 1, Calls: calls, Hosts: hostGroupsFor(calls)}
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

// hostGroupsFor builds the per-host summary the way a scan would, so the hosts
// command has something to aggregate.
func hostGroupsFor(calls []index.Call) []index.HostGroup {
	order := []string{}
	byHost := map[string]*index.HostGroup{}
	paths := map[string]map[string]bool{}
	for _, c := range calls {
		g, ok := byHost[c.Host]
		if !ok {
			byHost[c.Host] = &index.HostGroup{HostKey: c.Host, HostKind: c.HostKind, MaxConfidence: c.Confidence}
			order = append(order, c.Host)
			paths[c.Host] = map[string]bool{}
			g = byHost[c.Host]
		}
		g.CallCount++
		g.Methods = append(g.Methods, c.Method)
		paths[c.Host][c.Path] = true
	}
	out := make([]index.HostGroup, 0, len(order))
	for _, h := range order {
		byHost[h].PathCount = len(paths[h])
		out = append(out, *byHost[h])
	}
	return out
}

func runHostsIn(t *testing.T, root string, args ...string) string {
	t.Helper()
	var out, errOut bytes.Buffer
	env := Env{Stdout: &out, Stderr: &errOut, Cwd: root, Getenv: func(string) string { return "" }}
	if err := runHosts(env, append([]string{"--repo-path", root}, args...)); err != nil {
		t.Fatalf("runHosts: %v", err)
	}
	return out.String() + errOut.String()
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

const mappedConfig = `
version: 1
host_mappings:
  "${sym:Acme::LicenseAPI.base}": ["api.acme.com"]
  "${sym:client.base}": ["api.acme.com"]
`

// "${sym:Acme::LicenseAPI.base}" tells you nothing about which service you are
// looking at. The user already declared what it stands for; showing that is the
// whole point of having declared it.
func TestListShowsTheHostnameTheSymbolMapsTo(t *testing.T) {
	t.Parallel()
	root := writeRepo(t, mappedConfig)
	got := runListIn(t, root)
	if !strings.Contains(got, "api.acme.com") {
		t.Errorf("the mapped hostname is not shown:\n%s", got)
	}
	if strings.Contains(got, "${sym:Acme::LicenseAPI.base}") {
		t.Errorf("the raw symbol is still shown:\n%s", got)
	}
}

// The substitution is an assertion from configuration, not something the
// scanner saw, so it has to be visibly marked.
func TestAMappedHostnameIsMarkedAsAsserted(t *testing.T) {
	t.Parallel()
	root := writeRepo(t, mappedConfig)
	got := runListIn(t, root)
	if !strings.Contains(got, "api.acme.com*") {
		t.Errorf("the mapped hostname is not marked:\n%s", got)
	}
	if !strings.Contains(got, "host_mappings") {
		t.Errorf("no legend explaining the marker:\n%s", got)
	}
}

func TestRawHostsShowsTheSymbolAgain(t *testing.T) {
	t.Parallel()
	root := writeRepo(t, mappedConfig)
	got := runListIn(t, root, "--raw-hosts")
	if !strings.Contains(got, "${sym:Acme::LicenseAPI.base}") {
		t.Errorf("--raw-hosts did not show the symbol:\n%s", got)
	}
}

// A host with no mapping must be left exactly as the scanner recorded it,
// rather than quietly acquiring some other service's name.
func TestAnUnmappedSymbolIsLeftAlone(t *testing.T) {
	t.Parallel()
	root := writeRepo(t, mappedConfig, index.Call{
		ID: "c2", Method: "POST", Host: "${sym:Other::Thing.base}", Path: "/x",
		HostKind: "symbol", Language: "perl", Confidence: index.ConfLow,
		Location: index.Location{File: "lib/Other/Thing.pm", Line: 5},
	})
	got := runListIn(t, root)
	if !strings.Contains(got, "${sym:Other::Thing.base}") {
		t.Errorf("an unmapped symbol was not left alone:\n%s", got)
	}
}

// Several symbols routinely stand for one service. Once both display as that
// hostname, separate rows show the same name twice with different counts, which
// reads as a bug.
func TestHostsMergesSymbolsThatMapToTheSameHostname(t *testing.T) {
	t.Parallel()
	root := writeRepo(t, mappedConfig,
		index.Call{
			ID: "c2", Method: "GET", Host: "${sym:client.base}", Path: "/records/{id}",
			HostKind: "symbol", Language: "perl", Confidence: index.ConfLow,
			Location: index.Location{File: "bin/report", Line: 12},
		},
		index.Call{
			ID: "c3", Method: "DELETE", Host: "${sym:client.base}", Path: "/records/{id}/lock",
			HostKind: "symbol", Language: "perl", Confidence: index.ConfLow,
			Location: index.Location{File: "bin/report", Line: 20},
		},
	)
	got := runHostsIn(t, root)
	if n := strings.Count(got, "api.acme.com*"); n != 1 {
		t.Fatalf("api.acme.com appears %d times, want exactly 1 merged row:\n%s", n, got)
	}
	// 3 calls across 2 distinct paths: /records/{id} is reached through both
	// symbols and must not be counted twice.
	if !strings.Contains(got, "3") || !strings.Contains(got, "2") {
		t.Errorf("merged counts look wrong (want 3 calls, 2 paths):\n%s", got)
	}
	if !strings.Contains(got, "DELETE,GET") {
		t.Errorf("methods were not unioned across the merged symbols:\n%s", got)
	}
}

// --unresolved exists to show what still needs a mapping. A symbol the user has
// already mapped is resolved, just not by the scanner, and listing it would
// send them to fix what is already fixed.
func TestUnresolvedSkipsSymbolsThatAreAlreadyMapped(t *testing.T) {
	t.Parallel()
	root := writeRepo(t, mappedConfig, index.Call{
		ID: "c2", Method: "POST", Host: "${sym:Other::Thing.base}", Path: "/x",
		HostKind: "symbol", Language: "perl", Confidence: index.ConfLow,
		Location: index.Location{File: "lib/Other/Thing.pm", Line: 5},
	})
	got := runHostsIn(t, root, "--unresolved")
	if strings.Contains(got, "api.acme.com") {
		t.Errorf("a mapped host was reported as unresolved:\n%s", got)
	}
	if !strings.Contains(got, "${sym:Other::Thing.base}") {
		t.Errorf("the genuinely unresolved symbol is missing:\n%s", got)
	}
}
