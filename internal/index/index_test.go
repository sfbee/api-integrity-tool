package index

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sfbee/api-integrity-tool/internal/detect"
	"github.com/sfbee/api-integrity-tool/internal/normalize"
)

func call(file string, line int, host, method, path string) Call {
	return Call{
		Host: host, HostKind: normalize.HostLiteral, Method: method, Path: path,
		Kind: KindHTTP, Scheme: "https", Client: "net/http", Pattern: "net/http.pkgfunc",
		Detector: "go/ast", Language: detect.LangGo, Score: 90,
		Location: Location{File: file, Line: line},
	}
}

func indexOf(scanID, commit string, calls ...Call) *Index {
	AssignIdentity(calls)
	i := &Index{
		SchemaVersion: SchemaVersion,
		Tool:          ToolInfo{Name: "api-integrity-tool", Version: "test", DetectorVersion: DetectorVersion},
		Repo:          RepoInfo{Root: "fixture"},
		Scan:          ScanInfo{ID: scanID, Commit: commit, StartedAt: time.Unix(0, 0).UTC()},
		Calls:         calls,
	}
	finish(i)
	return i
}

func TestFingerprintIdentifiesTheTarget(t *testing.T) {
	t.Parallel()
	a := ComputeFingerprint(KindHTTP, "api.example.com", "POST", "/api/v1/user/add")
	b := ComputeFingerprint(KindHTTP, "api.example.com", "POST", "/api/v1/user/add")
	if a != b {
		t.Errorf("same target produced different fingerprints: %s vs %s", a, b)
	}
	for _, other := range []string{
		ComputeFingerprint(KindHTTP, "api.other.com", "POST", "/api/v1/user/add"),
		ComputeFingerprint(KindHTTP, "api.example.com", "GET", "/api/v1/user/add"),
		ComputeFingerprint(KindHTTP, "api.example.com", "POST", "/api/v1/user/remove"),
		ComputeFingerprint(KindWS, "api.example.com", "POST", "/api/v1/user/add"),
	} {
		if a == other {
			t.Errorf("different targets collided on %s", a)
		}
	}
	if !strings.HasPrefix(a, "f_") {
		t.Errorf("fingerprint %q lacks the f_ prefix", a)
	}
}

// The whole point of excluding the line number from the ID: inserting an import
// must not renumber every call and orphan the user's upstream links.
func TestIDIsStableAcrossLineDrift(t *testing.T) {
	t.Parallel()
	early := []Call{call("a.go", 10, "api.example.com", "GET", "/v1/x")}
	later := []Call{call("a.go", 42, "api.example.com", "GET", "/v1/x")}
	AssignIdentity(early)
	AssignIdentity(later)
	if early[0].ID != later[0].ID {
		t.Errorf("ID changed with line number: %s vs %s", early[0].ID, later[0].ID)
	}
}

func TestIDDistinguishesRepeatedCallsInOneFile(t *testing.T) {
	t.Parallel()
	calls := []Call{
		call("a.go", 10, "api.example.com", "GET", "/v1/x"),
		call("a.go", 20, "api.example.com", "GET", "/v1/x"),
	}
	AssignIdentity(calls)
	if calls[0].ID == calls[1].ID {
		t.Fatalf("two call sites share ID %s", calls[0].ID)
	}
	if calls[0].Fingerprint != calls[1].Fingerprint {
		t.Errorf("same endpoint should share a fingerprint")
	}
}

func TestIDDiffersAcrossFiles(t *testing.T) {
	t.Parallel()
	calls := []Call{
		call("a.go", 10, "api.example.com", "GET", "/v1/x"),
		call("b.go", 10, "api.example.com", "GET", "/v1/x"),
	}
	AssignIdentity(calls)
	if calls[0].ID == calls[1].ID {
		t.Error("calls in different files share an ID")
	}
}

func TestSortIsTotalAndDeterministic(t *testing.T) {
	t.Parallel()
	mk := func() []Call {
		return []Call{
			call("z.go", 5, "h.example.com", "GET", "/c"),
			call("a.go", 30, "h.example.com", "GET", "/a"),
			call("a.go", 5, "h.example.com", "POST", "/b"),
			call("a.go", 5, "h.example.com", "GET", "/b"),
		}
	}
	first := mk()
	AssignIdentity(first)
	for range 20 {
		other := mk()
		AssignIdentity(other)
		for i := range first {
			if first[i].ID != other[i].ID {
				t.Fatalf("order varied between runs at position %d: %s vs %s", i, first[i].ID, other[i].ID)
			}
		}
	}
	// No two entries may compare equal, or the order is not total.
	for i := 1; i < len(first); i++ {
		a, b := first[i-1], first[i]
		if !lessByPosition(a, b) && !lessByPosition(b, a) && a.ID == b.ID {
			t.Errorf("entries %d and %d are indistinguishable", i-1, i)
		}
	}
}

func TestEncodeIsCanonical(t *testing.T) {
	t.Parallel()
	i := indexOf("s_1", "abc", call("a.go", 1, "api.example.com", "GET", "/v1/x"))
	i.Stats.FilesSkipped = map[string]int{"too_large": 2, "binary": 1, "excluded": 3}
	a, err := Encode(i)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Encode(i)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a, b) {
		t.Error("Encode is not deterministic")
	}
	if !bytes.HasSuffix(a, []byte("}\n")) || bytes.HasSuffix(a, []byte("\n\n")) {
		t.Error("want exactly one trailing newline")
	}
	if bytes.Contains(a, []byte("\r")) {
		t.Error("encoded index contains CR")
	}
	// Map keys must be sorted, which encoding/json guarantees; assert it so a
	// future switch to a different encoder cannot silently break diffability.
	s := string(a)
	if strings.Index(s, `"binary"`) > strings.Index(s, `"excluded"`) ||
		strings.Index(s, `"excluded"`) > strings.Index(s, `"too_large"`) {
		t.Error("map keys are not sorted in the encoded output")
	}
	if strings.Contains(s, `\u003c`) {
		t.Error("HTML escaping is enabled; URLs would be mangled")
	}
}

func TestEncodeHasNoAbsolutePaths(t *testing.T) {
	t.Parallel()
	i := indexOf("s_1", "abc", call("internal/client/client.go", 1, "api.example.com", "GET", "/v1/x"))
	data, err := Encode(i)
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"/Users/", "/home/", "C:\\", os.TempDir()} {
		if bad != "" && bytes.Contains(data, []byte(bad)) {
			t.Errorf("encoded index leaks an absolute path fragment %q", bad)
		}
	}
}

func TestSaveLoadRoundTrip(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	want := indexOf("s_1", "abc", call("a.go", 1, "api.example.com", "GET", "/v1/x"))
	if err := Save(dir, want); err != nil {
		t.Fatal(err)
	}
	got, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got == nil {
		t.Fatal("Load returned nil after Save")
	}
	if len(got.Calls) != 1 || got.Calls[0].ID != want.Calls[0].ID {
		t.Errorf("round trip lost the call: %+v", got.Calls)
	}
	// A second Save must leave no temp files behind.
	if err := Save(dir, want); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(filepath.Join(dir, DirName))
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".tmp") {
			t.Errorf("temp file left behind: %s", e.Name())
		}
	}
}

func TestLoadMissingIsNotAnError(t *testing.T) {
	t.Parallel()
	got, err := Load(t.TempDir())
	if err != nil || got != nil {
		t.Errorf("Load of a fresh dir = %v, %v; want nil, nil", got, err)
	}
}

func TestLoadRejectsNewerSchema(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, DirName), 0o755); err != nil {
		t.Fatal(err)
	}
	body := []byte(`{"schema_version": 9999}`)
	if err := os.WriteFile(filepath.Join(dir, DirName, IndexFileName), body, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(dir); err == nil {
		t.Fatal("want an error for a newer schema, got nil")
	} else if !strings.Contains(err.Error(), "upgrade the tool") {
		t.Errorf("error should tell the user what to do, got: %v", err)
	}
}

func TestMergeFirstScan(t *testing.T) {
	t.Parallel()
	next := indexOf("s_1", "c1", call("a.go", 1, "api.example.com", "GET", "/v1/x"))
	got, rep := Merge(nil, next, MergeOptions{})
	if rep.Added != 1 || rep.Removed != 0 {
		t.Errorf("report = %+v, want 1 added", rep)
	}
	lc := got.Calls[0].Lifecycle
	if lc.FirstSeenScan != "s_1" || lc.LastSeenScan != "s_1" || lc.Status != StatusActive {
		t.Errorf("lifecycle = %+v", lc)
	}
	if !rep.Changed() {
		t.Error("Changed() = false on a first scan with calls")
	}
}

func TestMergeIsIdempotent(t *testing.T) {
	t.Parallel()
	c := call("a.go", 1, "api.example.com", "GET", "/v1/x")
	first, _ := Merge(nil, indexOf("s_1", "c1", c), MergeOptions{})
	second, rep := Merge(first, indexOf("s_2", "c2", c), MergeOptions{})
	if rep.Added != 0 || rep.Removed != 0 || rep.Restored != 0 || rep.Pruned != 0 {
		t.Errorf("re-scanning identical code changed the index: %+v", rep)
	}
	if rep.Changed() {
		t.Error("Changed() = true for an unchanged re-scan")
	}
	if got := second.Calls[0].Lifecycle; got.FirstSeenScan != "s_1" || got.LastSeenScan != "s_2" {
		t.Errorf("lifecycle = %+v, want first s_1 last s_2", got)
	}
}

func TestMergeTracksAMovedCall(t *testing.T) {
	t.Parallel()
	prev, _ := Merge(nil, indexOf("s_1", "c1", call("a.go", 10, "api.example.com", "GET", "/v1/x")), MergeOptions{})
	got, rep := Merge(prev, indexOf("s_2", "c2", call("a.go", 99, "api.example.com", "GET", "/v1/x")), MergeOptions{})
	if rep.Added != 0 || rep.Removed != 0 {
		t.Errorf("a moved line should not add or remove: %+v", rep)
	}
	if len(rep.Relocated) != 1 || rep.Relocated[0].OldLine != 10 || rep.Relocated[0].NewLine != 99 {
		t.Errorf("Relocated = %+v", rep.Relocated)
	}
	if got.Calls[0].Lifecycle.FirstSeenScan != "s_1" {
		t.Error("history lost when the line moved")
	}
}

func TestMergeTracksARenamedFile(t *testing.T) {
	t.Parallel()
	prev, _ := Merge(nil, indexOf("s_1", "c1", call("old.go", 10, "api.example.com", "GET", "/v1/x")), MergeOptions{})
	got, rep := Merge(prev, indexOf("s_2", "c2", call("new.go", 10, "api.example.com", "GET", "/v1/x")), MergeOptions{})
	if rep.Added != 0 || rep.Removed != 0 {
		t.Errorf("a renamed file should not add or remove: %+v", rep)
	}
	if got.Calls[0].Lifecycle.FirstSeenScan != "s_1" {
		t.Error("history lost when the file was renamed")
	}
}

func TestMergeMarksAndPrunesRemovedCalls(t *testing.T) {
	t.Parallel()
	kept := call("a.go", 1, "api.example.com", "GET", "/keep")
	gone := call("a.go", 2, "api.example.com", "GET", "/gone")
	cur, _ := Merge(nil, indexOf("s_0", "c0", kept, gone), MergeOptions{})

	opts := MergeOptions{PruneAfterMissingScans: 2}
	cur, rep := Merge(cur, indexOf("s_1", "c1", kept), opts)
	if rep.Removed != 1 || len(cur.Calls) != 2 {
		t.Fatalf("first absence: report %+v, %d calls", rep, len(cur.Calls))
	}
	var removed *Call
	for i := range cur.Calls {
		if cur.Calls[i].Path == "/gone" {
			removed = &cur.Calls[i]
		}
	}
	if removed == nil || removed.Lifecycle.Status != StatusRemoved || removed.Lifecycle.MissingScans != 1 {
		t.Fatalf("removed call = %+v", removed)
	}
	// A removed call is excluded from the derived host summary counts.
	for _, h := range cur.Hosts {
		if h.HostKey == "api.example.com" && h.CallCount != 1 {
			t.Errorf("host CallCount = %d, want 1 (removed calls excluded)", h.CallCount)
		}
	}

	cur, _ = Merge(cur, indexOf("s_2", "c2", kept), opts)
	cur, rep = Merge(cur, indexOf("s_3", "c3", kept), opts)
	if rep.Pruned != 1 {
		t.Errorf("want the call pruned after exceeding the retention, got %+v", rep)
	}
	if len(cur.Calls) != 1 {
		t.Errorf("want 1 call after pruning, got %d", len(cur.Calls))
	}
}

func TestMergeRestoresAReturningCall(t *testing.T) {
	t.Parallel()
	kept := call("a.go", 1, "api.example.com", "GET", "/keep")
	flaky := call("a.go", 2, "api.example.com", "GET", "/flaky")
	cur, _ := Merge(nil, indexOf("s_0", "c0", kept, flaky), MergeOptions{})
	cur, _ = Merge(cur, indexOf("s_1", "c1", kept), MergeOptions{})
	cur, rep := Merge(cur, indexOf("s_2", "c2", kept, flaky), MergeOptions{})
	if rep.Restored != 1 {
		t.Errorf("want 1 restored, got %+v", rep)
	}
	for _, c := range cur.Calls {
		if c.Path == "/flaky" {
			if c.Lifecycle.Status != StatusActive {
				t.Errorf("restored call still marked %s", c.Lifecycle.Status)
			}
			if c.Lifecycle.FirstSeenScan != "s_0" {
				t.Errorf("restored call lost its original first-seen: %+v", c.Lifecycle)
			}
		}
	}
}

// A filtered scan must never conclude that out-of-scope calls were deleted.
// Without this guard, "scan --lang go" would wipe every Python call from the index.
func TestMergePartialScanDoesNotRemoveOutOfScopeCalls(t *testing.T) {
	t.Parallel()
	goCall := call("a.go", 1, "api.example.com", "GET", "/go")
	pyCall := call("b.py", 1, "api.example.com", "GET", "/py")
	pyCall.Language = detect.LangPython
	cur, _ := Merge(nil, indexOf("s_0", "c0", goCall, pyCall), MergeOptions{})

	narrowed := indexOf("s_1", "c1", goCall)
	narrowed.Scan.Partial = true
	got, rep := Merge(cur, narrowed, MergeOptions{
		Partial:      true,
		PartialScope: func(c Call) bool { return c.Language == detect.LangGo },
	})
	if rep.Removed != 0 {
		t.Errorf("a Go-only scan removed %d calls; it must not touch other languages", rep.Removed)
	}
	if rep.CarriedFwd != 1 {
		t.Errorf("CarriedFwd = %d, want 1", rep.CarriedFwd)
	}
	if len(got.Calls) != 2 {
		t.Fatalf("want both calls retained, got %d", len(got.Calls))
	}
	for _, c := range got.Calls {
		if c.Path == "/py" && c.Lifecycle.Status != StatusActive {
			t.Errorf("out-of-scope call was marked %s", c.Lifecycle.Status)
		}
	}
}

func TestBuildHostsAggregates(t *testing.T) {
	t.Parallel()
	a := call("a.go", 1, "api.example.com", "GET", "/v1/x")
	b := call("a.go", 2, "api.example.com", "POST", "/v1/y")
	c := call("b.py", 3, "api.other.com", "GET", "/z")
	c.Language = detect.LangPython
	c.Score = 40
	hosts := BuildHosts([]Call{a, b, c}, map[string]string{"api.example.com": "Example"})
	if len(hosts) != 2 {
		t.Fatalf("want 2 host groups, got %d", len(hosts))
	}
	if hosts[0].HostKey != "api.example.com" || hosts[1].HostKey != "api.other.com" {
		t.Errorf("host groups not sorted: %+v", hosts)
	}
	h := hosts[0]
	if h.CallCount != 2 || h.PathCount != 2 || h.Vendor != "Example" {
		t.Errorf("group = %+v", h)
	}
	if strings.Join(h.Methods, ",") != "GET,POST" {
		t.Errorf("Methods = %v, want sorted GET,POST", h.Methods)
	}
	if hosts[1].MaxConfidence != ConfLow {
		t.Errorf("MaxConfidence = %q, want low for score 40", hosts[1].MaxConfidence)
	}
}

func TestConfidenceBuckets(t *testing.T) {
	t.Parallel()
	for score, want := range map[int]Confidence{0: ConfLow, 49: ConfLow, 50: ConfMedium, 79: ConfMedium, 80: ConfHigh, 100: ConfHigh} {
		if got := ConfidenceFor(score); got != want {
			t.Errorf("ConfidenceFor(%d) = %q, want %q", score, got, want)
		}
	}
}
