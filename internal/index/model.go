// Package index defines the on-disk index of outbound API calls and the rules
// for merging a fresh scan into an existing one.
//
// The index is a committed, reviewable artifact. Its highest-value use is the
// git diff: a pull request that adds "POST https://api.newvendor.com/v1/charge"
// shows up in review. Two consequences follow, and both shape this file.
//
// First, encoding must be byte-deterministic -- stable sort order, sorted map
// keys, no absolute paths, no wall-clock values in comparable positions --
// otherwise every scan produces diff noise and people stop reading it.
//
// Second, identity must be stable. Call.ID deliberately excludes the line
// number: adding an import at the top of a file must not renumber every ID and
// orphan the upstream links and annotations a team has curated against them.
package index

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/stephen-bee/endpoint-monitor/internal/detect"
	"github.com/stephen-bee/endpoint-monitor/internal/normalize"
)

// SchemaVersion is bumped for breaking changes to the on-disk shape. A newer
// file than the binary understands is a hard error, never a silent misread.
const SchemaVersion = 1

// DetectorVersion is bumped whenever detection or normalization semantics
// change. It invalidates the parse cache and is compared in golden tests, so
// behavioural drift is visible rather than mysterious.
const DetectorVersion = 1

// DirName is the repo-local directory holding the index and its companions.
const DirName = ".api-integrity"

// IndexFileName is the index file inside DirName.
const IndexFileName = "index.json"

// Confidence is a coarse bucket derived from Score.
type Confidence string

const (
	ConfHigh   Confidence = "high"
	ConfMedium Confidence = "medium"
	ConfLow    Confidence = "low"
)

// ConfidenceFor maps a 0..100 score to its bucket.
func ConfidenceFor(score int) Confidence {
	switch {
	case score >= 80:
		return ConfHigh
	case score >= 50:
		return ConfMedium
	default:
		return ConfLow
	}
}

// CallKind distinguishes protocols. Only http is indexed by default.
type CallKind string

const (
	KindHTTP    CallKind = "http"
	KindWS      CallKind = "ws"
	KindGRPC    CallKind = "grpc"
	KindGraphQL CallKind = "graphql"
	KindSDK     CallKind = "sdk"
)

// Status tracks whether a call is still present in the code.
type Status string

const (
	StatusActive  Status = "active"
	StatusRemoved Status = "removed"
)

// MethodAny is recorded when the HTTP method cannot be determined.
const MethodAny = "ANY"

// Index is the whole artifact.
type Index struct {
	SchemaVersion int         `json:"schema_version"`
	Tool          ToolInfo    `json:"tool"`
	Repo          RepoInfo    `json:"repo"`
	Scan          ScanInfo    `json:"scan"`
	Stats         Stats       `json:"stats"`
	Hosts         []HostGroup `json:"hosts"`
	Calls         []Call      `json:"calls"`
}

// ToolInfo identifies the producer.
type ToolInfo struct {
	Name            string `json:"name"`
	Version         string `json:"version"`
	DetectorVersion int    `json:"detector_version"`
}

// RepoInfo describes the scanned repository. Root is a basename only: an
// absolute path here would leak the developer's home directory into a committed
// file and break golden tests across machines.
type RepoInfo struct {
	Root          string `json:"root"`
	Remote        string `json:"remote,omitempty"`
	DefaultBranch string `json:"default_branch,omitempty"`
}

// ScanInfo records one scan.
type ScanInfo struct {
	ID         string    `json:"id"`
	Commit     string    `json:"commit"`
	Dirty      bool      `json:"dirty"`
	Branch     string    `json:"branch,omitempty"`
	StartedAt  time.Time `json:"started_at"`
	DurationMS int64     `json:"duration_ms"`
	// Partial is set when scan-time filters narrowed traversal, which makes
	// "absent from this scan" mean "not looked at" rather than "deleted". Merge
	// depends on this distinction to avoid destroying a team's index.
	Partial bool     `json:"partial"`
	Filters []string `json:"filters,omitempty"`
}

// Stats summarizes a scan. Every skipped file and dropped site is counted, so
// "why didn't it find my call?" always has an answer.
type Stats struct {
	FilesWalked   int            `json:"files_walked"`
	FilesScanned  int            `json:"files_scanned"`
	FilesSkipped  map[string]int `json:"files_skipped,omitempty"`
	BytesScanned  int64          `json:"bytes_scanned"`
	SitesDetected int            `json:"sites_detected"`
	SitesDropped  map[string]int `json:"sites_dropped,omitempty"`
	ByLanguage    map[string]int `json:"by_language,omitempty"`
	ParseErrors   int            `json:"parse_errors"`
	UnresolvedTop []string       `json:"unresolved_top,omitempty"`
}

// Call is one detected outbound API call.
type Call struct {
	ID          string              `json:"id"`
	Fingerprint string              `json:"fingerprint"`
	Host        string              `json:"host"`
	HostKind    normalize.HostKind  `json:"host_kind"`
	Vendor      string              `json:"vendor,omitempty"`
	Scheme      string              `json:"scheme,omitempty"`
	Port        int                 `json:"port,omitempty"`
	Method      string              `json:"method"`
	Path        string              `json:"path"`
	PathVars    []normalize.PathVar `json:"path_vars,omitempty"`
	QueryKeys   []string            `json:"query_keys,omitempty"`
	Kind        CallKind            `json:"kind"`
	RawExpr     string              `json:"raw_expr"`
	Location    Location            `json:"location"`
	Language    detect.Language     `json:"language"`
	Client      string              `json:"client"`
	Pattern     string              `json:"pattern"`
	Detector    string              `json:"detector"`
	Confidence  Confidence          `json:"confidence"`
	Score       int                 `json:"score"`
	Flags       []string            `json:"flags,omitempty"`
	Unresolved  []string            `json:"unresolved,omitempty"`
	Lifecycle   Lifecycle           `json:"lifecycle"`
}

// Location points at the call site in the scanned repo.
type Location struct {
	File     string `json:"file"`
	Line     int    `json:"line"`
	Column   int    `json:"column,omitempty"`
	EndLine  int    `json:"end_line,omitempty"`
	Function string `json:"function,omitempty"`
}

// Lifecycle tracks a call across scans, which is what lets the tool report
// "this endpoint is new in this PR" and "this one disappeared".
type Lifecycle struct {
	FirstSeenScan   string `json:"first_seen_scan"`
	FirstSeenCommit string `json:"first_seen_commit,omitempty"`
	LastSeenScan    string `json:"last_seen_scan"`
	LastSeenCommit  string `json:"last_seen_commit,omitempty"`
	Status          Status `json:"status"`
	MissingScans    int    `json:"missing_scans,omitempty"`
}

// HostGroup is a derived per-host summary. It is always recomputed, never
// merged, so it cannot drift out of step with Calls.
type HostGroup struct {
	HostKey       string             `json:"host_key"`
	HostKind      normalize.HostKind `json:"host_kind"`
	Vendor        string             `json:"vendor,omitempty"`
	CallCount     int                `json:"call_count"`
	PathCount     int                `json:"path_count"`
	Methods       []string           `json:"methods,omitempty"`
	Languages     []string           `json:"languages,omitempty"`
	MaxConfidence Confidence         `json:"max_confidence"`
}

// hashPrefix is the identity hash prefix length in hex characters. 16 hex
// characters is 64 bits: collision-free in practice for a repo's call sites,
// and short enough to read in a diff.
const hashPrefix = 16

// ComputeFingerprint identifies what a call targets, independent of where it is
// written. Three files calling the same endpoint share a fingerprint, which is
// what makes reports aggregate and annotations survive refactors.
func ComputeFingerprint(kind CallKind, host, method, path string) string {
	sum := sha256.Sum256([]byte(strings.Join([]string{"v1", string(kind), host, method, path}, "\x00")))
	return "f_" + hex.EncodeToString(sum[:])[:hashPrefix]
}

// ComputeID identifies a call uniquely within a repo. The line number is
// excluded on purpose (see the package comment); the ordinal disambiguates the
// same endpoint called twice from one file.
func ComputeID(fingerprint, file, client string, ordinal int) string {
	sum := sha256.Sum256([]byte(strings.Join([]string{"v1", fingerprint, file, client, strconv.Itoa(ordinal)}, "\x00")))
	return "c_" + hex.EncodeToString(sum[:])[:hashPrefix]
}

// ScanID derives a deterministic-per-scan identifier.
func ScanID(commit string, startedAt time.Time) string {
	sum := sha256.Sum256([]byte(commit + "\x00" + startedAt.UTC().Format(time.RFC3339Nano)))
	return "s_" + hex.EncodeToString(sum[:])[:12]
}

// AssignIdentity fills Fingerprint and ID for every call and sorts the slice
// into canonical order. Ordinals are assigned by ascending line within each
// (file, fingerprint) group so they are stable as unrelated code moves.
func AssignIdentity(calls []Call) {
	for i := range calls {
		calls[i].Fingerprint = ComputeFingerprint(calls[i].Kind, calls[i].Host, calls[i].Method, calls[i].Path)
		calls[i].Flags = sortUnique(calls[i].Flags)
		calls[i].Unresolved = sortUnique(calls[i].Unresolved)
		calls[i].QueryKeys = sortUnique(calls[i].QueryKeys)
		if calls[i].Confidence == "" {
			calls[i].Confidence = ConfidenceFor(calls[i].Score)
		}
	}
	// Order by position first so ordinals follow source order.
	sort.SliceStable(calls, func(i, j int) bool { return lessByPosition(calls[i], calls[j]) })
	ordinals := map[string]int{}
	for i := range calls {
		key := calls[i].Location.File + "\x00" + calls[i].Fingerprint + "\x00" + calls[i].Client
		n := ordinals[key]
		ordinals[key] = n + 1
		calls[i].ID = ComputeID(calls[i].Fingerprint, calls[i].Location.File, calls[i].Client, n)
	}
	Sort(calls)
}

func lessByPosition(a, b Call) bool {
	if a.Location.File != b.Location.File {
		return a.Location.File < b.Location.File
	}
	if a.Location.Line != b.Location.Line {
		return a.Location.Line < b.Location.Line
	}
	if a.Location.Column != b.Location.Column {
		return a.Location.Column < b.Location.Column
	}
	if a.Fingerprint != b.Fingerprint {
		return a.Fingerprint < b.Fingerprint
	}
	return a.Client < b.Client
}

// Sort puts calls in canonical order. The final ID tiebreak makes the order
// total, so output cannot vary between runs.
func Sort(calls []Call) {
	sort.SliceStable(calls, func(i, j int) bool {
		if lessByPosition(calls[i], calls[j]) {
			return true
		}
		if lessByPosition(calls[j], calls[i]) {
			return false
		}
		return calls[i].ID < calls[j].ID
	})
}

// BuildHosts recomputes the derived host summary from calls.
func BuildHosts(calls []Call, vendors map[string]string) []HostGroup {
	type acc struct {
		g       HostGroup
		paths   map[string]bool
		methods map[string]bool
		langs   map[string]bool
		best    int
	}
	byHost := map[string]*acc{}
	for _, c := range calls {
		if c.Lifecycle.Status == StatusRemoved {
			continue
		}
		a, ok := byHost[c.Host]
		if !ok {
			a = &acc{
				g:       HostGroup{HostKey: c.Host, HostKind: c.HostKind, Vendor: vendors[c.Host]},
				paths:   map[string]bool{},
				methods: map[string]bool{},
				langs:   map[string]bool{},
				best:    -1,
			}
			byHost[c.Host] = a
		}
		if a.g.Vendor == "" && c.Vendor != "" {
			a.g.Vendor = c.Vendor
		}
		a.g.CallCount++
		a.paths[c.Path] = true
		a.methods[c.Method] = true
		a.langs[string(c.Language)] = true
		if c.Score > a.best {
			a.best = c.Score
		}
	}
	out := make([]HostGroup, 0, len(byHost))
	for _, a := range byHost {
		a.g.PathCount = len(a.paths)
		a.g.Methods = sortedSetKeys(a.methods)
		a.g.Languages = sortedSetKeys(a.langs)
		a.g.MaxConfidence = ConfidenceFor(a.best)
		out = append(out, a.g)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].HostKey < out[j].HostKey })
	return out
}

// Encode writes i in the canonical form: two-space indent, unescaped HTML,
// sorted map keys (encoding/json guarantees this), and exactly one trailing
// newline.
func Encode(i *Index) ([]byte, error) {
	var b strings.Builder
	enc := json.NewEncoder(&b)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	if err := enc.Encode(i); err != nil {
		return nil, fmt.Errorf("encode index: %w", err)
	}
	// Encode already appends exactly one newline.
	return []byte(b.String()), nil
}

// Save atomically writes the index under dir/DirName. The temp file is created
// in the destination directory so the rename cannot cross filesystems, and an
// interrupted write leaves the previous index intact.
func Save(dir string, i *Index) error {
	outDir := filepath.Join(dir, DirName)
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return fmt.Errorf("create %s: %w", outDir, err)
	}
	data, err := Encode(i)
	if err != nil {
		return err
	}
	dst := filepath.Join(outDir, IndexFileName)
	tmp, err := os.CreateTemp(outDir, ".index-*.tmp")
	if err != nil {
		return fmt.Errorf("create temp index: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("write temp index: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("sync temp index: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp index: %w", err)
	}
	if err := os.Chmod(tmpName, 0o644); err != nil {
		return fmt.Errorf("chmod temp index: %w", err)
	}
	if err := os.Rename(tmpName, dst); err != nil {
		return fmt.Errorf("replace index: %w", err)
	}
	return nil
}

// Load reads the index under dir/DirName. A missing file is not an error: it
// returns nil so callers can treat "first scan" uniformly.
func Load(dir string) (*Index, error) {
	path := filepath.Join(dir, DirName, IndexFileName)
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	var i Index
	if err := json.Unmarshal(data, &i); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if i.SchemaVersion > SchemaVersion {
		return nil, fmt.Errorf("%s was written by a newer version of this tool (schema %d, this binary understands %d); upgrade the tool",
			path, i.SchemaVersion, SchemaVersion)
	}
	return &i, nil
}

func sortUnique(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	if len(out) == 0 {
		return nil
	}
	sort.Strings(out)
	return out
}

func sortedSetKeys(m map[string]bool) []string {
	if len(m) == 0 {
		return nil
	}
	out := make([]string, 0, len(m))
	for k := range m {
		if k != "" {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}
