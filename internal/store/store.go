// Package store persists the mutable state that the index does not cover:
// upstream repository links, decisions not to monitor a host, findings, and
// per-upstream check state.
//
// Three processes can touch this concurrently -- an MCP server running a check,
// the dashboard acknowledging a finding, and a CLI `check` in another terminal.
// Every mutation therefore takes an advisory file lock, re-reads state, applies
// the change and writes atomically, so a lost update is not possible even
// though the backing store is a plain JSON file.
//
// JSON rather than a database: the state is small, a human can read it when
// something looks wrong, and it avoids a dependency for a problem that a lock
// and an atomic rename already solve.
package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/sfbee/api-integrity-tool/internal/model"
)

// Version is the state schema version.
const Version = 1

// FileName is the state file inside the .api-integrity directory.
const FileName = "state.json"

// lockName is the advisory lock guarding read-modify-write cycles.
const lockName = ".state.lock"

// UpstreamState is what we remember about one upstream between checks. Without
// it every run would re-analyze the whole history and re-report every finding.
type UpstreamState struct {
	DefaultBranch string    `json:"default_branch,omitempty"`
	LastHeadSHA   string    `json:"last_head_sha,omitempty"`
	LastCheckedAt time.Time `json:"last_checked_at,omitempty"`
	// PushedAtSeen is the cheapest possible gate: if the repository has not been
	// pushed since we last looked, the entire upstream is skipped.
	PushedAtSeen   time.Time `json:"pushed_at_seen,omitempty"`
	LastReleaseTag string    `json:"last_release_tag,omitempty"`
	LastTagName    string    `json:"last_tag_name,omitempty"`
	SpecPaths      []string  `json:"spec_paths,omitempty"`
	// ETags are keyed by request URL. A 304 response costs no rate limit at
	// all, which is the whole reason for storing these.
	ETags               map[string]string `json:"etags,omitempty"`
	Status              string            `json:"status,omitempty"`
	LastError           string            `json:"last_error,omitempty"`
	ConsecutiveFailures int               `json:"consecutive_failures,omitempty"`
	// SkipUntilRun backs off a repository that keeps failing, so a deleted repo
	// does not burn API quota on every run.
	SkipUntilRun int `json:"skip_until_run,omitempty"`
}

// Run records one check.
type Run struct {
	ID          string       `json:"id"`
	Seq         int          `json:"seq"`
	StartedAt   time.Time    `json:"started_at"`
	FinishedAt  *time.Time   `json:"finished_at,omitempty"`
	Trigger     string       `json:"trigger"`
	Checked     int          `json:"upstreams_checked"`
	Skipped     int          `json:"upstreams_skipped"`
	APICalls    int          `json:"api_calls"`
	NewFindings int          `json:"findings_new"`
	Counts      model.Counts `json:"counts"`
	Degraded    []string     `json:"degraded,omitempty"`
	Errors      []string     `json:"errors,omitempty"`
	Complete    bool         `json:"complete"`
}

// State is the whole persisted document.
type State struct {
	Version   int                      `json:"version"`
	UpdatedAt time.Time                `json:"updated_at"`
	Upstreams []model.Upstream         `json:"upstreams,omitempty"`
	Decisions []model.Decision         `json:"decisions,omitempty"`
	Findings  []model.Finding          `json:"findings,omitempty"`
	Checks    map[string]UpstreamState `json:"checks,omitempty"`
	Runs      []Run                    `json:"runs,omitempty"`
	RunSeq    int                      `json:"run_seq,omitempty"`
}

// MaxRuns bounds the retained run history so the file cannot grow without limit.
const MaxRuns = 50

// Store reads and writes State under a repository directory.
type Store struct {
	dir string
	now func() time.Time
	// mu serializes writers inside this process; the file lock handles other
	// processes. Both are needed: a mutex alone would not stop a second CLI
	// invocation, and a file lock alone can be re-entered by goroutines.
	mu sync.Mutex
}

// Open returns a store rooted at repoDir/.api-integrity, creating the directory
// if needed. now may be nil, in which case time.Now is used.
func Open(repoDir string, now func() time.Time) (*Store, error) {
	if now == nil {
		now = time.Now
	}
	dir := filepath.Join(repoDir, ".api-integrity")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("create %s: %w", dir, err)
	}
	return &Store{dir: dir, now: now}, nil
}

// Dir returns the state directory.
func (s *Store) Dir() string { return s.dir }

// Path returns the state file path.
func (s *Store) Path() string { return filepath.Join(s.dir, FileName) }

// Read returns a copy of the current state. A missing file yields an empty
// state rather than an error, so first use needs no special handling.
func (s *Store) Read() (*State, error) {
	unlock, err := s.lock(true)
	if err != nil {
		return nil, err
	}
	defer unlock()
	return s.readLocked()
}

func (s *Store) readLocked() (*State, error) {
	data, err := os.ReadFile(s.Path())
	if errors.Is(err, os.ErrNotExist) {
		return &State{Version: Version, Checks: map[string]UpstreamState{}}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", s.Path(), err)
	}
	var st State
	if err := json.Unmarshal(data, &st); err != nil {
		return nil, fmt.Errorf("parse %s: %w", s.Path(), err)
	}
	if st.Version > Version {
		return nil, fmt.Errorf("%s was written by a newer version of this tool (schema %d, this binary understands %d); upgrade the tool",
			s.Path(), st.Version, Version)
	}
	if st.Checks == nil {
		st.Checks = map[string]UpstreamState{}
	}
	return &st, nil
}

// Update applies fn to the state under an exclusive lock and writes the result.
// fn may be called only once; if it returns an error nothing is written.
func (s *Store) Update(fn func(*State) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	unlock, err := s.lock(false)
	if err != nil {
		return err
	}
	defer unlock()

	st, err := s.readLocked()
	if err != nil {
		return err
	}
	if err := fn(st); err != nil {
		return err
	}
	st.Version = Version
	st.UpdatedAt = s.now().UTC()
	normalize(st)
	return s.writeLocked(st)
}

func (s *Store) writeLocked(st *State) error {
	var buf strings.Builder
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	if err := enc.Encode(st); err != nil {
		return fmt.Errorf("encode state: %w", err)
	}
	tmp, err := os.CreateTemp(s.dir, ".state-*.tmp")
	if err != nil {
		return fmt.Errorf("create temp state: %w", err)
	}
	name := tmp.Name()
	defer os.Remove(name)
	if _, err := tmp.WriteString(buf.String()); err != nil {
		tmp.Close()
		return fmt.Errorf("write temp state: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("sync temp state: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp state: %w", err)
	}
	// State can name private repositories, so it is not world-readable.
	if err := os.Chmod(name, 0o600); err != nil {
		return fmt.Errorf("chmod temp state: %w", err)
	}
	if err := os.Rename(name, s.Path()); err != nil {
		return fmt.Errorf("replace state: %w", err)
	}
	return nil
}

// normalize keeps the document in a stable order so diffs stay readable and
// tests do not depend on insertion order.
func normalize(st *State) {
	sort.SliceStable(st.Upstreams, func(i, j int) bool {
		a, b := st.Upstreams[i], st.Upstreams[j]
		if a.Host != b.Host {
			return a.Host < b.Host
		}
		if a.PathPrefix != b.PathPrefix {
			return a.PathPrefix > b.PathPrefix // longest prefix first
		}
		if a.Priority != b.Priority {
			return a.Priority < b.Priority
		}
		return a.Repo.Key() < b.Repo.Key()
	})
	sort.SliceStable(st.Decisions, func(i, j int) bool { return st.Decisions[i].Host < st.Decisions[j].Host })
	model.SortFindings(st.Findings)
	sort.SliceStable(st.Runs, func(i, j int) bool { return st.Runs[i].Seq > st.Runs[j].Seq })
	if len(st.Runs) > MaxRuns {
		st.Runs = st.Runs[:MaxRuns]
	}
}

// LinkUpstream adds or replaces the link for (host, repo key, path prefix).
// Re-linking the same triple updates it in place rather than accumulating
// duplicates.
func (s *Store) LinkUpstream(u model.Upstream) error {
	return s.Update(func(st *State) error {
		now := s.now().UTC()
		if u.Role == "" {
			u.Role = model.RoleImplementation
		}
		if u.Status == "" {
			u.Status = "active"
		}
		u.UpdatedAt = now
		for i := range st.Upstreams {
			e := &st.Upstreams[i]
			if e.Host == u.Host && e.Repo.Key() == u.Repo.Key() && e.PathPrefix == u.PathPrefix {
				u.CreatedAt = e.CreatedAt
				*e = u
				return nil
			}
		}
		u.CreatedAt = now
		st.Upstreams = append(st.Upstreams, u)
		// Linking a host answers the question a decision was suppressing.
		st.Decisions = dropDecision(st.Decisions, u.Host)
		return nil
	})
}

// UnlinkHost removes every upstream for a host, reporting how many went.
func (s *Store) UnlinkHost(host string) (int, error) {
	var removed int
	err := s.Update(func(st *State) error {
		kept := st.Upstreams[:0]
		for _, u := range st.Upstreams {
			if u.Host == host {
				removed++
				continue
			}
			kept = append(kept, u)
		}
		st.Upstreams = kept
		return nil
	})
	return removed, err
}

// SetDecision records that a host is deliberately unlinked. A "later" decision
// gets an expiry so a dismissal does not become permanent silence.
func (s *Store) SetDecision(d model.Decision) error {
	return s.Update(func(st *State) error {
		if d.DecidedAt.IsZero() {
			d.DecidedAt = s.now().UTC()
		}
		if d.Kind == model.DecisionLater && d.ExpiresAt == nil {
			t := d.DecidedAt.Add(7 * 24 * time.Hour)
			d.ExpiresAt = &t
		}
		st.Decisions = append(dropDecision(st.Decisions, d.Host), d)
		return nil
	})
}

// ClearDecision removes any decision for a host, so it will be asked about again.
func (s *Store) ClearDecision(host string) error {
	return s.Update(func(st *State) error {
		st.Decisions = dropDecision(st.Decisions, host)
		return nil
	})
}

func dropDecision(in []model.Decision, host string) []model.Decision {
	out := in[:0]
	for _, d := range in {
		if d.Host != host {
			out = append(out, d)
		}
	}
	return out
}

// UpsertFindings merges fresh findings into the stored set, matching on
// fingerprint. An existing finding has its occurrence count and last-seen time
// advanced while its acknowledgement is preserved -- re-reporting something the
// user already dismissed is the fastest way to make them ignore the tool.
func (s *Store) UpsertFindings(fresh []model.Finding) (added int, updated int, err error) {
	err = s.Update(func(st *State) error {
		byFP := make(map[string]int, len(st.Findings))
		for i, f := range st.Findings {
			byFP[f.Fingerprint] = i
		}
		now := s.now().UTC()
		for _, f := range fresh {
			if i, ok := byFP[f.Fingerprint]; ok {
				e := &st.Findings[i]
				e.Occurrences++
				e.LastSeenAt = now
				e.CommitSHA, e.BaseSHA, e.HeadSHA = f.CommitSHA, f.BaseSHA, f.HeadSHA
				e.CompareURL = f.CompareURL
				e.Evidence = f.Evidence
				e.Endpoints = f.Endpoints
				e.Corroborated = e.Corroborated || f.Corroborated
				// An acknowledged finding resurfaces only if it got worse.
				if f.Severity.Rank() < e.Severity.Rank() {
					e.Severity = f.Severity
					if e.Status == model.StatusAcked {
						e.Status = model.StatusOpen
						e.StatusNote = "reopened: severity increased"
					}
				}
				updated++
				continue
			}
			f.FirstSeenAt, f.LastSeenAt = now, now
			f.Occurrences = 1
			if f.Status == "" {
				f.Status = model.StatusOpen
			}
			st.Findings = append(st.Findings, f)
			byFP[f.Fingerprint] = len(st.Findings) - 1
			added++
		}
		return nil
	})
	return added, updated, err
}

// SetFindingStatus updates one finding's triage state.
func (s *Store) SetFindingStatus(id, status, note, by string, mutedUntil *time.Time) error {
	return s.Update(func(st *State) error {
		for i := range st.Findings {
			if st.Findings[i].ID != id && st.Findings[i].Fingerprint != id {
				continue
			}
			now := s.now().UTC()
			f := &st.Findings[i]
			f.Status, f.StatusNote, f.StatusBy, f.StatusAt = status, note, by, &now
			f.MutedUntil = mutedUntil
			return nil
		}
		return fmt.Errorf("no finding with id %q", id)
	})
}

// SetCheckState records per-upstream state after a check.
func (s *Store) SetCheckState(key string, us UpstreamState) error {
	return s.Update(func(st *State) error {
		if st.Checks == nil {
			st.Checks = map[string]UpstreamState{}
		}
		st.Checks[key] = us
		return nil
	})
}

// StartRun allocates a run record and returns it.
func (s *Store) StartRun(trigger string) (Run, error) {
	var run Run
	err := s.Update(func(st *State) error {
		st.RunSeq++
		run = Run{
			ID:        fmt.Sprintf("r_%d", st.RunSeq),
			Seq:       st.RunSeq,
			StartedAt: s.now().UTC(),
			Trigger:   trigger,
		}
		st.Runs = append(st.Runs, run)
		return nil
	})
	return run, err
}

// FinishRun records the outcome of a run.
func (s *Store) FinishRun(run Run) error {
	return s.Update(func(st *State) error {
		t := s.now().UTC()
		run.FinishedAt = &t
		run.Complete = true
		for i := range st.Runs {
			if st.Runs[i].ID == run.ID {
				st.Runs[i] = run
				return nil
			}
		}
		st.Runs = append(st.Runs, run)
		return nil
	})
}

// UpstreamsForHost returns the upstreams covering a host, most specific first.
func (st *State) UpstreamsForHost(host string) []model.Upstream {
	var out []model.Upstream
	for _, u := range st.Upstreams {
		if u.Host == host {
			out = append(out, u)
		}
	}
	return out
}

// UpstreamsForEndpoint returns the upstreams covering one endpoint path on a
// host. The longest matching path prefix wins, so a monorepo can route
// /billing/ and /identity/ to different repositories.
func (st *State) UpstreamsForEndpoint(host, path string) []model.Upstream {
	var out []model.Upstream
	for _, u := range st.UpstreamsForHost(host) {
		if u.Matches(path) {
			out = append(out, u)
		}
	}
	return out
}

// DecisionFor returns the active decision for a host, if any.
func (st *State) DecisionFor(host string, now time.Time) (model.Decision, bool) {
	for _, d := range st.Decisions {
		if d.Host == host && d.Active(now) {
			return d, true
		}
	}
	return model.Decision{}, false
}

// NeedsLinking reports whether a host should be asked about: it has no upstream
// and no active decision suppressing the question.
func (st *State) NeedsLinking(host string, now time.Time) bool {
	if len(st.UpstreamsForHost(host)) > 0 {
		return false
	}
	_, decided := st.DecisionFor(host, now)
	return !decided
}

// LinkedRepos returns every distinct upstream repository, keyed for dedup.
func (st *State) LinkedRepos() []model.Upstream {
	seen := map[string]bool{}
	var out []model.Upstream
	for _, u := range st.Upstreams {
		if u.Status != "" && u.Status != "active" {
			continue
		}
		k := u.Repo.Key()
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, u)
	}
	return out
}

// statFile is a thin wrapper so tests can assert file permissions without
// importing os alongside the store.
func statFile(path string) (os.FileInfo, error) { return os.Stat(path) }
