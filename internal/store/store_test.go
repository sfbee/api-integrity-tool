package store

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stephen-bee/endpoint-monitor/internal/model"
)

func fixedNow(t time.Time) func() time.Time { return func() time.Time { return t } }

func newStore(t *testing.T) *Store {
	t.Helper()
	s, err := Open(t.TempDir(), fixedNow(time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestReadMissingStateIsEmptyNotAnError(t *testing.T) {
	t.Parallel()
	st, err := newStore(t).Read()
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if len(st.Upstreams) != 0 || st.Checks == nil {
		t.Errorf("want an empty initialised state, got %+v", st)
	}
}

func TestLinkUpstreamIsIdempotent(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	u := model.Upstream{
		Host: "api.example.com",
		Repo: model.RepoRef{Provider: model.ProviderGitHub, GitHost: "github.com", Owner: "acme", Name: "api"},
		Role: model.RoleImplementation, Source: model.SourceCLI,
	}
	for i := 0; i < 3; i++ {
		if err := s.LinkUpstream(u); err != nil {
			t.Fatal(err)
		}
	}
	st, _ := s.Read()
	if len(st.Upstreams) != 1 {
		t.Fatalf("re-linking the same repository duplicated it: %+v", st.Upstreams)
	}
}

// A host can legitimately be served by several repositories, distinguished by
// path prefix.
func TestHostCanHaveSeveralUpstreams(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	mk := func(name, prefix string) model.Upstream {
		return model.Upstream{
			Host:       "api.acme.com",
			Repo:       model.RepoRef{Provider: model.ProviderGitHub, GitHost: "github.com", Owner: "acme", Name: name},
			PathPrefix: prefix, Role: model.RoleImplementation, Source: model.SourceCLI,
		}
	}
	for _, u := range []model.Upstream{mk("billing", "/billing/"), mk("identity", "/identity/"), mk("specs", "")} {
		if err := s.LinkUpstream(u); err != nil {
			t.Fatal(err)
		}
	}
	st, _ := s.Read()
	if len(st.Upstreams) != 3 {
		t.Fatalf("want 3 upstreams, got %d", len(st.Upstreams))
	}
	// The longest matching prefix must come first, and the catch-all still applies.
	got := st.UpstreamsForEndpoint("api.acme.com", "/billing/charge")
	if len(got) != 2 || got[0].Repo.Name != "billing" {
		t.Errorf("endpoint routing = %+v; want billing first then the catch-all", names(got))
	}
	if got := st.UpstreamsForEndpoint("api.acme.com", "/other/thing"); len(got) != 1 || got[0].Repo.Name != "specs" {
		t.Errorf("unprefixed endpoint = %v, want only specs", names(got))
	}
}

func names(us []model.Upstream) []string {
	out := make([]string, 0, len(us))
	for _, u := range us {
		out = append(out, u.Repo.Name)
	}
	return out
}

func TestLinkingClearsASuppressingDecision(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	if err := s.SetDecision(model.Decision{Host: "api.x.com", Kind: model.DecisionUnmonitored, Reason: model.ReasonNoise}); err != nil {
		t.Fatal(err)
	}
	if err := s.LinkUpstream(model.Upstream{
		Host:   "api.x.com",
		Repo:   model.RepoRef{Provider: model.ProviderGitHub, GitHost: "github.com", Owner: "o", Name: "r"},
		Source: model.SourceCLI,
	}); err != nil {
		t.Fatal(err)
	}
	st, _ := s.Read()
	if _, ok := st.DecisionFor("api.x.com", time.Now()); ok {
		t.Error("linking a host should clear the decision that was suppressing it")
	}
}

// A "later" deferral must expire, or dismissing a prompt once silences the host
// forever.
func TestLaterDecisionExpires(t *testing.T) {
	t.Parallel()
	base := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	s, err := Open(t.TempDir(), fixedNow(base))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SetDecision(model.Decision{Host: "api.x.com", Kind: model.DecisionLater, DecidedBy: "cli"}); err != nil {
		t.Fatal(err)
	}
	st, _ := s.Read()
	if _, ok := st.DecisionFor("api.x.com", base.Add(24*time.Hour)); !ok {
		t.Error("a deferral should still hold a day later")
	}
	if _, ok := st.DecisionFor("api.x.com", base.Add(8*24*time.Hour)); ok {
		t.Error("a deferral should have expired after a week")
	}
	if !st.NeedsLinking("api.x.com", base.Add(8*24*time.Hour)) {
		t.Error("an expired deferral should make the host askable again")
	}
}

func TestUnmonitoredDecisionSuppressesLinking(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	if err := s.SetDecision(model.Decision{
		Host: "api.internal.corp", Kind: model.DecisionUnmonitored, Reason: model.ReasonInternal,
	}); err != nil {
		t.Fatal(err)
	}
	st, _ := s.Read()
	if st.NeedsLinking("api.internal.corp", time.Now().Add(100*24*time.Hour)) {
		t.Error("an unmonitored host should never be asked about again")
	}
}

// The property that matters most: an acknowledged finding must not come back
// just because the same upstream change is seen again.
func TestUpsertPreservesAcknowledgement(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	f := model.Finding{
		ID: "f1", Fingerprint: "fp1", Signal: "openapi.path_removed",
		Severity: model.SeverityBreaking, Host: "api.x.com", Status: model.StatusOpen,
	}
	if _, _, err := s.UpsertFindings([]model.Finding{f}); err != nil {
		t.Fatal(err)
	}
	if err := s.SetFindingStatus("f1", model.StatusAcked, "known", "me", nil); err != nil {
		t.Fatal(err)
	}
	added, updated, err := s.UpsertFindings([]model.Finding{f})
	if err != nil {
		t.Fatal(err)
	}
	if added != 0 || updated != 1 {
		t.Errorf("added=%d updated=%d, want 0 and 1", added, updated)
	}
	st, _ := s.Read()
	if st.Findings[0].Status != model.StatusAcked {
		t.Errorf("status = %q, want the acknowledgement preserved", st.Findings[0].Status)
	}
	if st.Findings[0].Occurrences != 2 {
		t.Errorf("occurrences = %d, want 2", st.Findings[0].Occurrences)
	}
}

// An acknowledged finding SHOULD resurface if it gets worse: dismissing a
// "risky" is not consent to ignore a later "breaking".
func TestAcknowledgedFindingReopensWhenSeverityIncreases(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	f := model.Finding{ID: "f1", Fingerprint: "fp1", Severity: model.SeverityRisky, Status: model.StatusOpen}
	s.UpsertFindings([]model.Finding{f})
	s.SetFindingStatus("f1", model.StatusAcked, "", "me", nil)

	worse := f
	worse.Severity = model.SeverityBreaking
	if _, _, err := s.UpsertFindings([]model.Finding{worse}); err != nil {
		t.Fatal(err)
	}
	st, _ := s.Read()
	if st.Findings[0].Status != model.StatusOpen {
		t.Errorf("status = %q, want it reopened", st.Findings[0].Status)
	}
	if st.Findings[0].Severity != model.SeverityBreaking {
		t.Errorf("severity = %q, want breaking", st.Findings[0].Severity)
	}
}

// Concurrent mutations must not lose updates. Without the lock plus re-read,
// the last writer would clobber everything the others did.
func TestConcurrentUpdatesDoNotLoseData(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	const n = 24
	var wg sync.WaitGroup
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			errs <- s.LinkUpstream(model.Upstream{
				Host:   fmt.Sprintf("api%02d.example.com", i),
				Repo:   model.RepoRef{Provider: model.ProviderGitHub, GitHost: "github.com", Owner: "o", Name: fmt.Sprintf("r%02d", i)},
				Source: model.SourceCLI,
			})
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("LinkUpstream: %v", err)
		}
	}
	st, _ := s.Read()
	if len(st.Upstreams) != n {
		t.Errorf("got %d upstreams, want %d: concurrent writes lost data", len(st.Upstreams), n)
	}
}

func TestRunHistoryIsBounded(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	for i := 0; i < MaxRuns+10; i++ {
		if _, err := s.StartRun("test"); err != nil {
			t.Fatal(err)
		}
	}
	st, _ := s.Read()
	if len(st.Runs) > MaxRuns {
		t.Errorf("kept %d runs, want at most %d", len(st.Runs), MaxRuns)
	}
	// The newest run must survive the trim.
	if st.Runs[0].Seq != MaxRuns+10 {
		t.Errorf("newest run seq = %d, want %d", st.Runs[0].Seq, MaxRuns+10)
	}
}

func TestStateFileIsNotWorldReadable(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	if err := s.LinkUpstream(model.Upstream{
		Host:   "api.x.com",
		Repo:   model.RepoRef{Provider: model.ProviderGitHub, GitHost: "github.com", Owner: "private", Name: "repo"},
		Source: model.SourceCLI,
	}); err != nil {
		t.Fatal(err)
	}
	// State names private repositories, so it must not be world-readable.
	fi, err := statFile(s.Path())
	if err != nil {
		t.Fatal(err)
	}
	if perm := fi.Mode().Perm(); perm&0o077 != 0 {
		t.Errorf("state file mode = %04o, want no group or other access", perm)
	}
}
