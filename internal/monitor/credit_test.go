package monitor

import (
	"testing"

	"github.com/sfbee/api-integrity-tool/internal/classify"
	"github.com/sfbee/api-integrity-tool/internal/config"
	"github.com/sfbee/api-integrity-tool/internal/index"
	"github.com/sfbee/api-integrity-tool/internal/model"
)

func creditUpstream() model.Upstream {
	return model.Upstream{
		Host: "api.acme.com",
		Repo: model.RepoRef{Provider: model.ProviderGitHub, GitHost: "github.com", Owner: "acme", Name: "billing"},
	}
}

// A call whose host the scanner could not resolve loses confidence, and the
// finding about it inherits that loss. Once the user declares in host_mappings
// what the host is, the uncertainty the penalty was charging for is gone -- and
// it was being charged on exactly the calls that matter most, since a base URL
// held in configuration is the normal shape for an internal upstream.
//
// Without this, a path the repository demonstrably calls could be deleted
// upstream and still be graded info.
func TestADeclaredHostRestoresTheConfidenceItsSymbolCost(t *testing.T) {
	t.Parallel()
	call := index.Call{
		ID: "c1", Method: "GET", Host: "${sym:client.base}", Path: "/keys/{id}",
		Score: 32, Confidence: index.ConfLow, Flags: []string{"regex_detector", "symbolic_host"},
	}
	idx := &index.Index{Calls: []index.Call{call}}
	up := creditUpstream()
	cfg := &config.File{HostMappings: map[string][]string{
		"${sym:client.base}": {"api.acme.com"},
	}}

	ts := targetsFor(idx, up, cfg)
	if len(ts.Targets) != 1 {
		t.Fatalf("got %d targets, want 1", len(ts.Targets))
	}
	if got := ts.Targets[0].Score; got != 32+classify.SymbolicHostPenalty {
		t.Errorf("score = %d, want %d", got, 32+classify.SymbolicHostPenalty)
	}
}

// The credit is for a declaration, not for being symbolic. A symbol with no
// mapping is still genuinely unresolved.
func TestAnUndeclaredSymbolKeepsItsPenalty(t *testing.T) {
	t.Parallel()
	idx := &index.Index{Calls: []index.Call{{
		ID: "c1", Method: "GET", Host: "api.acme.com", Path: "/keys/{id}",
		Score: 32, Confidence: index.ConfLow, Flags: []string{"regex_detector", "symbolic_host"},
	}}}
	up := creditUpstream()
	// The host matches the upstream directly, so nothing was declared about it.
	ts := targetsFor(idx, up, &config.File{})
	if got := ts.Targets[0].Score; got != 32 {
		t.Errorf("score = %d, want it unchanged at 32", got)
	}
}

// The detector penalty is a different claim: a regex match really is weaker
// evidence than a parsed one, and no amount of configuration changes that.
func TestTheDetectorPenaltyIsNotCredited(t *testing.T) {
	t.Parallel()
	idx := &index.Index{Calls: []index.Call{{
		ID: "c1", Method: "GET", Host: "${sym:client.base}", Path: "/keys/{id}",
		Score: 32, Confidence: index.ConfLow, Flags: []string{"regex_detector", "symbolic_host"},
	}}}
	up := creditUpstream()
	cfg := &config.File{HostMappings: map[string][]string{"${sym:client.base}": {"api.acme.com"}}}
	ts := targetsFor(idx, up, cfg)
	// 32 + 15 only. A full pardon would be 32 + 15 + 20.
	if got := ts.Targets[0].Score; got >= 32+classify.SymbolicHostPenalty+20 {
		t.Errorf("score = %d; the regex_detector penalty should still apply", got)
	}
}
