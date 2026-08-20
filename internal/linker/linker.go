// Package linker decides which API hosts still need an upstream repository, and
// applies the answers from every available source.
//
// The design principle is that the best linking experience is the one that
// never asks a question. Sources are tried cheapest-first: the committed config
// file, then the curated well-known table, and only then a human. Anything
// still unresolved is returned as structured work rather than blocking, so an
// agent or a person can supply it later without the tool having stalled.
package linker

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/stephen-bee/endpoint-monitor/internal/config"
	"github.com/stephen-bee/endpoint-monitor/internal/index"
	"github.com/stephen-bee/endpoint-monitor/internal/model"
	"github.com/stephen-bee/endpoint-monitor/internal/store"
	"github.com/stephen-bee/endpoint-monitor/internal/upstream"
)

// HostRequest is one host that may need linking.
type HostRequest struct {
	Host            string
	EndpointCount   int
	SampleEndpoints []model.EndpointRef
	Symbolic        bool
	Guesses         []upstream.Guess
}

// NeedsLink is the machine-readable description of an unanswered host. It is
// what the MCP server returns when it cannot ask interactively, and what the
// CLI prints when it is not attached to a terminal.
type NeedsLink struct {
	Host            string   `json:"host"`
	EndpointCount   int      `json:"endpoint_count"`
	SampleEndpoints []string `json:"sample_endpoints,omitempty"`
	SuggestedRepo   string   `json:"suggested_repo_url,omitempty"`
	SuggestedWhy    string   `json:"suggested_repo_reason,omitempty"`
	// Symbolic marks a host that came from a variable, so it may not be a real
	// hostname at all. Those usually want a host_mappings entry rather than a
	// repository.
	Symbolic bool `json:"symbolic,omitempty"`
}

// Report summarizes what a sync did.
type Report struct {
	Linked        []model.Upstream `json:"linked,omitempty"`
	Unmonitored   []string         `json:"unmonitored,omitempty"`
	NeedsLink     []NeedsLink      `json:"needs_linking,omitempty"`
	AlreadyLinked int              `json:"already_linked"`
}

// Linker applies link decisions to the store.
type Linker struct {
	Store  *store.Store
	Config *config.File
	Now    func() time.Time
	// Remote is this repository's own origin URL, used only to improve guesses.
	Remote string
}

func (l *Linker) now() time.Time {
	if l.Now != nil {
		return l.Now()
	}
	return time.Now()
}

// HostRequestsFromIndex derives the link candidates from a scanned index,
// strongest evidence first so the samples shown to a human are the ones most
// likely to be real.
func HostRequestsFromIndex(idx *index.Index, remote string) []HostRequest {
	if idx == nil {
		return nil
	}
	byHost := map[string][]index.Call{}
	for _, c := range idx.Calls {
		if c.Lifecycle.Status == index.StatusRemoved {
			continue
		}
		byHost[c.Host] = append(byHost[c.Host], c)
	}
	out := make([]HostRequest, 0, len(byHost))
	for host, calls := range byHost {
		sort.SliceStable(calls, func(i, j int) bool { return calls[i].Score > calls[j].Score })
		req := HostRequest{
			Host:          host,
			EndpointCount: len(calls),
			Symbolic:      strings.HasPrefix(host, "${") || host == "self",
			Guesses:       upstream.GuessRepo(host, remote),
		}
		for i, c := range calls {
			if i >= 5 {
				break
			}
			req.SampleEndpoints = append(req.SampleEndpoints, model.EndpointRef{
				ID: c.ID, Method: c.Method, Path: c.Path,
				CallSite: fmt.Sprintf("%s:%d", c.Location.File, c.Location.Line),
			})
		}
		out = append(out, req)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].EndpointCount != out[j].EndpointCount {
			return out[i].EndpointCount > out[j].EndpointCount
		}
		return out[i].Host < out[j].Host
	})
	return out
}

// SyncConfig imports the committed configuration into the store. Config-sourced
// links are replaced wholesale on every load so that deleting an entry from the
// file actually removes it, while links added at runtime survive.
func (l *Linker) SyncConfig() error {
	if l.Config == nil {
		return nil
	}
	cfgUps, err := l.Config.ConfiguredUpstreams()
	if err != nil {
		return err
	}
	cfgDecisions := l.Config.ConfiguredDecisions()
	now := l.now().UTC()

	return l.Store.Update(func(st *store.State) error {
		kept := st.Upstreams[:0]
		for _, u := range st.Upstreams {
			if u.Source != model.SourceConfig {
				kept = append(kept, u)
			}
		}
		st.Upstreams = kept
		for _, u := range cfgUps {
			u.CreatedAt, u.UpdatedAt = now, now
			st.Upstreams = append(st.Upstreams, u)
		}

		keptD := st.Decisions[:0]
		for _, d := range st.Decisions {
			if d.DecidedBy != model.SourceConfig {
				keptD = append(keptD, d)
			}
		}
		st.Decisions = keptD
		for _, d := range cfgDecisions {
			d.DecidedAt = now
			st.Decisions = append(st.Decisions, d)
		}
		return nil
	})
}

// AutoLink applies the curated well-known table to every host that still needs
// an upstream, and reports what remains.
func (l *Linker) AutoLink(reqs []HostRequest) (Report, error) {
	var rep Report
	if err := l.SyncConfig(); err != nil {
		return rep, err
	}
	st, err := l.Store.Read()
	if err != nil {
		return rep, err
	}
	now := l.now()

	for _, req := range reqs {
		if len(st.UpstreamsForHost(req.Host)) > 0 {
			rep.AlreadyLinked++
			continue
		}
		if d, ok := st.DecisionFor(req.Host, now); ok {
			rep.Unmonitored = append(rep.Unmonitored, req.Host+" ("+d.Reason+")")
			continue
		}
		if wk, ok := upstream.LookupWellKnown(req.Host); ok {
			ref, perr := upstream.ParseRepoRef(wk.Repo)
			if perr == nil {
				u := model.Upstream{
					Host: req.Host, Repo: ref, Role: wk.Role,
					Source: model.SourceWellKnown, Confidence: 1.0, Status: "active",
					Note: wk.Vendor,
				}
				if err := l.Store.LinkUpstream(u); err != nil {
					return rep, err
				}
				rep.Linked = append(rep.Linked, u)
				continue
			}
		}
		rep.NeedsLink = append(rep.NeedsLink, needsLinkFor(req))
	}
	return rep, nil
}

func needsLinkFor(req HostRequest) NeedsLink {
	n := NeedsLink{
		Host:          req.Host,
		EndpointCount: req.EndpointCount,
		Symbolic:      req.Symbolic,
	}
	for _, e := range req.SampleEndpoints {
		n.SampleEndpoints = append(n.SampleEndpoints, e.Method+" "+e.Path)
	}
	// Only a reasonably plausible guess is worth showing; a wild one is noise
	// that invites a careless yes.
	if len(req.Guesses) > 0 && req.Guesses[0].Confidence >= 0.3 {
		n.SuggestedRepo = req.Guesses[0].Repo.Canonical()
		n.SuggestedWhy = req.Guesses[0].Why
	}
	return n
}

// LinkOptions are the knobs shared by every way of linking a host.
type LinkOptions struct {
	PathPrefix string
	Role       model.Role
	Ref        string
	Note       string
	Priority   int
	Source     string
}

// Link records one host-to-repository link.
func (l *Linker) Link(host, repoURL string, opts LinkOptions) (model.Upstream, error) {
	host = strings.TrimSpace(host)
	if host == "" {
		return model.Upstream{}, fmt.Errorf("a host is required")
	}
	ref, err := upstream.ParseRepoRef(repoURL)
	if err != nil {
		return model.Upstream{}, err
	}
	if opts.Ref != "" {
		ref.Ref = opts.Ref
	}
	role := opts.Role
	if role == "" {
		role = model.RoleImplementation
	}
	if !role.Valid() {
		return model.Upstream{}, fmt.Errorf("unknown role %q; want implementation, spec_only or gateway", role)
	}
	source := opts.Source
	if source == "" {
		source = model.SourceCLI
	}
	u := model.Upstream{
		Host: host, Repo: ref, PathPrefix: opts.PathPrefix, Role: role,
		Priority: opts.Priority, Note: opts.Note,
		Source: source, Confidence: 1.0, Status: "active",
	}
	return u, l.Store.LinkUpstream(u)
}

// Unmonitor records that a host is deliberately not watched.
func (l *Linker) Unmonitor(host, reason, by string) error {
	if reason == "" {
		reason = model.ReasonOther
	}
	return l.Store.SetDecision(model.Decision{
		Host: host, Kind: model.DecisionUnmonitored,
		Reason: reason, DecidedBy: by, DecidedAt: l.now().UTC(),
	})
}

// Defer records that a host should be asked about again later.
func (l *Linker) Defer(host, by string) error {
	return l.Store.SetDecision(model.Decision{
		Host: host, Kind: model.DecisionLater, DecidedBy: by, DecidedAt: l.now().UTC(),
	})
}

// PromptOptions configures interactive linking.
type PromptOptions struct {
	In  io.Reader
	Out io.Writer
	// Interactive must be false unless a human is genuinely present. Prompting
	// when stdin is a pipe hangs a build; prompting in MCP mode corrupts the
	// JSON-RPC stream, because there stdin IS the transport.
	Interactive bool
	Max         int
}

// Prompt asks about each unlinked host on a terminal, and returns whatever is
// still unanswered. Prompts go to the writer given (stderr in practice) so that
// stdout stays machine-readable.
func (l *Linker) Prompt(needs []NeedsLink, opts PromptOptions) ([]NeedsLink, error) {
	if !opts.Interactive || len(needs) == 0 {
		return needs, nil
	}
	out := opts.Out
	if out == nil {
		out = os.Stderr
	}
	reader := bufio.NewReader(opts.In)
	maxAsk := opts.Max
	if maxAsk <= 0 {
		maxAsk = 10
	}

	var remaining []NeedsLink
	for i, n := range needs {
		if i >= maxAsk {
			remaining = append(remaining, needs[i:]...)
			break
		}
		fmt.Fprintf(out, "\n%s — %d call(s)\n", n.Host, n.EndpointCount)
		for _, s := range n.SampleEndpoints {
			fmt.Fprintf(out, "    %s\n", s)
		}
		if n.Symbolic {
			fmt.Fprintf(out, "  This host came from a variable, so it may not be a real hostname.\n"+
				"  Consider a host_mappings entry in .api-integrity.yml instead.\n")
		}
		if n.SuggestedRepo != "" {
			fmt.Fprintf(out, "  Suggestion: %s (%s)\n", n.SuggestedRepo, n.SuggestedWhy)
		}
		fmt.Fprintf(out, "  Repository to watch, or [s]kip / [n]ever / [q]uit: ")

		line, err := reader.ReadString('\n')
		if err != nil && strings.TrimSpace(line) == "" {
			// Input ended: treat the rest as unanswered rather than looping.
			remaining = append(remaining, needs[i:]...)
			return remaining, nil
		}
		answer := strings.TrimSpace(line)

		switch strings.ToLower(answer) {
		case "q", "quit":
			remaining = append(remaining, needs[i:]...)
			return remaining, nil
		case "s", "skip", "":
			if answer == "" && n.SuggestedRepo != "" {
				// An empty answer accepts the suggestion only when there is one.
				if _, err := l.Link(n.Host, n.SuggestedRepo, LinkOptions{Source: model.SourceCLI}); err != nil {
					fmt.Fprintf(out, "  could not link: %v\n", err)
					remaining = append(remaining, n)
				}
				continue
			}
			if err := l.Defer(n.Host, model.SourceCLI); err != nil {
				return remaining, err
			}
			continue
		case "n", "never":
			fmt.Fprintf(out, "  Why? [closed_source/internal/third_party_no_repo/noise/other]: ")
			reasonLine, _ := reader.ReadString('\n')
			reason := strings.TrimSpace(reasonLine)
			if err := l.Unmonitor(n.Host, reason, model.SourceCLI); err != nil {
				return remaining, err
			}
			continue
		}

		if _, err := l.Link(n.Host, answer, LinkOptions{Source: model.SourceCLI}); err != nil {
			fmt.Fprintf(out, "  %v\n", err)
			remaining = append(remaining, n)
			continue
		}
		fmt.Fprintf(out, "  linked.\n")
	}
	return remaining, nil
}
