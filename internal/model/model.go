// Package model holds the domain types shared by the linker, the monitor, the
// MCP server and the dashboard. It performs no I/O and imports nothing from the
// rest of the program, so every other package can depend on it freely.
package model

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// Provider identifies where an upstream repository is hosted.
type Provider string

const (
	ProviderGitHub  Provider = "github"
	ProviderGitLab  Provider = "gitlab"
	ProviderGeneric Provider = "generic"
)

// Role records what an upstream repository actually contains, which decides
// which analyzers are worth running against it.
type Role string

const (
	// RoleImplementation is the service's source code.
	RoleImplementation Role = "implementation"
	// RoleSpecOnly holds only an API description. This matters more than it
	// sounds: api.stripe.com is closed source, but stripe/openapi is public, and
	// a spec-only repo gets the high-signal structural spec diff while skipping
	// route analysis entirely.
	RoleSpecOnly Role = "spec_only"
	// RoleGateway is a proxy or gateway configuration.
	RoleGateway Role = "gateway"
)

// Valid reports whether r is a known role.
func (r Role) Valid() bool {
	switch r {
	case RoleImplementation, RoleSpecOnly, RoleGateway:
		return true
	}
	return false
}

// RepoRef is a normalized reference to an upstream repository.
type RepoRef struct {
	Provider Provider `json:"provider"`
	GitHost  string   `json:"git_host"`
	Owner    string   `json:"owner"`
	Name     string   `json:"name"`
	// Subpath scopes a monorepo, as in github.com/org/repo//services/api.
	Subpath string `json:"subpath,omitempty"`
	// Ref pins a branch or tag. Empty means the repository default branch.
	Ref string `json:"ref,omitempty"`
}

// Canonical renders the reference in its display form.
func (r RepoRef) Canonical() string {
	var b strings.Builder
	b.WriteString("https://")
	b.WriteString(r.GitHost)
	b.WriteByte('/')
	b.WriteString(r.Owner)
	b.WriteByte('/')
	b.WriteString(r.Name)
	if r.Subpath != "" {
		b.WriteString("//")
		b.WriteString(r.Subpath)
	}
	if r.Ref != "" {
		b.WriteByte('@')
		b.WriteString(r.Ref)
	}
	return b.String()
}

// Key is the identity used for deduplication. Owner and name are case-folded
// because GitHub treats them case-insensitively: links to "Org/Repo" and
// "org/repo" must not both exist.
func (r RepoRef) Key() string {
	return strings.Join([]string{
		string(r.Provider), strings.ToLower(r.GitHost),
		strings.ToLower(r.Owner), strings.ToLower(r.Name), r.Subpath,
	}, "|")
}

// Slug is the "owner/name" form used in API paths and log lines.
func (r RepoRef) Slug() string { return r.Owner + "/" + r.Name }

// BlobURL builds a permalink pinned to a commit, so evidence in a finding does
// not rot when the branch moves on.
func (r RepoRef) BlobURL(sha, path string, line int) string {
	u := fmt.Sprintf("https://%s/%s/%s/blob/%s/%s", r.GitHost, r.Owner, r.Name, sha, path)
	if line > 0 {
		u += fmt.Sprintf("#L%d", line)
	}
	return u
}

// Zero reports whether the reference is empty.
func (r RepoRef) Zero() bool { return r.Owner == "" && r.Name == "" }

// Upstream links one API host to one repository.
type Upstream struct {
	Host string  `json:"host"`
	Repo RepoRef `json:"repo"`
	// PathPrefix restricts this upstream to endpoints beneath it, so one host
	// can be served by several repositories. An empty prefix matches every
	// endpoint on the host.
	PathPrefix string `json:"path_prefix,omitempty"`
	Role       Role   `json:"role"`
	// Priority breaks ties when several upstreams match; lower wins.
	Priority int `json:"priority,omitempty"`
	// Source records how the link was established, for auditability.
	Source     string    `json:"source"`
	Confidence float64   `json:"confidence,omitempty"`
	Note       string    `json:"note,omitempty"`
	Status     string    `json:"status,omitempty"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
}

// Matches reports whether this upstream covers the given endpoint path.
func (u Upstream) Matches(path string) bool {
	return u.PathPrefix == "" || strings.HasPrefix(path, u.PathPrefix)
}

// Link sources, ordered roughly by how much they should be trusted.
const (
	SourceConfig      = "config"
	SourceFlag        = "flag"
	SourceWellKnown   = "wellknown"
	SourceElicitation = "elicitation"
	SourceCLI         = "cli"
	SourceWeb         = "web"
	SourceMCP         = "mcp"
)

// Decision records that a host is deliberately not linked, so the tool stops
// asking about it.
type Decision struct {
	Host string `json:"host"`
	// Kind is "unmonitored" for a permanent choice or "later" for a deferral.
	Kind      string     `json:"kind"`
	Reason    string     `json:"reason,omitempty"`
	DecidedBy string     `json:"decided_by"`
	DecidedAt time.Time  `json:"decided_at"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
}

// Decision kinds and reasons.
const (
	DecisionUnmonitored = "unmonitored"
	DecisionLater       = "later"

	ReasonClosedSource     = "closed_source"
	ReasonInternal         = "internal"
	ReasonThirdPartyNoRepo = "third_party_no_repo"
	ReasonNoise            = "noise"
	ReasonOther            = "other"
)

// Active reports whether the decision still suppresses prompting at time now.
func (d Decision) Active(now time.Time) bool {
	if d.ExpiresAt == nil {
		return true
	}
	return now.Before(*d.ExpiresAt)
}

// Sticky reports whether the decision should survive the discovery of new
// endpoints on the host. Being closed-source or internal is a structural fact
// that new endpoints do not change; a vaguer "not now" should be revisited.
func (d Decision) Sticky() bool {
	switch d.Reason {
	case ReasonClosedSource, ReasonInternal:
		return true
	}
	return false
}

// Severity ranks a finding. There are only three levels on purpose: a scale
// with more gradations invites arguing about the middle instead of acting.
type Severity string

const (
	SeverityBreaking Severity = "breaking"
	SeverityRisky    Severity = "risky"
	SeverityInfo     Severity = "info"
)

// Rank returns a sortable weight, most severe first.
func (s Severity) Rank() int {
	switch s {
	case SeverityBreaking:
		return 0
	case SeverityRisky:
		return 1
	default:
		return 2
	}
}

// AtLeast reports whether s is at least as severe as min.
func (s Severity) AtLeast(min Severity) bool { return s.Rank() <= min.Rank() }

// ParseSeverity accepts a severity name, defaulting to info.
func ParseSeverity(s string) (Severity, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "info":
		return SeverityInfo, nil
	case "risky":
		return SeverityRisky, nil
	case "breaking":
		return SeverityBreaking, nil
	default:
		return "", fmt.Errorf("unknown severity %q: want breaking, risky or info", s)
	}
}

// Finding status values.
const (
	StatusOpen     = "open"
	StatusAcked    = "acked"
	StatusMuted    = "muted"
	StatusResolved = "resolved"
)

// Evidence cites the exact upstream change behind a finding. Without this a
// finding is an accusation; with it, a reviewer can judge in seconds.
type Evidence struct {
	Kind         string `json:"kind"`
	File         string `json:"file,omitempty"`
	OldPath      string `json:"old_path,omitempty"`
	Line         int    `json:"line,omitempty"`
	Hunk         string `json:"hunk,omitempty"`
	JSONPointer  string `json:"json_pointer,omitempty"`
	Before       string `json:"before,omitempty"`
	After        string `json:"after,omitempty"`
	PermalinkURL string `json:"permalink_url,omitempty"`
}

// Evidence kinds.
const (
	EvidenceDiffHunk      = "diff_hunk"
	EvidenceSpecNode      = "spec_node"
	EvidenceRouteDecl     = "route_decl"
	EvidenceReleaseNote   = "release_note"
	EvidenceCommitMessage = "commit_message"
)

// EndpointRef points back at one of my calls that a finding affects.
type EndpointRef struct {
	ID       string `json:"id"`
	Method   string `json:"method"`
	Path     string `json:"path"`
	CallSite string `json:"call_site,omitempty"`
}

// Finding is one detected risk to one or more of my endpoints.
type Finding struct {
	ID          string   `json:"id"`
	Fingerprint string   `json:"fingerprint"`
	Signal      string   `json:"signal"`
	Severity    Severity `json:"severity"`
	Confidence  float64  `json:"confidence"`
	// Corroborated marks a finding supported by a second independent signal. It
	// sorts first but deliberately does not raise severity: automatic promotion
	// is how these tools become noisy and get ignored.
	Corroborated bool   `json:"corroborated,omitempty"`
	Title        string `json:"title"`
	Detail       string `json:"detail,omitempty"`
	Suggestion   string `json:"suggestion,omitempty"`

	Host       string  `json:"host"`
	Repo       RepoRef `json:"repo"`
	CommitSHA  string  `json:"commit_sha,omitempty"`
	BaseSHA    string  `json:"base_sha,omitempty"`
	HeadSHA    string  `json:"head_sha,omitempty"`
	CompareURL string  `json:"compare_url,omitempty"`

	Evidence  []Evidence    `json:"evidence,omitempty"`
	Endpoints []EndpointRef `json:"endpoints,omitempty"`

	FirstSeenAt time.Time  `json:"first_seen_at"`
	LastSeenAt  time.Time  `json:"last_seen_at"`
	Occurrences int        `json:"occurrences"`
	Status      string     `json:"status"`
	StatusNote  string     `json:"status_note,omitempty"`
	StatusBy    string     `json:"status_by,omitempty"`
	StatusAt    *time.Time `json:"status_at,omitempty"`
	MutedUntil  *time.Time `json:"muted_until,omitempty"`
}

// EndpointIDs returns the affected endpoint IDs, sorted.
func (f Finding) EndpointIDs() []string {
	out := make([]string, 0, len(f.Endpoints))
	for _, e := range f.Endpoints {
		out = append(out, e.ID)
	}
	sort.Strings(out)
	return out
}

// Visible reports whether a finding should appear in default listings at time
// now. Acknowledged and resolved findings are hidden, and a mute is honoured
// only until it expires.
func (f Finding) Visible(now time.Time) bool {
	switch f.Status {
	case StatusAcked, StatusResolved:
		return false
	case StatusMuted:
		return f.MutedUntil != nil && now.After(*f.MutedUntil)
	default:
		return true
	}
}

// SortFindings orders findings for display: most severe first, then
// corroborated, then most recently seen, then by ID so the order is total.
func SortFindings(fs []Finding) {
	sort.SliceStable(fs, func(i, j int) bool {
		a, b := fs[i], fs[j]
		if a.Severity != b.Severity {
			return a.Severity.Rank() < b.Severity.Rank()
		}
		if a.Corroborated != b.Corroborated {
			return a.Corroborated
		}
		if !a.LastSeenAt.Equal(b.LastSeenAt) {
			return a.LastSeenAt.After(b.LastSeenAt)
		}
		return a.ID < b.ID
	})
}

// Counts summarizes findings by severity.
type Counts struct {
	Breaking int `json:"breaking"`
	Risky    int `json:"risky"`
	Info     int `json:"info"`
	Total    int `json:"total"`
}

// CountBySeverity tallies fs.
func CountBySeverity(fs []Finding) Counts {
	var c Counts
	for _, f := range fs {
		switch f.Severity {
		case SeverityBreaking:
			c.Breaking++
		case SeverityRisky:
			c.Risky++
		default:
			c.Info++
		}
		c.Total++
	}
	return c
}
