package upstream

import (
	"embed"
	"encoding/json"
	"fmt"
	"strings"
	"sync"

	"github.com/sfbee/api-integrity-tool/internal/model"
)

//go:embed wellknown/hosts.json
var wellKnownFS embed.FS

// WellKnown is one curated host-to-repository mapping.
type WellKnown struct {
	Host   string     `json:"host"`
	Vendor string     `json:"vendor"`
	Repo   string     `json:"repo"`
	Role   model.Role `json:"role"`
}

type wellKnownFile struct {
	Hosts []WellKnown `json:"hosts"`
}

var (
	wkOnce  sync.Once
	wkTable []WellKnown
	wkErr   error
)

// WellKnownTable returns the embedded catalogue.
//
// This table is the highest-leverage part of the linking flow. The best linking
// experience is the one that never asks a question, and most repositories call
// a handful of well-known third-party APIs, so a curated answer for those
// removes the prompt entirely.
func WellKnownTable() ([]WellKnown, error) {
	wkOnce.Do(func() {
		data, err := wellKnownFS.ReadFile("wellknown/hosts.json")
		if err != nil {
			wkErr = fmt.Errorf("read embedded well-known hosts: %w", err)
			return
		}
		var f wellKnownFile
		if err := json.Unmarshal(data, &f); err != nil {
			wkErr = fmt.Errorf("parse embedded well-known hosts: %w", err)
			return
		}
		wkTable = f.Hosts
	})
	return wkTable, wkErr
}

// LookupWellKnown returns the curated mapping for a host. An exact match wins
// over a wildcard, so a specific entry can override "*.googleapis.com".
func LookupWellKnown(host string) (WellKnown, bool) {
	table, err := WellKnownTable()
	if err != nil {
		return WellKnown{}, false
	}
	h := strings.ToLower(strings.TrimSpace(host))
	var wildcard WellKnown
	var haveWildcard bool
	for _, e := range table {
		pattern := strings.ToLower(e.Host)
		if pattern == h {
			return e, true
		}
		if suffix, ok := strings.CutPrefix(pattern, "*."); ok {
			if strings.HasSuffix(h, "."+suffix) && !haveWildcard {
				wildcard, haveWildcard = e, true
			}
		}
	}
	return wildcard, haveWildcard
}

// Guess is a suggested link that has not been applied.
type Guess struct {
	Repo       model.RepoRef
	Why        string
	Confidence float64
}

// GuessRepo proposes a repository for a host without committing to it.
//
// Only the curated table is trusted enough to apply automatically. Everything
// else is a suggestion a human or an agent confirms, because a wrong link
// produces confidently wrong findings later, which is worse than no findings.
func GuessRepo(host string, repoRemote string) []Guess {
	var out []Guess
	if wk, ok := LookupWellKnown(host); ok {
		if ref, err := ParseRepoRef(wk.Repo); err == nil {
			out = append(out, Guess{Repo: ref, Why: "well-known " + wk.Vendor + " API", Confidence: 1.0})
			return out
		}
	}
	if isSymbolicHost(host) {
		return nil
	}

	// If this repository's own remote is github.com/acme/web and the call goes
	// to api.acme.com, the upstream is very likely under the same organisation.
	if repoRemote != "" {
		if mine, err := ParseRepoRef(repoRemote); err == nil {
			if label := hostLabel(host); label != "" && strings.EqualFold(label, mine.Owner) {
				out = append(out, Guess{
					Repo:       model.RepoRef{Provider: mine.Provider, GitHost: mine.GitHost, Owner: mine.Owner, Name: "api"},
					Why:        "host label matches this repository's organisation " + mine.Owner,
					Confidence: 0.5,
				})
			}
		}
	}

	// api.foo.com -> foo/foo is a weak but occasionally correct shape.
	if label := hostLabel(host); label != "" {
		out = append(out, Guess{
			Repo:       model.RepoRef{Provider: model.ProviderGitHub, GitHost: "github.com", Owner: label, Name: label},
			Why:        "derived from the hostname",
			Confidence: 0.3,
		})
	}
	return out
}

// isSymbolicHost reports whether a host is one of our placeholders rather than
// a real name, in which case guessing is meaningless.
func isSymbolicHost(host string) bool {
	return strings.HasPrefix(host, "${") || host == "self"
}

// hostLabel extracts the organisation-ish label from a hostname:
// "api.acme.com" and "acme.io" both yield "acme".
func hostLabel(host string) string {
	h := strings.ToLower(strings.TrimSpace(host))
	if isSymbolicHost(h) || h == "" {
		return ""
	}
	parts := strings.Split(h, ".")
	// Drop common service prefixes and the public suffix.
	for len(parts) > 1 {
		switch parts[0] {
		case "api", "www", "app", "rest", "graph", "hooks", "sandbox", "staging", "dev", "test":
			parts = parts[1:]
			continue
		}
		break
	}
	if len(parts) == 0 {
		return ""
	}
	return parts[0]
}
