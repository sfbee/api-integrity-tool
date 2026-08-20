// Package config loads .api-integrity.yml, the committed per-repository
// configuration.
//
// The file is the team's shared answer to questions the tool would otherwise
// ask every developer individually: which repository backs which API host,
// which hosts are deliberately unmonitored, which endpoints matter, and what a
// symbolic host actually resolves to.
package config

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/stephen-bee/endpoint-monitor/internal/model"
	"github.com/stephen-bee/endpoint-monitor/internal/upstream"
)

// FileNames are the accepted config file names, in search order.
var FileNames = []string{".api-integrity.yml", ".api-integrity.yaml"}

// File is the parsed configuration.
type File struct {
	Version int `yaml:"version"`

	Scan    ScanConfig   `yaml:"scan"`
	Filters FilterConfig `yaml:"filters"`

	// HostMappings resolves a symbolic host to one or more real hostnames.
	// Applied at query time rather than baked into the index, so editing this
	// never churns call identities.
	HostMappings map[string][]string `yaml:"host_mappings"`

	// Upstreams accepts either a bare repository string or a list of entries,
	// because one host is usually served by one repository but sometimes by
	// several.
	Upstreams map[string]UpstreamList `yaml:"upstreams"`

	Unmonitored []UnmonitoredEntry `yaml:"unmonitored"`

	GitHub GitHubConfig `yaml:"github"`

	// Path records where this was loaded from, for error messages.
	Path string `yaml:"-"`
}

// ScanConfig narrows what a scan reads.
type ScanConfig struct {
	Languages          []string `yaml:"languages"`
	PathGlobs          []string `yaml:"path_globs"`
	ExcludePaths       []string `yaml:"exclude_paths"`
	IncludeTests       bool     `yaml:"include_tests"`
	IncludeInternal    bool     `yaml:"include_internal"`
	CollapseNumericIDs bool     `yaml:"collapse_numeric_ids"`
	MaxFileSize        int64    `yaml:"max_file_size"`
}

// FilterConfig is the team's default view of the index. Command-line filters
// are unioned with these rather than replacing them, so an ad-hoc flag cannot
// silently discard the shared baseline.
type FilterConfig struct {
	Endpoints        []string `yaml:"endpoints"`
	Hosts            []string `yaml:"hosts"`
	Regexes          []string `yaml:"regexes"`
	Methods          []string `yaml:"methods"`
	ExcludeHosts     []string `yaml:"exclude_hosts"`
	ExcludeEndpoints []string `yaml:"exclude_endpoints"`
	MinConfidence    string   `yaml:"min_confidence"`
}

// Empty reports whether no filter is configured.
func (f FilterConfig) Empty() bool {
	return len(f.Endpoints) == 0 && len(f.Hosts) == 0 && len(f.Regexes) == 0 &&
		len(f.Methods) == 0 && len(f.ExcludeHosts) == 0 && len(f.ExcludeEndpoints) == 0 &&
		f.MinConfidence == ""
}

// GitHubConfig tunes API access.
type GitHubConfig struct {
	// MinRemaining stops scheduling new upstreams once the rate-limit budget
	// falls below this, so a check degrades to partial results instead of
	// exhausting the quota the user needs for other work.
	MinRemaining int    `yaml:"min_remaining"`
	MaxWaitSecs  int    `yaml:"max_wait_seconds"`
	TokenCommand string `yaml:"token_command"`
	BaseURL      string `yaml:"base_url"`
}

// UnmonitoredEntry records a host the team has decided not to watch.
type UnmonitoredEntry struct {
	Host   string `yaml:"host"`
	Reason string `yaml:"reason"`
	Note   string `yaml:"note"`
}

// UpstreamEntry is one repository link in the config file.
type UpstreamEntry struct {
	Repo       string     `yaml:"repo"`
	PathPrefix string     `yaml:"path_prefix"`
	Role       model.Role `yaml:"role"`
	Ref        string     `yaml:"ref"`
	Priority   int        `yaml:"priority"`
	Note       string     `yaml:"note"`
}

// UpstreamList allows a host to map to either one repository or several.
type UpstreamList []UpstreamEntry

// UnmarshalYAML accepts the shorthand form
//
//	api.stripe.com: github.com/stripe/openapi
//
// as well as the full list form, because requiring the verbose spelling for the
// common single-repository case makes the file tedious to write by hand.
func (l *UpstreamList) UnmarshalYAML(node *yaml.Node) error {
	switch node.Kind {
	case yaml.ScalarNode:
		var s string
		if err := node.Decode(&s); err != nil {
			return err
		}
		*l = UpstreamList{{Repo: s}}
		return nil
	case yaml.MappingNode:
		var e UpstreamEntry
		if err := node.Decode(&e); err != nil {
			return err
		}
		*l = UpstreamList{e}
		return nil
	case yaml.SequenceNode:
		var es []UpstreamEntry
		if err := node.Decode(&es); err != nil {
			return err
		}
		*l = es
		return nil
	default:
		return fmt.Errorf("line %d: an upstream must be a repository string, a mapping, or a list of mappings", node.Line)
	}
}

// Find returns the config path for a repository, or "" when there is none.
func Find(repoDir string) string {
	for _, name := range FileNames {
		p := filepath.Join(repoDir, name)
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return p
		}
	}
	return ""
}

// Load reads the configuration for a repository. A missing file yields a zero
// File and no error, so callers never need to special-case its absence.
func Load(repoDir string) (*File, error) {
	path := Find(repoDir)
	if path == "" {
		return &File{}, nil
	}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return &File{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	var f File
	dec := yaml.NewDecoder(strings.NewReader(string(data)))
	// A typo in a key would otherwise be silently ignored, which is how a team
	// discovers months later that their config never took effect.
	dec.KnownFields(true)
	// An empty or comment-only file decodes to io.EOF, which is not an error.
	if err := dec.Decode(&f); err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	f.Path = path
	if f.Version > 1 {
		return nil, fmt.Errorf("%s declares version %d, which this binary does not understand", path, f.Version)
	}
	if err := f.validate(); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &f, nil
}

func (f *File) validate() error {
	for host, list := range f.Upstreams {
		if host == "" {
			return errors.New("an upstreams key is empty")
		}
		for i, e := range list {
			if strings.TrimSpace(e.Repo) == "" {
				return fmt.Errorf("upstreams[%s][%d]: repo is required", host, i)
			}
			if _, err := upstream.ParseRepoRef(e.Repo); err != nil {
				return fmt.Errorf("upstreams[%s][%d]: %w", host, i, err)
			}
			if e.Role != "" && !e.Role.Valid() {
				return fmt.Errorf("upstreams[%s][%d]: unknown role %q; want implementation, spec_only or gateway", host, i, e.Role)
			}
		}
	}
	for i, u := range f.Unmonitored {
		if strings.TrimSpace(u.Host) == "" {
			return fmt.Errorf("unmonitored[%d]: host is required", i)
		}
	}
	if f.Filters.MinConfidence != "" {
		switch f.Filters.MinConfidence {
		case "low", "medium", "high":
		default:
			return fmt.Errorf("filters.min_confidence %q: want low, medium or high", f.Filters.MinConfidence)
		}
	}
	return nil
}

// ConfiguredUpstreams converts the config into domain upstreams.
func (f *File) ConfiguredUpstreams() ([]model.Upstream, error) {
	var out []model.Upstream
	for host, list := range f.Upstreams {
		for _, e := range list {
			ref, err := upstream.ParseRepoRef(e.Repo)
			if err != nil {
				return nil, fmt.Errorf("upstreams[%s]: %w", host, err)
			}
			if e.Ref != "" {
				ref.Ref = e.Ref
			}
			role := e.Role
			if role == "" {
				role = model.RoleImplementation
			}
			out = append(out, model.Upstream{
				Host: host, Repo: ref, PathPrefix: e.PathPrefix, Role: role,
				Priority: e.Priority, Note: e.Note,
				Source: model.SourceConfig, Confidence: 1.0, Status: "active",
			})
		}
	}
	return out, nil
}

// ConfiguredDecisions converts the unmonitored list into decisions.
func (f *File) ConfiguredDecisions() []model.Decision {
	out := make([]model.Decision, 0, len(f.Unmonitored))
	for _, u := range f.Unmonitored {
		reason := u.Reason
		if reason == "" {
			reason = model.ReasonOther
		}
		out = append(out, model.Decision{
			Host: u.Host, Kind: model.DecisionUnmonitored,
			Reason: reason, DecidedBy: model.SourceConfig,
		})
	}
	return out
}

// ResolveHost expands a symbolic host to the concrete hostnames configured for
// it, or returns the host unchanged.
func (f *File) ResolveHost(host string) []string {
	if hosts, ok := f.HostMappings[host]; ok && len(hosts) > 0 {
		return hosts
	}
	return []string{host}
}

// Example is a documented starter configuration, written by `config init`.
const Example = `# api-integrity-tool configuration. Commit this file: it is the team's shared
# answer to "which repository is behind this API host?".
version: 1

# Which repository backs each API host. Either shorthand:
#
#   api.stripe.com: github.com/stripe/openapi
#
# or the full form when a host needs a path prefix, a role or a monorepo
# subpath. role is one of implementation, spec_only or gateway; spec_only means
# the repository holds only an OpenAPI description, which is the usual case for
# a third-party API whose implementation is closed source.
upstreams: {}
#   api.stripe.com: github.com/stripe/openapi
#   api.acme.com:
#     - repo: github.com/acme/monorepo//services/billing
#       path_prefix: /billing/
#       role: implementation
#     - repo: github.com/acme/api-specs
#       role: spec_only
#       priority: 50

# Hosts you have deliberately decided not to monitor. reason is one of
# closed_source, internal, third_party_no_repo, noise or other. Recording the
# reason stops the tool asking again.
unmonitored: []
#   - host: api.internal.corp
#     reason: internal

# What a symbolic host actually is. The scanner records a host read from an
# environment variable as ${env:NAME} rather than guessing; this is where you
# tell it the answer. Applied when querying, so editing it never rewrites the
# index.
host_mappings: {}
#   "${env:BILLING_BASE_URL}": ["billing.acme.internal"]

# The team's default view of the index. Command-line filters are unioned with
# these, never replaced.
filters: {}
#   endpoints:
#     - /api/v1/user/add
#   exclude_hosts:
#     - api.legacy.example.com

scan: {}
#   include_tests: false
#   exclude_paths: ["legacy/**"]

github: {}
#   min_remaining: 100
`
