// Package upstream maps an API host to the repository behind it, and normalizes
// the many ways a person can write a repository URL into one canonical form.
package upstream

import (
	"fmt"
	"net/url"
	"path"
	"strings"

	"github.com/sfbee/api-integrity-tool/internal/model"
)

// ParseRepoRef accepts every spelling of a repository reference we expect a
// human or a config file to produce, and returns one canonical form.
//
// Accepted:
//
//	https://github.com/Org/Repo[.git][/]
//	http://github.com/org/repo                 (upgraded to https)
//	git@github.com:org/repo.git
//	ssh://git@github.com/org/repo
//	git://github.com/org/repo
//	github.com/org/repo                        (scheme omitted)
//	org/repo, gh:org/repo                      (github.com assumed)
//	github.com/org/repo//services/api          (monorepo subpath)
//	https://github.com/org/repo/tree/main/svc  (subpath and ref from a browse URL)
//	github.com/org/repo@v2, github.com/org/repo#release-2
//
// Rejected with an actionable message rather than a guess, because linking the
// wrong repository produces confident nonsense later.
func ParseRepoRef(s string) (model.RepoRef, error) {
	raw := strings.TrimSpace(s)
	if raw == "" {
		return model.RepoRef{}, fmt.Errorf("empty repository reference")
	}
	if strings.HasPrefix(strings.ToLower(raw), "file://") {
		return model.RepoRef{}, fmt.Errorf("local paths cannot be monitored: %q", s)
	}

	// A trailing @ref or #ref pins a branch or tag. Split it off before URL
	// parsing, but only when the "@" is not part of an scp-style address.
	ref := ""
	if i := strings.LastIndexByte(raw, '#'); i > 0 {
		ref, raw = raw[i+1:], raw[:i]
	} else if i := strings.LastIndexByte(raw, '@'); i > 0 && !strings.Contains(raw[i:], "/") {
		// Only an "@" after the final "/" pins a ref. Requiring that keeps the
		// "@" in "git@github.com/..." and "user@host" out of it. A branch name
		// containing a slash therefore needs the "#ref" form.
		ref, raw = raw[i+1:], raw[:i]
	}

	// A Terraform-style "//" separates the repository from a subpath inside it.
	// The search must start after any scheme separator, or the "//" in
	// "https://" is mistaken for the subpath marker.
	subpath := ""
	searchFrom := 0
	if i := strings.Index(raw, "://"); i >= 0 {
		searchFrom = i + 3
	}
	if i := strings.Index(raw[searchFrom:], "//"); i >= 0 {
		at := searchFrom + i
		subpath, raw = raw[at+2:], raw[:at]
	}

	host, pathPart, err := splitHostPath(raw)
	if err != nil {
		return model.RepoRef{}, err
	}

	segs := splitSegments(pathPart)
	if len(segs) < 2 {
		return model.RepoRef{}, fmt.Errorf("%q names an owner but not a repository; use owner/repo", s)
	}
	owner, name := segs[0], strings.TrimSuffix(segs[1], ".git")
	if owner == "" || name == "" {
		return model.RepoRef{}, fmt.Errorf("could not read owner and repository from %q", s)
	}

	// A browse or pull-request URL points into a repository; recover the useful
	// part instead of failing outright.
	if rest := segs[2:]; len(rest) > 0 {
		switch rest[0] {
		case "tree", "blob":
			if len(rest) > 1 {
				if ref == "" {
					ref = rest[1]
				}
				if sub := strings.Join(rest[2:], "/"); sub != "" && subpath == "" {
					subpath = sub
				}
			}
		case "pull", "issues", "commit", "commits", "releases", "actions", "wiki", "compare":
			// The repository itself is what we monitor; drop the rest.
		default:
			if subpath == "" {
				subpath = strings.Join(rest, "/")
			}
		}
	}

	subpath = cleanSubpath(subpath)
	if strings.Contains(subpath, "..") {
		return model.RepoRef{}, fmt.Errorf("subpath %q may not contain %q", subpath, "..")
	}

	return model.RepoRef{
		Provider: providerFor(host),
		GitHost:  strings.ToLower(host),
		Owner:    owner,
		Name:     name,
		Subpath:  subpath,
		Ref:      strings.TrimSpace(ref),
	}, nil
}

// splitHostPath separates the git host from the repository path, handling
// scp-style addresses, explicit schemes, bare host paths and "owner/repo".
func splitHostPath(raw string) (host, pathPart string, err error) {
	lower := strings.ToLower(raw)

	// scp-style: git@github.com:org/repo.git
	if !strings.Contains(lower, "://") && strings.Contains(raw, "@") && strings.Contains(raw, ":") {
		at := strings.Index(raw, "@")
		colon := strings.Index(raw[at:], ":") + at
		return raw[at+1 : colon], raw[colon+1:], nil
	}

	if strings.Contains(lower, "://") {
		u, perr := url.Parse(raw)
		if perr != nil {
			return "", "", fmt.Errorf("could not parse %q as a URL: %w", raw, perr)
		}
		switch strings.ToLower(u.Scheme) {
		case "http", "https", "ssh", "git":
		default:
			return "", "", fmt.Errorf("unsupported scheme %q in %q", u.Scheme, raw)
		}
		// A password in a repository URL is a credential leak waiting to be
		// committed to a config file.
		if u.User != nil {
			if _, hasPass := u.User.Password(); hasPass {
				return "", "", fmt.Errorf("remove the embedded credentials from %q before linking it", raw)
			}
		}
		return u.Hostname(), u.Path, nil
	}

	// "gh:org/repo" shorthand.
	if rest, ok := strings.CutPrefix(raw, "gh:"); ok {
		return "github.com", rest, nil
	}

	segs := splitSegments(raw)
	// A first segment containing a dot is a hostname; otherwise assume GitHub.
	if len(segs) > 0 && strings.Contains(segs[0], ".") {
		return segs[0], strings.Join(segs[1:], "/"), nil
	}
	return "github.com", raw, nil
}

func splitSegments(p string) []string {
	var out []string
	for _, s := range strings.Split(p, "/") {
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}

func cleanSubpath(s string) string {
	s = strings.Trim(strings.TrimSpace(s), "/")
	if s == "" {
		return ""
	}
	return path.Clean(s)
}

func providerFor(host string) model.Provider {
	h := strings.ToLower(host)
	switch {
	case h == "github.com" || strings.HasSuffix(h, ".github.com"):
		return model.ProviderGitHub
	case strings.Contains(h, "gitlab"):
		return model.ProviderGitLab
	default:
		return model.ProviderGeneric
	}
}
