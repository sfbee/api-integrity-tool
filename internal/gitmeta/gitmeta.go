// Package gitmeta reads the small amount of git state the index records.
//
// Everything here is behind an interface. Golden-file tests must produce
// byte-identical output on any machine, which is impossible if the scanner
// reads the real HEAD of a fixture directory -- so tests inject a Static
// provider with a fixed commit.
package gitmeta

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// Info is the git state attached to a scan.
type Info struct {
	Root          string
	Commit        string
	Branch        string
	Remote        string
	DefaultBranch string
	Dirty         bool
	HasCommits    bool
}

// Provider reports git state for a directory.
type Provider interface {
	Info(ctx context.Context, dir string) (Info, error)
}

// Static returns fixed information. Tests use it so goldens never depend on the
// machine they run on.
type Static struct{ I Info }

// Info implements Provider.
func (s Static) Info(context.Context, string) (Info, error) { return s.I, nil }

// Git shells out to the git binary.
type Git struct {
	// Timeout bounds each git invocation. A hung git must not hang a scan.
	Timeout time.Duration
}

// DefaultTimeout is the per-command timeout when none is set.
const DefaultTimeout = 5 * time.Second

// FindRoot walks up from dir looking for a .git entry and returns the
// repository root. When none is found it returns dir unchanged, because
// scanning a plain directory is legitimate.
func FindRoot(dir string) string {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return dir
	}
	cur := abs
	for {
		if _, err := os.Stat(filepath.Join(cur, ".git")); err == nil {
			return cur
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			return abs
		}
		cur = parent
	}
}

// Info implements Provider by asking git. Every field degrades independently: a
// repository with no commits, no remote or no git binary at all still yields a
// usable Info rather than an error, because none of this is essential to
// producing an index.
func (g Git) Info(ctx context.Context, dir string) (Info, error) {
	info := Info{Root: FindRoot(dir)}
	if _, err := exec.LookPath("git"); err != nil {
		return info, nil
	}
	run := func(args ...string) (string, bool) {
		to := g.Timeout
		if to <= 0 {
			to = DefaultTimeout
		}
		cctx, cancel := context.WithTimeout(ctx, to)
		defer cancel()
		cmd := exec.CommandContext(cctx, "git", args...)
		cmd.Dir = info.Root
		// Keep git from prompting for credentials or reading a pager.
		cmd.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0", "GIT_PAGER=cat")
		out, err := cmd.Output()
		if err != nil {
			return "", false
		}
		return strings.TrimSpace(string(out)), true
	}

	if sha, ok := run("rev-parse", "HEAD"); ok && sha != "" {
		info.Commit = sha
		info.HasCommits = true
	}
	if br, ok := run("rev-parse", "--abbrev-ref", "HEAD"); ok && br != "HEAD" {
		info.Branch = br
	}
	if remote, ok := run("config", "--get", "remote.origin.url"); ok {
		info.Remote = normalizeRemote(remote)
	}
	if head, ok := run("symbolic-ref", "--short", "refs/remotes/origin/HEAD"); ok {
		info.DefaultBranch = strings.TrimPrefix(head, "origin/")
	}
	if status, ok := run("status", "--porcelain", "--untracked-files=no"); ok {
		info.Dirty = status != ""
	}
	return info, nil
}

// normalizeRemote converts an SSH remote to its https form and strips the .git
// suffix, so the recorded value is a URL a human can click.
func normalizeRemote(remote string) string {
	remote = strings.TrimSpace(remote)
	remote = strings.TrimSuffix(remote, ".git")
	if strings.HasPrefix(remote, "git@") {
		if rest, ok := strings.CutPrefix(remote, "git@"); ok {
			if host, p, found := strings.Cut(rest, ":"); found {
				return "https://" + host + "/" + p
			}
		}
	}
	remote = strings.TrimPrefix(remote, "ssh://git@")
	if strings.HasPrefix(remote, "http://") {
		return "https://" + strings.TrimPrefix(remote, "http://")
	}
	return remote
}
