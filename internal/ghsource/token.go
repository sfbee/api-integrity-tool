package ghsource

import (
	"context"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"time"
)

// TokenSource supplies a GitHub credential.
type TokenSource interface {
	Token(ctx context.Context) (string, error)
}

// TokenFunc adapts a function to TokenSource.
type TokenFunc func(ctx context.Context) (string, error)

// Token implements TokenSource.
func (f TokenFunc) Token(ctx context.Context) (string, error) { return f(ctx) }

// StaticToken returns a fixed credential.
func StaticToken(tok string) TokenSource {
	return TokenFunc(func(context.Context) (string, error) { return tok, nil })
}

// ChainTokenSource tries each source in order and caches the first success for
// the process lifetime. Shelling out to `gh` on every request would be slow and
// would spam the user's keychain.
type ChainTokenSource struct {
	// Getenv is the environment lookup, injectable for tests.
	Getenv func(string) string
	// Command is an optional shell command that prints a token.
	Command string
	// Exec runs a command; injectable so tests never spawn a real process.
	Exec func(ctx context.Context, name string, args ...string) ([]byte, error)

	once sync.Once
	tok  string
	err  error
}

// Token resolves a credential from, in order: GITHUB_TOKEN, GH_TOKEN,
// GITHUB_PERSONAL_ACCESS_TOKEN, a configured command, then `gh auth token`.
func (c *ChainTokenSource) Token(ctx context.Context) (string, error) {
	c.once.Do(func() {
		getenv := c.Getenv
		if getenv == nil {
			getenv = func(string) string { return "" }
		}
		for _, name := range []string{"GITHUB_TOKEN", "GH_TOKEN", "GITHUB_PERSONAL_ACCESS_TOKEN"} {
			if v := strings.TrimSpace(getenv(name)); v != "" {
				c.tok = v
				return
			}
		}
		run := c.Exec
		if run == nil {
			run = defaultExec
		}
		if c.Command != "" {
			// A configured command is deliberately run through the shell so a
			// user can write "pass show github/token" or similar.
			if out, err := run(ctx, "sh", "-c", c.Command); err == nil {
				if v := strings.TrimSpace(string(out)); v != "" {
					c.tok = v
					return
				}
			}
		}
		if out, err := run(ctx, "gh", "auth", "token"); err == nil {
			if v := strings.TrimSpace(string(out)); v != "" {
				c.tok = v
				return
			}
		}
		c.err = ErrUnauthenticated
	})
	return c.tok, c.err
}

func defaultExec(ctx context.Context, name string, args ...string) ([]byte, error) {
	// A credential helper that hangs must not hang the tool.
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	return exec.CommandContext(ctx, name, args...).Output()
}

// tokenPattern matches GitHub's credential formats, so they can be scrubbed
// from anything we print. A token leaking into a log or an error message is a
// real incident, and it is far too easy to do accidentally.
var tokenPattern = regexp.MustCompile(`\b(gh[pousr]_[A-Za-z0-9]{16,}|github_pat_[A-Za-z0-9_]{20,})\b`)

// Redact removes credentials from text. Both the known token value and anything
// matching GitHub's formats are replaced, because an error string can contain a
// credential the caller never held.
func Redact(s string, known ...string) string {
	for _, k := range known {
		if len(k) >= 8 {
			s = strings.ReplaceAll(s, k, "[redacted]")
		}
	}
	return tokenPattern.ReplaceAllString(s, "[redacted]")
}
