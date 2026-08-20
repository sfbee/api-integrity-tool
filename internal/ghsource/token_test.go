package ghsource

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestTokenChainPrefersEnvironment(t *testing.T) {
	t.Parallel()
	env := map[string]string{"GH_TOKEN": "from-gh-token"}
	c := &ChainTokenSource{
		Getenv: func(k string) string { return env[k] },
		Exec: func(context.Context, string, ...string) ([]byte, error) {
			t.Error("should not shell out when the environment supplies a token")
			return nil, nil
		},
	}
	got, err := c.Token(context.Background())
	if err != nil || got != "from-gh-token" {
		t.Fatalf("Token() = %q, %v", got, err)
	}
}

func TestTokenChainFallsBackToGhCLI(t *testing.T) {
	t.Parallel()
	var calls [][]string
	c := &ChainTokenSource{
		Getenv: func(string) string { return "" },
		Exec: func(_ context.Context, name string, args ...string) ([]byte, error) {
			calls = append(calls, append([]string{name}, args...))
			return []byte("gho_fromcli\n"), nil
		},
	}
	got, err := c.Token(context.Background())
	if err != nil || got != "gho_fromcli" {
		t.Fatalf("Token() = %q, %v", got, err)
	}
	if len(calls) != 1 || calls[0][0] != "gh" {
		t.Errorf("calls = %v, want a single gh invocation", calls)
	}
	// The result is cached; a second call must not shell out again.
	if _, err := c.Token(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(calls) != 1 {
		t.Errorf("token was not cached: %d invocations", len(calls))
	}
}

func TestTokenChainReportsUnauthenticated(t *testing.T) {
	t.Parallel()
	c := &ChainTokenSource{
		Getenv: func(string) string { return "" },
		Exec:   func(context.Context, string, ...string) ([]byte, error) { return nil, errors.New("no gh") },
	}
	if _, err := c.Token(context.Background()); !errors.Is(err, ErrUnauthenticated) {
		t.Errorf("err = %v, want ErrUnauthenticated", err)
	}
}

// A credential in a log line or an error message is a real incident, so
// redaction must catch both the known value and anything token-shaped.
func TestRedact(t *testing.T) {
	t.Parallel()
	tests := []struct{ in, known, wantAbsent string }{
		{"failed with ghp_abcdefghij0123456789ABCDEF", "", "ghp_abcdefghij0123456789ABCDEF"},
		{"token gho_1234567890abcdefghijKLMNOP failed", "", "gho_1234567890abcdefghijKLMNOP"},
		{"using github_pat_11ABCDEFG0abcdefghijklmnop", "", "github_pat_11ABCDEFG0abcdefghijklmnop"},
		{"Authorization: Bearer my-custom-secret-value", "my-custom-secret-value", "my-custom-secret-value"},
	}
	for _, tc := range tests {
		got := Redact(tc.in, tc.known)
		if strings.Contains(got, tc.wantAbsent) {
			t.Errorf("Redact(%q) = %q, still contains the credential", tc.in, got)
		}
		if !strings.Contains(got, "[redacted]") {
			t.Errorf("Redact(%q) = %q, want a redaction marker", tc.in, got)
		}
	}
	// A short "known" value must not be used as a needle, or redaction would
	// mangle ordinary text.
	if got := Redact("the quick brown fox", "the"); got != "the quick brown fox" {
		t.Errorf("short known values should be ignored, got %q", got)
	}
}
