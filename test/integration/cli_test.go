// Package integration exercises the built binary end to end.
package integration

import (
	"bufio"
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

var (
	buildOnce sync.Once
	binPath   string
	buildErr  error
)

// binary builds the CLI once per test binary and returns its path.
func binary(t *testing.T) string {
	t.Helper()
	buildOnce.Do(func() {
		dir, err := os.MkdirTemp("", "ait-bin-*")
		if err != nil {
			buildErr = err
			return
		}
		binPath = filepath.Join(dir, "api-integrity-tool")
		cmd := exec.Command("go", "build", "-o", binPath, "./cmd/api-integrity-tool")
		cmd.Dir = repoRoot(nil)
		out, err := cmd.CombinedOutput()
		if err != nil {
			buildErr = err
			binPath = string(out)
		}
	})
	if buildErr != nil {
		t.Fatalf("building the binary failed: %v\n%s", buildErr, binPath)
	}
	return binPath
}

// repoRoot walks up to the directory holding go.mod.
func repoRoot(t *testing.T) string {
	dir, err := os.Getwd()
	if err != nil {
		if t != nil {
			t.Fatal(err)
		}
		return "."
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "."
		}
		dir = parent
	}
}

// run executes the binary in a directory and returns stdout, stderr and the
// exit code. Stdout and stderr are captured separately on purpose: several
// guarantees in this tool are about which stream something goes to.
func run(t *testing.T, dir string, env []string, args ...string) (string, string, int) {
	t.Helper()
	cmd := exec.Command(binary(t), args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), env...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	code := 0
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
	} else if err != nil {
		t.Fatalf("running %v: %v", args, err)
	}
	return stdout.String(), stderr.String(), code
}

// demoRepo creates a small git repository with outbound API calls in it.
func demoRepo(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	write := func(name, body string) {
		full := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("go.mod", "module example.com/demo\n\ngo 1.27\n")
	write("client.go", `package demo

import "net/http"

const stripeBase = "https://api.stripe.com"

func Charge()   { http.Post(stripeBase+"/v1/charges", "application/json", nil) }
func Invoices() { http.Get(stripeBase + "/v1/invoices") }
func Widgets()  { http.Get("https://api.widgetco.io/api/v1/widgets") }
func Debug()    { http.Get("http://127.0.0.1:9000/debug") }
`)
	write("server.go", `package demo

import "net/http"

func Routes() {
	http.HandleFunc("/internal/health", func(w http.ResponseWriter, r *http.Request) {})
}
`)
	for _, args := range [][]string{
		{"init", "-q"},
		{"-c", "user.email=t@example.com", "-c", "user.name=T", "add", "-A"},
		{"-c", "user.email=t@example.com", "-c", "user.name=T", "commit", "-qm", "initial"},
	} {
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	return dir
}

func TestScanListHostsFlow(t *testing.T) {
	t.Parallel()
	dir := demoRepo(t)

	// The human-readable summary is a diagnostic and goes to stderr, leaving
	// stdout clean for --format json. That split is the contract.
	stdout, stderr, code := run(t, dir, nil, "scan")
	if code != 0 {
		t.Fatalf("scan exited %d: %s%s", code, stdout, stderr)
	}
	if !strings.Contains(stderr, "outbound calls") {
		t.Errorf("scan summary unexpected:\n%s", stderr)
	}
	// The route definition and the localhost call must be rejected, not indexed.
	if !strings.Contains(stderr, "rejected") {
		t.Errorf("scan should report rejected call sites:\n%s", stderr)
	}
	if strings.TrimSpace(stdout) != "" {
		t.Errorf("scan wrote to stdout in text mode, which must stay parseable:\n%s", stdout)
	}

	stdout, _, code = run(t, dir, nil, "list")
	if code != 0 {
		t.Fatalf("list exited %d", code)
	}
	for _, want := range []string{"api.stripe.com", "/v1/charges", "api.widgetco.io"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("list output missing %q:\n%s", want, stdout)
		}
	}
	for _, unwanted := range []string{"127.0.0.1", "/internal/health"} {
		if strings.Contains(stdout, unwanted) {
			t.Errorf("list should not contain %q:\n%s", unwanted, stdout)
		}
	}

	// JSON output must be machine-readable on stdout alone.
	stdout, _, code = run(t, dir, nil, "list", "--format", "json")
	if code != 0 {
		t.Fatalf("list --format json exited %d", code)
	}
	var calls []map[string]any
	if err := json.Unmarshal([]byte(stdout), &calls); err != nil {
		t.Fatalf("list --format json did not produce clean JSON: %v\n%s", err, stdout)
	}
	if len(calls) == 0 {
		t.Error("expected some calls in the JSON output")
	}
}

// scan --check is the CI drift gate, so its exit codes are part of the contract.
func TestScanCheckExitCodes(t *testing.T) {
	t.Parallel()
	dir := demoRepo(t)
	run(t, dir, nil, "scan")

	if _, _, code := run(t, dir, nil, "scan", "--check"); code != 0 {
		t.Errorf("--check on an up-to-date index exited %d, want 0", code)
	}

	extra := filepath.Join(dir, "extra.go")
	body := "package demo\n\nimport \"net/http\"\n\nfunc New() { http.Get(\"https://api.newvendor.io/v1/thing\") }\n"
	if err := os.WriteFile(extra, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, code := run(t, dir, nil, "scan", "--check"); code != 1 {
		t.Errorf("--check after adding a call exited %d, want 1", code)
	}
	if err := os.Remove(extra); err != nil {
		t.Fatal(err)
	}
	if _, _, code := run(t, dir, nil, "scan", "--check"); code != 0 {
		t.Errorf("--check after reverting exited %d, want 0", code)
	}
}

func TestLinkingCommands(t *testing.T) {
	t.Parallel()
	dir := demoRepo(t)
	run(t, dir, nil, "scan")

	// The curated table links the well-known host with no interaction.
	stdout, _, code := run(t, dir, nil, "link-hosts")
	if code != 0 {
		t.Fatalf("link-hosts exited %d: %s", code, stdout)
	}
	if !strings.Contains(stdout, "stripe/openapi") {
		t.Errorf("expected api.stripe.com to be auto-linked:\n%s", stdout)
	}
	if !strings.Contains(stdout, "api.widgetco.io") {
		t.Errorf("expected the unknown host to be reported as needing a link:\n%s", stdout)
	}

	// Flags must work after the positional argument, which is how people type it.
	stdout, stderr, code := run(t, dir, nil, "link", "api.widgetco.io", "--repo", "github.com/widgetco/api", "--role", "spec_only")
	if code != 0 {
		t.Fatalf("link exited %d: %s%s", code, stdout, stderr)
	}
	if !strings.Contains(stdout, "widgetco/api") {
		t.Errorf("link output:\n%s", stdout)
	}

	stdout, _, _ = run(t, dir, nil, "upstreams")
	if !strings.Contains(stdout, "spec_only") {
		t.Errorf("upstreams should show the role:\n%s", stdout)
	}

	stdout, _, _ = run(t, dir, nil, "link-hosts")
	if strings.Contains(stdout, "still need an upstream") {
		t.Errorf("every host should be linked by now:\n%s", stdout)
	}
}

// A check without a credential must explain itself rather than fail obscurely.
func TestDoctorReportsMissingToken(t *testing.T) {
	t.Parallel()
	dir := demoRepo(t)
	run(t, dir, nil, "scan")
	env := []string{"GITHUB_TOKEN=", "GH_TOKEN=", "PATH=/nonexistent"}
	stdout, _, code := run(t, dir, env, "doctor")
	if code != 0 {
		t.Fatalf("doctor exited %d", code)
	}
	if !strings.Contains(stdout, "github token: NOT FOUND") {
		t.Errorf("doctor should report the missing credential:\n%s", stdout)
	}
	if !strings.Contains(stdout, "Everything except `check` works without one") {
		t.Errorf("doctor should say what still works:\n%s", stdout)
	}
}

// The guarantee that keeps the MCP transport usable: in mcp mode stdout carries
// JSON-RPC and nothing else. One stray line of logging corrupts the stream and
// the session dies with an unhelpful parse error, so this is asserted rather
// than trusted to discipline.
func TestMCPModeKeepsStdoutPure(t *testing.T) {
	t.Parallel()
	dir := demoRepo(t)

	initialize := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{` +
		`"protocolVersion":"2025-06-18","capabilities":{},` +
		`"clientInfo":{"name":"probe","version":"1"}}}` + "\n"

	cmd := exec.Command(binary(t), "mcp", "-v")
	cmd.Dir = dir
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	if _, err := stdin.Write([]byte(initialize)); err != nil {
		t.Fatal(err)
	}

	// Read the response before closing stdin: closing it immediately races the
	// server's reply, which is what makes a naive version of this test flaky.
	var stdout bytes.Buffer
	lines := make(chan string, 1)
	go func() {
		r := bufio.NewReader(stdoutPipe)
		for {
			line, err := r.ReadString('\n')
			if line != "" {
				stdout.WriteString(line)
				select {
				case lines <- line:
				default:
				}
			}
			if err != nil {
				return
			}
		}
	}()
	select {
	case <-lines:
	case <-time.After(20 * time.Second):
		cmd.Process.Kill()
		t.Fatalf("no JSON-RPC response within the timeout; stderr:\n%s", stderr.String())
	}
	stdin.Close()
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case <-done:
	case <-time.After(20 * time.Second):
		cmd.Process.Kill()
		t.Fatal("mcp mode did not exit after stdin closed")
	}

	out := strings.TrimSpace(stdout.String())
	if out == "" {
		t.Fatalf("no response on stdout; stderr was:\n%s", stderr.String())
	}
	// Every line of stdout must be a JSON-RPC message and nothing else.
	for i, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var msg map[string]any
		if err := json.Unmarshal([]byte(line), &msg); err != nil {
			t.Fatalf("stdout line %d is not JSON (%v): %q", i+1, err, line)
		}
		if msg["jsonrpc"] != "2.0" {
			t.Errorf("stdout line %d is not a JSON-RPC message: %q", i+1, line)
		}
	}
	// -v was passed, so diagnostics must exist and must be on stderr.
	if !strings.Contains(stderr.String(), "serving MCP over stdio") {
		t.Errorf("expected the startup diagnostic on stderr, got:\n%s", stderr.String())
	}
}

func TestUnknownCommandExplainsItself(t *testing.T) {
	t.Parallel()
	_, stderr, code := run(t, t.TempDir(), nil, "frobnicate")
	if code == 0 {
		t.Error("an unknown command should fail")
	}
	if !strings.Contains(stderr, "unknown command") || !strings.Contains(stderr, "scan") {
		t.Errorf("stderr should name the unknown command and list the real ones:\n%s", stderr)
	}
}

func TestVersionIsOnStdout(t *testing.T) {
	t.Parallel()
	stdout, _, code := run(t, t.TempDir(), nil, "version")
	if code != 0 || strings.TrimSpace(stdout) == "" {
		t.Errorf("version exited %d with stdout %q", code, stdout)
	}
}
