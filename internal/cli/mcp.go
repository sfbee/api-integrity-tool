package cli

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/sfbee/api-integrity-tool/internal/config"
	"github.com/sfbee/api-integrity-tool/internal/ghsource"
	"github.com/sfbee/api-integrity-tool/internal/gitmeta"
	"github.com/sfbee/api-integrity-tool/internal/mcpserver"
)

// runMCP serves the Model Context Protocol over stdio.
//
// Stdout is the JSON-RPC transport, so nothing else may write to it: a single
// stray line of output corrupts the stream and the session dies with an
// unhelpful parse error. Logging is redirected to stderr here rather than left
// to discipline, and cli_test asserts that a real `initialize` exchange
// produces exactly one JSON object on stdout.
func runMCP(env Env, args []string) error {
	fs := newFlagSet(env, "mcp")
	repoPath := fs.String("repo-path", "", "repository the tools operate on (default: current directory)")
	verbose := fs.Bool("v", false, "log tool activity to stderr")
	if err := fs.Parse(args); err != nil {
		return err
	}

	root := *repoPath
	if root == "" {
		root = env.Cwd
	}
	if r := gitmeta.FindRoot(root); r != "" {
		root = r
	}

	// Force the standard logger to stderr for the lifetime of the process.
	log.SetOutput(os.Stderr)
	log.SetFlags(0)
	log.SetPrefix("api-integrity-tool: ")

	logf := func(string, ...any) {}
	if *verbose {
		logf = func(format string, a ...any) {
			fmt.Fprintf(os.Stderr, "api-integrity-tool: "+format+"\n", a...)
		}
	}

	srv := mcpserver.New(mcpserver.Deps{
		RepoPath: root,
		Version:  Version(),
		Logf:     logf,
		NewSource: func(cfg *config.File) (ghsource.GitHubSource, error) {
			return newGitHubSource(env, cfg)
		},
	})

	// A client disconnect or a signal should shut the session down cleanly
	// rather than leaving a half-written frame behind.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	logf("serving MCP over stdio for %s", root)
	if err := srv.Run(ctx); err != nil && ctx.Err() == nil {
		return err
	}
	return nil
}
