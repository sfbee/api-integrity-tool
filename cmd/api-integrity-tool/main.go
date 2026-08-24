// Command api-integrity-tool indexes the outbound API calls a repository makes,
// links each API host to the upstream repository behind it, and watches those
// upstreams for changes that would break those calls.
//
// Subcommands:
//
//	api-integrity-tool scan [--repo-path P] [--endpoint /api/v1/user/add]...
//	                                      index outbound API calls
//	api-integrity-tool list [filters]     query the index
//	api-integrity-tool hosts              show hosts and their upstream links
//	api-integrity-tool --view-results     open the authenticated results dashboard
//
// It also runs as a Model Context Protocol server over stdio, so an agent can
// drive the same operations:
//
//	api-integrity-tool mcp
package main

import (
	"os"

	"github.com/sfbee/api-integrity-tool/internal/cli"
)

func main() {
	os.Exit(cli.Main(cli.OSEnv(os.Args[1:])))
}
