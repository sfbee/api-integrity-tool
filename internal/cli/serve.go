package cli

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"github.com/stephen-bee/endpoint-monitor/internal/config"
	"github.com/stephen-bee/endpoint-monitor/internal/ghsource"
	"github.com/stephen-bee/endpoint-monitor/internal/web"
)

func runServe(env Env, args []string) error {
	fs := newFlagSet(env, "serve")
	repoPath := fs.String("repo-path", "", "repository to serve (default: current directory)")
	port := fs.Int("port", web.DefaultPort, "port to listen on")
	autoPort := fs.Bool("auto-port", false, "pick any free port instead of failing when the chosen one is busy")
	open := fs.Bool("open", false, "try to open the dashboard in the default browser")
	if err := fs.Parse(args); err != nil {
		return err
	}

	l, root, err := newLinker(env, *repoPath)
	if err != nil {
		return err
	}
	if err := l.SyncConfig(); err != nil {
		return err
	}

	// If the port is busy, say who has it rather than silently drifting to
	// another one: a dashboard that moves breaks bookmarks and scripts.
	if !*autoPort {
		if busy, mine := probePort(*port); busy {
			if mine {
				return fmt.Errorf("port %d already serves an api-integrity-tool dashboard.\n"+
					"Stop that process, or use --auto-port for a second one on a free port.", *port)
			}
			return fmt.Errorf("port %d is in use by another program; use --port N or --auto-port", *port)
		}
	} else {
		*port = 0
	}

	srv, err := web.New(web.Options{
		RepoPath: root,
		Store:    l.Store,
		Config:   l.Config,
		Port:     *port,
		Version:  Version(),
		NewSource: func(cfg *config.File) (ghsource.GitHubSource, error) {
			return newGitHubSource(env, cfg)
		},
		Logf: func(format string, a ...any) { fmt.Fprintf(env.Stderr, format+"\n", a...) },
	})
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	errc := make(chan error, 1)
	go func() { errc <- srv.Serve(ctx) }()

	// Give the listener a moment so the printed URL is already live, and so a
	// bind failure is reported instead of a URL that does not work.
	select {
	case err := <-errc:
		if err != nil {
			return err
		}
		return nil
	case <-time.After(150 * time.Millisecond):
	}

	loginURL := srv.LoginURL()
	fmt.Fprintf(env.Stderr, "==> Results dashboard listening on 127.0.0.1:%d\n", srv.Port())
	fmt.Fprintf(env.Stderr, "    Open: %s\n", loginURL)
	fmt.Fprintf(env.Stderr, "    This link is valid only while this process runs. Ctrl-C to stop.\n")

	if *open {
		openBrowser(env, loginURL)
	}

	if err := <-errc; err != nil {
		return err
	}
	fmt.Fprintln(env.Stderr, "==> Dashboard stopped")
	return nil
}

// probePort reports whether a port is occupied and, if so, whether the occupant
// is one of our own dashboards.
func probePort(port int) (busy bool, mine bool) {
	addr := net.JoinHostPort("127.0.0.1", fmt.Sprint(port))
	ln, err := net.Listen("tcp", addr)
	if err == nil {
		ln.Close()
		return false, false
	}
	client := &http.Client{Timeout: 750 * time.Millisecond}
	resp, herr := client.Get("http://" + addr + "/healthz")
	if herr != nil {
		return true, false
	}
	defer resp.Body.Close()
	buf := make([]byte, 256)
	n, _ := resp.Body.Read(buf)
	return true, containsString(string(buf[:n]), "api-integrity-tool")
}

func containsString(haystack, needle string) bool {
	return len(needle) > 0 && len(haystack) >= len(needle) && indexOfString(haystack, needle) >= 0
}

func indexOfString(h, n string) int {
	for i := 0; i+len(n) <= len(h); i++ {
		if h[i:i+len(n)] == n {
			return i
		}
	}
	return -1
}

// openBrowser is best-effort: failing to open a browser must not fail the
// command, since the URL has already been printed.
func openBrowser(env Env, url string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", url)
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	default:
		cmd = exec.Command("xdg-open", url)
	}
	if err := cmd.Start(); err != nil {
		fmt.Fprintf(env.Stderr, "    (could not open a browser: %v)\n", err)
		return
	}
	go func() { _ = cmd.Wait() }()
}
