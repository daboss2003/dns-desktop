// Command gatewaydns-desktop is GatewayDNS Desktop.
//
// It is a desktop application: a window, a menu-bar item, and a resolver
// running behind both. It is also, with -headless, the same application with no
// user interface at all — which is what runs on a Raspberry Pi in a cupboard.
// Both are one binary and one code path; only the shell around it differs.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/daboss2003/dns-desktop/internal/app"
	"github.com/daboss2003/dns-desktop/internal/build"
	"github.com/daboss2003/dns-desktop/internal/ui"
)

type listFlag []string

func (f *listFlag) String() string { return strings.Join(*f, ",") }
func (f *listFlag) Set(v string) error {
	*f = append(*f, v)
	return nil
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "gatewaydns-desktop: "+err.Error())
		os.Exit(1)
	}
}

func run(args []string) error {
	fs := flag.NewFlagSet("gatewaydns-desktop", flag.ContinueOnError)
	var (
		listen     = fs.String("listen", app.DefaultListen, "address the resolver answers on")
		uiPort     = fs.Int("ui-port", 0, "loopback port for the interface (0 picks a free one)")
		headless   = fs.Bool("headless", false, "run with no window or menu-bar item")
		version    = fs.Bool("version", false, "print build information and exit")
		noLog      = fs.Bool("no-query-log", false, "keep no record of what was looked up")
		stateDir   = fs.String("state-dir", "", "where to keep device names and settings")
		verbose    = fs.Bool("v", false, "log more")
		upstreams  listFlag
		blocklists listFlag
	)
	fs.Var(&upstreams, "upstream", "an upstream resolver; repeat for more, in preference order")
	fs.Var(&blocklists, "blocklist", "a filter list to load; repeat for more")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *version {
		fmt.Print(build.Current())
		return nil
	}

	level := slog.LevelInfo
	if *verbose {
		level = slog.LevelDebug
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))

	a, err := app.New(app.Options{
		Listen:     *listen,
		Upstreams:  upstreams,
		Blocklists: blocklists,
		StateDir:   *stateDir,
		NoQueryLog: *noLog,
		Logger:     log,
	})
	if err != nil {
		return err
	}
	defer a.Close()

	// Anything a previous run left on this machine goes first. A process that
	// was killed could not clean up after itself, and a firewall rule or a
	// running access point from an hour ago is a machine whose owner cannot get
	// online with nothing on it to explain why.
	if rep, err := a.ReconcileGateway(context.Background()); err != nil {
		log.Warn("could not check for leftovers from a previous run", slog.String("error", err.Error()))
	} else if !rep.Clean() {
		log.Info("cleaned up after a previous run",
			slog.Any("found", rep.Found), slog.Any("removed", rep.Removed))
		for _, f := range rep.Failed {
			log.Error("could not clean up", slog.String("what", f))
		}
	}

	// The resolver first, and its failure is fatal: everything else in this
	// program exists to show what it is doing.
	served := make(chan error, 1)
	go func() { served <- a.Serve() }()

	// Then the interface. Its own failure is not fatal — a resolver with no
	// dashboard is still filtering, and taking the network down because a
	// window would not open would be the wrong trade.
	srv, addr, err := startUI(a, *uiPort, log)
	if err != nil {
		log.Error("the interface will not be available", slog.String("error", err.Error()))
	}
	if srv != nil {
		defer func() {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			_ = srv.Shutdown(ctx)
		}()
	}

	// A bind failure arrives here rather than being swallowed by the shell,
	// because "port 53 needs administrator rights" is the first thing most
	// people meet and it has to be said out loud.
	select {
	case err := <-served:
		if err != nil {
			return err
		}
	case <-time.After(150 * time.Millisecond):
	}

	if *headless {
		return runHeadless(a, served, log)
	}
	return runShell(a, addr, log)
}

// startUI binds loopback and serves the interface.
func startUI(a *app.App, port int, log *slog.Logger) (*http.Server, string, error) {
	h, err := ui.New(ui.Options{App: a, Logger: log})
	if err != nil {
		return nil, "", err
	}
	// Loopback, always. This endpoint renames devices, changes filtering and
	// reads a browsing history; serving it on a network interface would be a
	// management surface on whatever network the laptop is attached to.
	l, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		return nil, "", fmt.Errorf("binding the interface port: %w", err)
	}
	srv := ui.HTTPServer(h)
	go func() {
		if err := srv.Serve(l); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error("the interface stopped", slog.String("error", err.Error()))
		}
	}()
	// The token goes into the URL fragment rather than the query string: a
	// fragment is never sent to a server, never logged, and never appears in a
	// Referer. The page reads it, stashes it, and clears it from the address
	// bar before anything else runs.
	addr := fmt.Sprintf("http://%s/#t=%s", l.Addr().String(), h.Token())

	// The token is written to a file only this user can read, and the log line
	// names the file rather than the token. A credential in a log is a
	// credential in the system journal, readable by every administrator and
	// kept for as long as the journal is.
	tokenPath, err := a.SaveUIToken(h.Token())
	if err != nil {
		log.Warn("could not save the interface token", slog.String("error", err.Error()))
	}
	log.Info("interface ready",
		slog.String("addr", "http://"+l.Addr().String()),
		slog.String("token_file", tokenPath))
	return srv, addr, nil
}
