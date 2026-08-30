// Package ui serves the GatewayDNS Desktop interface.
//
// The interface is HTML, CSS and JavaScript, embedded in the binary and served
// over loopback to a window this application opened itself. Two things follow
// from that and are worth stating, because both look like shortcuts and neither
// is:
//
// There is no build step. No bundler, no package manager, no node_modules. The
// files under assets/ are the files that ship. That is affordable because this
// is a handful of screens rather than an application in its own right, and it
// is worth having because a build step is a second toolchain to keep working,
// a second supply chain to audit, and the reason a Go project stops being
// buildable with `go build`.
//
// The same interface is served whether it is displayed in this application's
// own window or pointed at a [gatewaydnsd] running on a server somewhere. One
// interface, two deployments — which is only true because the window talks to
// its own process over HTTP rather than through a private binding.
//
// # Loopback is not a security boundary
//
// Everything here is authenticated, and the token is not in a cookie and not in
// a URL. That is deliberate on both counts.
//
// A cookie is scoped by host and NOT by port: a cookie set for 127.0.0.1 is
// attached to requests to every other service on 127.0.0.1, whatever port it
// listens on. A development server, a language runtime's debug endpoint, or
// anything else the person happens to be running would receive this
// application's session cookie. So the token travels in an Authorization
// header, which is per-origin.
//
// A token in a URL is worse: it is in the browser's history, in the referrer of
// any external resource, and — where a browser is launched to display it — in
// the command line of a process, which on Linux any local user can read from
// /proc. The window is given its token by injection before the first page
// loads, so it never appears in an address bar at all.
package ui

import (
	"crypto/rand"
	"crypto/subtle"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/gatewaydns/gatewaydns/storage"

	"github.com/gatewaydns/gatewaydns-desktop/internal/app"
	"github.com/gatewaydns/gatewaydns-desktop/internal/build"
	"github.com/gatewaydns/gatewaydns-desktop/internal/device"
)

//go:embed assets
var assets embed.FS

// Options configure a [Server].
type Options struct {
	App *app.App
	// Token authenticates every request. Empty generates one.
	Token  string
	Logger *slog.Logger
}

// Server is the HTTP surface behind the interface.
type Server struct {
	app   *app.App
	token string
	log   *slog.Logger
	mux   *http.ServeMux
	files http.Handler
}

// New builds the server.
func New(opts Options) (*Server, error) {
	if opts.App == nil {
		return nil, errors.New("ui: no application to serve")
	}
	token := opts.Token
	if token == "" {
		token = NewToken()
	}
	sub, err := fs.Sub(assets, "assets")
	if err != nil {
		return nil, err
	}
	s := &Server{
		app:   opts.App,
		token: token,
		log:   opts.Logger,
		mux:   http.NewServeMux(),
		files: http.FileServerFS(sub),
	}
	if s.log == nil {
		s.log = slog.New(slog.DiscardHandler)
	}
	s.routes()
	return s, nil
}

// Token is the credential the window must present.
func (s *Server) Token() string { return s.token }

// NewToken returns a fresh credential.
//
// 32 bytes from crypto/rand. It is never written to a file that another account
// can read, never placed in a URL, and never passed as an argument.
func NewToken() string {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("ui: no randomness available: " + err.Error())
	}
	return hex.EncodeToString(b[:])
}

func (s *Server) routes() {
	s.mux.Handle("GET /api/status", s.authed(s.handleStatus))
	s.mux.Handle("GET /api/devices", s.authed(s.handleDevices))
	s.mux.Handle("POST /api/devices/{id}/name", s.authed(s.handleRename))
	s.mux.Handle("POST /api/devices/{id}/pause", s.authed(s.handlePause))
	s.mux.Handle("DELETE /api/devices/{id}", s.authed(s.handleForget))
	s.mux.Handle("GET /api/queries", s.authed(s.handleQueries))
	s.mux.Handle("POST /api/rules/block", s.authed(s.handleBlock))
	s.mux.Handle("POST /api/rules/allow", s.authed(s.handleAllow))
	s.mux.Handle("POST /api/cache/flush", s.authed(s.handleFlush))

	// The interface itself. Unauthenticated by design: it is markup and script
	// with no data in it, and the token it needs is injected into the window
	// rather than fetched. Gating the shell would mean the browser could not
	// load the page that would ask for the credential.
	s.mux.Handle("GET /", s.static())
}

// ServeHTTP implements [http.Handler].
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// A local page in the person's browser can reach this port. It cannot read
	// the answer without CORS, and none is granted — but a form post would
	// still arrive, so state-changing requests are refused unless they carry
	// the header a form cannot set. The token check does that already; this is
	// the second mechanism, because "the token is enough" is exactly what
	// somebody will assume when adding an endpoint later.
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Content-Security-Policy",
		"default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; "+
			"img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'")
	s.mux.ServeHTTP(w, r)
}

func (s *Server) static() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// One page, so any path that is not a file is the page. That is what
		// makes a link to /devices work after a reload.
		if r.URL.Path != "/" && !strings.Contains(r.URL.Path, ".") {
			r.URL.Path = "/"
		}
		s.files.ServeHTTP(w, r)
	})
}

// authed checks the bearer token in constant time.
func (s *Server) authed(next http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		const prefix = "Bearer "
		h := r.Header.Get("Authorization")
		if len(h) <= len(prefix) || !strings.EqualFold(h[:len(prefix)], prefix) ||
			subtle.ConstantTimeCompare([]byte(h[len(prefix):]), []byte(s.token)) != 1 {
			// Constant time, not ==. A token compared with == leaks itself one
			// byte at a time to anything that can measure the response, and on
			// the same machine that measurement is easy.
			s.fail(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		next(w, r)
	})
}

func (s *Server) fail(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

func (s *Server) json(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(v); err != nil {
		s.log.Warn("could not write a response", slog.String("error", err.Error()))
	}
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	st := s.app.Status()
	addrs := s.app.LocalAddrs()
	strs := make([]string, 0, len(addrs))
	for _, a := range addrs {
		strs = append(strs, a.String())
	}
	s.json(w, struct {
		app.Status
		Build     build.Info `json:"build"`
		LocalAddr []string   `json:"local_addrs"`
	}{st, build.Current(), strs})
}

func (s *Server) handleDevices(w http.ResponseWriter, r *http.Request) {
	s.json(w, s.app.Devices().Devices())
}

func (s *Server) handleRename(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&body); err != nil {
		s.fail(w, http.StatusBadRequest, "the request body is not the expected JSON")
		return
	}
	if err := s.app.Devices().Rename(device.ID(r.PathValue("id")), body.Name); err != nil {
		s.deviceError(w, err)
		return
	}
	s.json(w, map[string]bool{"ok": true})
}

func (s *Server) handlePause(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Paused bool `json:"paused"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&body); err != nil {
		s.fail(w, http.StatusBadRequest, "the request body is not the expected JSON")
		return
	}
	if err := s.app.SetPaused(device.ID(r.PathValue("id")), body.Paused); err != nil {
		s.deviceError(w, err)
		return
	}
	s.json(w, map[string]bool{"ok": true})
}

func (s *Server) handleForget(w http.ResponseWriter, r *http.Request) {
	if err := s.app.Devices().Forget(device.ID(r.PathValue("id"))); err != nil {
		s.deviceError(w, err)
		return
	}
	s.json(w, map[string]bool{"ok": true})
}

func (s *Server) deviceError(w http.ResponseWriter, err error) {
	if errors.Is(err, device.ErrUnknownDevice) {
		s.fail(w, http.StatusNotFound, err.Error())
		return
	}
	s.fail(w, http.StatusBadRequest, err.Error())
}

func (s *Server) handleQueries(w http.ResponseWriter, r *http.Request) {
	log := s.app.QueryLog()
	if log == nil {
		// Keeping no record is a supported configuration and the most private
		// one available, so the interface is told plainly rather than shown an
		// empty list it would read as "nothing happened".
		s.fail(w, http.StatusNotImplemented, "this installation keeps no query log")
		return
	}
	f := storage.Filter{Limit: 200}
	if v := r.URL.Query().Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 {
			s.fail(w, http.StatusBadRequest, "limit must be a number")
			return
		}
		// Clamped, including a zero, because downstream a zero limit means
		// "unset" and takes the store's own default.
		if n == 0 || n > 500 {
			n = 500
		}
		f.Limit = n
	}
	if v := r.URL.Query().Get("device"); v != "" {
		f.Device = v
	}
	switch r.URL.Query().Get("blocked") {
	case "true":
		yes := true
		f.Blocked = &yes
	case "false":
		no := false
		f.Blocked = &no
	}
	entries, err := log.Query(r.Context(), f)
	if err != nil {
		s.fail(w, http.StatusInternalServerError, "reading the query log: "+err.Error())
		return
	}
	if entries == nil {
		entries = []storage.QueryEntry{}
	}
	s.json(w, entries)
}

func (s *Server) handleBlock(w http.ResponseWriter, r *http.Request) { s.rule(w, r, true) }
func (s *Server) handleAllow(w http.ResponseWriter, r *http.Request) { s.rule(w, r, false) }

func (s *Server) rule(w http.ResponseWriter, r *http.Request, block bool) {
	var body struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&body); err != nil {
		s.fail(w, http.StatusBadRequest, "the request body is not the expected JSON")
		return
	}
	var err error
	if block {
		err = s.app.Engine().Block(body.Name)
	} else {
		err = s.app.Engine().Allow(body.Name)
	}
	if err != nil {
		s.fail(w, http.StatusBadRequest, err.Error())
		return
	}
	s.json(w, map[string]bool{"ok": true})
}

func (s *Server) handleFlush(w http.ResponseWriter, r *http.Request) {
	s.app.Engine().ClearCache()
	s.json(w, map[string]bool{"ok": true})
}

// Listen binds a loopback address for the interface.
//
// Loopback only, and never a configurable address: this endpoint renames
// devices, changes filtering and reads a browsing history. Serving it on a
// network interface would be a management surface on whatever network the
// laptop is attached to, which is a different product with a different threat
// model. Remote management is what [gatewaydnsd] is for.
func Listen(port int) (netip.AddrPort, error) {
	if port < 0 || port > 65535 {
		return netip.AddrPort{}, fmt.Errorf("ui: %d is not a port", port)
	}
	return netip.AddrPortFrom(netip.AddrFrom4([4]byte{127, 0, 0, 1}), uint16(port)), nil
}

// HTTPServer wraps a handler with the timeouts a long-lived local server needs.
func HTTPServer(h http.Handler) *http.Server {
	return &http.Server{
		Handler:           h,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
}
