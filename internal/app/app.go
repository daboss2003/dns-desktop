// Package app is GatewayDNS Desktop with no user interface attached.
//
// Everything the product does lives here: the resolver, the device table, the
// query log, the policy, and — when a platform and a person permit it — the
// gateway. What is NOT here is any notion of a window, a tray icon, a browser
// or an HTTP request.
//
// That split is what lets the same application be a desktop program on a laptop
// and a headless service on a Raspberry Pi without either being a special case.
// The desktop build wraps this in a window; the headless build wraps it in a
// signal handler. Neither changes what the product does, and a bug in one shell
// cannot reach the other.
package app

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/gatewaydns/gatewaydns"
	"github.com/gatewaydns/gatewaydns/policy"
	"github.com/gatewaydns/gatewaydns/resolver"
	"github.com/gatewaydns/gatewaydns/storage"

	"github.com/gatewaydns/gatewaydns-desktop/internal/device"
	"github.com/gatewaydns/gatewaydns-desktop/internal/gateway"
)

// Options configure an [App].
type Options struct {
	// Listen is where the resolver answers. The default is loopback on 5353
	// rather than 0.0.0.0 on 53, and both halves of that are deliberate.
	//
	// Port 53 is privileged, and an application that demanded elevation before
	// it would start at all would be asking for the most dangerous thing it
	// could ask for, on first run, before showing anybody anything. Loopback,
	// because a resolver that listened on every interface the moment it was
	// installed would be an open resolver on whatever network the laptop
	// happened to be on — a coffee shop included.
	//
	// Serving the network is a thing somebody turns on, having been shown what
	// it means.
	Listen string

	// Upstreams are the resolvers to forward to, in preference order.
	Upstreams []string

	// Blocklists are paths to filter lists loaded at start-up.
	Blocklists []string

	// StateDir is where the device table and settings are kept. Empty selects
	// the platform's own place for application state.
	StateDir string

	// QueryLogRetention bounds the query log. It is a record of what everyone
	// on the network looked up, so the default is deliberately short and the
	// operator can shorten it further or turn it off.
	QueryLogRetention storage.RetentionPolicy

	// NoQueryLog keeps no record at all, which is the most private
	// configuration available and costs nothing to choose.
	NoQueryLog bool

	Logger *slog.Logger
}

// App is the running product.
type App struct {
	opts    Options
	log     *slog.Logger
	engine  *gatewaydns.Engine
	devices *device.Table
	store   storage.Store
	gw      gateway.Gateway
	caps    gateway.Capabilities

	mu       sync.Mutex
	pc       net.PacketConn
	listener net.Listener
	serving  bool
	started  time.Time
	closed   bool

	// profiles maps a device profile name to its rules. It is rebuilt whenever
	// the device table changes, and read on the query path through an atomic
	// swap inside the policy engine.
	profiles sync.Map // string -> *policy.Rules
}

// New builds the application. It opens no sockets; see [App.Serve].
func New(opts Options) (*App, error) {
	if len(opts.Upstreams) == 0 {
		opts.Upstreams = DefaultUpstreams()
	}
	if opts.Listen == "" {
		opts.Listen = DefaultListen
	}
	a := &App{
		opts: opts,
		log:  opts.Logger,
		gw:   gateway.New(),
	}
	if a.log == nil {
		a.log = slog.New(slog.NewTextHandler(io.Discard, nil))
	}

	dir, err := a.stateDir()
	if err != nil {
		return nil, err
	}

	a.devices = device.New(device.Options{
		OnChange: func() { a.saveDevices(dir) },
	})
	if err := a.loadDevices(dir); err != nil {
		// A state file that will not load must not stop the product starting.
		// A resolver that refuses to run because it could not read a list of
		// device names has turned a cosmetic loss into a network outage.
		a.log.Warn("could not restore the device list; starting with an empty one",
			slog.String("error", err.Error()))
	}

	if !opts.NoQueryLog {
		ret := opts.QueryLogRetention
		if ret == (storage.RetentionPolicy{}) {
			ret = DefaultRetention
		}
		store, err := storage.NewMemory(storage.MemoryOptions{Retention: ret})
		if err != nil {
			return nil, fmt.Errorf("app: building the query log: %w", err)
		}
		a.store = store
	}

	a.engine, err = gatewaydns.New(gatewaydns.Options{
		Upstreams: opts.Upstreams,
		QueryLog:  a.store,
		Logger:    a.log,
		// The two halves of per-device policy. Identify runs before anything
		// is decided or recorded, so one answer to "who asked this" reaches
		// the rules, the metrics and the log alike; Devices then says what
		// that identity means.
		Identify: a.devices.Identify,
		Devices:  policy.ResolverFunc(a.policyFor),
	})
	if err != nil {
		return nil, err
	}

	for _, path := range opts.Blocklists {
		stats, err := a.engine.AddBlocklistFile(path)
		if err != nil {
			// One unreadable list is not a reason to refuse to resolve. It is
			// a reason to say so loudly: the operator believes they are
			// filtering.
			a.log.Error("could not load a blocklist", slog.String("path", path),
				slog.String("error", err.Error()))
			continue
		}
		a.log.Info("loaded blocklist", slog.String("path", path),
			slog.Int("rules", stats.Blocked), slog.Int("exceptions", stats.Allowed))
	}

	if a.caps, err = a.gw.Capabilities(context.Background()); err != nil {
		a.log.Warn("could not read the platform's capabilities",
			slog.String("error", err.Error()))
	}
	return a, nil
}

// Defaults.
const (
	// DefaultListen is loopback on the unprivileged DNS port; see
	// [Options.Listen] for why it is not 0.0.0.0:53.
	DefaultListen = "127.0.0.1:5353"
)

// DefaultRetention keeps a day of history.
//
// Shorter than the engine's own week, because this runs on somebody's laptop
// and holds what every person in the household looked up. A day answers "why
// did that not load just now", which is what a desktop query log is opened for.
var DefaultRetention = storage.RetentionPolicy{MaxAge: 24 * time.Hour, MaxEntries: 50_000}

// DefaultUpstreams are encrypted by default.
//
// DNS over TLS rather than plain UDP, because the alternative discloses every
// name this network looks up to whoever carries the traffic — which on the
// laptop this runs on is frequently a network nobody here controls.
func DefaultUpstreams() []string {
	return []string{"tls://1.1.1.1:853", "tls://9.9.9.9:853"}
}

// policyFor returns the rules for a client. It runs on every query.
func (a *App) policyFor(c resolver.Client) *policy.Rules {
	if c.ID == "" {
		return nil
	}
	d, ok := a.devices.Get(device.ID(c.ID))
	if !ok {
		return nil
	}
	if d.Paused {
		return pausedRules()
	}
	if d.Profile == "" {
		return nil
	}
	if v, ok := a.profiles.Load(d.Profile); ok {
		return v.(*policy.Rules)
	}
	return nil
}

// pausedRules blocks everything.
//
// It is built once and shared: a paused device is a common state and rebuilding
// a matcher per query would put a compile on the query path.
var pausedRules = sync.OnceValue(func() *policy.Rules {
	b := policy.NewMatcherBuilder()
	// A pattern rather than a suffix rule, because a suffix rule on the root
	// is refused — and rightly, since it is almost always a mistake. Here it
	// is the intent: this device asked to be cut off.
	b.Add(policy.KindRegex, ".*", "paused")
	return &policy.Rules{Name: "paused", Block: b.Build()}
})

// Serve binds the configured address and answers until [App.Close].
func (a *App) Serve() error {
	a.mu.Lock()
	if a.closed {
		a.mu.Unlock()
		return errors.New("app: already closed")
	}
	if a.serving {
		a.mu.Unlock()
		return errors.New("app: already serving")
	}
	pc, err := net.ListenPacket("udp", a.opts.Listen)
	if err != nil {
		a.mu.Unlock()
		return a.listenError("udp", err)
	}
	l, err := net.Listen("tcp", a.opts.Listen)
	if err != nil {
		_ = pc.Close()
		a.mu.Unlock()
		return a.listenError("tcp", err)
	}
	a.pc, a.listener, a.serving, a.started = pc, l, true, time.Now()
	a.mu.Unlock()

	a.log.Info("resolving", slog.String("addr", a.opts.Listen),
		slog.Any("upstreams", a.opts.Upstreams))
	return a.engine.Serve(pc, l)
}

// listenError turns a bind failure into something a person can act on.
//
// "permission denied" on port 53 and "address already in use" on port 53 are
// the two failures every install of this kind of software meets, and neither
// message says what to do about it.
func (a *App) listenError(network string, err error) error {
	addr := a.opts.Listen
	_, port, _ := net.SplitHostPort(addr)
	switch {
	case errors.Is(err, os.ErrPermission) && port == "53":
		return fmt.Errorf(
			"cannot listen on %s: port 53 needs administrator rights. "+
				"Run GatewayDNS Desktop with them, or serve on port 5353 and point devices there: %w", addr, err)
	case isAddrInUse(err) && port == "53":
		return fmt.Errorf(
			"cannot listen on %s: something else is already serving DNS on this machine — "+
				"on Linux usually systemd-resolved or dnsmasq, on Windows the DNS Client service. "+
				"Stop it, or serve on port 5353 instead: %w", addr, err)
	case isAddrInUse(err):
		return fmt.Errorf("cannot listen on %s: the address is already in use: %w", addr, err)
	default:
		return fmt.Errorf("cannot listen on %s (%s): %w", addr, network, err)
	}
}

func isAddrInUse(err error) bool {
	var se *os.SyscallError
	if errors.As(err, &se) {
		return se.Err.Error() == "address already in use"
	}
	return false
}

// Status is what the interface shows.
type Status struct {
	Serving   bool          `json:"serving"`
	Listen    string        `json:"listen"`
	Uptime    time.Duration `json:"uptime_ns"`
	Upstreams []string      `json:"upstreams"`

	Queries    uint64 `json:"queries"`
	Blocked    uint64 `json:"blocked"`
	CacheHits  uint64 `json:"cache_hits"`
	BlockRules int    `json:"block_rules"`
	AllowRules int    `json:"allow_rules"`

	Devices int `json:"devices"`

	// Platform is what this machine could do about being a gateway, and why
	// not. It is here rather than behind a separate call because a person
	// looking at the dashboard is asking one question — "is this working, and
	// what else could it do" — and two round trips to answer it is two chances
	// to show a half-drawn screen.
	Platform     string               `json:"platform"`
	Capabilities gateway.Capabilities `json:"capabilities"`
}

// Status returns a snapshot.
func (a *App) Status() Status {
	a.mu.Lock()
	serving, started := a.serving, a.started
	a.mu.Unlock()

	s := Status{
		Serving:      serving,
		Listen:       a.opts.Listen,
		Upstreams:    a.opts.Upstreams,
		Platform:     a.gw.Platform(),
		Capabilities: a.caps,
		Devices:      len(a.devices.Devices()),
	}
	if serving {
		s.Uptime = time.Since(started)
	}
	st := a.engine.Stats()
	s.BlockRules, s.AllowRules = st.BlockRules, st.AllowRules
	s.Queries, s.Blocked = st.Queries.Queries, st.Blocked
	if st.Cache != nil {
		s.CacheHits = st.Cache.Hits
	}
	return s
}

// Devices returns the device table.
func (a *App) Devices() *device.Table { return a.devices }

// Engine returns the resolver, for the interface's rule and cache controls.
func (a *App) Engine() *gatewaydns.Engine { return a.engine }

// QueryLog returns the store, or nil when none is kept.
func (a *App) QueryLog() storage.Store { return a.store }

// Gateway returns the platform gateway.
func (a *App) Gateway() gateway.Gateway { return a.gw }

// Close stops everything and saves what should outlive the process.
func (a *App) Close() error {
	a.mu.Lock()
	if a.closed {
		a.mu.Unlock()
		return nil
	}
	a.closed, a.serving = true, false
	a.mu.Unlock()

	// State first, because the rest of this can fail and the device names are
	// the part a person would notice losing.
	if dir, err := a.stateDir(); err == nil {
		a.saveDevices(dir)
	}
	var errs []error
	if err := a.devices.Close(); err != nil {
		errs = append(errs, err)
	}
	if err := a.engine.Close(); err != nil {
		errs = append(errs, err)
	}
	a.mu.Lock()
	pc, l := a.pc, a.listener
	a.mu.Unlock()
	if pc != nil {
		_ = pc.Close()
	}
	if l != nil {
		_ = l.Close()
	}
	return errors.Join(errs...)
}

// Shutdown stops accepting and lets queries in flight finish.
func (a *App) Shutdown(ctx context.Context) error { return a.engine.Shutdown(ctx) }

// stateDir returns the directory this application keeps state in, creating it.
func (a *App) stateDir() (string, error) {
	if a.opts.StateDir != "" {
		return a.opts.StateDir, ensureDir(a.opts.StateDir)
	}
	base, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("app: finding a place to keep state: %w", err)
	}
	dir := filepath.Join(base, "GatewayDNS")
	return dir, ensureDir(dir)
}

// ensureDir creates a directory only this user can read.
//
// 0700 because of what is in it: a list of every device on the network with the
// names a person gave them. On a shared machine that is not for the other
// accounts.
func ensureDir(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("app: creating %s: %w", dir, err)
	}
	return nil
}

const devicesFile = "devices.json"

func (a *App) loadDevices(dir string) error {
	b, err := os.ReadFile(filepath.Join(dir, devicesFile))
	if errors.Is(err, os.ErrNotExist) {
		return nil // A first run is not a failure.
	}
	if err != nil {
		return err
	}
	var state device.State
	if err := unmarshal(b, &state); err != nil {
		return err
	}
	return a.devices.Restore(state)
}

// saveDevices writes the device table, atomically.
//
// Through a temporary file and a rename, because the alternative is a truncated
// document if the machine loses power mid-write — and the file being written is
// every device name a person has typed.
func (a *App) saveDevices(dir string) {
	b, err := marshal(a.devices.Snapshot())
	if err != nil {
		a.log.Error("could not encode the device list", slog.String("error", err.Error()))
		return
	}
	path := filepath.Join(dir, devicesFile)
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		a.log.Error("could not write the device list", slog.String("error", err.Error()))
		return
	}
	if err := os.Rename(tmp, path); err != nil {
		a.log.Error("could not replace the device list", slog.String("error", err.Error()))
		_ = os.Remove(tmp)
	}
}

// StateDir is where this application keeps its state, creating it if needed.
func (a *App) StateDir() (string, error) { return a.stateDir() }

// SaveUIToken writes the interface credential where the person running this can
// find it, and nobody else can.
//
// It exists for the headless build, which has no window to hand the token to. A
// file readable only by this user is the least bad channel: logging it would
// put a live credential into the system journal, where it is readable by every
// administrator and kept for as long as the journal is; passing it on a command
// line would make it readable by every local user through /proc.
func (a *App) SaveUIToken(token string) (string, error) {
	dir, err := a.stateDir()
	if err != nil {
		return "", err
	}
	path := filepath.Join(dir, "ui-token")
	if err := os.WriteFile(path, []byte(token+"\n"), 0o600); err != nil {
		return "", fmt.Errorf("app: writing the interface token: %w", err)
	}
	return path, nil
}

// SetPaused pauses or resumes a device, and is the tray's one-click control.
func (a *App) SetPaused(id device.ID, paused bool) error {
	return a.devices.SetPaused(id, paused)
}

// LocalAddrs returns the addresses a device on the network could point at.
//
// It is what the interface shows under "tell your devices to use this", and it
// excludes loopback, because telling somebody to point their phone at 127.0.0.1
// is the single most common way this kind of software is misconfigured.
func (a *App) LocalAddrs() []netip.Addr {
	ifaces, err := a.gw.Interfaces(context.Background())
	if err != nil {
		return nil
	}
	var out []netip.Addr
	for _, x := range ifaces {
		if !x.Up || x.Kind == gateway.KindLoopback {
			continue
		}
		for _, p := range x.Addrs {
			if a := p.Addr(); a.Is4() && !a.IsLoopback() && !a.IsLinkLocalUnicast() {
				out = append(out, a)
			}
		}
	}
	return out
}
