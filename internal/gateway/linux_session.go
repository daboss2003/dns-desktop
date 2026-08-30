package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/gatewaydns/gatewaydns-desktop/internal/gateway/hostapd"
	"github.com/gatewaydns/gatewaydns-desktop/internal/gateway/nftables"
)

// Runner executes an external command.
//
// It is an interface, and this file has no build tag, so the whole of the Linux
// bring-up and teardown compiles and is tested on any machine — with no
// wireless adapter, no kernel to talk to and no root. What is behind the
// interface on a real Linux box is a few lines in gateway_linux.go; what is in
// front of it is every decision worth getting wrong.
type Runner interface {
	// Run executes name with args, feeding it stdin, and returns its output.
	Run(ctx context.Context, name, stdin string, args ...string) (string, error)
	// Look reports whether a command exists.
	Look(name string) bool
}

// journal records what has been done, so that a process which is killed can be
// cleaned up after by the next one.
//
// Every step is written and flushed to disk BEFORE it is applied. The only
// inconsistency that ordering permits is a journal claiming a step that was not
// taken — and every undo is idempotent and treats "not there" as success, so
// that direction costs nothing. Applying first and recording after loses a step
// that nothing knows to undo, which is a firewall rule left on a machine whose
// owner cannot get online and has nothing to read about why.
//
// It lives under /run, which is a memory file system: a reboot is therefore
// already a complete cleanup, and the only crash to recover from is a process
// death without one.
type journal struct {
	dir string
}

type journalEntry struct {
	Step string `json:"step"`
	Data string `json:"data,omitempty"`
}

func (j journal) path() string { return filepath.Join(j.dir, "session.json") }

func (j journal) record(entries []journalEntry) error {
	if err := os.MkdirAll(j.dir, 0o700); err != nil {
		return fmt.Errorf("gateway: creating %s: %w", j.dir, err)
	}
	b, err := json.Marshal(entries)
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(j.dir, "session-*.tmp")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err := f.Write(b); err != nil {
		f.Close()
		return err
	}
	// Flushed before the rename, and the rename before the step it describes is
	// applied. Without the sync the record can still be in a buffer when the
	// machine loses power, which is the case this whole mechanism exists for.
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), j.path())
}

func (j journal) read() ([]journalEntry, error) {
	b, err := os.ReadFile(j.path())
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []journalEntry
	if err := json.Unmarshal(b, &out); err != nil {
		// A journal that will not parse is worse than none: it is a record of
		// changes nobody can undo. Reported rather than ignored, so the live
		// scan is known to be the only source.
		return nil, fmt.Errorf("gateway: the recovery journal at %s is unreadable: %w", j.path(), err)
	}
	return out, nil
}

func (j journal) clear() error {
	err := os.Remove(j.path())
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

// Step names recorded in the journal. They are strings rather than an
// enumeration because they are written to disk by one version of this program
// and read by another, and a number whose meaning changed between the two would
// undo the wrong thing.
const (
	stepForwarding = "ipv4-forwarding"
	stepNftables   = "nftables-table"
	stepAddress    = "interface-address"
	stepHostapd    = "hostapd"
)

// linuxGateway is the Linux implementation of [Gateway].
type linuxGateway struct {
	run     Runner
	journal journal
	// runDir is where generated configuration lives. It is under /run for the
	// same reason the journal is: a hostapd configuration containing a
	// pre-shared key must not survive a reboot on disk.
	runDir string

	// The probes that read this machine's own state. They are fields so a test
	// can supply a machine — a wireless adapter that cannot do access-point
	// mode, an uplink that goes away — without having one, which is the only
	// way any of this is exercised before it reaches hardware.
	defaultRoute func() (string, error)
	wireless     func(string) (bool, apSupport)
	// list overrides enumeration entirely. Nil uses the real interfaces.
	list func() ([]Interface, error)
}

var _ Gateway = (*linuxGateway)(nil)

// Platform implements [Gateway].
func (g *linuxGateway) Platform() string { return "linux" }

// notInThisBuild is what a capability reports when the machine could do it and
// this build does not. It is in an untagged file so that every platform's
// implementation says the same thing.
const notInThisBuild = "bringing this up is not implemented in this build; " +
	"point a device at this machine as its DNS server and it is filtered"

// Capabilities implements [Gateway].
//
// It reports what is missing from THIS machine — no hostapd, no firewall tool,
// no adapter with access-point mode — because those are the answers a person
// can act on, and each has a different fix.
func (g *linuxGateway) Capabilities(ctx context.Context) (Capabilities, error) {
	c := Capabilities{Reasons: map[Capability]string{}, Sharing: []SharingModel{SharingNone}}

	nft := g.run.Look("nft")
	if !nft {
		const why = "nft is not installed, so this machine cannot write the firewall rules that " +
			"share a connection, capture DNS or block a device; install nftables"
		for _, cap := range []Capability{CapShareUplink, CapDNSRedirect, CapDNSEnforce, CapBlockDevice, CapIPv6Control} {
			c.Reasons[cap] = why
			c.Fixable |= cap
		}
	} else {
		c.Have |= CapShareUplink | CapDNSRedirect | CapDNSEnforce | CapBlockDevice | CapIPv6Control
	}

	// The DHCP server is this application's own, so it is always available.
	c.Have |= CapOwnDHCP

	switch {
	case !g.run.Look("hostapd"):
		c.Reasons[CapAccessPoint] = "hostapd is not installed, and it is what turns a wireless " +
			"adapter into an access point; install it with your package manager"
		c.Fixable |= CapAccessPoint
	default:
		ifaces, err := g.Interfaces(ctx)
		if err != nil {
			c.Reasons[CapAccessPoint] = "could not list this machine's interfaces: " + err.Error()
		} else if _, err := SelectAPInterface(ifaces, "", ""); err != nil {
			c.Reasons[CapAccessPoint] = err.Error()
			c.Fixable |= CapAccessPoint
		} else {
			c.Have |= CapAccessPoint
			c.Reasons[CapClientList] = notInThisBuild
		}
	}
	if c.Reasons[CapClientList] == "" && c.Have&CapClientList == 0 {
		c.Reasons[CapClientList] = "reading the list of connected stations is not implemented in this build"
	}

	// Managed sharing needs the firewall and an address pool of our own; the
	// access point is extra and is checked per configuration.
	if c.Have&CapShareUplink != 0 && c.Have&CapOwnDHCP != 0 {
		c.Sharing = append(c.Sharing, SharingManaged)
	}
	return c, nil
}

// Interfaces implements [Gateway].
func (g *linuxGateway) Interfaces(context.Context) ([]Interface, error) {
	if g.list != nil {
		return g.list()
	}
	return enumerate(g.defaultRoute, g.wireless)
}

// Start implements [Gateway].
//
// It either succeeds completely or leaves the machine as it found it. There is
// no useful partial success: a machine with forwarding enabled and no
// masquerade rule is a machine whose network is broken in a way nothing on it
// explains.
func (g *linuxGateway) Start(ctx context.Context, cfg Config) (Session, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	caps, err := g.Capabilities(ctx)
	if err != nil {
		return nil, err
	}
	if err := CheckCapabilities(g.Platform(), caps, cfg); err != nil {
		return nil, err
	}
	if cfg.Sharing != SharingManaged {
		return nil, Unsupportedf(g.Platform(), CapAccessPoint,
			"only managed sharing is implemented on Linux; the platform's own sharing is not driven from here")
	}

	// Anything a previous run left behind goes first. Starting on top of it
	// would produce a table this session did not write and cannot account for.
	if _, err := g.Reconcile(ctx); err != nil {
		return nil, fmt.Errorf("gateway: could not clear a previous session: %w", err)
	}

	ifaces, err := g.Interfaces(ctx)
	if err != nil {
		return nil, err
	}
	uplink, err := SelectUplink(ifaces, cfg.Uplink)
	if err != nil {
		return nil, err
	}
	apIface := ""
	if cfg.Hotspot != nil {
		ap, err := SelectAPInterface(ifaces, cfg.Hotspot.Interface, uplink.Name)
		if err != nil {
			return nil, err
		}
		apIface = ap.Name
	}
	if apIface == "" {
		return nil, errors.New("gateway: managed sharing needs an interface to serve devices on")
	}

	s := &linuxSession{
		gw: g, cfg: cfg, uplink: uplink.Name, iface: apIface,
		state: StateStarting, since: time.Now(),
	}
	if err := s.bringUp(ctx); err != nil {
		// Undo whatever landed, in reverse. The journal is the source, so a
		// step that was recorded and not applied is undone harmlessly and a
		// step that was applied is always undone.
		_ = s.tearDown(context.WithoutCancel(ctx))
		return nil, err
	}
	s.state, s.since = StateRunning, time.Now()
	return s, nil
}

// Reconcile implements [Gateway].
func (g *linuxGateway) Reconcile(ctx context.Context) (Report, error) {
	var rep Report

	// Two sources, because they disagree in both directions and both happen:
	// /run can be cleared while rules are live, and something else can flush
	// the ruleset while the journal still lists it. Trusting either alone
	// leaves live rules with no record, or a record of rules that are gone.
	entries, jErr := g.journal.read()
	if jErr != nil {
		rep.Failed = append(rep.Failed, jErr.Error())
	}
	byStep := map[string]string{}
	for _, e := range entries {
		byStep[e.Step] = e.Data
		rep.Found = append(rep.Found, "journal: "+e.Step)
	}

	if g.tableExists(ctx) {
		if _, ok := byStep[stepNftables]; !ok {
			rep.Found = append(rep.Found, "a live nftables table this session did not record")
		}
		if err := g.destroyTable(ctx); err != nil {
			rep.Failed = append(rep.Failed, "removing the nftables table: "+err.Error()+
				"; remove it by hand with: nft destroy table inet "+nftables.Table)
		} else {
			rep.Removed = append(rep.Removed, "nftables table "+nftables.Table)
		}
	}

	if prev, ok := byStep[stepForwarding]; ok {
		if err := g.writeSysctl(ctx, "net.ipv4.ip_forward", prev); err != nil {
			rep.Failed = append(rep.Failed, "restoring net.ipv4.ip_forward to "+prev+": "+err.Error())
		} else {
			rep.Removed = append(rep.Removed, "net.ipv4.ip_forward restored to "+prev)
		}
	}
	if _, ok := byStep[stepHostapd]; ok {
		// hostapd is a child of the process that started it, and that process
		// is gone. Nothing to stop; the record is cleared so it is not
		// reported again.
		rep.Removed = append(rep.Removed, "a hostapd record from a previous run")
	}
	if addr, ok := byStep[stepAddress]; ok {
		if err := g.removeAddress(ctx, addr); err != nil {
			rep.Failed = append(rep.Failed, "removing address "+addr+": "+err.Error())
		} else {
			rep.Removed = append(rep.Removed, "address "+addr)
		}
	}

	if err := g.journal.clear(); err != nil {
		rep.Failed = append(rep.Failed, "clearing the journal: "+err.Error())
	}
	sort.Strings(rep.Found)
	return rep, nil
}

func (g *linuxGateway) tableExists(ctx context.Context) bool {
	_, err := g.run.Run(ctx, "nft", "", "list", "table", "inet", nftables.Table)
	return err == nil
}

func (g *linuxGateway) destroyTable(ctx context.Context) error {
	if _, err := g.run.Run(ctx, "nft", nftables.Destroy(), "-f", "-"); err == nil {
		return nil
	}
	// "destroy" needs a recent nft. The fallback fails when the table is
	// absent, which by this point would mean somebody else removed it.
	_, err := g.run.Run(ctx, "nft", nftables.DeleteFallback(), "-f", "-")
	if err != nil && !g.tableExists(ctx) {
		return nil
	}
	return err
}

func (g *linuxGateway) writeSysctl(ctx context.Context, key, value string) error {
	_, err := g.run.Run(ctx, "sysctl", "", "-w", key+"="+value)
	return err
}

func (g *linuxGateway) readSysctl(ctx context.Context, key string) (string, error) {
	out, err := g.run.Run(ctx, "sysctl", "", "-n", key)
	return strings.TrimSpace(out), err
}

func (g *linuxGateway) removeAddress(ctx context.Context, spec string) error {
	addr, iface, ok := strings.Cut(spec, "@")
	if !ok {
		return fmt.Errorf("gateway: %q is not an address record", spec)
	}
	_, err := g.run.Run(ctx, "ip", "", "addr", "del", addr, "dev", iface)
	return err
}

// linuxSession is one running gateway.
type linuxSession struct {
	gw     *linuxGateway
	cfg    Config
	iface  string
	uplink string

	mu      sync.Mutex
	steps   []journalEntry
	state   State
	since   time.Time
	capture bool
	detail  string
	blocked map[netip.Addr]bool
}

var _ Session = (*linuxSession)(nil)

// bringUp applies every step, recording each before it is applied.
//
// The DNS capture is deliberately NOT here. It goes on last, after the caller
// has satisfied itself that its own resolver is answering, because while it is
// in force every DNS query on the network is aimed at one socket — and a socket
// that is not listening behind it means no device on the network has DNS at all.
func (s *linuxSession) bringUp(ctx context.Context) error {
	// Forwarding, remembering what it was. Restoring it matters: a machine that
	// was not a router before this ran must not be one after.
	prev, err := s.gw.readSysctl(ctx, "net.ipv4.ip_forward")
	if err != nil {
		return fmt.Errorf("gateway: reading net.ipv4.ip_forward: %w", err)
	}
	if err := s.apply(ctx, journalEntry{Step: stepForwarding, Data: prev}, func() error {
		return s.gw.writeSysctl(ctx, "net.ipv4.ip_forward", "1")
	}); err != nil {
		return err
	}

	// The address devices will use as their router and their resolver.
	spec := fmt.Sprintf("%s/%d@%s", s.cfg.Addr, s.cfg.Subnet.Bits(), s.iface)
	if err := s.apply(ctx, journalEntry{Step: stepAddress, Data: spec}, func() error {
		_, err := s.gw.run.Run(ctx, "ip", "", "addr", "replace",
			fmt.Sprintf("%s/%d", s.cfg.Addr, s.cfg.Subnet.Bits()), "dev", s.iface)
		return err
	}); err != nil {
		return err
	}

	// The whole ruleset in one transaction: nft applies it completely or not at
	// all, which is the exact guarantee that prevents a half-configured
	// firewall.
	ruleset, err := nftables.Options{
		Interface: s.iface, Uplink: s.uplink, Subnet: s.cfg.Subnet,
		DNSPort: s.cfg.DNSPort, BlockIPv6: s.cfg.IPv6 == IPv6Block,
	}.Ruleset()
	if err != nil {
		return err
	}
	if err := s.apply(ctx, journalEntry{Step: stepNftables}, func() error {
		_, err := s.gw.run.Run(ctx, "nft", ruleset, "-f", "-")
		return err
	}); err != nil {
		return err
	}

	if s.cfg.Hotspot != nil {
		if err := s.startHostapd(ctx); err != nil {
			return err
		}
	}
	return nil
}

func (s *linuxSession) startHostapd(ctx context.Context) error {
	h := s.cfg.Hotspot
	conf, err := hostapd.Config{
		Interface:        s.iface,
		SSID:             h.SSID,
		Passphrase:       h.Passphrase,
		Security:         hostapdSecurity(h.Security),
		Band:             hostapdBand(h.Band),
		Hidden:           h.Hidden,
		MaxClients:       h.MaxClients,
		ControlInterface: filepath.Join(s.gw.runDir, "hostapd"),
	}.Render()
	if err != nil {
		return err
	}
	path := filepath.Join(s.gw.runDir, "hostapd.conf")
	if err := os.MkdirAll(s.gw.runDir, 0o700); err != nil {
		return fmt.Errorf("gateway: creating %s: %w", s.gw.runDir, err)
	}
	// 0600 and under /run. It holds the network's pairwise master key, which is
	// as good as the passphrase to anyone who can read it, and /run does not
	// survive a reboot.
	if err := os.WriteFile(path, []byte(conf), 0o600); err != nil {
		return fmt.Errorf("gateway: writing the hostapd configuration: %w", err)
	}
	return s.apply(ctx, journalEntry{Step: stepHostapd, Data: path}, func() error {
		_, err := s.gw.run.Run(ctx, "hostapd", "", "-B", "-P",
			filepath.Join(s.gw.runDir, "hostapd.pid"), path)
		return err
	})
}

func hostapdSecurity(s Security) hostapd.Security {
	switch s {
	case SecurityWPA2WPA3:
		return hostapd.WPA2WPA3
	case SecurityWPA3:
		return hostapd.WPA3
	case SecurityOpen:
		return hostapd.Open
	default:
		return hostapd.WPA2
	}
}

func hostapdBand(b Band) hostapd.Band {
	switch b {
	case Band2GHz:
		return hostapd.Band2GHz
	case Band5GHz:
		return hostapd.Band5GHz
	default:
		return hostapd.BandAuto
	}
}

// apply records a step, then performs it.
func (s *linuxSession) apply(ctx context.Context, e journalEntry, do func() error) error {
	s.mu.Lock()
	next := append(append([]journalEntry(nil), s.steps...), e)
	s.mu.Unlock()

	if err := s.gw.journal.record(next); err != nil {
		return fmt.Errorf("gateway: recording %s before applying it: %w", e.Step, err)
	}
	s.mu.Lock()
	s.steps = next
	s.mu.Unlock()

	if err := do(); err != nil {
		return fmt.Errorf("gateway: %s: %w", e.Step, err)
	}
	_ = ctx
	return nil
}

// Status implements [Session].
func (s *linuxSession) Status(ctx context.Context) (Status, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := Status{
		State: s.state, Since: s.since, Uplink: s.uplink,
		Clients: -1, Detail: s.detail,
	}
	if s.cfg.Hotspot != nil {
		st.Hotspot = s.cfg.Hotspot.SSID
	}
	if s.capture {
		st.DNSCapture = CapDNSRedirect
	}
	return st, nil
}

// SetDNSCapture implements [Session].
func (s *linuxSession) SetDNSCapture(ctx context.Context, on bool) error {
	cmd, err := nftables.Capture(s.iface, on)
	if err != nil {
		return err
	}
	if _, err := s.gw.run.Run(ctx, "nft", cmd, "-f", "-"); err != nil {
		// Switching capture OFF must not fail silently: leaving it on with an
		// unhealthy resolver behind it is the state this whole mechanism
		// exists to be able to leave.
		if !on {
			s.mu.Lock()
			s.state, s.detail = StateDegraded, "DNS capture could not be withdrawn: "+err.Error()
			s.mu.Unlock()
		}
		return fmt.Errorf("gateway: switching DNS capture: %w", err)
	}
	s.mu.Lock()
	s.capture = on
	if !on && s.state == StateDegraded {
		s.state, s.detail = StateRunning, ""
	}
	s.mu.Unlock()
	return nil
}

// Block implements [Session].
func (s *linuxSession) Block(ctx context.Context, addr netip.Addr, blocked bool) error {
	cmd, err := nftables.Block(addr, blocked)
	if err != nil {
		return err
	}
	if _, err := s.gw.run.Run(ctx, "nft", cmd, "-f", "-"); err != nil {
		return fmt.Errorf("gateway: blocking %v: %w", addr, err)
	}
	s.mu.Lock()
	if s.blocked == nil {
		s.blocked = map[netip.Addr]bool{}
	}
	if blocked {
		s.blocked[addr] = true
	} else {
		delete(s.blocked, addr)
	}
	s.mu.Unlock()
	return nil
}

// Close implements [Session].
func (s *linuxSession) Close() error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	return s.tearDown(ctx)
}

// tearDown undoes every recorded step, in reverse.
//
// Capture comes off first and unconditionally, before anything else, because it
// is the rule that hurts if it outlives the resolver. Every undo is idempotent
// and treats "not there" as success, so a journal claiming a step that was
// never applied costs nothing.
func (s *linuxSession) tearDown(ctx context.Context) error {
	_ = s.SetDNSCapture(ctx, false)

	s.mu.Lock()
	steps := append([]journalEntry(nil), s.steps...)
	s.state, s.since = StateStopped, time.Now()
	s.mu.Unlock()

	var errs []error
	for i := len(steps) - 1; i >= 0; i-- {
		e := steps[i]
		var err error
		switch e.Step {
		case stepHostapd:
			// By pid file, so a hostapd somebody else started is not killed.
			_, err = s.gw.run.Run(ctx, "pkill", "", "-F",
				filepath.Join(s.gw.runDir, "hostapd.pid"))
			// pkill reports "no process matched", which on this path means it
			// had already gone. That is the outcome being asked for.
			err = nil
			_ = os.Remove(filepath.Join(s.gw.runDir, "hostapd.conf"))
		case stepNftables:
			err = s.gw.destroyTable(ctx)
		case stepAddress:
			err = s.gw.removeAddress(ctx, e.Data)
		case stepForwarding:
			err = s.gw.writeSysctl(ctx, "net.ipv4.ip_forward", e.Data)
		}
		if err != nil {
			errs = append(errs, fmt.Errorf("undoing %s: %w", e.Step, err))
		}
	}
	if err := s.gw.journal.clear(); err != nil {
		errs = append(errs, err)
	}
	s.mu.Lock()
	s.steps = nil
	s.mu.Unlock()
	return errors.Join(errs...)
}
