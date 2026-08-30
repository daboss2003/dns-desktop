package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/gatewaydns/gatewaydns-desktop/internal/gateway/winnet"
)

// Step names recorded in the Windows journal.
const (
	stepTethering = "mobile-hotspot"
	stepNat       = "address-translation"
	stepWinAddr   = "interface-address"
	stepWinFwd    = "interface-forwarding"
)

// windowsGateway is the Windows implementation of [Gateway].
//
// Like the Linux one, everything except the command runner and the elevation
// check is here with no build tag, so the bring-up, the teardown and the
// capability reporting are exercised by the test suite on any machine.
type windowsGateway struct {
	run     Runner
	journal journal
	// elevated reports administrator rights. It is a field because the answer
	// decides what Capabilities reports, and a test needs both answers.
	elevated func() bool
	list     func() ([]Interface, error)
}

var _ Gateway = (*windowsGateway)(nil)

// Platform implements [Gateway].
func (g *windowsGateway) Platform() string { return "windows" }

const noRewriteOnWindows = "Windows has no user-mode way to rewrite a packet's destination, so DNS " +
	"cannot be silently redirected here; this machine can instead refuse every other resolver, " +
	"which is the dns-enforce capability"

const needsAdmin = "this needs administrator rights, and GatewayDNS Desktop is not running with them; " +
	"restart it as an administrator"

// tetheringProbe is what the status script reports.
type tetheringProbe struct {
	Capability string `json:"capability"`
	State      string `json:"state"`
	Clients    []struct {
		MAC   string   `json:"mac"`
		Names []string `json:"names"`
	} `json:"clients"`
}

// Capabilities implements [Gateway].
func (g *windowsGateway) Capabilities(ctx context.Context) (Capabilities, error) {
	c := Capabilities{Reasons: map[Capability]string{}, Sharing: []SharingModel{SharingNone}}

	// Never available, and it names the alternative in the same breath so that
	// a reader is not left believing DNS cannot be captured here at all.
	c.Reasons[CapDNSRedirect] = noRewriteOnWindows

	if !g.elevated() {
		for _, cap := range []Capability{
			CapAccessPoint, CapShareUplink, CapDNSEnforce, CapBlockDevice,
			CapIPv6Control, CapOwnDHCP, CapClientList,
		} {
			c.Reasons[cap] = needsAdmin
			c.Fixable |= cap
		}
		return c, nil
	}

	// The hotspot, probed rather than assumed. Microsoft documents this exact
	// call as the way to find out, and its answers are specific enough to act
	// on: a policy, the hardware, the edition, or a missing declaration in this
	// program's own manifest.
	probe, err := g.probeTethering(ctx)
	switch {
	case err != nil:
		c.Reasons[CapAccessPoint] = "could not ask Windows whether it can share a hotspot: " + err.Error()
	case probe.Capability == "Enabled":
		c.Have |= CapAccessPoint | CapClientList
	default:
		c.Reasons[CapAccessPoint] = tetheringReason(probe.Capability)
		if probe.Capability == "DisabledByHardwareLimitation" {
			c.Fixable |= CapAccessPoint
		}
		c.Reasons[CapClientList] = "there is no hotspot to list the clients of"
	}

	// Address translation. It is limited to one per host, so somebody else's
	// is a real reason ours cannot exist and is reported as itself.
	switch other, err := g.otherNat(ctx); {
	case err != nil:
		c.Reasons[CapShareUplink] = "could not ask Windows about address translation: " + err.Error() +
			"; this usually means Hyper-V is not enabled, and it cannot be enabled on Home editions"
	case other != "":
		c.Reasons[CapShareUplink] = fmt.Sprintf(
			"Windows allows one address translation per machine and %q already has it — "+
				"Docker, WSL and Hyper-V each install one", other)
		c.Fixable |= CapShareUplink
	default:
		c.Have |= CapShareUplink | CapOwnDHCP
	}

	// Blocking a device and enforcing DNS are the same mechanism — filters at
	// the forwarding layer — and it is not in this build. It is worth saying
	// which mechanism, because the obvious one does not work: a Windows
	// Firewall rule naming a remote address does not stop a device reaching the
	// internet through a shared connection, since the firewall's filters never
	// see forwarded traffic.
	const pendingFilters = "blocking a device and enforcing DNS need filters at the forwarding layer, " +
		"which are not in this build; a Windows Firewall rule cannot do it, because the firewall " +
		"never sees forwarded traffic"
	c.Reasons[CapBlockDevice] = pendingFilters
	c.Reasons[CapDNSEnforce] = pendingFilters
	c.Reasons[CapIPv6Control] = pendingFilters

	if c.Have&CapAccessPoint != 0 {
		// The hotspot brings its own addressing and its own DNS proxy, so this
		// model creates the Wi-Fi and gives up per-device identity. See ADR
		// 0007.
		c.Sharing = append(c.Sharing, SharingPlatform)
	}
	if c.Have&CapShareUplink != 0 && c.Have&CapOwnDHCP != 0 {
		c.Sharing = append(c.Sharing, SharingManaged)
	}
	return c, nil
}

// tetheringReason turns Windows' own answer into one a person can act on.
func tetheringReason(capability string) string {
	switch capability {
	case "DisabledByGroupPolicy":
		return "a group policy on this machine forbids sharing a hotspot"
	case "DisabledByHardwareLimitation":
		return "this machine's wireless adapter cannot host an access point; a USB adapter that can would work"
	case "DisabledByOperator":
		return "the mobile operator for this connection forbids tethering"
	case "DisabledBySku":
		return "this edition of Windows does not include the Mobile Hotspot"
	case "DisabledByRequiredAppNotInstalled":
		return "Windows says a component the Mobile Hotspot needs is not installed"
	case "DisabledBySystemCapability":
		return "GatewayDNS Desktop is not declared to Windows as allowed to control Wi-Fi, " +
			"so it cannot start the Mobile Hotspot; turn the hotspot on in Windows Settings instead " +
			"and this machine will serve the devices that join it"
	default:
		return "Windows will not say why the Mobile Hotspot is unavailable (" + capability + ")"
	}
}

func (g *windowsGateway) probeTethering(ctx context.Context) (tetheringProbe, error) {
	out, err := g.run.Run(ctx, "powershell", winnet.AwaitHelper+winnet.TetheringStatus(),
		"-NoProfile", "-NonInteractive", "-Command", "-")
	if err != nil {
		return tetheringProbe{}, errors.New(firstLine(out, err))
	}
	var p tetheringProbe
	if err := json.Unmarshal([]byte(strings.TrimSpace(out)), &p); err != nil {
		return tetheringProbe{}, fmt.Errorf("could not read the answer: %w", err)
	}
	return p, nil
}

// otherNat returns the name of an address translation that is not ours, or "".
func (g *windowsGateway) otherNat(ctx context.Context) (string, error) {
	out, err := g.run.Run(ctx, "powershell", winnet.NatStatus(),
		"-NoProfile", "-NonInteractive", "-Command", "-")
	if err != nil {
		return "", errors.New(firstLine(out, err))
	}
	trimmed := strings.TrimSpace(out)
	if trimmed == "" || trimmed == "null" {
		return "", nil
	}
	// One translation marshals as an object and several as an array, which is
	// PowerShell's convention and not an inconsistency worth fighting.
	var one struct {
		Name string `json:"Name"`
	}
	if err := json.Unmarshal([]byte(trimmed), &one); err == nil {
		if one.Name != "" && one.Name != winnet.NatName {
			return one.Name, nil
		}
		return "", nil
	}
	var many []struct {
		Name string `json:"Name"`
	}
	if err := json.Unmarshal([]byte(trimmed), &many); err != nil {
		return "", fmt.Errorf("could not read the answer: %w", err)
	}
	for _, n := range many {
		if n.Name != winnet.NatName {
			return n.Name, nil
		}
	}
	return "", nil
}

func firstLine(out string, err error) string {
	for line := range strings.SplitSeq(out, "\n") {
		if s := strings.TrimSpace(line); s != "" {
			return s
		}
	}
	return err.Error()
}

// Interfaces implements [Gateway].
func (g *windowsGateway) Interfaces(context.Context) ([]Interface, error) {
	if g.list != nil {
		return g.list()
	}
	return enumerate(windowsDefaultRouteFn, windowsWirelessFn)
}

// Start implements [Gateway].
func (g *windowsGateway) Start(ctx context.Context, cfg Config) (Session, error) {
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
	if _, err := g.Reconcile(ctx); err != nil {
		return nil, fmt.Errorf("gateway: could not clear a previous session: %w", err)
	}

	s := &windowsSession{gw: g, cfg: cfg, state: StateStarting, since: time.Now()}
	if err := s.bringUp(ctx); err != nil {
		_ = s.tearDown(context.WithoutCancel(ctx))
		return nil, err
	}
	s.state, s.since = StateRunning, time.Now()
	return s, nil
}

// Reconcile implements [Gateway].
func (g *windowsGateway) Reconcile(ctx context.Context) (Report, error) {
	var rep Report
	entries, err := g.journal.read()
	if err != nil {
		rep.Failed = append(rep.Failed, err.Error())
	}
	for i := len(entries) - 1; i >= 0; i-- {
		e := entries[i]
		rep.Found = append(rep.Found, "journal: "+e.Step)
		var undoErr error
		switch e.Step {
		case stepTethering:
			_, undoErr = g.run.Run(ctx, "powershell", winnet.AwaitHelper+winnet.TetheringStop(),
				"-NoProfile", "-NonInteractive", "-Command", "-")
		case stepNat:
			_, undoErr = g.run.Run(ctx, "powershell", winnet.NatRemove(),
				"-NoProfile", "-NonInteractive", "-Command", "-")
		case stepWinAddr:
			undoErr = g.undoAddress(ctx, e.Data)
		case stepWinFwd:
			undoErr = g.undoForwarding(ctx, e.Data)
		}
		if undoErr != nil {
			rep.Failed = append(rep.Failed, "undoing "+e.Step+": "+undoErr.Error())
		} else {
			rep.Removed = append(rep.Removed, e.Step)
		}
	}
	if err := g.journal.clear(); err != nil {
		rep.Failed = append(rep.Failed, "clearing the journal: "+err.Error())
	}
	return rep, nil
}

// undoAddress removes an address recorded as "addr@interface".
func (g *windowsGateway) undoAddress(ctx context.Context, spec string) error {
	addrStr, iface, ok := strings.Cut(spec, "@")
	if !ok {
		return fmt.Errorf("gateway: %q is not an address record", spec)
	}
	addr, err := netip.ParseAddr(addrStr)
	if err != nil {
		return err
	}
	script, err := winnet.AddressRemove(iface, addr)
	if err != nil {
		return err
	}
	_, err = g.run.Run(ctx, "powershell", script, "-NoProfile", "-NonInteractive", "-Command", "-")
	return err
}

// undoForwarding restores a setting recorded as "state@interface".
func (g *windowsGateway) undoForwarding(ctx context.Context, spec string) error {
	state, iface, ok := strings.Cut(spec, "@")
	if !ok {
		return fmt.Errorf("gateway: %q is not a forwarding record", spec)
	}
	script, err := winnet.Forwarding(iface, strings.EqualFold(state, "Enabled"))
	if err != nil {
		return err
	}
	_, err = g.run.Run(ctx, "powershell", script, "-NoProfile", "-NonInteractive", "-Command", "-")
	return err
}

// windowsSession is one running gateway.
type windowsSession struct {
	gw  *windowsGateway
	cfg Config

	mu     sync.Mutex
	steps  []journalEntry
	state  State
	since  time.Time
	detail string
}

var _ Session = (*windowsSession)(nil)

func (s *windowsSession) bringUp(ctx context.Context) error {
	if s.cfg.Sharing == SharingPlatform {
		// The Mobile Hotspot brings its own addressing, its own DHCP and its
		// own DNS proxy, so there is exactly one thing to do and nothing to
		// undo but this.
		script, err := winnet.TetheringStart(winnet.Hotspot{
			SSID:       s.cfg.Hotspot.SSID,
			Passphrase: s.cfg.Hotspot.Passphrase,
		})
		if err != nil {
			return err
		}
		return s.apply(journalEntry{Step: stepTethering}, func() error {
			out, err := s.gw.run.Run(ctx, "powershell", winnet.AwaitHelper+script,
				"-NoProfile", "-NonInteractive", "-Command", "-")
			if err != nil {
				return errors.New(firstLine(out, err))
			}
			return nil
		})
	}

	// Managed sharing: our address, our forwarding, our translation — and our
	// DHCP server above this, which is what keeps each device's own address on
	// its queries and makes per-device policy work.
	ifaces, err := s.gw.Interfaces(ctx)
	if err != nil {
		return err
	}
	iface, err := SelectUplink(ifaces, s.cfg.Uplink)
	if err != nil {
		return err
	}
	served := s.cfg.Uplink
	if served == "" {
		served = iface.Name
	}

	prev, err := s.gw.run.Run(ctx, "powershell", mustScript(winnet.ForwardingState(served)),
		"-NoProfile", "-NonInteractive", "-Command", "-")
	if err != nil {
		return fmt.Errorf("gateway: reading the forwarding setting: %w", err)
	}
	prev = strings.TrimSpace(prev)

	addrSpec := fmt.Sprintf("%s@%s", s.cfg.Addr, served)
	if err := s.apply(journalEntry{Step: stepWinAddr, Data: addrSpec}, func() error {
		script, err := winnet.AddressAssign(served, s.cfg.Addr, s.cfg.Subnet.Bits())
		if err != nil {
			return err
		}
		out, err := s.gw.run.Run(ctx, "powershell", script, "-NoProfile", "-NonInteractive", "-Command", "-")
		if err != nil {
			return errors.New(firstLine(out, err))
		}
		return nil
	}); err != nil {
		return err
	}

	if err := s.apply(journalEntry{Step: stepWinFwd, Data: prev + "@" + served}, func() error {
		script, err := winnet.Forwarding(served, true)
		if err != nil {
			return err
		}
		out, err := s.gw.run.Run(ctx, "powershell", script, "-NoProfile", "-NonInteractive", "-Command", "-")
		if err != nil {
			return errors.New(firstLine(out, err))
		}
		return nil
	}); err != nil {
		return err
	}

	return s.apply(journalEntry{Step: stepNat}, func() error {
		script, err := winnet.NatCreate(s.cfg.Subnet)
		if err != nil {
			return err
		}
		out, err := s.gw.run.Run(ctx, "powershell", script, "-NoProfile", "-NonInteractive", "-Command", "-")
		if err != nil {
			return errors.New(firstLine(out, err))
		}
		return nil
	})
}

func mustScript(s string, err error) string {
	if err != nil {
		return "throw " + winnet.Quote(err.Error())
	}
	return s
}

// apply records a step, then performs it. See the Linux session for why the
// order is that way round and not the other.
func (s *windowsSession) apply(e journalEntry, do func() error) error {
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
	return nil
}

// Status implements [Session].
func (s *windowsSession) Status(ctx context.Context) (Status, error) {
	s.mu.Lock()
	st := Status{State: s.state, Since: s.since, Uplink: s.cfg.Uplink, Clients: -1, Detail: s.detail}
	if s.cfg.Hotspot != nil {
		st.Hotspot = s.cfg.Hotspot.SSID
	}
	platform := s.cfg.Sharing == SharingPlatform
	s.mu.Unlock()

	// The connected stations, when the hotspot is ours to ask about. This is
	// what a device list is built from on this platform, where our own DHCP
	// server does not run.
	if platform {
		if p, err := s.gw.probeTethering(ctx); err == nil {
			st.Clients = len(p.Clients)
		}
	}
	return st, nil
}

// SetDNSCapture implements [Session].
func (s *windowsSession) SetDNSCapture(ctx context.Context, on bool) error {
	if !on {
		// Nothing was ever installed, so there is nothing to withdraw — and
		// reporting success is right: the caller asked for capture to be off
		// and it is off.
		return nil
	}
	return Unsupportedf("windows", CapDNSEnforce,
		"filters at the forwarding layer are not in this build; devices are still filtered when they "+
			"use the resolver they were given, which on this machine is every device that honours DHCP")
}

// Block implements [Session].
func (s *windowsSession) Block(ctx context.Context, addr netip.Addr, blocked bool) error {
	if !blocked {
		return nil
	}
	return Unsupportedf("windows", CapBlockDevice,
		"cutting a device off needs a filter at the forwarding layer, which is not in this build; "+
			"a Windows Firewall rule cannot do it, because the firewall never sees forwarded traffic")
}

// Close implements [Session].
func (s *windowsSession) Close() error {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	return s.tearDown(ctx)
}

func (s *windowsSession) tearDown(ctx context.Context) error {
	s.mu.Lock()
	steps := append([]journalEntry(nil), s.steps...)
	s.state, s.since = StateStopped, time.Now()
	s.mu.Unlock()

	var errs []error
	for i := len(steps) - 1; i >= 0; i-- {
		e := steps[i]
		var err error
		switch e.Step {
		case stepTethering:
			_, err = s.gw.run.Run(ctx, "powershell", winnet.AwaitHelper+winnet.TetheringStop(),
				"-NoProfile", "-NonInteractive", "-Command", "-")
		case stepNat:
			_, err = s.gw.run.Run(ctx, "powershell", winnet.NatRemove(),
				"-NoProfile", "-NonInteractive", "-Command", "-")
		case stepWinAddr:
			err = s.gw.undoAddress(ctx, e.Data)
		case stepWinFwd:
			err = s.gw.undoForwarding(ctx, e.Data)
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

// The probes that read this machine's own routing and radio state. They are
// variables so that this file needs no build tag: on Windows an init function
// points them at the real implementations, and everywhere else they answer
// "nothing", which is correct for a machine that is not Windows.
var (
	windowsDefaultRouteFn = func() (string, error) { return "", errNoDefaultRoute }
	windowsWirelessFn     = func(string) (bool, apSupport) { return false, apSupport{} }
)
