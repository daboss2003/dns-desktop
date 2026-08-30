package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/gatewaydns/gatewaydns/dnsmsg"

	"github.com/gatewaydns/gatewaydns-desktop/internal/device"
	"github.com/gatewaydns/gatewaydns-desktop/internal/dhcp"
	"github.com/gatewaydns/gatewaydns-desktop/internal/gateway"
)

// GatewaySettings is what a person chose in the interface.
//
// It is separate from [gateway.Config] because it is persisted and shown back
// to them: it holds a choice, while the config holds the consequences of that
// choice worked out against what the platform can do.
type GatewaySettings struct {
	// Sharing is which arrangement to use. See [gateway.SharingModel].
	Sharing gateway.SharingModel `json:"-"`
	// SharingName is the same thing as text, because that is what survives a
	// round trip through a settings file that a person may open.
	SharingName string `json:"sharing"`

	// Hotspot, when one is wanted.
	SSID       string `json:"ssid,omitempty"`
	Passphrase string `json:"passphrase,omitempty"`
	Hidden     bool   `json:"hidden,omitempty"`

	// Interface is the adapter to serve devices on, and Uplink the one traffic
	// leaves through. Empty means "choose one".
	Interface string `json:"interface,omitempty"`
	Uplink    string `json:"uplink,omitempty"`

	// Subnet and Addr are the network handed to devices. Empty selects
	// [DefaultGatewaySubnet].
	Subnet string `json:"subnet,omitempty"`

	// CaptureDNS forces devices to use this resolver even when they were
	// configured with another. It is off by default and stays off until
	// somebody asks, because it is the one setting whose failure mode is every
	// device on the network losing DNS at once.
	CaptureDNS bool `json:"capture_dns,omitempty"`

	// AllowIPv6 forwards IPv6 without filtering it. Off means IPv6 from the
	// served subnet is refused, which is the safe direction: a dual-stack
	// client that picks up a v6 route resolves over v6 and bypasses every rule
	// while the v4 counters look healthy.
	AllowIPv6 bool `json:"allow_ipv6,omitempty"`
}

// DefaultGatewaySubnet is the network devices are given.
//
// 10.42.0.0/24 rather than 192.168.x: a gateway hands addresses to devices that
// are usually also on somebody's home network, and colliding with it produces
// routing that half works. The 10.42 range is conventional for exactly this and
// is unlikely to be the router's.
const DefaultGatewaySubnet = "10.42.0.0/24"

// gatewayState is everything about a running gateway.
type gatewayState struct {
	mu       sync.Mutex
	settings GatewaySettings
	session  gateway.Session
	dhcp     *dhcp.Server
	dhcpConn net.PacketConn
	pool     *dhcp.Pool
	stop     chan struct{}
	wg       sync.WaitGroup
}

// GatewayStatus is what the interface shows about sharing.
type GatewayStatus struct {
	Running  bool            `json:"running"`
	Settings GatewaySettings `json:"settings"`
	Status   gateway.Status  `json:"status"`
	// Leases is how many devices have taken an address from us, and is -1 when
	// this arrangement does not include our own DHCP server.
	Leases int `json:"leases"`
	// Detail explains a state that is not simply running.
	Detail string `json:"detail,omitempty"`
}

// GatewayStatus returns it.
func (a *App) GatewayStatus() GatewayStatus {
	a.gwState.mu.Lock()
	sess, pool, settings := a.gwState.session, a.gwState.pool, a.gwState.settings
	a.gwState.mu.Unlock()

	out := GatewayStatus{Settings: settings, Leases: -1}
	if sess == nil {
		return out
	}
	out.Running = true
	if st, err := sess.Status(context.Background()); err == nil {
		out.Status = st
		out.Detail = st.Detail
	}
	if pool != nil {
		out.Leases = pool.Stats().Leased
	}
	return out
}

// StartGateway brings the gateway up.
//
// The order is the part that matters. The platform's own work comes first, then
// our DHCP server if this arrangement includes one, and DNS capture LAST and
// only if it was asked for — because while capture is in force every DNS query
// on the network is aimed at one socket, and switching it on before that socket
// is known to be answering is how a hotspot comes up with no DNS at all.
func (a *App) StartGateway(ctx context.Context, s GatewaySettings) error {
	a.gwState.mu.Lock()
	if a.gwState.session != nil {
		a.gwState.mu.Unlock()
		return errors.New("app: the gateway is already running; stop it first")
	}
	a.gwState.mu.Unlock()

	cfg, err := a.gatewayConfig(s)
	if err != nil {
		return err
	}
	sess, err := a.gw.Start(ctx, cfg)
	if err != nil {
		return err
	}

	a.gwState.mu.Lock()
	a.gwState.session, a.gwState.settings = sess, s
	a.gwState.stop = make(chan struct{})
	a.gwState.mu.Unlock()

	// Our own DHCP server, where this arrangement leaves the addressing to us.
	// It is what makes a device tell us its name and its hardware address, and
	// what keeps each device's own address on its queries.
	if cfg.Sharing == gateway.SharingManaged {
		if err := a.startDHCP(cfg); err != nil {
			_ = a.StopGateway(ctx)
			return fmt.Errorf("app: the gateway came up but its DHCP server did not: %w", err)
		}
	}

	if s.CaptureDNS {
		if err := a.captureWhenHealthy(ctx, sess); err != nil {
			// Not fatal. A gateway without capture still filters every device
			// that uses the resolver it was given, which is nearly all of them
			// — and refusing to share the connection over it would be a worse
			// trade than saying so.
			a.log.Warn("DNS capture could not be switched on",
				slog.String("error", err.Error()))
		}
	}

	a.saveGatewaySettings(s)
	a.gwState.mu.Lock()
	stop := a.gwState.stop
	a.gwState.mu.Unlock()
	a.gwState.wg.Add(1)
	go a.watchResolver(stop)
	a.log.Info("gateway running",
		slog.String("sharing", cfg.Sharing.String()),
		slog.String("subnet", cfg.Subnet.String()),
		slog.Bool("capture", s.CaptureDNS))
	return nil
}

// captureWhenHealthy switches interception on, but only after checking that the
// resolver behind it is answering.
//
// The check is the point. A redirect with nothing listening behind it is not a
// degraded network, it is a network with no DNS at all, and the person
// experiencing it reads it as "the internet is down".
func (a *App) captureWhenHealthy(ctx context.Context, sess gateway.Session) error {
	if err := a.resolverHealthy(ctx); err != nil {
		return fmt.Errorf("this machine's own resolver is not answering, so capturing DNS "+
			"would leave every device without it: %w", err)
	}
	return sess.SetDNSCapture(ctx, true)
}

// resolverHealthy asks our own resolver a question.
//
// Through the engine's handler rather than over a socket: this is asking
// whether resolution works, not whether a socket is bound, and a check that
// went out over the network would fail for reasons that have nothing to do with
// the thing being checked.
func (a *App) resolverHealthy(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	q := new(dnsmsg.Message)
	q.SetQuestion(dnsmsg.MustParseName("localhost."), dnsmsg.TypeA, dnsmsg.ClassINET)
	_, err := a.engine.Resolve(ctx, q)
	return err
}

// watchResolver withdraws DNS capture if this machine's resolver stops
// answering.
//
// It is the other half of switching capture on carefully. The resolver can die
// after the gateway is up — a crash, a configuration reload that fails, an
// upstream that goes away — and every second between that and the capture
// coming off is a second in which no device on the network can resolve
// anything.
// The stop channel is a PARAMETER and not read from the struct, which is not a
// style choice: StopGateway sets the field to nil, and a goroutine that read it
// afterwards would receive on a nil channel — which blocks forever, so the Wait
// that StopGateway does next never returns and shutdown deadlocks. Taking it at
// the moment the goroutine is started removes the race entirely.
func (a *App) watchResolver(stop <-chan struct{}) {
	defer a.gwState.wg.Done()

	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	failures := 0
	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
		}
		a.gwState.mu.Lock()
		sess, capturing := a.gwState.session, a.gwState.settings.CaptureDNS
		a.gwState.mu.Unlock()
		if sess == nil || !capturing {
			continue
		}

		if err := a.resolverHealthy(context.Background()); err != nil {
			failures++
			// Two consecutive failures, not one: a single timeout is a slow
			// upstream, and withdrawing capture on one would flap the
			// network's DNS every time a resolver was briefly busy.
			if failures >= 2 {
				a.log.Error("withdrawing DNS capture: this machine's resolver has stopped answering",
					slog.String("error", err.Error()))
				if err := sess.SetDNSCapture(context.Background(), false); err != nil {
					a.log.Error("could not withdraw DNS capture; devices may have no DNS",
						slog.String("error", err.Error()))
				}
				failures = 0
			}
			continue
		}
		failures = 0
	}
}

// StopGateway takes it all down.
func (a *App) StopGateway(ctx context.Context) error {
	a.gwState.mu.Lock()
	sess, srv, conn, stop := a.gwState.session, a.gwState.dhcp, a.gwState.dhcpConn, a.gwState.stop
	a.gwState.session, a.gwState.dhcp, a.gwState.dhcpConn, a.gwState.pool = nil, nil, nil, nil
	a.gwState.stop = nil
	a.gwState.mu.Unlock()

	if stop != nil {
		close(stop)
	}
	a.gwState.wg.Wait()

	var errs []error
	if srv != nil {
		if err := srv.Shutdown(ctx); err != nil {
			errs = append(errs, fmt.Errorf("stopping the DHCP server: %w", err))
		}
	}
	if conn != nil {
		_ = conn.Close()
	}
	if sess != nil {
		// Closing the session withdraws DNS capture first, then undoes
		// everything else in reverse.
		if err := sess.Close(); err != nil {
			errs = append(errs, fmt.Errorf("stopping the gateway: %w", err))
		}
	}
	if len(errs) == 0 && sess != nil {
		a.log.Info("gateway stopped")
	}
	return errors.Join(errs...)
}

// startDHCP runs our own DHCP server on the served subnet.
func (a *App) startDHCP(cfg gateway.Config) error {
	// The pool starts above this machine's own address and leaves the low
	// addresses free, which is where an operator will want to put a static
	// reservation for a printer or a server.
	first, last, err := poolRange(cfg.Subnet, cfg.Addr)
	if err != nil {
		return err
	}
	pool, err := dhcp.NewPool(dhcp.PoolOptions{
		Subnet: cfg.Subnet, First: first, Last: last,
		Excluded: []netip.Addr{cfg.Addr},
	})
	if err != nil {
		return err
	}

	srv, err := dhcp.NewServer(dhcp.ServerOptions{
		Pool:     pool,
		ServerID: cfg.Addr,
		Router:   cfg.Addr,
		// This machine, which is the entire point: it is how a device is told
		// to ask us, and therefore how filtering reaches a device nobody
		// configured by hand.
		DNS:     []netip.Addr{cfg.Addr},
		Logger:  a.log,
		OnBound: a.devices.ObserveLease,
	})
	if err != nil {
		return err
	}

	pc, err := net.ListenPacket("udp4", fmt.Sprintf(":%d", dhcp.ServerPort))
	if err != nil {
		return fmt.Errorf("listening on the DHCP port: %w "+
			"(port 67 needs administrator rights, and something else may already serve DHCP here)", err)
	}

	a.gwState.mu.Lock()
	a.gwState.dhcp, a.gwState.dhcpConn, a.gwState.pool = srv, pc, pool
	a.gwState.mu.Unlock()

	go func() {
		if err := srv.Serve(pc); err != nil {
			a.log.Error("the DHCP server stopped", slog.String("error", err.Error()))
		}
	}()
	a.log.Info("handing out addresses",
		slog.String("range", first.String()+"-"+last.String()),
		slog.String("dns", cfg.Addr.String()))
	return nil
}

// poolRange picks the allocatable range within a subnet.
func poolRange(subnet netip.Prefix, gw netip.Addr) (netip.Addr, netip.Addr, error) {
	if !subnet.IsValid() || !subnet.Addr().Is4() {
		return netip.Addr{}, netip.Addr{}, fmt.Errorf("app: %v is not a usable subnet", subnet)
	}
	if subnet.Bits() > 29 {
		return netip.Addr{}, netip.Addr{}, fmt.Errorf(
			"app: %v is too small to hand out addresses from", subnet)
	}
	base := subnet.Masked().Addr().As4()
	v := uint32(base[0])<<24 | uint32(base[1])<<16 | uint32(base[2])<<8 | uint32(base[3])
	size := uint32(1) << (32 - subnet.Bits())
	// Ten addresses reserved at the bottom for the gateway and for anything an
	// operator wants to pin, and the broadcast address left off the top.
	firstV := v + 10
	lastV := v + size - 2
	const maxPool = 4096
	if lastV-firstV+1 > maxPool {
		lastV = firstV + maxPool - 1
	}
	return addrOf(firstV), addrOf(lastV), nil
}

func addrOf(v uint32) netip.Addr {
	return netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)})
}

// gatewayConfig works a person's choices out against what the platform can do.
func (a *App) gatewayConfig(s GatewaySettings) (gateway.Config, error) {
	sharing := s.Sharing
	if s.SharingName != "" {
		switch s.SharingName {
		case "managed":
			sharing = gateway.SharingManaged
		case "platform":
			sharing = gateway.SharingPlatform
		case "none":
			sharing = gateway.SharingNone
		default:
			return gateway.Config{}, fmt.Errorf(
				"app: %q is not a sharing model; it is none, platform or managed", s.SharingName)
		}
	}

	subnet := netip.MustParsePrefix(DefaultGatewaySubnet)
	if s.Subnet != "" {
		p, err := netip.ParsePrefix(s.Subnet)
		if err != nil {
			return gateway.Config{}, fmt.Errorf("app: %q is not a subnet: %w", s.Subnet, err)
		}
		subnet = p
	}
	// This machine takes the first usable address, which is what devices are
	// told is their router and their resolver.
	gwAddr := subnet.Masked().Addr().Next()

	// The port the resolver is ACTUALLY on, not the one that was configured.
	// A configured port of zero means the operating system chose one, and a
	// redirect naming zero points at nothing — which, because a redirect is
	// in force for every device on the network, is every device losing DNS at
	// once rather than one setting being wrong.
	dnsPort := int(a.BoundPort())
	if dnsPort == 0 {
		_, port, err := net.SplitHostPort(a.opts.Listen)
		if err != nil {
			return gateway.Config{}, fmt.Errorf("app: the resolver's address %q is not host:port: %w", a.opts.Listen, err)
		}
		if dnsPort, err = net.LookupPort("udp", port); err != nil {
			return gateway.Config{}, fmt.Errorf("app: %q is not a port: %w", port, err)
		}
	}
	if dnsPort == 0 {
		return gateway.Config{}, errors.New(
			"app: this machine's resolver is not listening yet, so devices could not be pointed at it; " +
				"start the resolver before sharing the connection")
	}

	cfg := gateway.Config{
		Sharing: sharing,
		Uplink:  s.Uplink,
		Subnet:  subnet,
		Addr:    gwAddr,
		DNSPort: dnsPort,
		IPv6:    gateway.IPv6Block,
	}
	if s.AllowIPv6 {
		cfg.IPv6 = gateway.IPv6Allow
	}
	if sharing != gateway.SharingNone && s.SSID != "" {
		cfg.Hotspot = &gateway.HotspotConfig{
			Interface:  s.Interface,
			SSID:       s.SSID,
			Passphrase: s.Passphrase,
			Hidden:     s.Hidden,
		}
	}
	return cfg, nil
}

const gatewayFile = "gateway.json"

func (a *App) saveGatewaySettings(s GatewaySettings) {
	dir, err := a.stateDir()
	if err != nil {
		return
	}
	b, err := marshal(s)
	if err != nil {
		return
	}
	// 0600: it holds the network's passphrase.
	path := filepath.Join(dir, gatewayFile)
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		a.log.Error("could not save the gateway settings", slog.String("error", err.Error()))
		return
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
	}
}

// LoadGatewaySettings returns what was last used, so the interface opens
// showing it rather than an empty form.
func (a *App) LoadGatewaySettings() GatewaySettings {
	dir, err := a.stateDir()
	if err != nil {
		return GatewaySettings{}
	}
	b, err := os.ReadFile(filepath.Join(dir, gatewayFile))
	if err != nil {
		return GatewaySettings{}
	}
	var s GatewaySettings
	if err := unmarshal(b, &s); err != nil {
		return GatewaySettings{}
	}
	return s
}

// ReconcileGateway removes anything a previous run left behind.
//
// It is called at start-up, before anything else, because a process that was
// killed could not clean up after itself — and a machine whose firewall still
// carries half a session from an hour ago is a machine whose owner cannot get
// online and has nothing to read about why.
func (a *App) ReconcileGateway(ctx context.Context) (gateway.Report, error) {
	return a.gw.Reconcile(ctx)
}

// BlockDevice cuts a device off from the network entirely, where the platform
// can do it.
//
// It is not the same as pausing, which refuses the device's DNS: a device with
// a hardcoded resolver, or one speaking DNS over HTTPS to an address it already
// knows, does not notice a refused name.
func (a *App) BlockDevice(ctx context.Context, id device.ID, blocked bool) error {
	a.gwState.mu.Lock()
	sess := a.gwState.session
	a.gwState.mu.Unlock()
	if sess == nil {
		return errors.New("app: no gateway is running, so there is no network to cut a device off from")
	}
	d, ok := a.devices.Get(id)
	if !ok {
		return device.ErrUnknownDevice
	}
	if len(d.Addrs) == 0 {
		return fmt.Errorf("app: %s has no address to block", d.DisplayName())
	}
	var errs []error
	for _, addr := range d.Addrs {
		if err := sess.Block(ctx, addr, blocked); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}
