package app

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gatewaydns/gatewaydns-desktop/internal/gateway"
)

// fakeGateway is a platform that can do everything, so the wiring above it can
// be exercised on a machine that can do none of it.
type fakeGateway struct {
	mu        sync.Mutex
	started   []gateway.Config
	closed    int
	capture   []bool
	startErr  error
	reconcile gateway.Report
}

func (f *fakeGateway) Platform() string { return "fake" }

func (f *fakeGateway) Capabilities(context.Context) (gateway.Capabilities, error) {
	return gateway.Capabilities{
		Have: gateway.CapAccessPoint | gateway.CapShareUplink | gateway.CapDNSRedirect |
			gateway.CapOwnDHCP | gateway.CapIPv6Control | gateway.CapBlockDevice,
		Sharing: []gateway.SharingModel{gateway.SharingNone, gateway.SharingPlatform, gateway.SharingManaged},
	}, nil
}

func (f *fakeGateway) Interfaces(context.Context) ([]gateway.Interface, error) {
	return []gateway.Interface{
		{Name: "eth0", Kind: gateway.KindWired, Up: true, HasDefaultRoute: true},
		{Name: "wlan0", Kind: gateway.KindWireless, Up: true, SupportsAP: true},
	}, nil
}

func (f *fakeGateway) Start(_ context.Context, cfg gateway.Config) (gateway.Session, error) {
	if f.startErr != nil {
		return nil, f.startErr
	}
	f.mu.Lock()
	f.started = append(f.started, cfg)
	f.mu.Unlock()
	return &fakeSession{gw: f, cfg: cfg}, nil
}

func (f *fakeGateway) Reconcile(context.Context) (gateway.Report, error) { return f.reconcile, nil }

func (f *fakeGateway) calls() ([]gateway.Config, []bool, int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]gateway.Config(nil), f.started...), append([]bool(nil), f.capture...), f.closed
}

type fakeSession struct {
	gw  *fakeGateway
	cfg gateway.Config
	mu  sync.Mutex
	on  bool
}

func (s *fakeSession) Status(context.Context) (gateway.Status, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := gateway.Status{State: gateway.StateRunning, Clients: -1}
	if s.cfg.Hotspot != nil {
		st.Hotspot = s.cfg.Hotspot.SSID
	}
	if s.on {
		st.DNSCapture = gateway.CapDNSRedirect
	}
	return st, nil
}

func (s *fakeSession) SetDNSCapture(_ context.Context, on bool) error {
	s.mu.Lock()
	s.on = on
	s.mu.Unlock()
	s.gw.mu.Lock()
	s.gw.capture = append(s.gw.capture, on)
	s.gw.mu.Unlock()
	return nil
}

func (s *fakeSession) Block(context.Context, netip.Addr, bool) error { return nil }

func (s *fakeSession) Close() error {
	s.gw.mu.Lock()
	s.gw.closed++
	s.gw.mu.Unlock()
	return nil
}

func testApp(t testing.TB, gw gateway.Gateway) *App {
	t.Helper()
	a, err := New(Options{
		// A real port, because a gateway config carries the port devices are
		// redirected to and a zero there points at nothing.
		Listen:     "127.0.0.1:15399",
		Upstreams:  []string{"udp://192.0.2.53:53"},
		StateDir:   t.TempDir(),
		NoQueryLog: true,
		Gateway:    gw,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = a.Close() })
	return a
}

// The order is the whole point: the platform's work, then our DHCP, then
// capture — and capture only if it was asked for.
func TestStartingAGatewayDoesNotCaptureUnlessAsked(t *testing.T) {
	t.Parallel()
	gw := &fakeGateway{}
	a := testApp(t, gw)

	err := a.StartGateway(context.Background(), GatewaySettings{
		SharingName: "platform", SSID: "Home", Passphrase: "correct horse",
	})
	if err != nil {
		t.Fatalf("StartGateway: %v", err)
	}
	defer a.StopGateway(context.Background())

	started, capture, _ := gw.calls()
	if len(started) != 1 {
		t.Fatalf("the gateway was started %d times", len(started))
	}
	if started[0].Hotspot == nil || started[0].Hotspot.SSID != "Home" {
		t.Errorf("the hotspot was not passed through: %+v", started[0].Hotspot)
	}
	for _, on := range capture {
		if on {
			t.Fatal("DNS capture was switched on without being asked for")
		}
	}
	st := a.GatewayStatus()
	if !st.Running || st.Status.Hotspot != "Home" {
		t.Errorf("status = %+v", st)
	}
}

// Capture is switched on only after this machine's own resolver has been shown
// to answer. A redirect with nothing listening behind it is not a degraded
// network — it is a network with no DNS at all.
func TestCaptureIsSwitchedOnOnlyWhenTheResolverAnswers(t *testing.T) {
	t.Parallel()
	gw := &fakeGateway{}
	a := testApp(t, gw)

	// The resolver cannot answer: its upstream is a black hole and nothing is
	// serving. So capture must not be switched on, and the gateway must still
	// come up, because a gateway without capture still filters every device
	// that uses the resolver it was given.
	err := a.StartGateway(context.Background(), GatewaySettings{
		SharingName: "platform", SSID: "Home", Passphrase: "correct horse", CaptureDNS: true,
	})
	if err != nil {
		t.Fatalf("StartGateway: %v", err)
	}
	defer a.StopGateway(context.Background())

	_, capture, _ := gw.calls()
	for _, on := range capture {
		if on {
			t.Error("capture was switched on while the resolver was not answering")
		}
	}
	if !a.GatewayStatus().Running {
		t.Error("the gateway was refused merely because capture could not be switched on")
	}
}

// Managed sharing means we hand out the addresses, which is what keeps each
// device's own address on its queries.
func TestManagedSharingStartsOurOwnDHCP(t *testing.T) {
	t.Parallel()
	gw := &fakeGateway{}
	a := testApp(t, gw)

	err := a.StartGateway(context.Background(), GatewaySettings{SharingName: "managed"})
	// Binding port 67 needs privileges this test does not have, and that is
	// the expected outcome — what matters is that it was ATTEMPTED, and that
	// the failure took the gateway down with it rather than leaving a
	// half-started one.
	if err == nil {
		defer a.StopGateway(context.Background())
		st := a.GatewayStatus()
		if st.Leases < 0 {
			t.Error("managed sharing is running with no DHCP server of its own")
		}
		return
	}
	if !strings.Contains(err.Error(), "DHCP") {
		t.Fatalf("err = %v, want it to name the DHCP server", err)
	}
	if a.GatewayStatus().Running {
		t.Error("the gateway was left running after its DHCP server failed to start")
	}
	if _, _, closed := gw.calls(); closed == 0 {
		t.Error("the platform session was not closed after the failure")
	}
}

// The address handed out has to be inside the subnet and must not be the
// network address, or every device is broken in a way that looks like hardware.
func TestTheGatewayTakesTheFirstUsableAddress(t *testing.T) {
	t.Parallel()
	gw := &fakeGateway{}
	a := testApp(t, gw)
	if err := a.StartGateway(context.Background(), GatewaySettings{
		SharingName: "platform", SSID: "Home", Passphrase: "correct horse",
	}); err != nil {
		t.Fatal(err)
	}
	defer a.StopGateway(context.Background())

	started, _, _ := gw.calls()
	cfg := started[0]
	if !cfg.Subnet.Contains(cfg.Addr) {
		t.Fatalf("address %v is outside subnet %v", cfg.Addr, cfg.Subnet)
	}
	if cfg.Addr == cfg.Subnet.Masked().Addr() {
		t.Error("the gateway took the network address")
	}
	if cfg.DNSPort == 0 {
		t.Error("the resolver's port was not passed to the gateway, so a redirect would go nowhere")
	}
}

// The pool leaves room at the bottom for reservations and never includes the
// broadcast address.
func TestThePoolRangeIsSane(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct{ subnet, first, last string }{
		{"10.42.0.0/24", "10.42.0.10", "10.42.0.254"},
		{"192.168.5.0/24", "192.168.5.10", "192.168.5.254"},
		{"10.0.0.0/22", "10.0.0.10", "10.0.3.254"},
	} {
		p := netip.MustParsePrefix(tc.subnet)
		first, last, err := poolRange(p, p.Masked().Addr().Next())
		if err != nil {
			t.Errorf("%s: %v", tc.subnet, err)
			continue
		}
		if first.String() != tc.first || last.String() != tc.last {
			t.Errorf("%s: range = %v-%v, want %v-%v", tc.subnet, first, last, tc.first, tc.last)
		}
		if !p.Contains(first) || !p.Contains(last) {
			t.Errorf("%s: the range leaves the subnet", tc.subnet)
		}
	}
	// A subnet too small to hand anything out of is refused rather than
	// producing a range that wraps.
	if _, _, err := poolRange(netip.MustParsePrefix("10.0.0.0/30"), netip.MustParseAddr("10.0.0.1")); err == nil {
		t.Error("a /30 was accepted as a pool")
	}
}

// Stopping puts the machine back, and stopping twice is harmless — which the
// shutdown path depends on, since it stops the gateway and the deferred Close
// stops it again.
func TestStoppingIsIdempotent(t *testing.T) {
	t.Parallel()
	gw := &fakeGateway{}
	a := testApp(t, gw)
	if err := a.StartGateway(context.Background(), GatewaySettings{
		SharingName: "platform", SSID: "Home", Passphrase: "correct horse",
	}); err != nil {
		t.Fatal(err)
	}
	if err := a.StopGateway(context.Background()); err != nil {
		t.Fatalf("first stop: %v", err)
	}
	if err := a.StopGateway(context.Background()); err != nil {
		t.Errorf("second stop: %v", err)
	}
	if _, _, closed := gw.calls(); closed != 1 {
		t.Errorf("the session was closed %d times, want once", closed)
	}
	if a.GatewayStatus().Running {
		t.Error("status still reports a running gateway")
	}
}

// Two gateways at once would each undo the other's work on the way down.
func TestOnlyOneGatewayAtATime(t *testing.T) {
	t.Parallel()
	gw := &fakeGateway{}
	a := testApp(t, gw)
	s := GatewaySettings{SharingName: "platform", SSID: "Home", Passphrase: "correct horse"}
	if err := a.StartGateway(context.Background(), s); err != nil {
		t.Fatal(err)
	}
	defer a.StopGateway(context.Background())
	if err := a.StartGateway(context.Background(), s); err == nil {
		t.Error("a second gateway was started over the first")
	}
}

// The settings are shown back to whoever set them, so the form opens filled in
// rather than empty.
func TestSettingsSurviveARestart(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	gw := &fakeGateway{}
	a, err := New(Options{
		Listen: "127.0.0.1:15398", Upstreams: []string{"udp://192.0.2.53:53"},
		StateDir: dir, NoQueryLog: true, Gateway: gw,
	})
	if err != nil {
		t.Fatal(err)
	}
	want := GatewaySettings{SharingName: "platform", SSID: "Sam's Wi-Fi", Passphrase: "correct horse", CaptureDNS: true}
	if err := a.StartGateway(context.Background(), want); err != nil {
		t.Fatal(err)
	}
	_ = a.StopGateway(context.Background())
	_ = a.Close()

	again, err := New(Options{
		Listen: "127.0.0.1:15398", Upstreams: []string{"udp://192.0.2.53:53"},
		StateDir: dir, NoQueryLog: true, Gateway: gw,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer again.Close()
	got := again.LoadGatewaySettings()
	if got.SSID != want.SSID || got.SharingName != want.SharingName || !got.CaptureDNS {
		t.Errorf("settings = %+v, want %+v", got, want)
	}
}

// A platform that cannot do what was asked says so, and the refusal reaches the
// caller rather than becoming a generic failure.
func TestARefusalReachesTheCaller(t *testing.T) {
	t.Parallel()
	gw := &fakeGateway{startErr: gateway.Unsupportedf("fake", gateway.CapAccessPoint, "no radio")}
	a := testApp(t, gw)
	err := a.StartGateway(context.Background(), GatewaySettings{
		SharingName: "platform", SSID: "Home", Passphrase: "correct horse",
	})
	if !errors.Is(err, gateway.ErrUnsupported) {
		t.Errorf("err = %v, want ErrUnsupported", err)
	}
	if !strings.Contains(err.Error(), "no radio") {
		t.Errorf("err = %v, want the platform's own reason", err)
	}
	if a.GatewayStatus().Running {
		t.Error("status reports a gateway that never started")
	}
}

func TestUnknownSharingModelIsRefused(t *testing.T) {
	t.Parallel()
	a := testApp(t, &fakeGateway{})
	err := a.StartGateway(context.Background(), GatewaySettings{SharingName: "sideways"})
	if err == nil || !strings.Contains(err.Error(), "none, platform or managed") {
		t.Errorf("err = %v, want it to list the models", err)
	}
}

// Closing the application must take the gateway down with it: a firewall rule
// or a running access point that outlived the process would leave somebody with
// no network and nothing on the screen to explain it.
func TestClosingTheApplicationStopsTheGateway(t *testing.T) {
	t.Parallel()
	gw := &fakeGateway{}
	a, err := New(Options{
		Listen: "127.0.0.1:15398", Upstreams: []string{"udp://192.0.2.53:53"},
		StateDir: t.TempDir(), NoQueryLog: true, Gateway: gw,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := a.StartGateway(context.Background(), GatewaySettings{
		SharingName: "platform", SSID: "Home", Passphrase: "correct horse",
	}); err != nil {
		t.Fatal(err)
	}
	if err := a.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if _, _, closed := gw.calls(); closed != 1 {
		t.Error("closing the application left the gateway running")
	}
	_ = time.Now
}
