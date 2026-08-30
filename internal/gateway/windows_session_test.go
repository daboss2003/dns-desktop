package gateway

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"
)

// winRunner answers the probes the Windows gateway makes.
type winRunner struct {
	fakeRunner
	capability string // what the tethering probe reports
	nats       string // what Get-NetNat reports
	natErr     bool   // Get-NetNat fails, as it does with no Hyper-V
}

func (w *winRunner) Run(ctx context.Context, name, stdin string, args ...string) (string, error) {
	w.fakeRunner.mu.Lock()
	w.fakeRunner.calls = append(w.fakeRunner.calls, call{name: name, args: args, stdin: stdin})
	failOn, failed := w.fakeRunner.failOn, w.fakeRunner.failed
	if failOn != "" && strings.Contains(stdin, failOn) && !failed {
		w.fakeRunner.failed = true
		w.fakeRunner.mu.Unlock()
		return "", errors.New("the fake runner was told to fail here")
	}
	w.fakeRunner.mu.Unlock()

	switch {
	case strings.Contains(stdin, "GetTetheringCapabilityFromConnectionProfile"):
		cap := w.capability
		if cap == "" {
			cap = "Enabled"
		}
		return `{"capability":"` + cap + `","state":"Off","clients":[]}`, nil
	case strings.Contains(stdin, "Get-NetNat"):
		if w.natErr {
			return "", errors.New("The term 'Get-NetNat' is not recognized")
		}
		if w.nats == "" {
			return "", nil
		}
		return w.nats, nil
	case strings.Contains(stdin, "Get-NetIPInterface"):
		return "Disabled\n", nil
	}
	return "", nil
}

func testWindows(t testing.TB, r Runner, elevated bool) *windowsGateway {
	t.Helper()
	return &windowsGateway{
		run: r, journal: journal{dir: t.TempDir()},
		elevated: func() bool { return elevated },
		list: func() ([]Interface, error) {
			return []Interface{
				{Name: "Wi-Fi", Kind: KindWireless, Up: true, HasDefaultRoute: true},
				{Name: "Ethernet", Kind: KindWired, Up: true},
			}, nil
		},
	}
}

// A capability the process cannot exercise is a control that fails when
// pressed, which is exactly what capability reporting exists to prevent.
func TestWindowsReportsNothingWithoutAdministratorRights(t *testing.T) {
	t.Parallel()
	g := testWindows(t, &winRunner{}, false)
	caps, err := g.Capabilities(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if caps.Have != 0 {
		t.Errorf("an unelevated process claims %v", caps.Have)
	}
	if !strings.Contains(caps.Reason(CapAccessPoint), "administrator") {
		t.Errorf("reason = %q, want it to say what to do", caps.Reason(CapAccessPoint))
	}
	if caps.Fixable&CapAccessPoint == 0 {
		t.Error("restarting elevated is not marked as something a person could do")
	}
	// Resolving for devices pointed here needs nothing and is still offered.
	if !caps.Supports(SharingNone) {
		t.Error("an unelevated process offers no sharing model at all")
	}
}

// Exactly one capability is a permanent no on this platform, and it names the
// alternative in the same breath so nobody concludes DNS cannot be captured
// here at all.
func TestWindowsCannotRewriteButSaysWhatItCanDo(t *testing.T) {
	t.Parallel()
	g := testWindows(t, &winRunner{}, true)
	caps, err := g.Capabilities(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if caps.Has(CapDNSRedirect) {
		t.Error("Windows claims it can rewrite a packet's destination")
	}
	why := caps.Reason(CapDNSRedirect)
	if !strings.Contains(why, "dns-enforce") {
		t.Errorf("reason = %q, want it to name the capability that does work", why)
	}
	if caps.Fixable&CapDNSRedirect != 0 {
		t.Error("rewriting is marked fixable; nothing a person installs makes it possible")
	}
}

// Windows' own answers are specific enough to act on, and each calls for a
// different action. Collapsing them into "unavailable" wastes the information.
func TestTetheringReasonsAreActionable(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct{ capability, want string }{
		{"DisabledByGroupPolicy", "group policy"},
		{"DisabledByHardwareLimitation", "USB adapter"},
		{"DisabledBySku", "edition of Windows"},
		{"DisabledBySystemCapability", "Windows Settings"},
		{"DisabledByOperator", "mobile operator"},
	} {
		g := testWindows(t, &winRunner{capability: tc.capability}, true)
		caps, err := g.Capabilities(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if caps.Has(CapAccessPoint) {
			t.Errorf("%s: an access point is offered", tc.capability)
		}
		if !strings.Contains(caps.Reason(CapAccessPoint), tc.want) {
			t.Errorf("%s: reason = %q, want it to mention %q", tc.capability, caps.Reason(CapAccessPoint), tc.want)
		}
		if caps.Supports(SharingPlatform) {
			t.Errorf("%s: platform sharing is offered with no hotspot available", tc.capability)
		}
	}
}

// Windows allows one address translation per machine, so somebody else's is the
// reason ours cannot exist — and naming it is an answer where "could not
// create" is not.
func TestAnotherNATIsReportedByName(t *testing.T) {
	t.Parallel()
	g := testWindows(t, &winRunner{nats: `{"Name":"DockerNAT","InternalIPInterfaceAddressPrefix":"172.17.0.0/16"}`}, true)
	caps, err := g.Capabilities(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if caps.Has(CapShareUplink) {
		t.Error("sharing is offered while another translation holds the one slot")
	}
	if !strings.Contains(caps.Reason(CapShareUplink), "DockerNAT") {
		t.Errorf("reason = %q, want it to name what has the slot", caps.Reason(CapShareUplink))
	}

	// Our own does not count against us: it is what a previous run left.
	ours := testWindows(t, &winRunner{nats: `{"Name":"GatewayDNS","InternalIPInterfaceAddressPrefix":"10.42.0.0/24"}`}, true)
	caps, _ = ours.Capabilities(context.Background())
	if !caps.Has(CapShareUplink) {
		t.Errorf("our own leftover translation blocked us: %s", caps.Reason(CapShareUplink))
	}

	// Several marshal as an array, which is PowerShell's convention.
	many := testWindows(t, &winRunner{nats: `[{"Name":"GatewayDNS"},{"Name":"WSL"}]`}, true)
	caps, _ = many.Capabilities(context.Background())
	if !strings.Contains(caps.Reason(CapShareUplink), "WSL") {
		t.Errorf("an array of translations was not read: %q", caps.Reason(CapShareUplink))
	}
}

// No Hyper-V means no Get-NetNat, and that is not a mysterious failure: it is
// the Home edition, and saying so saves an afternoon.
func TestNoHyperVIsExplained(t *testing.T) {
	t.Parallel()
	g := testWindows(t, &winRunner{natErr: true}, true)
	caps, err := g.Capabilities(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if caps.Has(CapShareUplink) {
		t.Error("sharing is offered on a machine that cannot do address translation")
	}
	if !strings.Contains(caps.Reason(CapShareUplink), "Home editions") {
		t.Errorf("reason = %q, want it to name the edition problem", caps.Reason(CapShareUplink))
	}
	// The hotspot is unaffected: it brings its own translation.
	if !caps.Supports(SharingPlatform) {
		t.Error("the hotspot is unavailable merely because New-NetNat is")
	}
}

// The obvious tool does not work, and the reason has to be in the message or
// somebody will reach for it again.
func TestBlockingSaysWhyTheFirewallCannotDoIt(t *testing.T) {
	t.Parallel()
	g := testWindows(t, &winRunner{}, true)
	caps, _ := g.Capabilities(context.Background())
	why := caps.Reason(CapBlockDevice)
	if !strings.Contains(why, "forwarded traffic") {
		t.Errorf("reason = %q, want it to say why a firewall rule cannot do it", why)
	}

	s := &windowsSession{gw: g, cfg: Config{Sharing: SharingPlatform}}
	err := s.Block(context.Background(), netip.MustParseAddr("192.168.137.5"), true)
	if !errors.Is(err, ErrUnsupported) {
		t.Errorf("err = %v, want ErrUnsupported", err)
	}
	// Unblocking is not an error: the caller asked for the device not to be
	// blocked, and it is not.
	if err := s.Block(context.Background(), netip.MustParseAddr("192.168.137.5"), false); err != nil {
		t.Errorf("unblocking failed: %v", err)
	}
	// Same for switching capture off.
	if err := s.SetDNSCapture(context.Background(), false); err != nil {
		t.Errorf("withdrawing a capture that was never installed failed: %v", err)
	}
}

// The hotspot brings its own everything, so bring-up is one step — and one step
// is all that is journalled and all that is undone.
func TestTheHotspotIsOneStep(t *testing.T) {
	t.Parallel()
	r := &winRunner{}
	g := testWindows(t, r, true)

	cfg := Config{
		Sharing: SharingPlatform, DNSPort: 5335,
		Hotspot: &HotspotConfig{SSID: "Home", Passphrase: "correct horse"},
	}
	s, err := g.Start(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	if r.index("StartTetheringAsync") < 0 {
		t.Error("the hotspot was never started")
	}
	if r.index("New-NetNat") >= 0 {
		t.Error("an address translation was created as well; the hotspot brings its own")
	}

	before := len(r.ran())
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	var stopped bool
	for _, c := range r.ran()[before:] {
		if strings.Contains(c.stdin, "StopTetheringAsync") {
			stopped = true
		}
	}
	if !stopped {
		t.Error("closing left the hotspot running")
	}
	if entries, _ := g.journal.read(); len(entries) != 0 {
		t.Error("the journal was not cleared")
	}
}

// Managed sharing is the arrangement that keeps per-device identity, and it has
// three steps that must be undone in reverse.
func TestManagedSharingIsUndoneInReverse(t *testing.T) {
	t.Parallel()
	r := &winRunner{}
	g := testWindows(t, r, true)

	cfg := Config{
		Sharing: SharingManaged, Uplink: "Ethernet", DNSPort: 5335,
		Subnet: netip.MustParsePrefix("10.42.0.0/24"), Addr: netip.MustParseAddr("10.42.0.1"),
		// Explicitly allowing IPv6, because this build cannot block it on
		// Windows and refuses managed sharing that asks it to. See
		// TestManagedSharingIsRefusedWhileIPv6CannotBeBlocked.
		IPv6: IPv6Allow,
	}
	s, err := g.Start(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	for _, want := range []string{"New-NetIPAddress", "-Forwarding Enabled", "New-NetNat"} {
		if r.index(want) < 0 {
			t.Errorf("bring-up never ran %s", want)
		}
	}
	before := len(r.ran())
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	teardown := r.ran()[before:]
	natAt, fwdAt, addrAt := -1, -1, -1
	for i, c := range teardown {
		switch {
		case strings.Contains(c.stdin, "Remove-NetNat"):
			natAt = i
		case strings.Contains(c.stdin, "-Forwarding Disabled"):
			fwdAt = i
		case strings.Contains(c.stdin, "Remove-NetIPAddress"):
			addrAt = i
		}
	}
	if natAt < 0 || fwdAt < 0 || addrAt < 0 {
		t.Fatalf("teardown missed a step: nat=%d forwarding=%d address=%d", natAt, fwdAt, addrAt)
	}
	if !(natAt < fwdAt && fwdAt < addrAt) {
		t.Errorf("teardown ran out of order: nat=%d forwarding=%d address=%d", natAt, fwdAt, addrAt)
	}
}

// A failure partway through must leave the machine as it was found.
func TestAFailedBringUpIsUndone(t *testing.T) {
	t.Parallel()
	r := &winRunner{}
	r.fakeRunner.failOn = "New-NetNat -Name"
	g := testWindows(t, r, true)

	cfg := Config{
		Sharing: SharingManaged, Uplink: "Ethernet", DNSPort: 5335,
		Subnet: netip.MustParsePrefix("10.42.0.0/24"), Addr: netip.MustParseAddr("10.42.0.1"),
		IPv6: IPv6Allow,
	}
	if _, err := g.Start(context.Background(), cfg); err == nil {
		t.Fatal("Start succeeded despite the translation failing")
	}
	if r.index("-Forwarding Disabled") < 0 {
		t.Error("forwarding was left enabled after a failed bring-up")
	}
	if r.index("Remove-NetIPAddress") < 0 {
		t.Error("the address was left assigned after a failed bring-up")
	}
	if entries, _ := g.journal.read(); len(entries) != 0 {
		t.Error("the journal still lists steps after the failure was undone")
	}
}

// A process that is killed cannot clean up after itself, so the next one does.
func TestWindowsReconcileUndoesALeftoverSession(t *testing.T) {
	t.Parallel()
	r := &winRunner{}
	g := testWindows(t, r, true)
	if err := g.journal.record([]journalEntry{
		{Step: stepWinAddr, Data: "10.42.0.1@Ethernet"},
		{Step: stepWinFwd, Data: "Disabled@Ethernet"},
		{Step: stepNat},
	}); err != nil {
		t.Fatal(err)
	}
	rep, err := g.Reconcile(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if rep.Clean() {
		t.Error("Reconcile found nothing to clean with a journal listing three steps")
	}
	if r.index("Remove-NetNat") < 0 || r.index("Remove-NetIPAddress") < 0 {
		t.Error("the leftover session was not undone")
	}
	if r.index("-Forwarding Disabled") < 0 {
		t.Error("forwarding was not restored to what the journal recorded")
	}
	if entries, _ := g.journal.read(); len(entries) != 0 {
		t.Error("the journal was not cleared, so the next run would try again")
	}
}

// The default is to fail closed, and a platform that cannot fail closed is
// refused rather than quietly shipping a gateway that leaks.
//
// "We did not configure IPv6" is not "IPv6 does not happen": a dual-stack
// client that picks up a v6 route resolves over v6 and bypasses every rule,
// while the v4 counters look perfectly healthy. Since this build has no
// forwarding-layer filters on Windows, managed sharing here must be an explicit
// decision to accept that — not a default nobody was told about.
func TestManagedSharingIsRefusedWhileIPv6CannotBeBlocked(t *testing.T) {
	t.Parallel()
	g := testWindows(t, &winRunner{}, true)
	cfg := Config{
		Sharing: SharingManaged, Uplink: "Ethernet", DNSPort: 5335,
		Subnet: netip.MustParsePrefix("10.42.0.0/24"), Addr: netip.MustParseAddr("10.42.0.1"),
		// IPv6Block, the zero value and the safe direction.
	}
	_, err := g.Start(context.Background(), cfg)
	if err == nil {
		t.Fatal("managed sharing started on a platform that cannot stop IPv6 bypassing it")
	}
	if !errors.Is(err, ErrUnsupported) {
		t.Errorf("err = %v, want ErrUnsupported", err)
	}
	if !strings.Contains(err.Error(), "ipv6-control") {
		t.Errorf("err = %v, want it to name the capability that is missing", err)
	}
	// And with the operator's eyes open, it proceeds.
	cfg.IPv6 = IPv6Allow
	s, err := g.Start(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Start with IPv6 explicitly allowed: %v", err)
	}
	_ = s.Close()
}
