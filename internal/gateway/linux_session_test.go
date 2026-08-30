package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
)

// fakeRunner records what would have been run, and can be told to fail.
type fakeRunner struct {
	mu      sync.Mutex
	calls   []call
	missing map[string]bool
	// failOn makes the nth matching command fail, so a partial bring-up can be
	// produced at any step.
	failOn  string
	failed  bool
	tableUp bool
}

type call struct {
	name  string
	args  []string
	stdin string
}

func (f *fakeRunner) Run(_ context.Context, name, stdin string, args ...string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, call{name: name, args: args, stdin: stdin})

	// The stdin too: nft is always invoked as "nft -f -", so a test that could
	// only match the arguments could not aim at one particular ruleset change.
	joined := name + " " + strings.Join(args, " ") + " " + stdin
	if f.failOn != "" && strings.Contains(joined, f.failOn) && !f.failed {
		f.failed = true
		return "", errors.New("the fake runner was told to fail here")
	}
	switch {
	case name == "nft" && len(args) > 0 && args[0] == "list":
		if !f.tableUp {
			return "", errors.New("No such file or directory")
		}
		return "table inet gatewaydns {}", nil
	case name == "nft" && strings.Contains(stdin, "table inet gatewaydns {"):
		f.tableUp = true
	case name == "nft" && strings.HasPrefix(stdin, "destroy table"):
		f.tableUp = false
	case name == "sysctl" && len(args) > 0 && args[0] == "-n":
		return "0\n", nil
	}
	return "", nil
}

func (f *fakeRunner) Look(name string) bool { return !f.missing[name] }

func (f *fakeRunner) ran() []call {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]call(nil), f.calls...)
}

func (f *fakeRunner) index(substr string) int {
	for i, c := range f.ran() {
		if strings.Contains(c.name+" "+strings.Join(c.args, " ")+" "+c.stdin, substr) {
			return i
		}
	}
	return -1
}

func testLinux(t testing.TB, r *fakeRunner) *linuxGateway {
	t.Helper()
	dir := t.TempDir()
	if r.missing == nil {
		r.missing = map[string]bool{}
	}
	return &linuxGateway{
		run: r, journal: journal{dir: dir}, runDir: dir,
		defaultRoute: func() (string, error) { return "eth0", nil },
		wireless: func(name string) (bool, apSupport) {
			return name == "wlan0", apSupport{supported: name == "wlan0"}
		},
	}
}

func linuxConfig() Config {
	return Config{
		Sharing: SharingManaged,
		Subnet:  netip.MustParsePrefix("10.42.0.0/24"),
		Addr:    netip.MustParseAddr("10.42.0.1"),
		DNSPort: 5335,
		Hotspot: &HotspotConfig{
			Interface: "wlan0", SSID: "Home", Passphrase: "correct horse battery",
		},
	}
}

// stubInterfaces describes a machine this one is not: a radio that can host an
// access point, and a wired uplink carrying the default route.
func stubInterfaces(g *linuxGateway) {
	g.list = func() ([]Interface, error) {
		return []Interface{
			{Name: "eth0", Kind: KindWired, Up: true, HasDefaultRoute: true},
			{Name: "wlan0", Kind: KindWireless, Up: true, SupportsAP: true},
			{Name: "lo", Kind: KindLoopback, Up: true},
		}, nil
	}
}

// stubNoRadio is a machine with no adapter that can host an access point, which
// is the ordinary case on a desktop and on most cheap USB dongles.
func stubNoRadio(g *linuxGateway) {
	g.list = func() ([]Interface, error) {
		return []Interface{
			{Name: "eth0", Kind: KindWired, Up: true, HasDefaultRoute: true},
			{Name: "wlan0", Kind: KindWireless, Up: true, APReason: "the driver does not report access-point mode"},
		}, nil
	}
}

// The whole point of the journal: a step is recorded and flushed to disk BEFORE
// it is applied. The only inconsistency that ordering permits is a record of a
// step that was not taken, and every undo treats "not there" as success — while
// the other order loses a step nothing knows to undo, which is a firewall rule
// left on a machine whose owner cannot get online.
func TestEveryStepIsRecordedBeforeItIsApplied(t *testing.T) {
	t.Parallel()
	r := &fakeRunner{}
	g := testLinux(t, r)
	stubInterfaces(g)

	// Fail at the last step, so the journal must already name every earlier one.
	r.failOn = "hostapd"
	_, err := g.Start(context.Background(), withInterfaces(g, linuxConfig()))
	if err == nil {
		t.Fatal("bring-up succeeded despite hostapd failing")
	}

	// Everything applied was undone, in reverse, so nothing is left behind.
	ran := r.ran()
	var undoAt, applyAt = -1, -1
	for i, c := range ran {
		if c.name == "sysctl" && len(c.args) > 1 && c.args[0] == "-w" && strings.HasSuffix(c.args[1], "=1") {
			applyAt = i
		}
		if c.name == "sysctl" && len(c.args) > 1 && c.args[0] == "-w" && strings.HasSuffix(c.args[1], "=0") {
			undoAt = i
		}
	}
	if applyAt < 0 {
		t.Fatal("forwarding was never enabled")
	}
	if undoAt < 0 {
		t.Error("forwarding was left enabled after a failed bring-up; the machine is now a router nobody asked for")
	}
	if r.tableUp {
		t.Error("the nftables table was left behind after a failed bring-up")
	}
	// And the journal is empty, so the next run has nothing to recover.
	if entries, _ := g.journal.read(); len(entries) != 0 {
		t.Errorf("the journal still lists %d steps after teardown", len(entries))
	}
}

// withInterfaces makes the hotspot interface one the stub reports.
func withInterfaces(g *linuxGateway, c Config) Config { return c }

// Capture is not part of bring-up. While it is in force every DNS query on the
// network is aimed at one socket, so it goes on only after the caller has
// satisfied itself that its own resolver is answering.
func TestBringUpDoesNotCaptureDNS(t *testing.T) {
	t.Parallel()
	r := &fakeRunner{}
	g := testLinux(t, r)
	stubInterfaces(g)

	s, err := g.Start(context.Background(), linuxConfig())
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer s.Close()

	if i := r.index("add element inet gatewaydns capture"); i >= 0 {
		t.Fatalf("bring-up switched DNS capture on, at step %d", i)
	}
	st, _ := s.Status(context.Background())
	if st.DNSCapture != 0 {
		t.Errorf("status reports capture %v before it was asked for", st.DNSCapture)
	}

	// And when it is asked for, it happens.
	if err := s.SetDNSCapture(context.Background(), true); err != nil {
		t.Fatalf("SetDNSCapture: %v", err)
	}
	if r.index("add element inet gatewaydns capture") < 0 {
		t.Error("capture was requested and no rule changed")
	}
	st, _ = s.Status(context.Background())
	if st.DNSCapture == 0 {
		t.Error("status does not report capture in force")
	}
}

// Capture comes off before anything else, because it is the one rule that hurts
// if it outlives the resolver behind it.
func TestTeardownWithdrawsCaptureFirst(t *testing.T) {
	t.Parallel()
	r := &fakeRunner{}
	g := testLinux(t, r)
	stubInterfaces(g)

	s, err := g.Start(context.Background(), linuxConfig())
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SetDNSCapture(context.Background(), true); err != nil {
		t.Fatal(err)
	}
	before := len(r.ran())
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	teardown := r.ran()[before:]
	if len(teardown) == 0 {
		t.Fatal("closing ran nothing")
	}
	first := teardown[0]
	if !strings.Contains(first.stdin, "delete element inet gatewaydns capture") {
		t.Errorf("teardown began with %v %v, want the capture withdrawal first", first.name, first.args)
	}
	// And the table goes before the address, which goes before forwarding is
	// restored: the reverse of the order they were applied in.
	destroyAt, addrAt, fwdAt := -1, -1, -1
	for i, c := range teardown {
		switch {
		case strings.HasPrefix(c.stdin, "destroy table"):
			destroyAt = i
		case c.name == "ip" && len(c.args) > 1 && c.args[1] == "del":
			addrAt = i
		case c.name == "sysctl" && len(c.args) > 1 && strings.HasSuffix(c.args[1], "=0"):
			fwdAt = i
		}
	}
	if destroyAt < 0 || addrAt < 0 || fwdAt < 0 {
		t.Fatalf("teardown missed a step: table=%d addr=%d forwarding=%d", destroyAt, addrAt, fwdAt)
	}
	if !(destroyAt < addrAt && addrAt < fwdAt) {
		t.Errorf("teardown ran out of order: table=%d addr=%d forwarding=%d", destroyAt, addrAt, fwdAt)
	}
}

// Forwarding must be restored to what it was, not set to zero. A machine that
// was already a router before this ran must still be one afterwards.
func TestForwardingIsRestoredToWhatItWas(t *testing.T) {
	t.Parallel()
	r := &fakeRunner{}
	g := testLinux(t, r)
	stubInterfaces(g)

	// A machine that was ALREADY forwarding before this ran: its sysctl read
	// reports 1, so teardown must put it back to 1 and not to 0.
	g.run = &alreadyForwarding{fakeRunner: r}

	s, err := g.Start(context.Background(), linuxConfig())
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	for _, c := range r.ran() {
		if c.name == "sysctl" && len(c.args) > 1 && c.args[1] == "net.ipv4.ip_forward=0" {
			t.Fatal("forwarding was switched off on a machine that had it on before this ran")
		}
	}
	if r.index("net.ipv4.ip_forward=1") < 0 {
		t.Error("forwarding was never restored")
	}
}

type alreadyForwarding struct{ *fakeRunner }

func (a *alreadyForwarding) Run(ctx context.Context, name, stdin string, args ...string) (string, error) {
	if name == "sysctl" && len(args) > 0 && args[0] == "-n" {
		a.fakeRunner.mu.Lock()
		a.fakeRunner.calls = append(a.fakeRunner.calls, call{name: name, args: args})
		a.fakeRunner.mu.Unlock()
		return "1\n", nil
	}
	return a.fakeRunner.Run(ctx, name, stdin, args...)
}

// A process that is killed cannot run its own cleanup, so the next one has to.
// A machine whose firewall still carries half a session from an hour ago is a
// machine whose owner cannot get online and has nothing to read about why.
func TestReconcileCleansUpAfterACrash(t *testing.T) {
	t.Parallel()
	r := &fakeRunner{}
	g := testLinux(t, r)

	// A journal left by a process that died: forwarding was off before, an
	// address was added, and a table was loaded.
	entries := []journalEntry{
		{Step: stepForwarding, Data: "0"},
		{Step: stepAddress, Data: "10.42.0.1/24@wlan0"},
		{Step: stepNftables},
	}
	if err := g.journal.record(entries); err != nil {
		t.Fatal(err)
	}
	r.tableUp = true

	rep, err := g.Reconcile(context.Background())
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if rep.Clean() {
		t.Error("Reconcile reported nothing to clean on a machine with a live table and a journal")
	}
	if r.tableUp {
		t.Error("the leftover table was not removed")
	}
	if r.index("net.ipv4.ip_forward=0") < 0 {
		t.Error("forwarding was not restored to what the journal recorded")
	}
	if r.index("addr del") < 0 {
		t.Error("the leftover address was not removed")
	}
	if entries, _ := g.journal.read(); len(entries) != 0 {
		t.Error("the journal was not cleared, so the next run would try again")
	}

	// And running it twice is harmless, which is what makes it safe to call at
	// every start-up.
	if _, err := g.Reconcile(context.Background()); err != nil {
		t.Errorf("a second Reconcile failed: %v", err)
	}
}

// The journal and reality disagree in both directions, and both happen: /run
// can be cleared while rules are live, and something else can flush the ruleset
// while the journal still lists it.
func TestReconcileFindsALiveTableWithNoJournal(t *testing.T) {
	t.Parallel()
	r := &fakeRunner{tableUp: true}
	g := testLinux(t, r)

	rep, err := g.Reconcile(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if r.tableUp {
		t.Error("a live table with no journal entry survived reconciliation")
	}
	found := strings.Join(rep.Found, " ")
	if !strings.Contains(found, "did not record") {
		t.Errorf("the report does not mention the unrecorded table: %v", rep.Found)
	}
}

// A journal that will not parse is a record of changes nobody can undo, and
// saying so is better than silently treating the machine as clean.
func TestAnUnreadableJournalIsReported(t *testing.T) {
	t.Parallel()
	r := &fakeRunner{}
	g := testLinux(t, r)
	if err := os.MkdirAll(g.journal.dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(g.journal.path(), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	rep, err := g.Reconcile(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Failed) == 0 || !strings.Contains(strings.Join(rep.Failed, " "), "unreadable") {
		t.Errorf("an unparseable journal was not reported: %+v", rep)
	}
}

// The configuration holds the network's pairwise master key, which is as good
// as the passphrase to anyone who can read it.
func TestTheHostapdConfigurationIsNotWorldReadable(t *testing.T) {
	t.Parallel()
	if runtime.GOOS == "windows" {
		// Windows has no POSIX permission bits: Go reports 0666 for every
		// regular file, and confidentiality there is an ACL that os.WriteFile's
		// mode argument does not touch. The code under test only ever runs on
		// Linux — it is reached through the Linux gateway — so this is a check
		// of Linux behaviour that happens to compile everywhere, and asserting
		// it on Windows would fail on a guarantee the platform does not have.
		t.Skip("file permission bits are not a Windows concept")
	}
	r := &fakeRunner{}
	g := testLinux(t, r)
	stubInterfaces(g)

	s, err := g.Start(context.Background(), linuxConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	path := filepath.Join(g.runDir, "hostapd.conf")
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("no configuration was written: %v", err)
	}
	if mode := fi.Mode().Perm(); mode&0o077 != 0 {
		t.Errorf("the configuration is mode %o; it holds the network's key", mode)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), linuxConfig().Hotspot.Passphrase) {
		t.Error("the passphrase is in the configuration file")
	}
}

// Capabilities must name what is missing from THIS machine, because "install
// hostapd" and "your only radio is carrying the connection you are sharing" are
// different problems with different fixes.
func TestLinuxCapabilitiesNameWhatIsMissing(t *testing.T) {
	t.Parallel()
	full := &fakeRunner{}
	g := testLinux(t, full)
	stubInterfaces(g)
	caps, err := g.Capabilities(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []Capability{CapShareUplink, CapDNSRedirect, CapDNSEnforce, CapOwnDHCP, CapAccessPoint} {
		if !caps.Has(want) {
			t.Errorf("%v is unavailable on a fully equipped machine: %s", want, caps.Reason(want))
		}
	}
	if !caps.Supports(SharingManaged) {
		t.Error("managed sharing is not offered on a machine that can do all of it")
	}

	noHostapd := &fakeRunner{missing: map[string]bool{"hostapd": true}}
	g2 := testLinux(t, noHostapd)
	stubInterfaces(g2)
	caps, _ = g2.Capabilities(context.Background())
	if caps.Has(CapAccessPoint) {
		t.Error("an access point is offered with no hostapd installed")
	}
	if !strings.Contains(caps.Reason(CapAccessPoint), "hostapd") {
		t.Errorf("reason = %q, want it to name hostapd", caps.Reason(CapAccessPoint))
	}
	if caps.Fixable&CapAccessPoint == 0 {
		t.Error("installing hostapd is not marked as something a person could do")
	}

	noNft := &fakeRunner{missing: map[string]bool{"nft": true}}
	g3 := testLinux(t, noNft)
	stubInterfaces(g3)
	caps, _ = g3.Capabilities(context.Background())
	if caps.Has(CapShareUplink) || caps.Supports(SharingManaged) {
		t.Error("sharing is offered with no firewall tool installed")
	}
	if !strings.Contains(caps.Reason(CapShareUplink), "nftables") {
		t.Errorf("reason = %q, want it to say what to install", caps.Reason(CapShareUplink))
	}
}

// The journal is written and flushed before the step, so the file has to be on
// disk in a readable state at that moment.
func TestTheJournalRoundTrips(t *testing.T) {
	t.Parallel()
	j := journal{dir: t.TempDir()}
	if got, err := j.read(); err != nil || got != nil {
		t.Fatalf("a fresh journal read as %v, %v", got, err)
	}
	want := []journalEntry{{Step: stepForwarding, Data: "1"}, {Step: stepNftables}}
	if err := j.record(want); err != nil {
		t.Fatal(err)
	}
	got, err := j.read()
	if err != nil {
		t.Fatal(err)
	}
	a, _ := json.Marshal(want)
	b, _ := json.Marshal(got)
	if string(a) != string(b) {
		t.Errorf("read back %s, want %s", b, a)
	}
	if err := j.clear(); err != nil {
		t.Fatal(err)
	}
	if got, _ := j.read(); got != nil {
		t.Error("the journal survived being cleared")
	}
	// Clearing twice is harmless, which teardown depends on.
	if err := j.clear(); err != nil {
		t.Errorf("clearing an absent journal failed: %v", err)
	}
}

func TestStartRefusesWhatItCannotDo(t *testing.T) {
	t.Parallel()
	r := &fakeRunner{missing: map[string]bool{"hostapd": true}}
	g := testLinux(t, r)
	stubInterfaces(g)

	_, err := g.Start(context.Background(), linuxConfig())
	if err == nil {
		t.Fatal("a hotspot was started with no hostapd")
	}
	if !errors.Is(err, ErrUnsupported) {
		t.Errorf("err = %v, want it to wrap ErrUnsupported", err)
	}
	// Nothing was touched on the way to refusing.
	if len(r.ran()) > 0 {
		for _, c := range r.ran() {
			if c.name == "nft" && strings.Contains(c.stdin, "table inet") {
				t.Error("a refused configuration still loaded a ruleset")
			}
		}
	}
}

// "No adapter supports access-point mode" and "your only adapter is carrying
// the connection you are sharing" are different problems with different fixes,
// and the second is far more common on a laptop.
func TestAMachineWithNoUsableRadioSaysSo(t *testing.T) {
	t.Parallel()
	r := &fakeRunner{}
	g := testLinux(t, r)
	stubNoRadio(g)

	caps, err := g.Capabilities(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if caps.Has(CapAccessPoint) {
		t.Fatal("an access point is offered on a machine whose radio cannot host one")
	}
	if !strings.Contains(caps.Reason(CapAccessPoint), "driver") {
		t.Errorf("reason = %q, want the driver's own reason", caps.Reason(CapAccessPoint))
	}
	// But sharing an existing network is still on offer: a machine with no
	// usable radio can still be the gateway for a wired subnet, and telling
	// somebody the whole product is unavailable would be wrong.
	if !caps.Has(CapShareUplink) {
		t.Error("sharing is unavailable merely because the radio cannot host an access point")
	}
	if !caps.Supports(SharingNone) {
		t.Error("even resolving for devices pointed here is unavailable")
	}
}

// The address is applied with "replace" rather than "add", because a bring-up
// after an unclean stop meets an address that is already there — and "add"
// fails on it, turning a recoverable state into a refusal to start.
func TestTheAddressIsAppliedIdempotently(t *testing.T) {
	t.Parallel()
	r := &fakeRunner{}
	g := testLinux(t, r)
	stubInterfaces(g)

	s, err := g.Start(context.Background(), linuxConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	var found bool
	for _, c := range r.ran() {
		if c.name == "ip" && len(c.args) >= 2 && c.args[0] == "addr" {
			found = true
			if c.args[1] != "replace" {
				t.Errorf("the address was applied with %q; a bring-up after an unclean stop would fail", c.args[1])
			}
		}
	}
	if !found {
		t.Error("no address was assigned to the served interface")
	}
}

// A device cut off must be cut off in both directions, and restoring it must
// use the same mechanism rather than a rule rewrite.
func TestBlockingADeviceIsSetMembership(t *testing.T) {
	t.Parallel()
	r := &fakeRunner{}
	g := testLinux(t, r)
	stubInterfaces(g)

	s, err := g.Start(context.Background(), linuxConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	addr := netip.MustParseAddr("10.42.0.7")
	if err := s.Block(context.Background(), addr, true); err != nil {
		t.Fatalf("Block: %v", err)
	}
	if r.index("add element inet gatewaydns blocked { 10.42.0.7 }") < 0 {
		t.Error("blocking did not add the address to the set")
	}
	if err := s.Block(context.Background(), addr, false); err != nil {
		t.Fatalf("unblock: %v", err)
	}
	if r.index("delete element inet gatewaydns blocked { 10.42.0.7 }") < 0 {
		t.Error("unblocking did not remove the address from the set")
	}
	// An IPv6 address has no place in an IPv4 set, and saying so beats writing
	// a rule that never matches.
	if err := s.Block(context.Background(), netip.MustParseAddr("fd00::1"), true); err == nil {
		t.Error("an IPv6 address was accepted")
	}
}

// A capture that cannot be withdrawn is the worst state this component has: it
// leaves every device on the network aimed at a socket that may not be
// answering. It must be visible rather than silent.
func TestAFailedWithdrawalIsReportedAsDegraded(t *testing.T) {
	t.Parallel()
	r := &fakeRunner{}
	g := testLinux(t, r)
	stubInterfaces(g)

	s, err := g.Start(context.Background(), linuxConfig())
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SetDNSCapture(context.Background(), true); err != nil {
		t.Fatal(err)
	}
	r.mu.Lock()
	r.failOn, r.failed = "delete element", false
	r.mu.Unlock()

	if err := s.SetDNSCapture(context.Background(), false); err == nil {
		t.Fatal("withdrawing capture reported success while failing")
	}
	st, _ := s.Status(context.Background())
	if st.State != StateDegraded {
		t.Errorf("state = %v, want degraded", st.State)
	}
	if !strings.Contains(st.Detail, "withdrawn") {
		t.Errorf("detail = %q, want it to say what is wrong", st.Detail)
	}
}
