package nftables

import (
	"errors"
	"net/netip"
	"strings"
	"testing"
)

func opts() Options {
	return Options{
		Interface: "wlan0",
		Uplink:    "eth0",
		Subnet:    netip.MustParsePrefix("10.42.0.0/24"),
		DNSPort:   5335,
		BlockIPv6: true,
	}
}

func render(t testing.TB, o Options) string {
	t.Helper()
	s, err := o.Ruleset()
	if err != nil {
		t.Fatalf("Ruleset: %v", err)
	}
	return s
}

// Everything this package writes must be inside one table it owns. A gateway
// that wrote into the system's own table could not tell its rules from anyone
// else's, and the cost of getting that wrong is a machine whose network is
// broken with nothing on it to explain why.
func TestEverythingIsInsideOneNamespacedTable(t *testing.T) {
	t.Parallel()
	s := render(t, opts())
	if !strings.HasPrefix(s, "table inet gatewaydns {") {
		t.Fatalf("the ruleset does not open our own table:\n%s", s)
	}
	// One table, and it closes. Anything at the top level after it would be a
	// rule outside our namespace.
	if n := strings.Count(s, "\ntable "); n != 0 {
		t.Errorf("%d further tables are declared", n)
	}
	depth := 0
	for _, line := range strings.Split(s, "\n") {
		depth += strings.Count(line, "{") - strings.Count(line, "}")
		if depth < 0 {
			t.Fatalf("unbalanced braces:\n%s", s)
		}
	}
	if depth != 0 {
		t.Errorf("the table is not closed:\n%s", s)
	}
	if !strings.Contains(Destroy(), "destroy table inet gatewaydns") {
		t.Errorf("teardown = %q", Destroy())
	}
}

// The uplink is a set of one element, so changing it is an atomic swap.
//
// Rewriting the masquerade rule when somebody unplugs the Ethernet leaves a
// window in which the subnet is forwarded but not translated, and every packet
// in it is dropped upstream as a martian — which a user experiences as "the
// hotspot broke when I moved the cable".
func TestTheUplinkIsSwappedAtomically(t *testing.T) {
	t.Parallel()
	s := render(t, opts())
	if !strings.Contains(s, "oifname @uplink masquerade") {
		t.Errorf("the masquerade rule names an interface directly rather than the set:\n%s", s)
	}
	if strings.Contains(s, `oifname "eth0" masquerade`) {
		t.Error("the uplink is named inside a rule, so changing it means rewriting the rule")
	}

	swap, err := SetUplinkTo("wlan1")
	if err != nil {
		t.Fatal(err)
	}
	// Flush and add together, or there is an instant with an empty set — and
	// an empty set matches nothing, so the masquerade stops applying.
	if !strings.Contains(swap, "flush set") || !strings.Contains(swap, "add element") {
		t.Errorf("the swap is not one transaction: %q", swap)
	}
	if strings.Index(swap, "flush set") > strings.Index(swap, "add element") {
		t.Errorf("the add comes before the flush, which would undo it: %q", swap)
	}
}

// Capture is switched by set membership, not by adding and removing rules. It
// goes on last and comes off first, and while it is on every DNS query on the
// network is aimed at one socket.
func TestCaptureIsMembershipNotARuleEdit(t *testing.T) {
	t.Parallel()
	s := render(t, opts())
	for _, proto := range []string{"udp", "tcp"} {
		want := "iifname @capture " + proto + " dport 53 redirect to :5335"
		if !strings.Contains(s, want) {
			t.Errorf("missing %q:\n%s", want, s)
		}
	}
	// The set starts empty, so a freshly loaded ruleset captures nothing. A
	// gateway that started intercepting the moment it came up would intercept
	// before its own resolver was known to be answering.
	// Located rather than indexed blindly: strings.Index returns -1 when it
	// finds nothing, and slicing on that panics — so a rename of the set would
	// have crashed this test instead of failing it.
	at := strings.Index(s, "set capture")
	if at < 0 {
		t.Fatalf("the ruleset declares no capture set:\n%s", s)
	}
	sets := s[at:]
	end := strings.Index(sets, "}")
	if end < 0 {
		t.Fatalf("the capture set is not closed:\n%s", sets)
	}
	if strings.Contains(sets[:end], "elements") {
		t.Error("the capture set is not empty at load; capture must be switched on deliberately")
	}

	on, err := Capture("wlan0", true)
	if err != nil {
		t.Fatal(err)
	}
	off, _ := Capture("wlan0", false)
	if !strings.HasPrefix(on, "add element") || !strings.HasPrefix(off, "delete element") {
		t.Errorf("on = %q, off = %q", on, off)
	}
}

// DNAT to loopback would need route_localnet, which makes all of 127.0.0.0/8
// routable from that interface — every loopback-only service on the machine
// becomes reachable from the guest network.
func TestCaptureRedirectsRatherThanDNATingToLoopback(t *testing.T) {
	t.Parallel()
	s := render(t, opts())
	if strings.Contains(s, "127.0.0.1") {
		t.Errorf("the ruleset DNATs to loopback, which exposes every loopback service to the guest network:\n%s", s)
	}
	if !strings.Contains(s, "redirect to :") {
		t.Error("the capture does not use redirect")
	}
}

// "We did not configure IPv6" is not "IPv6 does not happen". A dual-stack
// client that picks up a v6 route resolves over v6 and bypasses every rule
// here, while the v4 counters look perfectly healthy.
func TestIPv6FailsClosed(t *testing.T) {
	t.Parallel()
	s := render(t, opts())
	if !strings.Contains(s, `meta nfproto ipv6 iifname "wlan0" drop`) {
		t.Errorf("forwarded IPv6 from the served interface is not dropped:\n%s", s)
	}
	if !strings.Contains(s, `meta nfproto ipv6 oifname "wlan0" drop`) {
		t.Errorf("IPv6 towards the served interface is not dropped:\n%s", s)
	}

	allow := opts()
	allow.BlockIPv6 = false
	if s := render(t, allow); strings.Contains(s, "nfproto ipv6") {
		t.Error("IPv6 is dropped even when the operator asked for it to be forwarded")
	}
}

// A blocked device is cut off in both directions. Dropping only its outbound
// traffic leaves it able to receive, which is not what "pause the internet for
// this device" means.
func TestABlockedDeviceIsCutOffBothWays(t *testing.T) {
	t.Parallel()
	s := render(t, opts())
	sa := strings.Index(s, "ip saddr @blocked drop")
	da := strings.Index(s, "ip daddr @blocked drop")
	if sa < 0 || da < 0 {
		t.Fatalf("the blocked set is not enforced in both directions:\n%s", s)
	}
	// And before anything else in the chain, so nothing accepts it first.
	fwd := strings.Index(s, "chain forward")
	if sa < fwd {
		t.Error("the block rules are outside the forward chain")
	}

	one, err := Block(netip.MustParseAddr("10.42.0.7"), true)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(one, "add element inet gatewaydns blocked { 10.42.0.7 }") {
		t.Errorf("block = %q", one)
	}
	if _, err := Block(netip.MustParseAddr("fd00::1"), true); err == nil {
		t.Error("an IPv6 address was accepted into an IPv4 set")
	}

	// Restoring the whole set after a restart is one flush and one add, and is
	// stable for the same input so two renderings can be compared.
	all, err := BlockAll([]netip.Addr{
		netip.MustParseAddr("10.42.0.9"), netip.MustParseAddr("10.42.0.3"),
	})
	if err != nil {
		t.Fatal(err)
	}
	again, _ := BlockAll([]netip.Addr{
		netip.MustParseAddr("10.42.0.3"), netip.MustParseAddr("10.42.0.9"),
	})
	if all != again {
		t.Errorf("the same set rendered differently depending on order:\n%s\n---\n%s", all, again)
	}
	if !strings.Contains(all, "flush set") {
		t.Error("restoring the set does not clear it first, so stale entries would survive")
	}
}

// The ruleset is fed to a parser, so a name that could close a quoted string
// could add rules. Interface names cannot contain a quote, and the check is
// here because the name may have come from a configuration file.
func TestUnsafeInterfaceNamesAreRefused(t *testing.T) {
	t.Parallel()
	for _, name := range []string{
		`wlan0" ; drop`, "wlan0\nadd rule", "wlan0{}", "", strings.Repeat("a", 20), "wlan 0",
	} {
		o := opts()
		o.Interface = name
		if _, err := o.Ruleset(); err == nil {
			t.Errorf("interface %q was accepted", name)
		}
		o = opts()
		o.Uplink = name
		if _, err := o.Ruleset(); err == nil {
			t.Errorf("uplink %q was accepted", name)
		}
		if _, err := Capture(name, true); err == nil {
			t.Errorf("Capture accepted %q", name)
		}
		if _, err := SetUplinkTo(name); err == nil {
			t.Errorf("SetUplinkTo accepted %q", name)
		}
	}
	// And the error says what kind of problem it is, because one of these is a
	// typo and the other is somebody probing.
	o := opts()
	o.Interface = `x"y`
	if err := o.Validate(); !errors.Is(err, ErrUnsafeValue) {
		t.Errorf("err = %v, want ErrUnsafeValue", err)
	}
}

func TestValidationReportsEveryProblem(t *testing.T) {
	t.Parallel()
	err := Options{DNSPort: -1}.Validate()
	if err == nil {
		t.Fatal("an empty ruleset specification was accepted")
	}
	for _, want := range []string{"interface is required", "uplink is required", "subnet", "not a port"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error does not mention %q:\n%v", want, err)
		}
	}
}

// The same options must render byte-identically, or "has anything changed"
// cannot be answered — and reconciliation after a crash depends on answering it.
func TestRenderingIsStable(t *testing.T) {
	t.Parallel()
	first := render(t, opts())
	for range 20 {
		if got := render(t, opts()); got != first {
			t.Fatal("rendering is not deterministic")
		}
	}
}

// The masquerade must be scoped to the served subnet. Masquerading everything
// leaving the uplink would translate traffic that has nothing to do with this
// gateway, including the machine's own.
func TestMasqueradeIsScopedToTheServedSubnet(t *testing.T) {
	t.Parallel()
	s := render(t, opts())
	if !strings.Contains(s, "ip saddr 10.42.0.0/24 oifname @uplink masquerade") {
		t.Errorf("the masquerade is not scoped to the subnet:\n%s", s)
	}
}
