// Package nftables renders the firewall ruleset that makes a Linux machine a
// gateway.
//
// Like the hostapd package beside it, this builds text and runs nothing, so the
// part where the mistakes live is testable on any machine with no root and no
// kernel to talk to.
//
// # Everything dynamic is set membership, not a rule edit
//
// The ruleset is written once and never rewritten. The three things that change
// while a gateway is running — which interface the traffic leaves through,
// whether DNS is being captured, and which devices are cut off — are all
// membership in a named set, so changing one is a single atomic element
// operation rather than a rule being deleted and another added.
//
// That matters most for the uplink. Rewriting the masquerade rule when somebody
// unplugs the Ethernet and the Wi-Fi takes over leaves a window in which the
// subnet is forwarded but not translated, and every packet in that window is
// dropped upstream as a martian. The user experiences it as "the hotspot broke
// when I moved the cable". Swapping one element in a set has no such window.
//
// # Why the table is namespaced
//
// Everything lives in one table called gatewaydns. Nothing else is touched, and
// a scan for leftovers after a crash has an exact question to ask: does that
// table exist. A gateway that wrote into the system's own table could not tell
// its own rules from anyone else's, and the cost of getting that wrong is a
// machine whose network is broken with nothing on it to explain why.
//
// # Redirect, not DNAT to loopback
//
// The DNS capture is `redirect`, which maps to the incoming interface's own
// address. The obvious alternative — DNAT to 127.0.0.1 where the resolver
// already listens — requires net.ipv4.conf.<if>.route_localnet, and that makes
// all of 127.0.0.0/8 routable from that interface. Every loopback-only service
// on the machine would become reachable from the guest network, which is a
// larger hole than the product is worth.
package nftables

import (
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strings"
)

// Table is where every rule this package writes lives.
const Table = "gatewaydns"

// The named sets whose membership carries all the dynamic state.
const (
	// SetUplink holds exactly one interface: the one traffic leaves through.
	SetUplink = "uplink"
	// SetCapture holds the interfaces whose DNS is being captured. Empty means
	// capture is off, which is how it is switched without touching a rule.
	SetCapture = "capture"
	// SetBlocked holds the addresses cut off from the network.
	SetBlocked = "blocked"
)

// Options describe the gateway a ruleset should implement.
type Options struct {
	// Interface is the one devices are attached to.
	Interface string
	// Uplink is the interface traffic leaves through.
	Uplink string
	// Subnet is the network served to those devices.
	Subnet netip.Prefix
	// DNSPort is where this machine's resolver listens.
	DNSPort int
	// BlockIPv6 refuses to forward IPv6 from the served subnet.
	//
	// It is on by default in the caller, and the reason is that "we did not
	// configure IPv6" is not "IPv6 does not happen": a dual-stack client that
	// picks up a v6 route by any means resolves over v6 and bypasses every
	// rule here, while the v4 counters look perfectly healthy. Failing closed
	// turns a silent loss of filtering into a visible loss of connectivity.
	BlockIPv6 bool
}

// Validate reports every problem with the options.
func (o Options) Validate() error {
	var errs []error
	if err := safeIfname("interface", o.Interface); err != nil {
		errs = append(errs, err)
	}
	if err := safeIfname("uplink", o.Uplink); err != nil {
		errs = append(errs, err)
	}
	if !o.Subnet.IsValid() || !o.Subnet.Addr().Is4() {
		errs = append(errs, fmt.Errorf("nftables: subnet %v is not a valid IPv4 prefix", o.Subnet))
	}
	if o.DNSPort <= 0 || o.DNSPort > 65535 {
		errs = append(errs, fmt.Errorf("nftables: %d is not a port", o.DNSPort))
	}
	return errors.Join(errs...)
}

// ErrUnsafeValue reports a value that could change the ruleset's meaning.
var ErrUnsafeValue = errors.New("nftables: value contains a character that would change the ruleset's meaning")

// safeIfname checks an interface name.
//
// It is spliced into a quoted string in a ruleset that is fed to a parser, so a
// name containing a quote could close it and add rules. Interface names cannot
// contain one — the kernel forbids it — and the check is here anyway, because
// this name may have come from a configuration file somebody edited.
func safeIfname(what, name string) error {
	if name == "" {
		return fmt.Errorf("nftables: an %s is required", what)
	}
	if len(name) > 15 {
		return fmt.Errorf("nftables: %s %q is longer than an interface name can be", what, name)
	}
	for i, r := range name {
		ok := r == '.' || r == '-' || r == '_' ||
			(r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9')
		if !ok {
			return fmt.Errorf("%w: %s %q, at offset %d", ErrUnsafeValue, what, name, i)
		}
	}
	return nil
}

// Ruleset renders the whole table, ready for "nft -f -".
//
// One document and one transaction: nft applies it completely or not at all,
// which is the exact guarantee that prevents the half-configured firewall this
// component's worst outcome is named after. Building it up rule by rule would
// give up that guarantee for nothing.
//
// The table is deleted first. "delete table" on a table that does not exist is
// an error in older nft, so the caller feeds this to a command that tolerates
// it — see the destroy form below.
func (o Options) Ruleset() (string, error) {
	if err := o.Validate(); err != nil {
		return "", err
	}
	var b strings.Builder
	fmt.Fprintf(&b, "table inet %s {\n", Table)

	// Sets first: everything dynamic is membership in one of these.
	fmt.Fprintf(&b, "  set %s {\n    type ifname\n    elements = { \"%s\" }\n  }\n", SetUplink, o.Uplink)
	fmt.Fprintf(&b, "  set %s {\n    type ifname\n  }\n", SetCapture)
	fmt.Fprintf(&b, "  set %s {\n    type ipv4_addr\n    flags interval\n  }\n", SetBlocked)

	// Forwarding. The policy is accept, because this chain is one of several
	// on the machine and a drop policy here would break traffic that has
	// nothing to do with us.
	fmt.Fprintf(&b, "  chain forward {\n")
	fmt.Fprintf(&b, "    type filter hook forward priority filter; policy accept;\n")
	// Blocked devices first and terminal, so a device that is cut off is cut
	// off in both directions rather than only able to receive.
	fmt.Fprintf(&b, "    ip saddr @%s drop\n", SetBlocked)
	fmt.Fprintf(&b, "    ip daddr @%s drop\n", SetBlocked)
	if o.BlockIPv6 {
		// Fail closed. See [Options.BlockIPv6].
		fmt.Fprintf(&b, "    meta nfproto ipv6 iifname \"%s\" drop\n", o.Interface)
		fmt.Fprintf(&b, "    meta nfproto ipv6 oifname \"%s\" drop\n", o.Interface)
	}
	fmt.Fprintf(&b, "  }\n")

	// Source translation, so the subnet can reach anything.
	fmt.Fprintf(&b, "  chain postrouting {\n")
	fmt.Fprintf(&b, "    type nat hook postrouting priority srcnat; policy accept;\n")
	fmt.Fprintf(&b, "    ip saddr %s oifname @%s masquerade\n", o.Subnet, SetUplink)
	fmt.Fprintf(&b, "  }\n")

	// DNS capture, gated on set membership so it can be switched without
	// rewriting a rule. redirect, not DNAT to loopback — see the package
	// documentation.
	fmt.Fprintf(&b, "  chain prerouting {\n")
	fmt.Fprintf(&b, "    type nat hook prerouting priority dstnat; policy accept;\n")
	fmt.Fprintf(&b, "    iifname @%s udp dport 53 redirect to :%d\n", SetCapture, o.DNSPort)
	fmt.Fprintf(&b, "    iifname @%s tcp dport 53 redirect to :%d\n", SetCapture, o.DNSPort)
	fmt.Fprintf(&b, "  }\n")

	fmt.Fprintf(&b, "}\n")
	return b.String(), nil
}

// Destroy renders the teardown.
//
// "destroy" rather than "delete", because destroy succeeds on a table that is
// not there. Teardown runs on paths where the state is unknown — after a crash,
// after a partial start — and a cleanup that fails because there was nothing to
// clean is a cleanup that stops before the next step.
func Destroy() string {
	return fmt.Sprintf("destroy table inet %s\n", Table)
}

// DeleteFallback renders the teardown for an nft too old for "destroy".
//
// It is fed to a command whose failure is ignored, which is safe because the
// only way it fails is the table already being absent.
func DeleteFallback() string {
	return fmt.Sprintf("delete table inet %s\n", Table)
}

// SetUplinkTo renders an atomic swap of the uplink.
//
// Flush and add in one transaction, so there is no instant in which the set is
// empty — an empty uplink set matches nothing, so the masquerade rule would
// stop matching and every packet from the subnet would leave untranslated and
// be dropped upstream as a martian.
func SetUplinkTo(iface string) (string, error) {
	if err := safeIfname("uplink", iface); err != nil {
		return "", err
	}
	return fmt.Sprintf("flush set inet %s %s\nadd element inet %s %s { \"%s\" }\n",
		Table, SetUplink, Table, SetUplink, iface), nil
}

// Capture renders switching DNS capture on or off for an interface.
func Capture(iface string, on bool) (string, error) {
	if err := safeIfname("interface", iface); err != nil {
		return "", err
	}
	verb := "delete"
	if on {
		verb = "add"
	}
	return fmt.Sprintf("%s element inet %s %s { \"%s\" }\n", verb, Table, SetCapture, iface), nil
}

// Block renders cutting one address off from the network, or restoring it.
func Block(addr netip.Addr, blocked bool) (string, error) {
	if !addr.Is4() {
		return "", fmt.Errorf("nftables: %v is not an IPv4 address", addr)
	}
	verb := "delete"
	if blocked {
		verb = "add"
	}
	return fmt.Sprintf("%s element inet %s %s { %s }\n", verb, Table, SetBlocked, addr), nil
}

// BlockAll renders the whole blocked set, for restoring it after a restart.
func BlockAll(addrs []netip.Addr) (string, error) {
	var b strings.Builder
	fmt.Fprintf(&b, "flush set inet %s %s\n", Table, SetBlocked)
	if len(addrs) == 0 {
		return b.String(), nil
	}
	elems := make([]string, 0, len(addrs))
	for _, a := range addrs {
		if !a.Is4() {
			return "", fmt.Errorf("nftables: %v is not an IPv4 address", a)
		}
		elems = append(elems, a.String())
	}
	// Sorted, so the rendered document is the same for the same set and a
	// caller can compare two of them.
	sort.Strings(elems)
	fmt.Fprintf(&b, "add element inet %s %s { %s }\n", Table, SetBlocked, strings.Join(elems, ", "))
	return b.String(), nil
}
