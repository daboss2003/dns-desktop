// Package gateway turns a machine into a network gateway, on whatever platform
// it happens to be.
//
// This is the interface every platform implements and the one place the rest of
// the application is allowed to think about hotspots, NAT and firewalls. Get it
// wrong and platform detail leaks upward forever, which is the failure ADR 0001
// exists to prevent one layer down and which this package has to prevent at its
// own boundary.
//
// # Capabilities are part of the interface, not an implementation detail
//
// The temptation is a [Gateway] with a method per feature and implementations
// that return "not supported". That produces a user interface which discovers
// what it can do by trying and failing, and an application that cannot tell a
// missing feature from a broken one.
//
// So a platform states what it can do first, in [Gateway.Capabilities], and
// every refusal names a capability and gives a reason a person can read. This
// matters because the platforms genuinely differ, and the difference is large:
//
//   - Linux can create a Wi-Fi access point, given an adapter whose driver
//     supports AP mode. It can route, masquerade and redirect DNS.
//   - macOS cannot be driven into hosting an access point by any supported
//     interface. Internet Sharing exists, it is a preference pane, and it is
//     turned on by a person and not by a program. What macOS CAN do is be the
//     resolver for devices pointed at it, and share a connection once a person
//     has switched sharing on. Pretending otherwise would produce a product
//     that claims a hotspot it cannot create — worse than one that explains the
//     constraint and does the part it can.
//   - Windows does neither, today, and says so.
//
// A capability that is absent for a reason the user can fix ("no adapter on
// this machine supports AP mode") reads differently from one absent because the
// platform will never have it, and [Capabilities] distinguishes them.
//
// # The DNS redirect has its own lifetime
//
// Interception — forcing a device's hardcoded 8.8.8.8 to arrive here instead —
// is the point of the product for every device nobody can configure. It is also
// the single most dangerous rule the application installs, because while it is
// in force every DNS query on the network is aimed at one socket. If that
// socket stops listening, every device on the network has no DNS at all, and
// the person experiencing it reads it as "the internet is down".
//
// So it is not part of bring-up. [Session.SetDNSRedirect] turns it on and off
// within a session, it goes on last, it comes off first, and a caller that
// notices its own resolver is unhealthy is expected to pull it. A platform that
// cannot install it reports [CapDNSRedirect] absent rather than failing at the
// end of an otherwise successful bring-up.
//
// # Leaving nothing behind
//
// The worst outcome available to this package is not failing to start. It is
// starting, dying, and leaving a firewall half configured — because the machine
// then has no working network and nothing on it explains why. Every
// implementation must therefore be able to undo a session it did not create,
// which is what [Gateway.Reconcile] is for, and must namespace everything it
// installs so that a scan can find its own work and nobody else's.
package gateway

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"time"
)

// Capability is one thing a platform may be able to do.
//
// A bit set rather than a struct of booleans, because the common operations are
// "does this platform have all of these" and "what is missing", and both are
// one instruction on a bit set and a loop on a struct.
type Capability uint32

// The capabilities a gateway may have.
const (
	// CapAccessPoint creates a Wi-Fi access point that devices can join.
	CapAccessPoint Capability = 1 << iota
	// CapShareUplink routes and masquerades a local subnet out of an uplink,
	// which is what makes the devices behind the gateway able to reach
	// anything.
	CapShareUplink
	// CapDNSRedirect forces DNS from the served subnet to this machine's
	// resolver, whatever the device was configured with. It is what reaches a
	// device nobody can configure, and it is the rule that must be pulled the
	// moment the resolver behind it is unhealthy.
	CapDNSRedirect
	// CapBlockDevice cuts one device off from the network entirely, rather than
	// only refusing its DNS. Without it, "pause the internet for this device"
	// means "answer NXDOMAIN", which a device with a hardcoded address and a
	// DoH client will not notice.
	CapBlockDevice
	// CapIPv6Control governs IPv6 forwarding for the served subnet. Its absence
	// is a filtering hazard rather than a missing feature: a dual-stack client
	// that acquires IPv6 by any route resolves over IPv6 and bypasses every
	// rule here, while the IPv4 statistics look perfectly healthy.
	CapIPv6Control
)

var capNames = []struct {
	c    Capability
	name string
}{
	{CapAccessPoint, "access-point"},
	{CapShareUplink, "share-uplink"},
	{CapDNSRedirect, "dns-redirect"},
	{CapBlockDevice, "block-device"},
	{CapIPv6Control, "ipv6-control"},
}

func (c Capability) String() string {
	var have []string
	for _, n := range capNames {
		if c&n.c != 0 {
			have = append(have, n.name)
		}
	}
	if len(have) == 0 {
		return "none"
	}
	return strings.Join(have, ",")
}

// Split returns the individual capabilities in c.
func (c Capability) Split() []Capability {
	var out []Capability
	for _, n := range capNames {
		if c&n.c != 0 {
			out = append(out, n.c)
		}
	}
	return out
}

// Capabilities is what a platform can do on this machine, and why not.
type Capabilities struct {
	// Have is everything available.
	Have Capability `json:"-"`

	// Reasons explains every capability that is NOT in Have.
	//
	// It is required, not optional. A user interface that greys out "create a
	// hotspot" with no explanation produces a support question that cannot be
	// answered remotely, and the answers differ enormously: no wireless
	// adapter, an adapter whose driver has no AP mode, an adapter already in
	// use by the connection this machine is sharing, a platform that will never
	// support it.
	Reasons map[Capability]string `json:"-"`

	// Fixable lists the absent capabilities a person could do something about,
	// as opposed to those the platform will never have. "Buy a different USB
	// adapter" is advice; "macOS does not permit this" is not.
	Fixable Capability `json:"-"`
}

// Has reports whether every capability in want is available.
func (c Capabilities) Has(want Capability) bool { return c.Have&want == want }

// Missing returns the capabilities in want that are not available.
func (c Capabilities) Missing(want Capability) Capability { return want &^ c.Have }

// Reason explains why a capability is unavailable, or returns "" if it is.
func (c Capabilities) Reason(cap Capability) string {
	if c.Have&cap != 0 {
		return ""
	}
	if r, ok := c.Reasons[cap]; ok && r != "" {
		return r
	}
	return "not available on this platform"
}

// MarshalJSON renders capabilities the way a user interface needs them: a list
// of every capability with its availability and its reason, rather than a bit
// set the front end would have to know the meaning of.
func (c Capabilities) MarshalJSON() ([]byte, error) {
	type item struct {
		Name      string `json:"name"`
		Available bool   `json:"available"`
		Reason    string `json:"reason,omitempty"`
		Fixable   bool   `json:"fixable,omitempty"`
	}
	items := make([]item, 0, len(capNames))
	for _, n := range capNames {
		it := item{Name: n.name, Available: c.Have&n.c != 0}
		if !it.Available {
			it.Reason = c.Reason(n.c)
			it.Fixable = c.Fixable&n.c != 0
		}
		items = append(items, it)
	}
	return marshalJSON(items)
}

// InterfaceKind says what a network interface is, as far as this package cares.
type InterfaceKind uint8

// Interface kinds.
const (
	// KindOther is anything not usefully classified: a bridge, a tunnel, a
	// virtual machine's tap device.
	KindOther InterfaceKind = iota
	// KindWireless is a Wi-Fi interface, which may or may not be able to host
	// an access point.
	KindWireless
	// KindWired is Ethernet or anything that behaves like it.
	KindWired
	// KindLoopback is the loopback interface, listed so that a caller choosing
	// an uplink can see and reject it rather than wondering why it is absent.
	KindLoopback
)

func (k InterfaceKind) String() string {
	switch k {
	case KindWireless:
		return "wireless"
	case KindWired:
		return "wired"
	case KindLoopback:
		return "loopback"
	default:
		return "other"
	}
}

// Interface is a network interface a gateway could use.
type Interface struct {
	Name string        `json:"name"`
	Kind InterfaceKind `json:"-"`
	// Up reports whether the interface is administratively and operationally
	// up. A down interface is listed rather than hidden, because "my Wi-Fi
	// adapter is not in the list" is a worse experience than seeing it greyed.
	Up bool `json:"up"`
	// Addrs are the addresses currently configured on it.
	Addrs []netip.Prefix `json:"addrs,omitempty"`
	// HasDefaultRoute reports that traffic to the internet currently leaves
	// through this interface, which is how the uplink is chosen when nobody
	// chose one.
	HasDefaultRoute bool `json:"has_default_route"`
	// SupportsAP reports that this interface can host an access point. It is
	// meaningful only for [KindWireless] and is false everywhere else.
	SupportsAP bool `json:"supports_ap"`
	// APReason explains a false SupportsAP on a wireless interface — driver
	// without AP mode, adapter busy carrying the uplink, radio soft-blocked.
	APReason string `json:"ap_reason,omitempty"`
}

// Security is how a hotspot is protected.
type Security uint8

// Hotspot security modes.
const (
	// SecurityWPA2 is WPA2-PSK, and is the default.
	//
	// Not WPA2/WPA3 transitional, which looks like the more secure choice and
	// is the wrong default here: transitional mode advertises management frame
	// protection in the RSN element, and a well-known population of devices —
	// older Android phones, printers, smart televisions — will not associate
	// with an access point that does. Those are precisely the devices somebody
	// installs this product to filter, and a device that cannot join the
	// filtered network is not filtered at all.
	SecurityWPA2 Security = iota
	// SecurityWPA2WPA3 is transitional mode, for a network whose devices are
	// all recent.
	SecurityWPA2WPA3
	// SecurityWPA3 is WPA3-SAE only.
	SecurityWPA3
	// SecurityOpen is no protection at all. It is available because a captive
	// guest network is a real thing somebody may want, and it is never the
	// default: an open access point that also intercepts DNS is a worse
	// proposition than either on its own.
	SecurityOpen
)

func (s Security) String() string {
	switch s {
	case SecurityWPA2WPA3:
		return "wpa2/wpa3"
	case SecurityWPA3:
		return "wpa3"
	case SecurityOpen:
		return "open"
	default:
		return "wpa2"
	}
}

// Band is the radio band a hotspot uses.
type Band uint8

// Radio bands.
const (
	// BandAuto lets the platform choose, which is almost always right: the
	// choice is constrained by the regulatory domain, by what the adapter
	// supports, and — when the same adapter is carrying the uplink — by the
	// channel that uplink is already on.
	BandAuto Band = iota
	// Band2GHz is 2.4 GHz: slower, further, and understood by every device
	// ever made. It is what an old printer will join.
	Band2GHz
	// Band5GHz is 5 GHz.
	Band5GHz
)

func (b Band) String() string {
	switch b {
	case Band2GHz:
		return "2.4GHz"
	case Band5GHz:
		return "5GHz"
	default:
		return "auto"
	}
}

// HotspotConfig describes an access point to create.
type HotspotConfig struct {
	// Interface is the wireless interface to use. Empty selects one that
	// reports SupportsAP.
	Interface string `json:"interface,omitempty"`
	// SSID is the network name devices will see.
	SSID string `json:"ssid"`
	// Passphrase is the pre-shared key, 8 to 63 characters, ignored when
	// Security is [SecurityOpen].
	Passphrase string   `json:"passphrase,omitempty"`
	Security   Security `json:"-"`
	Band       Band     `json:"-"`
	// Hidden suppresses the SSID in beacons. It is offered because people ask
	// for it and is not security: the name is still in every association, and
	// hiding it makes client devices probe for the network wherever they go.
	Hidden bool `json:"hidden,omitempty"`
	// MaxClients bounds associations. Zero means the driver's own limit.
	MaxClients int `json:"max_clients,omitempty"`
}

// IPv6Mode says what to do about IPv6 on the served subnet.
type IPv6Mode uint8

// IPv6 modes.
const (
	// IPv6Block refuses IPv6 forwarding from the served subnet, and is the
	// default.
	//
	// "We did not configure IPv6" is not the same as "IPv6 does not happen". A
	// dual-stack client that acquires an IPv6 route by any means resolves over
	// IPv6 and bypasses every rule this product installs — on a gateway whose
	// entire purpose is filtering — while the IPv4 statistics look perfectly
	// healthy. Failing closed makes that a visible loss of connectivity instead
	// of an invisible loss of filtering.
	IPv6Block IPv6Mode = iota
	// IPv6Allow forwards IPv6 without filtering it, for an operator who has
	// read the above and wants IPv6 anyway.
	IPv6Allow
)

func (m IPv6Mode) String() string {
	if m == IPv6Allow {
		return "allow"
	}
	return "block"
}

// Config is one gateway session.
type Config struct {
	// Hotspot describes an access point to create. Nil means do not create one,
	// which is the configuration for a machine that is the gateway for devices
	// already on its network — the only configuration macOS supports, and a
	// perfectly ordinary one on Linux too.
	Hotspot *HotspotConfig `json:"hotspot,omitempty"`

	// Uplink is the interface traffic leaves through. Empty selects the one
	// currently carrying the default route.
	Uplink string `json:"uplink,omitempty"`

	// Subnet is the network served to devices behind the gateway, and Addr is
	// this machine's address within it. Addr must be inside Subnet, and is what
	// devices are told is their router and their DNS server.
	Subnet netip.Prefix `json:"subnet"`
	Addr   netip.Addr   `json:"addr"`

	// DNSPort is where this machine's resolver is listening. It is a field
	// rather than a constant because a resolver that has not been given
	// privileges listens on 5353, and the redirect has to send traffic to
	// wherever it actually is.
	DNSPort int `json:"dns_port"`

	// IPv6 says what to do about IPv6. See [IPv6Block].
	IPv6 IPv6Mode `json:"-"`
}

// Validate reports every problem with the configuration rather than the first,
// because a person fixing a form one error per attempt is a bad experience.
func (c Config) Validate() error {
	var errs []error
	if !c.Subnet.IsValid() {
		errs = append(errs, errors.New("gateway: subnet is required"))
	} else if !c.Subnet.Addr().Is4() {
		errs = append(errs, fmt.Errorf("gateway: subnet %v is not IPv4; the served subnet is IPv4 only", c.Subnet))
	}
	if !c.Addr.IsValid() {
		errs = append(errs, errors.New("gateway: the gateway's own address is required"))
	} else if c.Subnet.IsValid() && !c.Subnet.Contains(c.Addr) {
		errs = append(errs, fmt.Errorf(
			"gateway: address %v is outside subnet %v; devices would be told to route through an address they cannot reach",
			c.Addr, c.Subnet))
	}
	if c.DNSPort <= 0 || c.DNSPort > 65535 {
		errs = append(errs, fmt.Errorf("gateway: dns port %d is not a port", c.DNSPort))
	}
	if h := c.Hotspot; h != nil {
		errs = append(errs, h.validate()...)
	}
	return errors.Join(errs...)
}

func (h *HotspotConfig) validate() []error {
	var errs []error
	switch {
	case h.SSID == "":
		errs = append(errs, errors.New("gateway: the hotspot needs a name"))
	case len(h.SSID) > 32:
		errs = append(errs, fmt.Errorf("gateway: ssid is %d octets, and the maximum is 32", len(h.SSID)))
	}
	// Control characters are refused here as well as escaped at the point of
	// use. A configuration file for an access-point daemon is key=value with no
	// quoting, so a newline in a name supplied through a browser injects
	// directives — and "MyWiFi\nwpa=0" is an open network that looks protected
	// in every screen that shows it. Two mechanisms, because one of them
	// failing silently produces an unprotected network.
	if i := strings.IndexFunc(h.SSID, isControl); i >= 0 {
		errs = append(errs, fmt.Errorf("gateway: ssid contains a control character at offset %d", i))
	}
	if h.Security != SecurityOpen {
		switch n := len(h.Passphrase); {
		case n < 8:
			errs = append(errs, errors.New("gateway: the passphrase must be at least 8 characters"))
		case n > 63:
			errs = append(errs, errors.New("gateway: the passphrase must be at most 63 characters"))
		}
		if i := strings.IndexFunc(h.Passphrase, isControl); i >= 0 {
			errs = append(errs, fmt.Errorf("gateway: passphrase contains a control character at offset %d", i))
		}
	}
	if h.MaxClients < 0 {
		errs = append(errs, errors.New("gateway: max clients must not be negative"))
	}
	return errs
}

func isControl(r rune) bool { return r < 0x20 || r == 0x7f }

// Required reports the capabilities this configuration needs.
//
// A caller checks it against [Capabilities] before starting, so that a
// configuration a platform cannot satisfy is refused in one place with one
// explanation rather than partway through bring-up with whatever error the
// fifth step happened to produce.
func (c Config) Required() Capability {
	need := CapShareUplink
	if c.Hotspot != nil {
		need |= CapAccessPoint
	}
	if c.IPv6 == IPv6Block {
		need |= CapIPv6Control
	}
	return need
}

// State is where a session is.
type State uint8

// Session states.
const (
	// StateStopped is not running.
	StateStopped State = iota
	// StateStarting is partway through bring-up.
	StateStarting
	// StateRunning is up and serving.
	StateRunning
	// StateDegraded is up but with something missing — most often the DNS
	// redirect, withdrawn because the resolver behind it stopped answering. It
	// is a distinct state because it is the one an operator must be told
	// about: the network works and the filtering does not.
	StateDegraded
	// StateFailed is down after an error.
	StateFailed
)

func (s State) String() string {
	switch s {
	case StateStarting:
		return "starting"
	case StateRunning:
		return "running"
	case StateDegraded:
		return "degraded"
	case StateFailed:
		return "failed"
	default:
		return "stopped"
	}
}

// Status is what a session is currently doing.
type Status struct {
	State State `json:"-"`
	// Since is when the session entered this state.
	Since time.Time `json:"since"`
	// Uplink is the interface traffic is leaving through, which may have
	// changed since the session started.
	Uplink string `json:"uplink,omitempty"`
	// Hotspot is the access point's name when one is running.
	Hotspot string `json:"hotspot,omitempty"`
	// Clients is how many devices are associated with the access point, and is
	// -1 when the platform cannot tell.
	Clients int `json:"clients"`
	// DNSRedirect reports whether interception is currently in force. It is
	// separate from State because it changes within a session and is the single
	// most consequential thing in this struct.
	DNSRedirect bool `json:"dns_redirect"`
	// Detail explains a degraded or failed state in a sentence a person can
	// read.
	Detail string `json:"detail,omitempty"`
}

// Session is a running gateway.
//
// Closing it undoes everything it did. A session that cannot fully undo itself
// reports what it could not, because a half-configured firewall that nobody is
// told about is the worst outcome this package has.
type Session interface {
	// Status reports what the session is doing now.
	Status(ctx context.Context) (Status, error)

	// SetDNSRedirect turns interception on or off.
	//
	// It is separate from bring-up because its lifetime is: it goes on last,
	// comes off first, and a caller whose resolver has stopped answering is
	// expected to pull it immediately. While it is in force every DNS query on
	// the network is aimed at one socket, and a socket that is not listening
	// behind it means no device on the network has DNS at all.
	SetDNSRedirect(ctx context.Context, on bool) error

	// Block cuts one address off from the network, or restores it.
	//
	// Refusing a device's DNS is not the same as disconnecting it: a device
	// with a hardcoded resolver address, or one speaking DNS over HTTPS to an
	// address it already knows, does not notice a NXDOMAIN. Requires
	// [CapBlockDevice].
	Block(ctx context.Context, addr netip.Addr, blocked bool) error

	// Close stops the session and removes everything it installed.
	Close() error
}

// Report says what a [Gateway.Reconcile] found and did.
type Report struct {
	// Found describes leftovers from a previous run, in terms a person can
	// read: "3 firewall rules in table gatewaydns", "ip forwarding left on".
	Found []string `json:"found,omitempty"`
	// Removed is what was successfully undone.
	Removed []string `json:"removed,omitempty"`
	// Failed is what could not be, and is the important half: something left
	// behind that this package cannot remove needs a person, and needs to say
	// exactly what to remove by hand.
	Failed []string `json:"failed,omitempty"`
}

// Clean reports whether nothing was left behind.
func (r Report) Clean() bool { return len(r.Found) == 0 }

// Gateway is a platform's implementation of everything above.
type Gateway interface {
	// Platform names the implementation, for logs and for support questions.
	Platform() string

	// Capabilities reports what this platform can do on this machine. It is
	// consulted before anything is attempted, and its Reasons are shown to a
	// person, so it must be cheap enough to call whenever a screen is drawn.
	Capabilities(ctx context.Context) (Capabilities, error)

	// Interfaces lists what could carry a hotspot or an uplink.
	Interfaces(ctx context.Context) ([]Interface, error)

	// Start brings the gateway up.
	//
	// It must either succeed completely or leave the machine as it found it.
	// There is no useful partial success here: a machine with forwarding
	// enabled and no masquerade rule is a machine whose network is broken in a
	// way nothing on it explains.
	Start(ctx context.Context, cfg Config) (Session, error)

	// Reconcile removes anything a previous run left behind, and reports it.
	//
	// It is called at start-up, before anything else. A process that is killed
	// cannot run its own cleanup, so the next one has to — and a machine whose
	// firewall still carries half a session from an hour ago is a machine whose
	// owner cannot get online and has nothing to read about why.
	Reconcile(ctx context.Context) (Report, error)
}

// ErrUnsupported reports that a platform cannot do something.
//
// It is a distinct error because the caller's response differs entirely: an
// unsupported capability is a permanent fact to be shown in the interface,
// while a failure is something to retry or report.
var ErrUnsupported = errors.New("gateway: not supported")

// UnsupportedError names the capability that is missing and why.
type UnsupportedError struct {
	Capability Capability
	Platform   string
	Reason     string
}

func (e *UnsupportedError) Error() string {
	r := e.Reason
	if r == "" {
		r = "this platform does not provide it"
	}
	return fmt.Sprintf("gateway: %s cannot %s: %s", e.Platform, e.Capability, r)
}

// Unwrap implements the errors.Is contract for [ErrUnsupported].
func (e *UnsupportedError) Unwrap() error { return ErrUnsupported }

// Unsupportedf builds an [UnsupportedError].
func Unsupportedf(platform string, cap Capability, format string, args ...any) error {
	return &UnsupportedError{Capability: cap, Platform: platform, Reason: fmt.Sprintf(format, args...)}
}

// CheckCapabilities reports whether a configuration can be satisfied, naming
// every capability that is missing and why.
//
// One place, one explanation. The alternative is discovering the problem
// partway through bring-up and reporting whatever the failing step happened to
// say, which for a missing AP mode is an error about a netlink attribute.
func CheckCapabilities(platform string, have Capabilities, cfg Config) error {
	missing := have.Missing(cfg.Required())
	if missing == 0 {
		return nil
	}
	var errs []error
	for _, c := range missing.Split() {
		errs = append(errs, Unsupportedf(platform, c, "%s", have.Reason(c)))
	}
	return errors.Join(errs...)
}

// SelectUplink picks the interface traffic should leave through.
//
// Preferred when it is named and usable; otherwise the one carrying the default
// route. It refuses rather than guesses when there is no default route: a
// gateway with no uplink is a gateway that hands out addresses and connects
// devices to nothing, which looks to a user exactly like the product being
// broken.
func SelectUplink(ifaces []Interface, preferred string) (Interface, error) {
	if preferred != "" {
		i := slices.IndexFunc(ifaces, func(x Interface) bool { return x.Name == preferred })
		if i < 0 {
			return Interface{}, fmt.Errorf("gateway: no interface named %q", preferred)
		}
		if !ifaces[i].Up {
			return Interface{}, fmt.Errorf("gateway: interface %q is down", preferred)
		}
		return ifaces[i], nil
	}
	for _, x := range ifaces {
		if x.HasDefaultRoute && x.Up && x.Kind != KindLoopback {
			return x, nil
		}
	}
	return Interface{}, errors.New(
		"gateway: no interface carries the default route, so there is nothing to share; " +
			"connect this machine to a network first, or name an uplink explicitly")
}

// SelectAPInterface picks the wireless interface to host an access point.
//
// It skips the uplink: an adapter carrying the connection being shared can host
// an access point only if its driver permits that combination, and assuming it
// does produces a hotspot that comes up and drops the machine's own connection.
// Where the driver does permit it, the caller names the interface explicitly.
func SelectAPInterface(ifaces []Interface, preferred, uplink string) (Interface, error) {
	if preferred != "" {
		i := slices.IndexFunc(ifaces, func(x Interface) bool { return x.Name == preferred })
		if i < 0 {
			return Interface{}, fmt.Errorf("gateway: no interface named %q", preferred)
		}
		if !ifaces[i].SupportsAP {
			reason := ifaces[i].APReason
			if reason == "" {
				reason = "its driver does not report access-point mode"
			}
			return Interface{}, fmt.Errorf("gateway: %q cannot host an access point: %s", preferred, reason)
		}
		return ifaces[i], nil
	}
	for _, x := range ifaces {
		if x.SupportsAP && x.Name != uplink {
			return x, nil
		}
	}
	// The message names the specific reason where there is exactly one
	// candidate, because "no adapter supports AP mode" and "your only adapter
	// is busy carrying the connection you are sharing" call for different
	// actions and the second is far more common on a laptop.
	for _, x := range ifaces {
		if x.Kind == KindWireless && x.Name == uplink && x.SupportsAP {
			return Interface{}, fmt.Errorf(
				"gateway: the only adapter that can host an access point, %q, is carrying the "+
					"connection being shared; share a wired connection instead, or add a USB adapter", x.Name)
		}
	}
	return Interface{}, errors.New(
		"gateway: no wireless adapter on this machine reports access-point mode")
}
