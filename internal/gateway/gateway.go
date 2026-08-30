// Package gateway turns a machine into a network gateway, on whatever platform
// it happens to be.
//
// This is the interface every platform implements and the one place the rest of
// the application is allowed to think about hotspots, NAT and firewalls. Get it
// wrong and platform detail leaks upward forever, which is the failure ADR 0001
// exists to prevent one layer down and which this package has to prevent at its
// own boundary.
//
// # There are three ways to be a gateway, not one
//
// The obvious model — this application runs the access point, hands out the
// leases and writes the firewall rules — is a Linux model. Designing only for
// it makes every other platform look like a failed Linux, which is both wrong
// and the reason an earlier draft of this package reported Windows as capable
// of nothing at all.
//
// Windows and macOS both ship the whole apparatus as one unit: Mobile Hotspot
// and Internet Connection Sharing on one, Internet Sharing on the other. Each
// creates the access point, runs a DHCP server, and masquerades — and hands
// connecting devices THIS MACHINE as their resolver. A product whose value is
// filtering is therefore fully delivered by that arrangement, without owning
// any of the plumbing. See [SharingModel].
//
// So the models are:
//
//   - [SharingNone]. This machine resolves for devices pointed at it by a
//     router, by a person, or by anything else. It needs no capability at all
//     and works on every platform, and for a household whose router can be told
//     to hand out one DNS server it is the whole product.
//   - [SharingPlatform]. The operating system runs the access point, the DHCP
//     server and the NAT; this application turns it on and supplies the DNS.
//     Windows and macOS.
//   - [SharingManaged]. This application runs all of it. Linux, and the only
//     model that yields the full device identity a lease exchange carries.
//
// # Capabilities are part of the interface, not an implementation detail
//
// The temptation is a [Gateway] with a method per feature and implementations
// that return "not supported". That produces a user interface which discovers
// what it can do by trying and failing, and an application that cannot tell a
// missing feature from a broken one.
//
// So a platform states what it can do first, in [Gateway.Capabilities], and
// every refusal names a capability and gives a reason a person can read. A
// capability absent for a reason the user can fix ("no adapter on this machine
// supports AP mode") reads differently from one absent because the platform
// will never have it, and [Capabilities] distinguishes them.
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
	// CapDNSRedirect rewrites DNS from the served subnet to this machine's
	// resolver, whatever the device was configured with. The device believes it
	// is talking to 8.8.8.8 and gets a filtered answer, so nothing breaks.
	//
	// It is what reaches a device nobody can configure, and it is the rule that
	// must be pulled the moment the resolver behind it is unhealthy.
	CapDNSRedirect
	// CapDNSEnforce blocks DNS from the served subnet to anywhere but this
	// machine, without rewriting it.
	//
	// It is the harsher half of the same intent and exists separately because
	// one platform has only this one. Windows has no user-mode destination
	// rewrite at all — the whole FWP action set is block, permit and three
	// callout forms, redirection is a side effect only a kernel driver can
	// produce, and the redirect layers never see forwarded traffic anyway. What
	// Windows CAN do, from user mode and with no driver, is refuse the packet.
	//
	// The difference is visible to a user and must never be a silent default. A
	// device with a hardcoded resolver meets a redirect and is filtered; it
	// meets enforcement and either falls back to the resolver it was given —
	// which is the good case, and the common one — or simply stops resolving.
	// The second is a device that appears broken, so switching this on is a
	// decision an operator takes deliberately.
	//
	// Neither capability touches DNS over HTTPS to a hardcoded address. That is
	// worth saying plainly rather than implying: a perfect redirect on Linux
	// does not solve it either.
	CapDNSEnforce
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
	// CapOwnDHCP runs this application's own DHCP server on the served subnet,
	// rather than whatever the platform's sharing brings with it.
	//
	// It is what separates [SharingManaged] from [SharingPlatform], and what it
	// buys is identity: a lease exchange is the one moment a device states its
	// hardware address, its hostname and its vendor class together, and without
	// it the device table has only the addresses it sees querying. That is a
	// poorer device list, not a broken product — see [CapClientList] for what
	// fills the gap.
	CapOwnDHCP
	// CapClientList asks the platform which devices are currently connected.
	//
	// It matters most where [CapOwnDHCP] is absent: Windows will name the
	// stations attached to its hotspot even though it, and not this
	// application, gave them their addresses.
	CapClientList
)

var capNames = []struct {
	c    Capability
	name string
}{
	{CapAccessPoint, "access-point"},
	{CapShareUplink, "share-uplink"},
	{CapDNSRedirect, "dns-redirect"},
	{CapDNSEnforce, "dns-enforce"},
	{CapBlockDevice, "block-device"},
	{CapIPv6Control, "ipv6-control"},
	{CapOwnDHCP, "own-dhcp"},
	{CapClientList, "client-list"},
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

	// Sharing is every model this machine can offer, weakest first.
	//
	// It always contains at least [SharingNone], which needs nothing. A user
	// interface asks a person to choose from this rather than presenting one
	// arrangement and an apology.
	Sharing []SharingModel `json:"-"`
}

// Supports reports whether a sharing model is available.
func (c Capabilities) Supports(m SharingModel) bool { return slices.Contains(c.Sharing, m) }

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
	sharing := make([]string, 0, len(c.Sharing))
	for _, m := range c.Sharing {
		sharing = append(sharing, m.String())
	}
	return marshalJSON(struct {
		Capabilities []item   `json:"capabilities"`
		Sharing      []string `json:"sharing"`
	}{items, sharing})
}

// SharingModel says who runs the access point, the DHCP server and the NAT.
//
// It exists because the answer differs by platform in a way that changes what
// this application does rather than only how well it does it, and because a
// person choosing a mode is choosing between real alternatives on a machine
// that may offer more than one.
type SharingModel uint8

// The sharing models.
const (
	// SharingNone shares nothing. This machine resolves for devices that were
	// pointed at it by a router, by a person, or by a platform's own sharing
	// that somebody switched on themselves.
	//
	// It requires no capability and works everywhere, and it is not a fallback:
	// for a household whose router can be told to hand out one DNS server, it is
	// the whole product, with no firewall rules and nothing to clean up.
	SharingNone SharingModel = iota

	// SharingPlatform turns on the operating system's own sharing and supplies
	// the DNS.
	//
	// Windows Mobile Hotspot and Internet Connection Sharing, and macOS
	// Internet Sharing, each create the access point, run a DHCP server and
	// masquerade — and hand connecting devices this machine as their resolver.
	// So filtering is delivered in full without owning any of the plumbing.
	//
	// What is given up is identity. The platform's DHCP server takes the lease
	// exchange, so devices are known by what they query and by whatever the
	// platform will say about its own clients ([CapClientList]) rather than by
	// what they said about themselves.
	SharingPlatform

	// SharingManaged runs the access point, the DHCP server and the firewall
	// rules from this application.
	//
	// It is the most capable model and the most dangerous: everything it
	// installs it must be able to remove, including after being killed. It is
	// also the only model that yields a full device identity, and the only one
	// that can intercept the DNS of a device configured to ask somebody else.
	SharingManaged
)

func (m SharingModel) String() string {
	switch m {
	case SharingPlatform:
		return "platform"
	case SharingManaged:
		return "managed"
	default:
		return "none"
	}
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
	// Sharing says who runs the access point, the DHCP server and the NAT. The
	// zero value, [SharingNone], shares nothing and needs nothing.
	Sharing SharingModel `json:"-"`

	// Hotspot describes an access point to create. Nil means do not create one,
	// which is the configuration for a machine that is the gateway for devices
	// already on its network — and a perfectly ordinary one on every platform.
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

	// The served subnet is required only where this application assigns the
	// addresses. Under platform sharing the operating system picks the subnet —
	// Windows uses 192.168.137.0/24 and will not be argued with — so demanding
	// one here would refuse a configuration that works and invite an operator
	// to write a number that is then ignored.
	switch {
	case c.Sharing == SharingManaged && !c.Subnet.IsValid():
		errs = append(errs, errors.New("gateway: managed sharing needs a subnet to serve"))
	case c.Subnet.IsValid() && !c.Subnet.Addr().Is4():
		errs = append(errs, fmt.Errorf("gateway: subnet %v is not IPv4; the served subnet is IPv4 only", c.Subnet))
	}
	switch {
	case c.Sharing == SharingManaged && !c.Addr.IsValid():
		errs = append(errs, errors.New("gateway: managed sharing needs this machine's address on the served subnet"))
	case c.Addr.IsValid() && c.Subnet.IsValid() && !c.Subnet.Contains(c.Addr):
		errs = append(errs, fmt.Errorf(
			"gateway: address %v is outside subnet %v; devices would be told to route through an address they cannot reach",
			c.Addr, c.Subnet))
	}
	// The resolver's port is always needed: every model has to tell devices, or
	// the platform, where the DNS server actually is.
	if c.DNSPort <= 0 || c.DNSPort > 65535 {
		errs = append(errs, fmt.Errorf("gateway: dns port %d is not a port", c.DNSPort))
	}
	if h := c.Hotspot; h != nil {
		errs = append(errs, h.validate()...)
		if c.Sharing == SharingNone {
			errs = append(errs, errors.New(
				"gateway: a hotspot was configured but sharing is off; "+
					"choose the platform or managed sharing model, or remove the hotspot"))
		}
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
	var need Capability
	switch c.Sharing {
	case SharingNone:
		// Nothing at all. This machine resolves for whoever asks it, which
		// every platform can do and which needs no rule anywhere.
		return 0
	case SharingPlatform:
		// The operating system does the routing and the addressing, so the
		// only thing being asked for is the access point it manages.
		need = CapAccessPoint
	case SharingManaged:
		need = CapShareUplink | CapOwnDHCP
		if c.Hotspot != nil {
			need |= CapAccessPoint
		}
		// Only the managed model can be asked to fail IPv6 closed, because
		// only it owns the firewall. Under platform sharing the operating
		// system decides, and demanding the capability would refuse a
		// configuration that works.
		if c.IPv6 == IPv6Block {
			need |= CapIPv6Control
		}
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
	// DNSCapture reports whether interception is in force, and by which
	// mechanism: zero for none, [CapDNSRedirect] for a rewrite, or
	// [CapDNSEnforce] for a block. It is separate from State because it changes
	// within a session and is the single most consequential thing here — and it
	// names the mechanism because the two are not equivalent to the person
	// whose device stops working.
	DNSCapture Capability `json:"-"`
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

	// SetDNSCapture turns interception on or off, by whichever of
	// [CapDNSRedirect] and [CapDNSEnforce] the platform has — rewriting where
	// it can, refusing where it cannot.
	//
	// It is separate from bring-up because its lifetime is: it goes on last,
	// comes off first, and a caller whose resolver has stopped answering is
	// expected to pull it immediately. While it is in force every DNS query on
	// the network is aimed at one socket, and a socket that is not listening
	// behind it means no device on the network has DNS at all.
	//
	// [Status.DNSCapture] says which mechanism is actually in force, because
	// the two are not equivalent to the person whose device stops working.
	SetDNSCapture(ctx context.Context, on bool) error

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
	// The message names the specific reason wherever there is one, because
	// these call for different actions: "your only adapter is carrying the
	// connection you are sharing" means share a wired connection, "your
	// driver has no access-point mode" means buy a different adapter, and
	// "no wireless adapter" means something else entirely. Collapsing all
	// three into the last is how somebody with a working radio concludes they
	// have no Wi-Fi.
	for _, x := range ifaces {
		if x.Kind == KindWireless && x.Name == uplink && x.SupportsAP {
			return Interface{}, fmt.Errorf(
				"gateway: the only adapter that can host an access point, %q, is carrying the "+
					"connection being shared; share a wired connection instead, or add a USB adapter", x.Name)
		}
	}
	var reasons []string
	for _, x := range ifaces {
		if x.Kind != KindWireless {
			continue
		}
		why := x.APReason
		if why == "" {
			why = "its driver does not report access-point mode"
		}
		reasons = append(reasons, fmt.Sprintf("%s: %s", x.Name, why))
	}
	if len(reasons) > 0 {
		return Interface{}, fmt.Errorf(
			"gateway: no wireless adapter on this machine can host an access point (%s)",
			strings.Join(reasons, "; "))
	}
	return Interface{}, errors.New(
		"gateway: this machine has no wireless adapter, so it cannot host an access point")
}
