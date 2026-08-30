//go:build windows

package gateway

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

// New returns the gateway for this platform.
//
// Windows is a first-class platform here, which is worth saying because an
// earlier draft of this package reported it as capable of nothing at all. That
// was a modelling error rather than a fact about Windows: the package assumed
// the Linux arrangement — this application runs the access point, the DHCP
// server and the firewall — and Windows does not work that way, so it looked
// like a failed Linux.
//
// What Windows can actually do:
//
//   - Create an access point, through the Mobile Hotspot that ships with it.
//   - Share a connection, through that hotspot or through Windows NAT.
//   - Block one device from the network, through the Windows firewall.
//   - Refuse DNS to every resolver but ours, through user-mode filters.
//
// What it cannot do is REWRITE a DNS packet's destination. There is no
// user-mode destination rewrite on Windows: the whole filtering action set is
// block, permit and three callout forms, redirection is a side effect only a
// signed kernel driver can produce, and the layers that could do it never see
// forwarded traffic. So Windows captures DNS by refusing the alternatives —
// [CapDNSEnforce] rather than [CapDNSRedirect] — which reaches the same policy
// outcome by a route a person can notice. See ADR 0004.
func New() Gateway { return &windowsGateway{} }

type windowsGateway struct{}

var _ Gateway = (*windowsGateway)(nil)

// Platform implements [Gateway].
func (g *windowsGateway) Platform() string { return "windows" }

const noRewriteOnWindows = "Windows has no user-mode way to rewrite a packet's destination, so DNS " +
	"cannot be silently redirected here; this machine can instead refuse every other resolver, " +
	"which is the dns-enforce capability"

// Capabilities implements [Gateway].
func (g *windowsGateway) Capabilities(ctx context.Context) (Capabilities, error) {
	c := Capabilities{
		Reasons: map[Capability]string{},
		Sharing: []SharingModel{SharingNone},
	}

	// Never available, and not fixable by anything a person could install.
	c.Reasons[CapDNSRedirect] = noRewriteOnWindows

	// Everything below needs administrator rights. Reporting a capability the
	// process cannot exercise would produce a control that fails when pressed,
	// which is exactly what capability reporting exists to prevent.
	if !isElevated() {
		const why = "this needs administrator rights, and GatewayDNS Desktop is not running with them; " +
			"restart it as an administrator"
		for _, cap := range []Capability{
			CapAccessPoint, CapShareUplink, CapDNSEnforce, CapBlockDevice, CapIPv6Control, CapOwnDHCP,
		} {
			c.Reasons[cap] = why
			c.Fixable |= cap
		}
		c.Reasons[CapClientList] = why
		c.Fixable |= CapClientList
		return c, nil
	}

	// The rest is not in this build. Saying so is better than claiming a
	// capability whose Start would fail: a person reads this in the interface
	// and knows to point their router at this machine meanwhile.
	for _, cap := range []Capability{
		CapAccessPoint, CapShareUplink, CapDNSEnforce, CapBlockDevice,
		CapIPv6Control, CapOwnDHCP, CapClientList,
	} {
		c.Reasons[cap] = notInThisBuild
	}
	return c, nil
}

const notInThisBuild = "bringing a gateway up is not in this build; " +
	"point a device at this machine as its DNS server and it is filtered"

// Interfaces implements [Gateway].
func (g *windowsGateway) Interfaces(context.Context) ([]Interface, error) {
	return enumerate(windowsDefaultRoute, windowsWireless)
}

// Start implements [Gateway] by refusing, naming what is missing.
func (g *windowsGateway) Start(ctx context.Context, cfg Config) (Session, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	caps, err := g.Capabilities(ctx)
	if err != nil {
		return nil, err
	}
	return nil, CheckCapabilities(g.Platform(), caps, cfg)
}

// Reconcile implements [Gateway].
func (g *windowsGateway) Reconcile(context.Context) (Report, error) { return Report{}, nil }

// isElevated reports whether this process is running with administrator rights.
//
// Through the token's elevation flag rather than by checking group membership:
// a member of the Administrators group running unelevated has the group in its
// token but marked deny-only, so a membership check answers yes to a process
// that cannot in fact write a firewall rule. The distinction is the whole of
// User Account Control and getting it backwards produces a capability report
// that is wrong on the most common Windows configuration there is.
func isElevated() bool {
	var token windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY, &token); err != nil {
		return false
	}
	defer token.Close()
	return token.IsElevated()
}

// windowsDefaultRoute asks the routing table which interface carries the
// default route.
//
// Through GetBestRoute2 rather than by parsing `route print`, because the
// output of `route print` is localised — on a German Windows the headings are
// German — and a product that stopped detecting the uplink outside English
// locales would fail in a way nobody here would ever see.
func windowsDefaultRoute() (string, error) {
	// 0.0.0.0 stands for "anywhere": the best route to it is the default route.
	dest := windows.RawSockaddrInet4{Family: windows.AF_INET}
	var row mibIPForwardRow2
	var srcAddr windows.RawSockaddrInet6

	ret, _, _ := procGetBestRoute2.Call(
		0, // no interface LUID: let Windows choose
		0, // no interface index
		0, // no source address preference
		uintptr(unsafe.Pointer(&dest)),
		0, // no address sort options
		uintptr(unsafe.Pointer(&row)),
		uintptr(unsafe.Pointer(&srcAddr)),
	)
	if ret != 0 {
		return "", fmt.Errorf("gateway: GetBestRoute2: %w", windows.Errno(ret))
	}

	// The row names the interface by LUID, and everything else in this package
	// speaks the names a person sees.
	// NDIS_IF_MAX_STRING_SIZE, which x/sys does not export.
	const maxIfName = 256
	var name [maxIfName + 1]uint16
	ret, _, _ = procConvertInterfaceLuidToNameW.Call(
		uintptr(unsafe.Pointer(&row.interfaceLUID)),
		uintptr(unsafe.Pointer(&name[0])),
		uintptr(len(name)),
	)
	if ret != 0 {
		return "", fmt.Errorf("gateway: resolving the interface name: %w", windows.Errno(ret))
	}
	return windows.UTF16ToString(name[:]), nil
}

// mibIPForwardRow2 is the prefix of MIB_IPFORWARD_ROW2 that this package reads.
//
// Only the head of the structure is declared, because only the LUID is wanted
// and the caller allocates enough room for the whole thing. The padding is
// generous on purpose: a structure that grows in a future Windows would
// otherwise have GetBestRoute2 write past the end of this one.
type mibIPForwardRow2 struct {
	interfaceLUID  uint64
	interfaceIndex uint32
	_              [512]byte
}

var (
	modiphlpapi                     = windows.NewLazySystemDLL("iphlpapi.dll")
	procGetBestRoute2               = modiphlpapi.NewProc("GetBestRoute2")
	procConvertInterfaceLuidToNameW = modiphlpapi.NewProc("ConvertInterfaceLuidToNameW")
)

// windowsWireless reports whether an interface is Wi-Fi, and whether it can
// host an access point.
//
// `netsh wlan show interfaces` is the only way to enumerate wireless adapters
// without the WLAN API, and its output is localised — so this matches on the
// adapter NAME appearing in the output rather than on any English heading. That
// is a weaker test than parsing the fields, and it is the one that keeps
// working on a Windows whose language is not ours.
func windowsWireless(name string) (bool, apSupport) {
	out, err := exec.Command("netsh", "wlan", "show", "interfaces").Output()
	if err != nil {
		// No WLAN service, or no wireless adapters at all. Not an error: a
		// desktop with only Ethernet is an ordinary machine.
		return false, apSupport{}
	}
	if !strings.Contains(string(out), name) {
		return false, apSupport{}
	}
	return true, apSupport{
		reason: "whether this adapter can host the Windows Mobile Hotspot is not determined in this build",
	}
}
