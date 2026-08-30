//go:build windows

package gateway

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

// The probes, wired to the real implementations on this platform. They are
// variables so that the untagged session file can name them without a build
// tag of its own.
func init() {
	windowsDefaultRouteFn = windowsDefaultRouteImpl
	windowsWirelessFn = windowsWirelessImpl
}

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
//   - Block one device from the network, and refuse DNS to every resolver but
//     ours, through user-mode filters in the Windows Filtering Platform.
//
// Note which mechanism does the blocking, because the obvious one does not
// work: a Windows Firewall rule naming a remote address does NOT stop a device
// reaching the internet through a connection this machine is sharing. The
// firewall authors its filters at the layers that see sockets on this machine,
// and forwarded traffic never passes through them — bypassing firewall rules
// this way has been intended behaviour since Windows 10. Blocking a device has
// to happen at the forwarding layer, or it is a feature that looks right in the
// interface and does nothing.
//
// What it cannot do is REWRITE a DNS packet's destination. There is no
// user-mode destination rewrite on Windows: the whole filtering action set is
// block, permit and three callout forms, redirection is a side effect only a
// signed kernel driver can produce, and the layers that could do it never see
// forwarded traffic. So Windows captures DNS by refusing the alternatives —
// [CapDNSEnforce] rather than [CapDNSRedirect] — which reaches the same policy
// outcome by a route a person can notice. See ADR 0004.
func New() Gateway {
	return &windowsGateway{
		run:      psRunner{},
		journal:  journal{dir: windowsRunDir()},
		elevated: isElevated,
	}
}

// windowsRunDir is where the recovery journal lives.
//
// Under ProgramData rather than a temporary directory, because unlike Linux's
// /run it must survive nothing in particular — Windows has no memory file
// system a service can rely on — and because the alternative, a per-user
// directory, would hide a session started by an administrator from the
// administrator who comes to clean up after it.
func windowsRunDir() string {
	base := os.Getenv("ProgramData")
	if base == "" {
		base = os.TempDir()
	}
	return filepath.Join(base, "GatewayDNS", "run")
}

// psRunner runs PowerShell, which is how this platform's networking is driven.
type psRunner struct{}

func (psRunner) Run(ctx context.Context, name, stdin string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		if msg := strings.TrimSpace(string(out)); msg != "" {
			return string(out), errors.New(msg)
		}
	}
	return string(out), err
}

func (psRunner) Look(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

// isElevated reports whether this process is running with administrator rights.
//
// Through the token's elevation flag rather than by checking group membership:
// a member of the Administrators group running unelevated has the group in its
// token but marked deny-only, so a membership check answers yes for a process
// that cannot in fact write a firewall rule. That distinction is the whole of
// User Account Control, and getting it backwards produces a capability report
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
func windowsDefaultRouteImpl() (string, error) {
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
func windowsWirelessImpl(name string) (bool, apSupport) {
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
