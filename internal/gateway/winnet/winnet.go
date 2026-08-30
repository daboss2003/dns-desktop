// Package winnet builds the commands that make a Windows machine a gateway.
//
// Like the hostapd and nftables packages beside it, this produces text and runs
// nothing, so the part where the mistakes live compiles and is tested on any
// machine — which for Windows work done anywhere else is the only testing there
// is until it reaches a Windows box.
//
// # Two arrangements, and they are not interchangeable
//
// Windows can be a gateway in two ways, and the difference is not a detail of
// implementation. It decides whether per-device policy works at all.
//
// [Tethering] is the Mobile Hotspot. It creates the Wi-Fi, so devices join
// this machine directly — and underneath it is Internet Connection Sharing,
// which brings its own DHCP allocator and its own DNS proxy on 192.168.137.1.
// Clients are filtered, because that proxy forwards to whatever resolver this
// machine is configured with, and pointing that at our own resolver filters
// every one of them. What is lost is identity: every query arrives from the
// proxy, so they all look like one client. The connected stations can still be
// listed, with their hardware addresses and names, so a device LIST is possible
// — but a per-device rule is not.
//
// [NAT] is New-NetNat, which translates and nothing else. Our own DHCP server
// hands out the addresses and names our own resolver, so queries arrive from
// the devices that made them and per-device policy works in full. What is lost
// is the Wi-Fi: New-NetNat cannot create an access point, so this shares to a
// network that already exists. It also needs Hyper-V, which is not installable
// on Home editions.
//
// Neither is better. A household wanting a filtered guest network takes the
// first; one wanting rules for each child's tablet takes the second and points
// their router at this machine. The product's job is to say so rather than to
// pick one and be quietly worse at the other thing.
//
// # Quoting
//
// The network's name and passphrase come from a text field and end up inside a
// PowerShell string literal. A single quote in either would close it, and what
// follows is a statement. So both are validated for anything that could matter
// and then written into a single-quoted literal with quotes doubled, which is
// PowerShell's own escape and the only one that applies inside such a literal:
// no backslash, no dollar, no subexpression is interpreted there.
package winnet

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"
)

// ErrUnsafeValue reports a value that could change a command's meaning.
var ErrUnsafeValue = errors.New("winnet: value contains a character that would change the command's meaning")

// Quote renders a string as a PowerShell single-quoted literal.
//
// Doubling the quote is PowerShell's own escape and is sufficient BECAUSE the
// literal is single-quoted: inside one, no backslash, dollar sign, backtick or
// subexpression is interpreted, so the quote is the only character with power.
// A double-quoted literal would need far more and is deliberately not used.
func Quote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "''") + "'"
}

// checkSafe refuses characters that must never reach a command line.
//
// Control characters end statements. Everything else — spaces, punctuation,
// apostrophes in a network name — is ordinary and is handled by [Quote], and
// refusing it would make the product worse for nothing.
func checkSafe(what, s string) error {
	for i, r := range s {
		if r < 0x20 || r == 0x7f {
			return fmt.Errorf("%w: %s, at offset %d", ErrUnsafeValue, what, i)
		}
	}
	return nil
}

// Hotspot describes the access point to create.
type Hotspot struct {
	SSID       string
	Passphrase string
}

// Validate reports every problem with the hotspot.
func (h Hotspot) Validate() error {
	var errs []error
	switch n := len(h.SSID); {
	case n == 0:
		errs = append(errs, errors.New("winnet: the network needs a name"))
	case n > 32:
		errs = append(errs, fmt.Errorf("winnet: the name is %d octets and the maximum is 32", n))
	}
	if err := checkSafe("the name", h.SSID); err != nil {
		errs = append(errs, err)
	}
	switch n := len(h.Passphrase); {
	case n < 8:
		errs = append(errs, errors.New("winnet: the passphrase must be at least 8 characters"))
	case n > 63:
		errs = append(errs, errors.New("winnet: the passphrase must be at most 63 characters"))
	}
	if err := checkSafe("the passphrase", h.Passphrase); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

// tetheringPreamble activates the WinRT tethering type and finds the profile to
// share.
//
// Through PowerShell rather than hand-written COM interop. The type is the same
// one either way — Windows.Networking.NetworkOperators.NetworkOperatorTetheringManager
// — and PowerShell activates WinRT types directly, so this is not a shell
// wrapper around a command-line tool but the actual API with the vtable work
// done by something that already gets it right. Hand-rolling IInspectable
// dispatch, async completion handlers and string marshalling in Go is a
// meaningful amount of code whose failures are access violations.
const tetheringPreamble = `
$ErrorActionPreference = 'Stop'
[void][Windows.Networking.NetworkOperators.NetworkOperatorTetheringManager, Windows.Networking.NetworkOperators, ContentType=WindowsRuntime]
[void][Windows.Networking.Connectivity.NetworkInformation, Windows.Networking.Connectivity, ContentType=WindowsRuntime]
$profile = [Windows.Networking.Connectivity.NetworkInformation]::GetInternetConnectionProfile()
if ($null -eq $profile) { throw 'this machine has no internet connection to share' }
`

// TetheringStatus reports whether the hotspot is on, and why it cannot be.
//
// It probes with GetTetheringCapabilityFromConnectionProfile, which is the
// documented way to find out — including the one answer that decides whether
// this approach works at all from a program packaged as this one is:
// DisabledBySystemCapability means the manifest lacks the Wi-Fi control
// capability. Asking is better than assuming, because the documentation and
// the observed behaviour of comparable programs disagree about it.
func TetheringStatus() string {
	return tetheringPreamble + `
$cap = [Windows.Networking.NetworkOperators.NetworkOperatorTetheringManager]::GetTetheringCapabilityFromConnectionProfile($profile)
$mgr = $null
$state = 'Unknown'
$clients = @()
if ($cap -eq 'Enabled') {
  $mgr = [Windows.Networking.NetworkOperators.NetworkOperatorTetheringManager]::CreateFromConnectionProfile($profile)
  $state = $mgr.TetheringOperationalState.ToString()
  foreach ($c in $mgr.GetTetheringClients()) {
    $clients += [pscustomobject]@{ mac = $c.MacAddress; names = @($c.HostNames | ForEach-Object { $_.ToString() }) }
  }
}
[pscustomobject]@{ capability = $cap.ToString(); state = $state; clients = $clients } | ConvertTo-Json -Compress -Depth 4
`
}

// TetheringStart configures and starts the hotspot.
//
// Authentication is not configured, and that is not an omission: the property
// that would set it does not exist before Windows 11 24H2, so on the versions
// this product targets the system chooses — WPA2 in practice — and offering a
// control for it would be offering one that does nothing.
func TetheringStart(h Hotspot) (string, error) {
	if err := h.Validate(); err != nil {
		return "", err
	}
	return tetheringPreamble + fmt.Sprintf(`
$mgr = [Windows.Networking.NetworkOperators.NetworkOperatorTetheringManager]::CreateFromConnectionProfile($profile)
$cfg = $mgr.GetCurrentAccessPointConfiguration()
$cfg.Ssid = %s
$cfg.Passphrase = %s
Await ($mgr.ConfigureAccessPointAsync($cfg)) ([Windows.Foundation.IAsyncAction])
$result = Await ($mgr.StartTetheringAsync()) ([Windows.Foundation.IAsyncOperation[Windows.Networking.NetworkOperators.NetworkOperatorTetheringOperationResult]])
if ($result.Status -ne 'Success') { throw ('the hotspot did not start: ' + $result.Status + ' ' + $result.AdditionalErrorMessage) }
'started'
`, Quote(h.SSID), Quote(h.Passphrase)), nil
}

// TetheringStop stops the hotspot.
func TetheringStop() string {
	return tetheringPreamble + `
$cap = [Windows.Networking.NetworkOperators.NetworkOperatorTetheringManager]::GetTetheringCapabilityFromConnectionProfile($profile)
if ($cap -ne 'Enabled') { 'nothing to stop'; exit 0 }
$mgr = [Windows.Networking.NetworkOperators.NetworkOperatorTetheringManager]::CreateFromConnectionProfile($profile)
if ($mgr.TetheringOperationalState -eq 'Off') { 'already off'; exit 0 }
$result = Await ($mgr.StopTetheringAsync()) ([Windows.Foundation.IAsyncOperation[Windows.Networking.NetworkOperators.NetworkOperatorTetheringOperationResult]])
'stopped'
`
}

// AwaitHelper is the function the scripts above call to wait for a WinRT
// asynchronous operation.
//
// It is prepended to every script rather than being defined inside one, so that
// the scripts read as what they do. Reflection is needed because PowerShell has
// no direct way to await an IAsyncOperation: the generic AsTask overload has to
// be found and bound to the operation's own result type.
const AwaitHelper = `
function Await($op, $type) {
  $task = [System.WindowsRuntimeSystemExtensions].GetMethods() |
    Where-Object { $_.Name -eq 'AsTask' -and $_.GetParameters().Count -eq 1 -and $_.GetParameters()[0].ParameterType.Name -eq $type.Name } |
    Select-Object -First 1
  if ($null -eq $task) { throw 'this PowerShell cannot await a WinRT operation' }
  $m = $task.MakeGenericMethod($type.GenericTypeArguments)
  $t = $m.Invoke($null, @($op))
  $t.Wait(60000) | Out-Null
  if ($t.IsFaulted) { throw $t.Exception.InnerException.Message }
  $t.Result
}
`

// NatName is the name given to the address translation this product installs.
//
// Namespaced, so that a scan for leftovers has an exact question to ask and so
// that removing ours cannot remove somebody else's. Windows permits only one
// NAT network per host, so colliding with Docker or WSL is a real possibility
// and must be reported rather than resolved by force.
const NatName = "GatewayDNS"

// NatStatus lists the address translations on this machine.
//
// All of them, not only ours, because the one-per-host limit means somebody
// else's is the reason ours cannot be created — and "there is already a NAT
// called DockerNAT" is an answer, while "could not create" is not.
func NatStatus() string {
	return `$ErrorActionPreference='Stop'
Get-NetNat | Select-Object Name, InternalIPInterfaceAddressPrefix | ConvertTo-Json -Compress`
}

// NatCreate installs the address translation for a subnet.
func NatCreate(subnet netip.Prefix) (string, error) {
	if !subnet.IsValid() || !subnet.Addr().Is4() {
		return "", fmt.Errorf("winnet: %v is not a valid IPv4 prefix", subnet)
	}
	return fmt.Sprintf(`$ErrorActionPreference='Stop'
New-NetNat -Name %s -InternalIPInterfaceAddressPrefix %s | Out-Null
'created'`, Quote(NatName), Quote(subnet.String())), nil
}

// NatRemove removes it.
//
// It tolerates the translation being absent, because teardown runs on paths
// where the state is unknown — after a crash, after a partial start — and a
// cleanup that fails because there was nothing to clean is a cleanup that stops
// before the next step.
func NatRemove() string {
	return fmt.Sprintf(`$ErrorActionPreference='Continue'
Get-NetNat -Name %s -ErrorAction SilentlyContinue | Remove-NetNat -Confirm:$false -ErrorAction SilentlyContinue
'removed'`, Quote(NatName))
}

// AddressAssign gives an interface the address devices will use as their
// router and their resolver.
func AddressAssign(iface string, addr netip.Addr, bits int) (string, error) {
	if err := checkIface(iface); err != nil {
		return "", err
	}
	if !addr.Is4() {
		return "", fmt.Errorf("winnet: %v is not an IPv4 address", addr)
	}
	if bits <= 0 || bits > 32 {
		return "", fmt.Errorf("winnet: /%d is not an IPv4 prefix length", bits)
	}
	// The existing address is removed first, and its absence is tolerated: a
	// bring-up after an unclean stop meets an address that is already there,
	// and New-NetIPAddress fails on one rather than replacing it.
	return fmt.Sprintf(`$ErrorActionPreference='Continue'
Get-NetIPAddress -InterfaceAlias %s -AddressFamily IPv4 -ErrorAction SilentlyContinue |
  Where-Object { $_.IPAddress -eq %s } | Remove-NetIPAddress -Confirm:$false -ErrorAction SilentlyContinue
$ErrorActionPreference='Stop'
New-NetIPAddress -InterfaceAlias %s -IPAddress %s -PrefixLength %d | Out-Null
'assigned'`, Quote(iface), Quote(addr.String()), Quote(iface), Quote(addr.String()), bits), nil
}

// AddressRemove takes it away again.
func AddressRemove(iface string, addr netip.Addr) (string, error) {
	if err := checkIface(iface); err != nil {
		return "", err
	}
	return fmt.Sprintf(`$ErrorActionPreference='Continue'
Get-NetIPAddress -InterfaceAlias %s -AddressFamily IPv4 -ErrorAction SilentlyContinue |
  Where-Object { $_.IPAddress -eq %s } | Remove-NetIPAddress -Confirm:$false -ErrorAction SilentlyContinue
'removed'`, Quote(iface), Quote(addr.String())), nil
}

// Forwarding switches IPv4 forwarding on one interface.
//
// Per interface rather than the machine-wide IPEnableRouter registry value,
// which needs a reboot to take effect and turns forwarding on for every
// interface including the uplink.
func Forwarding(iface string, on bool) (string, error) {
	if err := checkIface(iface); err != nil {
		return "", err
	}
	state := "Disabled"
	if on {
		state = "Enabled"
	}
	return fmt.Sprintf(`$ErrorActionPreference='Stop'
Set-NetIPInterface -InterfaceAlias %s -AddressFamily IPv4 -Forwarding %s
'%s'`, Quote(iface), state, strings.ToLower(state)), nil
}

// ForwardingState reads it, so that teardown can restore what it found.
func ForwardingState(iface string) (string, error) {
	if err := checkIface(iface); err != nil {
		return "", err
	}
	return fmt.Sprintf(`$ErrorActionPreference='Stop'
(Get-NetIPInterface -InterfaceAlias %s -AddressFamily IPv4).Forwarding.ToString()`, Quote(iface)), nil
}

// checkIface validates an interface alias.
//
// Aliases on Windows are user-facing names that legitimately contain spaces —
// "Wi-Fi", "Local Area Connection" — so they cannot be constrained to a
// programmer's idea of a name. What they must not contain is a control
// character; the quote is handled by [Quote].
func checkIface(name string) error {
	if name == "" {
		return errors.New("winnet: an interface is required")
	}
	if len(name) > 256 {
		return fmt.Errorf("winnet: interface name is %d characters, which is longer than Windows allows", len(name))
	}
	return checkSafe("the interface name", name)
}
