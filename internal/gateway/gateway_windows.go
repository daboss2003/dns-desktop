//go:build windows

package gateway

// New returns the gateway for this platform.
//
// Windows gets an honest refusal rather than an implementation. The mechanism
// that would be needed — the Mobile Hotspot API in WinRT — is reachable only
// through COM, which means CGO or a hand-written interop layer, on a platform
// where the older and simpler hosted-network API was deprecated and removed.
// Doing it badly would produce a hotspot that half works and cannot be
// diagnosed; doing it properly is a milestone of its own.
//
// The rest of the application runs: on Windows, GatewayDNS Desktop is a
// filtering resolver with a user interface for the devices that point at it,
// which is most of the product and all of it for anyone whose router hands out
// this machine's address as the DNS server.
func New() Gateway {
	return &Unsupported{
		Name: "windows",
		Why: "GatewayDNS Desktop does not yet manage hotspots, NAT or firewall rules on Windows; " +
			"it serves DNS for devices that are pointed at this machine",
	}
}
