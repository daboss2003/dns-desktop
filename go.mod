// Module gatewaydns-desktop is the GatewayDNS desktop application.
//
// It turns a machine into a filtering DNS gateway for the devices around it: it
// manages a Wi-Fi hotspot where the platform allows one, hands out DHCP leases,
// configures NAT and firewall rules, and presents a user interface for the
// devices and the policies applied to them.
//
// It contains NO DNS logic. All of that comes from the engine, consumed as an
// ordinary versioned dependency — which is the boundary ADR 0001 exists to make
// real: the engine's go.mod has no require block at all, so it cannot import
// anything here without an edit that CI rejects.
//
// Unlike the engine, this module MAY take dependencies. It is a desktop
// application with platform-specific code and a release cadence of its own, and
// that is exactly why it is a separate module.
//
// The replace directive below is for local development against a checkout of
// the engine. It MUST be removed before release; a replace in a published go.mod
// is the classic way to ship something that does not build for anyone else, and
// the release check enforces its absence.
module github.com/daboss2003/dns-desktop

go 1.25.0

require github.com/daboss2003/dns v0.0.0

require (
	fyne.io/systray v1.12.2
	github.com/webview/webview_go v0.0.0-20240831120633-6173450d4dd6
	golang.org/x/sys v0.47.0
)

require github.com/godbus/dbus/v5 v5.1.0 // indirect

replace github.com/daboss2003/dns => ../dns
