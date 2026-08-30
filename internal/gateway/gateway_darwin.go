//go:build darwin

package gateway

import (
	"context"
	"os/exec"
	"strings"
)

// New returns the gateway for this platform.
//
// macOS is the constrained case, and the constraint is worth stating plainly
// rather than working around: there is no supported interface for a program to
// bring up a Wi-Fi access point. Internet Sharing exists and does exactly what
// this product wants, and it is a preference pane — a person turns it on, and
// what a program may do is notice that they have.
//
// What macOS can do, and what this implementation does, is be the resolver and
// the gateway for devices that are pointed at this machine: by a router handing
// out its address, by Internet Sharing that a person switched on, or by hand.
// That is most of the product, and it is honest about the part it is not.
func New() Gateway { return &darwinGateway{} }

type darwinGateway struct{}

var _ Gateway = (*darwinGateway)(nil)

// Platform implements [Gateway].
func (g *darwinGateway) Platform() string { return "macos" }

const noAPOnMacOS = "macOS has no supported interface for a program to create a Wi-Fi access point; " +
	"turn on Internet Sharing in System Settings and this machine will serve the devices that join it"

// Capabilities implements [Gateway].
func (g *darwinGateway) Capabilities(context.Context) (Capabilities, error) {
	c := Capabilities{Reasons: map[Capability]string{}}

	// Never available, and not fixable by anything a person could buy.
	c.Reasons[CapAccessPoint] = noAPOnMacOS

	// The rest depend on pfctl, which is present on every macOS but is
	// unusable without privilege. Reporting it as available here would be a
	// lie a person only discovers when bring-up fails, so it is checked.
	if _, err := exec.LookPath("pfctl"); err != nil {
		const why = "pfctl was not found, so this machine cannot install the packet-filter rules " +
			"that share a connection or redirect DNS"
		for _, cap := range []Capability{CapShareUplink, CapDNSRedirect, CapBlockDevice, CapIPv6Control} {
			c.Reasons[cap] = why
		}
		return c, nil
	}
	// Announced but not yet implemented. Saying so is better than claiming a
	// capability whose Start would fail: a person reads this in the interface
	// and knows to point their router at this machine instead of waiting for a
	// button that will not work.
	const pending = "sharing and DNS redirection on macOS are not in this build; " +
		"point a device at this machine as its DNS server and it is filtered"
	for _, cap := range []Capability{CapShareUplink, CapDNSRedirect, CapBlockDevice, CapIPv6Control} {
		c.Reasons[cap] = pending
	}
	return c, nil
}

// Interfaces implements [Gateway].
func (g *darwinGateway) Interfaces(context.Context) ([]Interface, error) {
	return enumerate(darwinDefaultRoute, darwinWireless)
}

// Start implements [Gateway] by refusing, with the capability that is missing.
func (g *darwinGateway) Start(_ context.Context, cfg Config) (Session, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	caps, err := g.Capabilities(context.Background())
	if err != nil {
		return nil, err
	}
	return nil, CheckCapabilities(g.Platform(), caps, cfg)
}

// Reconcile implements [Gateway]. Nothing is installed yet, so there is nothing
// to remove — but the method exists and is called, so that the day something is
// installed the call site does not have to change.
func (g *darwinGateway) Reconcile(context.Context) (Report, error) { return Report{}, nil }

// darwinDefaultRoute asks the routing table which interface carries the default
// route.
//
// Through `route -n get default` rather than by reading a file, because macOS
// has no /proc and the sysctl route dump is a binary format with no stable Go
// binding outside cgo. The output is parsed for one line, which is the smallest
// dependency on a text format this can have.
func darwinDefaultRoute() (string, error) {
	out, err := exec.Command("route", "-n", "get", "default").Output()
	if err != nil {
		return "", err
	}
	for line := range strings.SplitSeq(string(out), "\n") {
		name, value, ok := strings.Cut(strings.TrimSpace(line), ":")
		if ok && name == "interface" {
			return strings.TrimSpace(value), nil
		}
	}
	return "", errNoDefaultRoute
}

// darwinWireless reports whether an interface is Wi-Fi.
//
// The name is not enough — en0 is Wi-Fi on a laptop and Ethernet on a Mac mini
// — so this asks the system, and treats a failure as "not wireless" rather than
// as an error: an interface wrongly classified as wired is listed and unusable
// for a hotspot that macOS cannot create anyway.
func darwinWireless(name string) (bool, apSupport) {
	out, err := exec.Command("networksetup", "-listallhardwareports").Output()
	if err != nil {
		return false, apSupport{}
	}
	var wifi bool
	for line := range strings.SplitSeq(string(out), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "Hardware Port:") {
			wifi = strings.Contains(strings.ToLower(line), "wi-fi") ||
				strings.Contains(strings.ToLower(line), "airport")
			continue
		}
		if wifi && strings.HasPrefix(line, "Device:") {
			if strings.TrimSpace(strings.TrimPrefix(line, "Device:")) == name {
				return true, apSupport{reason: noAPOnMacOS}
			}
		}
	}
	return false, apSupport{}
}
