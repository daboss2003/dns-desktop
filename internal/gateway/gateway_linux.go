//go:build linux

package gateway

import (
	"bufio"
	"context"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

// New returns the gateway for this platform.
//
// Linux is the platform that can do all of it: an access point through hostapd,
// routing and masquerading through nftables or iptables, DNS redirection, and
// per-device blocking. This build reports what the machine could do and refuses
// to bring anything up, because a half-implemented gateway that leaves firewall
// rules behind is the worst thing this package can produce and is not worth
// shipping early.
func New() Gateway { return &linuxGateway{} }

type linuxGateway struct{}

var _ Gateway = (*linuxGateway)(nil)

// Platform implements [Gateway].
func (g *linuxGateway) Platform() string { return "linux" }

// Capabilities implements [Gateway].
//
// It reports what is MISSING from this machine specifically — no hostapd, no
// firewall tool, no adapter with AP mode — because those are the answers a
// person can act on, and they are different answers with different fixes.
func (g *linuxGateway) Capabilities(ctx context.Context) (Capabilities, error) {
	c := Capabilities{Reasons: map[Capability]string{}}

	if _, err := exec.LookPath("hostapd"); err != nil {
		c.Reasons[CapAccessPoint] = "hostapd is not installed, and it is what turns a wireless " +
			"adapter into an access point; install it with your package manager"
		c.Fixable |= CapAccessPoint
	} else if ifaces, err := g.Interfaces(ctx); err == nil {
		if _, err := SelectAPInterface(ifaces, "", ""); err != nil {
			c.Reasons[CapAccessPoint] = err.Error()
			c.Fixable |= CapAccessPoint
		} else {
			c.Reasons[CapAccessPoint] = notInThisBuild
		}
	}

	firewall := "nft"
	if _, err := exec.LookPath("nft"); err != nil {
		firewall = "iptables"
		if _, err := exec.LookPath("iptables"); err != nil {
			const why = "neither nft nor iptables is installed, so this machine cannot install the " +
				"firewall rules that share a connection or redirect DNS"
			for _, cap := range []Capability{CapShareUplink, CapDNSRedirect, CapBlockDevice, CapIPv6Control} {
				c.Reasons[cap] = why
				c.Fixable |= cap
			}
			return c, nil
		}
	}
	_ = firewall
	for _, cap := range []Capability{CapShareUplink, CapDNSRedirect, CapBlockDevice, CapIPv6Control} {
		c.Reasons[cap] = notInThisBuild
	}
	return c, nil
}

const notInThisBuild = "bringing a gateway up is not in this build; " +
	"point a device at this machine as its DNS server and it is filtered"

// Interfaces implements [Gateway].
func (g *linuxGateway) Interfaces(context.Context) ([]Interface, error) {
	return enumerate(linuxDefaultRoute, linuxWireless)
}

// Start implements [Gateway] by refusing, with the capability that is missing.
func (g *linuxGateway) Start(ctx context.Context, cfg Config) (Session, error) {
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
func (g *linuxGateway) Reconcile(context.Context) (Report, error) { return Report{}, nil }

// linuxDefaultRoute reads the routing table from /proc.
//
// From the file rather than by running `ip route`, because the file is a kernel
// interface with a fixed format and `ip` is a package that may not be
// installed. The destination and mask are both zero on the default route, and
// the flags must say the route is up.
func linuxDefaultRoute() (string, error) {
	f, err := os.Open("/proc/net/route")
	if err != nil {
		return "", err
	}
	defer f.Close()

	const (
		fieldIface = 0
		fieldDest  = 1
		fieldFlags = 3
		fieldMask  = 7
		rtfUp      = 0x0001
	)
	sc := bufio.NewScanner(f)
	sc.Scan() // the header
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) <= fieldMask {
			continue
		}
		if fields[fieldDest] != "00000000" || fields[fieldMask] != "00000000" {
			continue
		}
		flags, err := strconv.ParseUint(fields[fieldFlags], 16, 32)
		if err != nil || flags&rtfUp == 0 {
			continue
		}
		return fields[fieldIface], nil
	}
	return "", errNoDefaultRoute
}

// linuxWireless reports whether an interface is wireless, and whether it can
// host an access point.
//
// The wireless test is the presence of /sys/class/net/<name>/wireless, which
// the kernel creates for every cfg80211 device and which needs no tools and no
// privileges.
//
// Whether the driver supports AP mode cannot be read from sysfs — it lives in
// the nl80211 interface-combination attributes, over generic netlink — so this
// build reports it as unknown with a reason rather than guessing. Guessing
// optimistically produces a hotspot that fails to start with a driver error;
// guessing pessimistically hides a feature the machine has.
func linuxWireless(name string) (bool, apSupport) {
	if _, err := os.Stat("/sys/class/net/" + name + "/wireless"); err != nil {
		if _, err := os.Stat("/sys/class/net/" + name + "/phy80211"); err != nil {
			return false, apSupport{}
		}
	}
	return true, apSupport{reason: "whether this adapter's driver supports access-point mode " +
		"is not determined in this build"}
}
