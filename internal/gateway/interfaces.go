package gateway

import (
	"fmt"
	"net"
	"net/netip"
	"sort"
)

// enumerate lists the machine's interfaces, without deciding anything
// platform-specific about them.
//
// Kind and address enumeration come from the standard library and are the same
// everywhere. Two things are not portable and are supplied by the caller: which
// interface carries the default route, and whether a wireless interface can
// host an access point. Both are asked for as functions rather than being
// detected here, so that the portable half stays testable without a network.
func enumerate(defaultRoute func() (string, error), wireless func(string) (bool, apSupport)) ([]Interface, error) {
	sys, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("gateway: listing interfaces: %w", err)
	}
	route := ""
	if defaultRoute != nil {
		// A machine with no default route is a normal state — unplugged, or
		// still associating — and not an error. The uplink selector reports it
		// in terms a person can act on; here it is simply "no interface has it".
		if r, err := defaultRoute(); err == nil {
			route = r
		}
	}

	out := make([]Interface, 0, len(sys))
	for _, s := range sys {
		x := Interface{
			Name:            s.Name,
			Up:              s.Flags&net.FlagUp != 0 && s.Flags&net.FlagRunning != 0,
			HasDefaultRoute: s.Name == route,
		}
		switch {
		case s.Flags&net.FlagLoopback != 0:
			x.Kind = KindLoopback
		case wireless != nil:
			if isWireless, ap := wireless(s.Name); isWireless {
				x.Kind = KindWireless
				x.SupportsAP, x.APReason = ap.supported, ap.reason
			} else if s.Flags&net.FlagPointToPoint == 0 && len(s.HardwareAddr) == 6 {
				x.Kind = KindWired
			}
		case s.Flags&net.FlagPointToPoint == 0 && len(s.HardwareAddr) == 6:
			x.Kind = KindWired
		}

		addrs, err := s.Addrs()
		if err == nil {
			for _, a := range addrs {
				if p, ok := prefixOf(a); ok {
					x.Addrs = append(x.Addrs, p)
				}
			}
		}
		out = append(out, x)
	}

	// A stable order, so that a list redrawn in a user interface does not
	// reshuffle itself between polls. Usable interfaces first, then by name.
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.HasDefaultRoute != b.HasDefaultRoute {
			return a.HasDefaultRoute
		}
		if a.SupportsAP != b.SupportsAP {
			return a.SupportsAP
		}
		if a.Up != b.Up {
			return a.Up
		}
		return a.Name < b.Name
	})
	return out, nil
}

// apSupport is what a platform concluded about one wireless interface.
type apSupport struct {
	supported bool
	// reason explains a false supported, and is shown to a person, so it says
	// what to do rather than what failed.
	reason string
}

func prefixOf(a net.Addr) (netip.Prefix, bool) {
	n, ok := a.(*net.IPNet)
	if !ok {
		return netip.Prefix{}, false
	}
	addr, ok := netip.AddrFromSlice(n.IP)
	if !ok {
		return netip.Prefix{}, false
	}
	ones, _ := n.Mask.Size()
	addr = addr.Unmap()
	if addr.Is4() && ones > 32 {
		// A four-octet address carrying a 128-bit mask is the v4-in-v6 form,
		// whose mask counts the 96-bit prefix as well.
		ones -= 96
	}
	p, err := addr.Prefix(ones)
	if err != nil {
		return netip.Prefix{}, false
	}
	return p, true
}
