package gateway

import (
	"context"
)

// Unsupported is a [Gateway] for a platform that cannot be one.
//
// It is a real implementation rather than a nil interface, and every method
// answers rather than crashing, because the application above it must be able
// to run: on a platform with no gateway support GatewayDNS Desktop is still a
// filtering resolver with a user interface for the devices that point at it,
// which is most of the product. What it cannot do is create a hotspot, and it
// says so in a sentence rather than by being absent.
type Unsupported struct {
	// Name is the platform, for messages.
	Name string
	// Why explains, once, why nothing here is available.
	Why string
}

var _ Gateway = (*Unsupported)(nil)

// Platform implements [Gateway].
func (u *Unsupported) Platform() string { return u.Name }

// Capabilities implements [Gateway]: nothing, with a reason on every entry.
func (u *Unsupported) Capabilities(context.Context) (Capabilities, error) {
	reasons := make(map[Capability]string, len(capNames))
	for _, n := range capNames {
		reasons[n.c] = u.Why
	}
	// Nothing is Fixable: these are absent because of the platform, and telling
	// somebody to try a different adapter would waste their afternoon.
	//
	// SharingNone is still offered, and is not a consolation prize: this
	// machine resolves for every device pointed at it, which is the whole
	// product for anyone whose router can hand out one DNS server.
	return Capabilities{Reasons: reasons, Sharing: []SharingModel{SharingNone}}, nil
}

// Interfaces implements [Gateway]. It reports none rather than an error: there
// is nothing to choose between when nothing can be done with any of them.
func (u *Unsupported) Interfaces(context.Context) ([]Interface, error) { return nil, nil }

// Start implements [Gateway] by refusing.
//
// The configuration is validated first, so that a caller with both a bad
// configuration and an unsupported platform is told about the configuration —
// which is the problem they can fix.
func (u *Unsupported) Start(_ context.Context, cfg Config) (Session, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return nil, Unsupportedf(u.Name, cfg.Required(), "%s", u.Why)
}

// Reconcile implements [Gateway]. There is never anything to clean up, because
// nothing was ever installed.
func (u *Unsupported) Reconcile(context.Context) (Report, error) { return Report{}, nil }
