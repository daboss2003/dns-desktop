package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"strings"
	"testing"
)

func config(mutate func(*Config)) Config {
	c := Config{
		Sharing: SharingManaged,
		Subnet:  netip.MustParsePrefix("10.42.0.0/24"),
		Addr:    netip.MustParseAddr("10.42.0.1"),
		DNSPort: 53,
	}
	if mutate != nil {
		mutate(&c)
	}
	return c
}

// A refusal must name the capability and give a reason a person can act on. A
// user interface that greys out a control with no explanation produces a
// support question nobody can answer remotely.
func TestARefusalNamesTheCapabilityAndTheReason(t *testing.T) {
	t.Parallel()
	g := &Unsupported{Name: "testos", Why: "testos has no packet filter"}

	_, err := g.Start(context.Background(), config(func(c *Config) {
		c.Hotspot = &HotspotConfig{SSID: "home", Passphrase: "correcthorse"}
	}))
	if err == nil {
		t.Fatal("an unsupported platform started a gateway")
	}
	if !errors.Is(err, ErrUnsupported) {
		t.Errorf("err = %v, want it to wrap ErrUnsupported", err)
	}
	var ue *UnsupportedError
	if !errors.As(err, &ue) {
		t.Fatalf("err = %T, want an *UnsupportedError naming what is missing", err)
	}
	for _, want := range []string{"testos", "access-point", "no packet filter"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not mention %q", err, want)
		}
	}
}

// A bad configuration and an unsupported platform together must report the
// configuration, which is the problem the person can fix.
func TestABadConfigurationIsReportedBeforeAnUnsupportedPlatform(t *testing.T) {
	t.Parallel()
	g := &Unsupported{Name: "testos", Why: "no"}
	_, err := g.Start(context.Background(), Config{})
	if err == nil {
		t.Fatal("an empty configuration was accepted")
	}
	if errors.Is(err, ErrUnsupported) {
		t.Errorf("err = %v, want the configuration problem rather than the platform one", err)
	}
}

// Validate reports every problem rather than the first: a person fixing a form
// one error per attempt is a bad experience.
func TestValidateReportsEveryProblem(t *testing.T) {
	t.Parallel()
	err := Config{
		Subnet:  netip.MustParsePrefix("10.42.0.0/24"),
		Addr:    netip.MustParseAddr("192.168.9.9"),
		DNSPort: 0,
		Hotspot: &HotspotConfig{SSID: "", Passphrase: "short"},
	}.Validate()
	if err == nil {
		t.Fatal("an invalid configuration was accepted")
	}
	for _, want := range []string{"outside subnet", "dns port", "needs a name", "at least 8"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error does not mention %q:\n%v", want, err)
		}
	}
}

// An access-point configuration file is key=value with no quoting, so a newline
// in a name supplied through a browser injects directives — and "MyWiFi\nwpa=0"
// is an open network that looks protected in every screen that shows it.
func TestControlCharactersAreRefusedInHotspotStrings(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		cfg  HotspotConfig
	}{
		{"newline in ssid", HotspotConfig{SSID: "MyWiFi\nwpa=0", Passphrase: "correcthorse"}},
		{"newline in passphrase", HotspotConfig{SSID: "MyWiFi", Passphrase: "correct\nhorse"}},
		{"null in ssid", HotspotConfig{SSID: "My\x00WiFi", Passphrase: "correcthorse"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := config(func(c *Config) { c.Hotspot = &tc.cfg }).Validate()
			if err == nil {
				t.Fatal("accepted")
			}
			if !strings.Contains(err.Error(), "control character") {
				t.Errorf("err = %v, want it to name the control character", err)
			}
		})
	}

	// A perfectly ordinary name with spaces and punctuation is fine.
	if err := config(func(c *Config) {
		c.Hotspot = &HotspotConfig{SSID: "Sam's Wi-Fi (2.4)", Passphrase: "correct horse battery"}
	}).Validate(); err != nil {
		t.Errorf("an ordinary name was refused: %v", err)
	}
}

// An open network needs no passphrase, and demanding one would make the mode
// unusable.
func TestAnOpenHotspotNeedsNoPassphrase(t *testing.T) {
	t.Parallel()
	if err := config(func(c *Config) {
		c.Hotspot = &HotspotConfig{SSID: "guest", Security: SecurityOpen}
	}).Validate(); err != nil {
		t.Errorf("an open hotspot was refused: %v", err)
	}
}

// Required is what lets a configuration be refused in one place with one
// explanation, rather than partway through bring-up with whatever error the
// fifth step produced. It follows the sharing model, because the models ask for
// genuinely different things.
func TestRequiredCapabilitiesFollowTheSharingModel(t *testing.T) {
	t.Parallel()

	// Sharing nothing needs nothing. It is not a fallback: for a household
	// whose router can hand out one DNS server it is the whole product, and a
	// platform that could do nothing else would still deliver it.
	none := Config{Sharing: SharingNone, DNSPort: 53}
	if got := none.Required(); got != 0 {
		t.Errorf("sharing nothing requires %v, want no capability at all", got)
	}
	if err := none.Validate(); err != nil {
		t.Errorf("a resolver-only configuration was refused: %v", err)
	}

	// Platform sharing asks only for the access point the operating system
	// manages. Demanding share-uplink would refuse Windows and macOS for not
	// letting us write firewall rules they do not need us to write.
	platform := Config{
		Sharing: SharingPlatform, DNSPort: 53,
		Hotspot: &HotspotConfig{SSID: "home", Passphrase: "correcthorse"},
	}
	if got := platform.Required(); got != CapAccessPoint {
		t.Errorf("platform sharing requires %v, want the access point alone", got)
	}

	// Managed sharing owns everything, so it asks for everything.
	managed := config(func(c *Config) {
		c.Hotspot = &HotspotConfig{SSID: "home", Passphrase: "correcthorse"}
	})
	want := CapShareUplink | CapOwnDHCP | CapAccessPoint | CapIPv6Control
	if got := managed.Required(); got != want {
		t.Errorf("managed sharing requires %v, want %v", got, want)
	}

	// Blocking IPv6 is a capability rather than an absence of one, but only
	// where this application owns the firewall: under platform sharing the
	// operating system decides, and asking for it would refuse a working
	// configuration.
	if platform.Required()&CapIPv6Control != 0 {
		t.Error("platform sharing demands ipv6-control, which it does not own")
	}
	if config(nil).Required()&CapIPv6Control == 0 {
		t.Error("managed sharing does not require ipv6-control; an unconfigured v6 route bypasses every rule")
	}
}

// A subnet is required only where this application assigns the addresses.
// Windows uses 192.168.137.0/24 for its hotspot and will not be argued with, so
// demanding one under platform sharing would refuse a configuration that works
// and invite an operator to write a number that is then ignored.
func TestOnlyManagedSharingNeedsASubnet(t *testing.T) {
	t.Parallel()
	if err := (Config{
		Sharing: SharingPlatform, DNSPort: 53,
		Hotspot: &HotspotConfig{SSID: "home", Passphrase: "correcthorse"},
	}).Validate(); err != nil {
		t.Errorf("platform sharing was refused for having no subnet: %v", err)
	}
	err := (Config{Sharing: SharingManaged, DNSPort: 53}).Validate()
	if err == nil {
		t.Fatal("managed sharing was accepted with no subnet")
	}
	if !strings.Contains(err.Error(), "subnet") {
		t.Errorf("err = %v, want it to name the missing subnet", err)
	}
}

// A hotspot with sharing switched off is a contradiction, and the message says
// which of the two to change.
func TestAHotspotWithoutSharingIsRefused(t *testing.T) {
	t.Parallel()
	err := (Config{
		Sharing: SharingNone, DNSPort: 53,
		Hotspot: &HotspotConfig{SSID: "home", Passphrase: "correcthorse"},
	}).Validate()
	if err == nil {
		t.Fatal("a hotspot was accepted with sharing off")
	}
	if !strings.Contains(err.Error(), "sharing is off") {
		t.Errorf("err = %v", err)
	}
}

func TestCheckCapabilitiesNamesEveryMissingPiece(t *testing.T) {
	t.Parallel()
	have := Capabilities{
		Have: CapShareUplink | CapOwnDHCP,
		Reasons: map[Capability]string{
			CapAccessPoint: "no adapter supports access-point mode",
			CapIPv6Control: "no firewall tool is installed",
		},
	}
	err := CheckCapabilities("testos", have, config(func(c *Config) {
		c.Hotspot = &HotspotConfig{SSID: "home", Passphrase: "correcthorse"}
	}))
	if err == nil {
		t.Fatal("a configuration needing two absent capabilities was accepted")
	}
	for _, want := range []string{"access-point", "no adapter supports", "ipv6-control", "no firewall tool"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error does not mention %q:\n%v", want, err)
		}
	}

	// And a satisfiable configuration passes.
	all := Capabilities{Have: CapShareUplink | CapOwnDHCP | CapAccessPoint | CapIPv6Control}
	if err := CheckCapabilities("testos", all, config(func(c *Config) {
		c.Hotspot = &HotspotConfig{SSID: "home", Passphrase: "correcthorse"}
	})); err != nil {
		t.Errorf("a satisfiable configuration was refused: %v", err)
	}
}

// The front end must not have to know what a bit set means.
func TestCapabilitiesMarshalForAUserInterface(t *testing.T) {
	t.Parallel()
	c := Capabilities{
		Have:    CapShareUplink,
		Fixable: CapAccessPoint,
		Reasons: map[Capability]string{CapAccessPoint: "install hostapd"},
		Sharing: []SharingModel{SharingNone, SharingPlatform},
	}
	b, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Capabilities []struct {
			Name      string `json:"name"`
			Available bool   `json:"available"`
			Reason    string `json:"reason"`
			Fixable   bool   `json:"fixable"`
		} `json:"capabilities"`
		Sharing []string `json:"sharing"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatalf("decode %s: %v", b, err)
	}
	items := doc.Capabilities
	// The models are named, not implied: a person choosing how this will work
	// must be offered the alternatives rather than one arrangement and an
	// apology.
	if len(doc.Sharing) == 0 || doc.Sharing[0] != "none" {
		t.Errorf("sharing = %v, want at least the model that needs nothing", doc.Sharing)
	}
	if len(items) != len(capNames) {
		t.Fatalf("%d entries, want one per capability", len(items))
	}
	byName := map[string]int{}
	for i, it := range items {
		byName[it.Name] = i
	}
	if it := items[byName["share-uplink"]]; !it.Available || it.Reason != "" {
		t.Errorf("share-uplink = %+v, want available with no reason", it)
	}
	if it := items[byName["access-point"]]; it.Available || it.Reason != "install hostapd" || !it.Fixable {
		t.Errorf("access-point = %+v, want unavailable, fixable, with the reason", it)
	}
	// Every unavailable capability has SOME reason, even one nobody supplied.
	for _, it := range items {
		if !it.Available && it.Reason == "" {
			t.Errorf("%s is unavailable with no reason; the interface would grey a control silently", it.Name)
		}
	}
}

// A gateway with no uplink hands out addresses and connects devices to nothing,
// which looks to a user exactly like the product being broken.
func TestUplinkSelection(t *testing.T) {
	t.Parallel()
	ifaces := []Interface{
		{Name: "lo", Kind: KindLoopback, Up: true},
		{Name: "eth0", Kind: KindWired, Up: true, HasDefaultRoute: true},
		{Name: "wlan0", Kind: KindWireless, Up: true, SupportsAP: true},
		{Name: "wlan1", Kind: KindWireless, Up: false},
	}
	got, err := SelectUplink(ifaces, "")
	if err != nil || got.Name != "eth0" {
		t.Errorf("SelectUplink = %v, %v; want the interface with the default route", got.Name, err)
	}
	if got, err := SelectUplink(ifaces, "wlan0"); err != nil || got.Name != "wlan0" {
		t.Errorf("a named uplink = %v, %v", got.Name, err)
	}
	if _, err := SelectUplink(ifaces, "wlan1"); err == nil || !strings.Contains(err.Error(), "down") {
		t.Errorf("a down interface = %v, want a refusal saying so", err)
	}
	if _, err := SelectUplink(ifaces, "nope"); err == nil {
		t.Error("an interface that does not exist was accepted")
	}

	none := []Interface{{Name: "lo", Kind: KindLoopback, Up: true}}
	_, err = SelectUplink(none, "")
	if err == nil {
		t.Fatal("a machine with no default route produced an uplink")
	}
	if !strings.Contains(err.Error(), "connect this machine to a network") {
		t.Errorf("err = %q, want it to say what to do", err)
	}
}

// "No adapter supports AP mode" and "your only adapter is busy carrying the
// connection you are sharing" call for different actions, and the second is far
// more common on a laptop.
func TestAccessPointSelectionExplainsTheCommonFailure(t *testing.T) {
	t.Parallel()
	twoRadios := []Interface{
		{Name: "wlan0", Kind: KindWireless, Up: true, SupportsAP: true, HasDefaultRoute: true},
		{Name: "wlan1", Kind: KindWireless, Up: true, SupportsAP: true},
	}
	got, err := SelectAPInterface(twoRadios, "", "wlan0")
	if err != nil || got.Name != "wlan1" {
		t.Errorf("SelectAPInterface = %v, %v; want the radio that is not the uplink", got.Name, err)
	}

	oneRadio := []Interface{
		{Name: "wlan0", Kind: KindWireless, Up: true, SupportsAP: true, HasDefaultRoute: true},
	}
	_, err = SelectAPInterface(oneRadio, "", "wlan0")
	if err == nil {
		t.Fatal("the uplink was chosen to host the access point")
	}
	if !strings.Contains(err.Error(), "carrying the connection being shared") {
		t.Errorf("err = %q, want it to explain that the only radio is busy", err)
	}

	noAP := []Interface{{Name: "wlan0", Kind: KindWireless, Up: true, APReason: "driver has no AP mode"}}
	_, err = SelectAPInterface(noAP, "wlan0", "")
	if err == nil || !strings.Contains(err.Error(), "driver has no AP mode") {
		t.Errorf("err = %v, want the platform's own reason", err)
	}
	if _, err := SelectAPInterface(nil, "", ""); err == nil {
		t.Error("an access point was hosted on a machine with no wireless adapter")
	}
}

// Every platform this builds for must have a New that answers, because the
// application above it runs on all of them.
func TestThePlatformGatewayAnswers(t *testing.T) {
	t.Parallel()
	g := New()
	if g.Platform() == "" {
		t.Error("the gateway does not name its platform")
	}
	ctx := context.Background()

	caps, err := g.Capabilities(ctx)
	if err != nil {
		t.Fatalf("Capabilities: %v", err)
	}
	// Whatever this platform can do, every capability it cannot do has a
	// reason. That is the contract the user interface depends on.
	for _, n := range capNames {
		if caps.Have&n.c == 0 && caps.Reason(n.c) == "" {
			t.Errorf("%s is unavailable with no reason", n.name)
		}
	}

	// Every platform offers the model that needs nothing, because every
	// platform can resolve for devices pointed at it. A gateway that offered no
	// model at all would be telling a Windows user the product is not for them.
	if !caps.Supports(SharingNone) {
		t.Errorf("%s offers no sharing model at all: %v", g.Platform(), caps.Sharing)
	}

	if _, err := g.Interfaces(ctx); err != nil {
		t.Errorf("Interfaces: %v", err)
	}
	// Reconcile is called at start-up before anything else and must be safe on
	// a machine where nothing has ever run.
	rep, err := g.Reconcile(ctx)
	if err != nil {
		t.Errorf("Reconcile: %v", err)
	}
	if !rep.Clean() {
		t.Errorf("Reconcile found leftovers on a machine that has run nothing: %+v", rep)
	}

	// Start either works or refuses. The refusal may be either of two kinds
	// and the difference matters to the caller: an *UnsupportedError is a
	// permanent fact about the platform to be shown in the interface, while a
	// configuration error is something the person who asked can fix. What must
	// not happen is a panic, a half-started gateway, or a refusal that is
	// neither — an error the caller can only print.
	//
	// The test asserted UnsupportedError alone, and so failed on a Linux runner
	// with no wireless adapter, where the honest answer is that this
	// configuration names no interface to serve devices on.
	if _, err := g.Start(ctx, config(nil)); err != nil {
		var ue *UnsupportedError
		if !errors.As(err, &ue) && !isConfigRefusal(err) {
			t.Errorf("Start refused with %v (%T), which is neither a platform limit nor a "+
				"configuration problem the caller could act on", err, err)
		}
		// And whichever it was, nothing was left running.
		if rep, err := g.Reconcile(ctx); err == nil && !rep.Clean() {
			t.Errorf("a refused Start left something behind: %+v", rep)
		}
	}
}

// Enumeration must produce something coherent on whatever machine runs the
// tests, without a network of its own.
func TestEnumerationIsCoherent(t *testing.T) {
	t.Parallel()
	ifaces, err := enumerate(
		func() (string, error) { return "eth0", nil },
		func(name string) (bool, apSupport) {
			return name == "wlan0", apSupport{reason: "driver unknown"}
		},
	)
	if err != nil {
		t.Fatalf("enumerate: %v", err)
	}
	if len(ifaces) == 0 {
		t.Skip("this machine reports no interfaces")
	}
	var loopbacks, routed int
	seen := map[string]bool{}
	for _, x := range ifaces {
		if seen[x.Name] {
			t.Errorf("%s is listed twice", x.Name)
		}
		seen[x.Name] = true
		if x.Kind == KindLoopback {
			loopbacks++
			if x.SupportsAP {
				t.Errorf("%s is a loopback interface that claims to host access points", x.Name)
			}
		}
		if x.HasDefaultRoute {
			routed++
		}
		for _, p := range x.Addrs {
			if !p.IsValid() {
				t.Errorf("%s carries an invalid prefix %v", x.Name, p)
			}
		}
	}
	if loopbacks == 0 {
		t.Error("no loopback interface was listed; a caller choosing an uplink must be able to see and reject it")
	}
	if routed > 1 {
		t.Errorf("%d interfaces claim the default route", routed)
	}
}

// isConfigRefusal reports whether an error is this package telling the caller
// its configuration cannot be satisfied, as opposed to the platform being
// unable to do it at all.
//
// Matched on the message because these are plain errors by design: a
// configuration problem is one the person who asked can fix by asking for
// something else, and giving each its own type would be a taxonomy nobody
// switches on.
func isConfigRefusal(err error) bool {
	for _, s := range []string{
		"needs an interface", "needs a subnet", "needs this machine's address",
		"no interface named", "cannot host an access point", "no wireless adapter",
		"carries the default route", "is down",
	} {
		if strings.Contains(err.Error(), s) {
			return true
		}
	}
	return false
}
