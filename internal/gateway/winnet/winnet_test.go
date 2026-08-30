package winnet

import (
	"errors"
	"net/netip"
	"strings"
	"testing"
)

// The network's name and passphrase come from a text field and end up inside a
// PowerShell string literal. A single quote closes it, and what follows is a
// statement.
func TestAQuoteCannotEndTheLiteral(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct{ in, want string }{
		{"Home", "'Home'"},
		{"Sam's Wi-Fi", "'Sam''s Wi-Fi'"},
		{"'; Remove-Item C:\\ -Recurse; '", "'''; Remove-Item C:\\ -Recurse; '''"},
		{"$(whoami)", "'$(whoami)'"}, // Inert inside a single-quoted literal.
		{"`n", "'`n'"},               // So is a backtick escape.
		{"a\"b", "'a\"b'"},           // And a double quote.
	} {
		if got := Quote(tc.in); got != tc.want {
			t.Errorf("Quote(%q) = %s, want %s", tc.in, got, tc.want)
		}
	}

	// Every quote in the output is either the delimiter or doubled, which is
	// the property that makes the literal unbreakable.
	for _, in := range []string{"'", "''", "a'b'c", strings.Repeat("'", 9)} {
		q := Quote(in)
		body := q[1 : len(q)-1]
		for i := 0; i < len(body); i++ {
			if body[i] != '\'' {
				continue
			}
			if i+1 >= len(body) || body[i+1] != '\'' {
				t.Errorf("Quote(%q) = %s has a lone quote at %d", in, q, i)
				break
			}
			i++
		}
	}
}

// A control character ends a statement, and no quoting fixes that.
func TestControlCharactersAreRefused(t *testing.T) {
	t.Parallel()
	for _, h := range []Hotspot{
		{SSID: "Home\nRemove-Item C:\\", Passphrase: "correcthorse"},
		{SSID: "Home", Passphrase: "correct\r\nhorse"},
		{SSID: "Ho\x00me", Passphrase: "correcthorse"},
	} {
		err := h.Validate()
		if err == nil {
			t.Errorf("%+v was accepted", h)
			continue
		}
		if !errors.Is(err, ErrUnsafeValue) {
			t.Errorf("%+v: err = %v, want ErrUnsafeValue", h, err)
		}
		if _, err := TetheringStart(h); err == nil {
			t.Errorf("%+v produced a script", h)
		}
	}

	// An ordinary name with an apostrophe is fine, and reaches the script
	// intact.
	h := Hotspot{SSID: "Sam's Wi-Fi", Passphrase: "correct horse battery"}
	if err := h.Validate(); err != nil {
		t.Fatalf("an ordinary name was refused: %v", err)
	}
	s, err := TetheringStart(h)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(s, "'Sam''s Wi-Fi'") {
		t.Errorf("the name was not quoted into the script:\n%s", s)
	}
	if strings.Contains(s, "'Sam's Wi-Fi'") {
		t.Error("the name appears unescaped, which would end the literal")
	}
}

func TestHotspotValidationReportsEveryProblem(t *testing.T) {
	t.Parallel()
	err := Hotspot{SSID: strings.Repeat("x", 40), Passphrase: "short"}.Validate()
	if err == nil {
		t.Fatal("an invalid hotspot was accepted")
	}
	for _, want := range []string{"maximum is 32", "at least 8"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error does not mention %q:\n%v", want, err)
		}
	}
	if err := (Hotspot{Passphrase: "correcthorse"}).Validate(); err == nil ||
		!strings.Contains(err.Error(), "needs a name") {
		t.Errorf("err = %v, want it to ask for a name", err)
	}
}

// Authentication is deliberately not configured: the property that would set it
// does not exist before Windows 11 24H2, so on the versions this targets the
// system chooses. A script that set it would fail on most machines.
func TestTheHotspotScriptDoesNotConfigureAuthentication(t *testing.T) {
	t.Parallel()
	s, err := TetheringStart(Hotspot{SSID: "Home", Passphrase: "correcthorse"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(s, "AuthenticationKind") {
		t.Error("the script sets AuthenticationKind, which does not exist before Windows 11 24H2")
	}
	// It must check the result rather than assuming success: the operation
	// status is the entire diagnostic surface of this API, and "the hotspot
	// silently did not start" is the failure it prevents.
	if !strings.Contains(s, "$result.Status") {
		t.Error("the script does not check the operation's status")
	}
	if !strings.Contains(s, "AdditionalErrorMessage") {
		t.Error("the script discards the API's own error message")
	}
}

// The capability probe is the documented way to find out whether this API can
// be used at all from a program packaged as this one is, and its answer is
// needed before anything is attempted.
func TestTheStatusScriptProbesCapabilityFirst(t *testing.T) {
	t.Parallel()
	s := TetheringStatus()
	cap := strings.Index(s, "GetTetheringCapabilityFromConnectionProfile")
	create := strings.Index(s, "CreateFromConnectionProfile")
	if cap < 0 {
		t.Fatal("the status script does not probe the capability")
	}
	if create >= 0 && create < cap {
		t.Error("the manager is created before the capability is probed, so an unusable API throws instead of reporting")
	}
	// The connected stations are what rescues a device list on this platform,
	// where our own DHCP server does not run.
	for _, want := range []string{"GetTetheringClients", "MacAddress", "HostNames"} {
		if !strings.Contains(s, want) {
			t.Errorf("the status script does not read %s", want)
		}
	}
	if !strings.Contains(s, "ConvertTo-Json") {
		t.Error("the status script does not return something parseable")
	}
}

// Windows permits one NAT network per host, so somebody else's is the reason
// ours cannot be created — and "there is already one called DockerNAT" is an
// answer while "could not create" is not.
func TestTheNATIsNamespacedAndItsStatusListsEveryone(t *testing.T) {
	t.Parallel()
	create, err := NatCreate(netip.MustParsePrefix("10.42.0.0/24"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(create, "'GatewayDNS'") {
		t.Errorf("the translation is not named:\n%s", create)
	}
	if !strings.Contains(create, "'10.42.0.0/24'") {
		t.Errorf("the subnet is not quoted:\n%s", create)
	}
	// The status must not filter to ours, or the one-per-host collision is
	// invisible.
	if s := NatStatus(); strings.Contains(s, "GatewayDNS") {
		t.Errorf("the status only lists our own translation:\n%s", s)
	}
	// Removal tolerates absence, because teardown runs where the state is
	// unknown and a cleanup that fails stops before the next step.
	if r := NatRemove(); !strings.Contains(r, "SilentlyContinue") {
		t.Errorf("removal does not tolerate the translation being absent:\n%s", r)
	}
	if _, err := NatCreate(netip.MustParsePrefix("fd00::/64")); err == nil {
		t.Error("an IPv6 prefix was accepted")
	}
}

// A bring-up after an unclean stop meets an address that is already there, and
// New-NetIPAddress fails on one rather than replacing it.
func TestAssigningAnAddressToleratesOneAlreadyThere(t *testing.T) {
	t.Parallel()
	s, err := AddressAssign("Wi-Fi", netip.MustParseAddr("10.42.0.1"), 24)
	if err != nil {
		t.Fatal(err)
	}
	rm := strings.Index(s, "Remove-NetIPAddress")
	add := strings.Index(s, "New-NetIPAddress")
	if rm < 0 || add < 0 || rm > add {
		t.Errorf("the existing address is not removed first:\n%s", s)
	}
	if !strings.Contains(s, "-PrefixLength 24") {
		t.Errorf("the prefix length is missing:\n%s", s)
	}
	// Interface aliases on Windows are user-facing names with spaces in them.
	if !strings.Contains(s, "'Wi-Fi'") {
		t.Errorf("the interface alias is not quoted:\n%s", s)
	}
	if _, err := AddressAssign("Wi-Fi", netip.MustParseAddr("10.42.0.1"), 0); err == nil {
		t.Error("a zero prefix length was accepted")
	}
	if _, err := AddressAssign("", netip.MustParseAddr("10.42.0.1"), 24); err == nil {
		t.Error("an empty interface was accepted")
	}
}

// Interface aliases legitimately contain spaces, so they cannot be held to a
// programmer's idea of a name — but a control character still ends a statement.
func TestInterfaceAliasesAllowSpacesAndRefuseControlCharacters(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"Wi-Fi", "Local Area Connection", "Ethernet 2", "Wi-Fi (2.4 GHz)"} {
		if _, err := Forwarding(name, true); err != nil {
			t.Errorf("alias %q was refused: %v", name, err)
		}
	}
	for _, name := range []string{"Wi-Fi\nSet-Foo", "a\x00b", ""} {
		if _, err := Forwarding(name, true); err == nil {
			t.Errorf("alias %q was accepted", name)
		}
	}
}

// Per interface, not the machine-wide registry value: that one needs a reboot
// and turns forwarding on for the uplink too.
func TestForwardingIsPerInterface(t *testing.T) {
	t.Parallel()
	on, err := Forwarding("Wi-Fi", true)
	if err != nil {
		t.Fatal(err)
	}
	off, _ := Forwarding("Wi-Fi", false)
	if !strings.Contains(on, "-Forwarding Enabled") || !strings.Contains(off, "-Forwarding Disabled") {
		t.Errorf("on = %q\noff = %q", on, off)
	}
	if strings.Contains(on, "IPEnableRouter") {
		t.Error("the machine-wide registry value is used, which needs a reboot and affects the uplink")
	}
	// And it can be read back, so teardown restores what it found rather than
	// assuming it was off.
	read, err := ForwardingState("Wi-Fi")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(read, "Get-NetIPInterface") {
		t.Errorf("forwarding cannot be read back:\n%s", read)
	}
}

// PowerShell cannot await a WinRT operation directly, so the helper finds the
// right generic overload by reflection. If it is ever absent the scripts
// silently return an unfinished operation.
func TestTheAwaitHelperIsPresentAndChecked(t *testing.T) {
	t.Parallel()
	if !strings.Contains(AwaitHelper, "AsTask") {
		t.Error("the helper does not bind AsTask")
	}
	if !strings.Contains(AwaitHelper, "MakeGenericMethod") {
		t.Error("the helper does not bind the operation's own result type")
	}
	if !strings.Contains(AwaitHelper, "IsFaulted") {
		t.Error("the helper ignores a faulted operation, so a failure would read as success")
	}
	for _, s := range []string{TetheringStop()} {
		if strings.Contains(s, "Await ") && !strings.Contains(AwaitHelper, "function Await") {
			t.Error("a script awaits without the helper being defined")
		}
	}
}
