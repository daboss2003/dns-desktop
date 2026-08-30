package hostapd

import (
	"encoding/hex"
	"errors"
	"strings"
	"testing"
)

func base() Config {
	return Config{
		Interface:  "wlan0",
		SSID:       "Home",
		Passphrase: "correct horse battery",
		Country:    "gb",
	}
}

func render(t testing.TB, c Config) string {
	t.Helper()
	s, err := c.Render()
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	return s
}

// directives parses a rendered file the way hostapd would: one key=value per
// line, later wins. Reading it back this way is the point — a test that
// searched the text for a substring would not notice a second, later directive
// overriding the one it found.
func directives(s string) map[string]string {
	out := map[string]string{}
	for line := range strings.SplitSeq(s, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if ok {
			out[k] = v
		}
	}
	return out
}

// TestANameCannotAddADirective is the reason this package exists.
//
// hostapd.conf has no quoting, so a newline in a value is not a character in a
// value — it is the end of the line and the start of another directive. Both
// values here come from a text field in a user interface, and "MyWiFi\nwpa=0"
// is an OPEN network that reads as protected in every screen that shows it.
func TestANameCannotAddADirective(t *testing.T) {
	t.Parallel()
	hostile := []string{
		"MyWiFi\nwpa=0",
		"MyWiFi\r\nwpa=0",
		"MyWiFi\nauth_algs=0",
		"a\nssid2=\"6f70656e\"",
		"x\x00y",
	}
	for _, name := range hostile {
		c := base()
		c.SSID = name

		// Refused, which is the first of two mechanisms.
		err := c.Validate()
		if err == nil {
			t.Errorf("%q was accepted as a name", name)
			continue
		}
		if !errors.Is(err, ErrUnsafeValue) {
			t.Errorf("%q: err = %v, want ErrUnsafeValue", name, err)
		}
		if _, err := c.Render(); err == nil {
			t.Errorf("%q rendered a configuration", name)
		}
	}

	// And the second mechanism, which holds even if the first is ever removed:
	// the name is written as hexadecimal, which has no character that could
	// end a line. A name full of newlines still renders to one directive.
	c := base()
	c.SSID = "Sam & Ana's Wi-Fi"
	d := directives(render(t, c))
	if d["wpa"] != "2" {
		t.Errorf("wpa = %q, want 2", d["wpa"])
	}
	want := `"` + hex.EncodeToString([]byte(c.SSID)) + `"`
	if d["ssid2"] != want {
		t.Errorf("ssid2 = %q, want %q", d["ssid2"], want)
	}
	if _, ok := d["ssid"]; ok {
		t.Error("the name was also written as text, which is the form that can be injected into")
	}
}

// The passphrase is never written for WPA2: the derived key is, so the
// passphrase does not reach the file system at all.
func TestTheWPA2PassphraseNeverReachesTheFile(t *testing.T) {
	t.Parallel()
	c := base()
	out := render(t, c)
	if strings.Contains(out, c.Passphrase) {
		t.Fatal("the passphrase is in the configuration file")
	}
	d := directives(out)
	psk, ok := d["wpa_psk"]
	if !ok {
		t.Fatal("no derived key was written")
	}
	if len(psk) != 64 {
		t.Errorf("the key is %d characters, want 64 hexadecimal digits", len(psk))
	}
	if _, err := hex.DecodeString(psk); err != nil {
		t.Errorf("the key is not hexadecimal: %v", err)
	}
	if _, ok := d["wpa_passphrase"]; ok {
		t.Error("wpa_passphrase was written as well; the passphrase must not be in the file")
	}
}

// The derived key must be the one every client computes: PBKDF2-HMAC-SHA1,
// 4096 iterations, the network name as the salt. Getting it wrong produces an
// access point that beacons and that nothing can join, with no diagnostic
// beyond "wrong password".
func TestTheDerivedKeyMatchesTheStandard(t *testing.T) {
	t.Parallel()
	// IEEE 802.11i test vector: passphrase "password", SSID "IEEE".
	c := Config{Interface: "wlan0", SSID: "IEEE", Passphrase: "password"}
	const want = "f42c6fc52df0ebef9ebb4b90b38a5f902e83fe1b135a70e23aed762e9710a12e"
	if got := c.psk(); got != want {
		t.Errorf("psk = %s, want the 802.11i test vector %s", got, want)
	}
}

// A different name is a different key, because the name is the salt. A
// generator that ignored it would produce one key for every network with the
// same passphrase.
func TestTheKeyDependsOnTheName(t *testing.T) {
	t.Parallel()
	a, b := base(), base()
	b.SSID = "Other"
	if a.psk() == b.psk() {
		t.Error("two networks with different names derived the same key")
	}
}

// SAE needs the passphrase itself, so it is written as text — and '|' separates
// options in a WPA3 password, so a passphrase containing one adds options
// rather than characters.
func TestWPA3RefusesAPassphraseThatWouldAddOptions(t *testing.T) {
	t.Parallel()
	for _, sec := range []Security{WPA3, WPA2WPA3} {
		c := base()
		c.Security = sec
		c.Passphrase = "pass|mac_addr=ff:ff:ff:ff:ff:ff"
		if err := c.Validate(); err == nil {
			t.Errorf("security %d accepted a passphrase containing '|'", sec)
		} else if !errors.Is(err, ErrUnsafeValue) {
			t.Errorf("security %d: err = %v, want ErrUnsafeValue", sec, err)
		}
	}
	// WPA2 never writes the passphrase, so a '|' in it is only a character.
	c := base()
	c.Passphrase = "pass|word"
	if err := c.Validate(); err != nil {
		t.Errorf("WPA2 refused an ordinary passphrase containing '|': %v", err)
	}
}

// WPA2 is the default and transitional mode is not, which looks like the less
// secure choice and is not: transitional advertises management frame protection
// in the RSN element, and older Android phones, printers and televisions refuse
// to associate with an access point that does. Those are exactly the devices
// somebody installs this product to filter, and a device that cannot join the
// filtered network is not filtered.
func TestTheDefaultIsWPA2(t *testing.T) {
	t.Parallel()
	d := directives(render(t, base()))
	if d["wpa_key_mgmt"] != "WPA-PSK" {
		t.Errorf("wpa_key_mgmt = %q, want WPA-PSK", d["wpa_key_mgmt"])
	}
	if d["wpa"] != "2" {
		t.Errorf("wpa = %q, want 2 — WPA1 must never be offered", d["wpa"])
	}
	if d["auth_algs"] != "1" {
		t.Errorf("auth_algs = %q, want 1 — shared-key authentication is WEP", d["auth_algs"])
	}
	if _, ok := d["ieee80211w"]; ok {
		t.Error("management frame protection is advertised by default, which older devices refuse")
	}
	if d["rsn_pairwise"] != "CCMP" {
		t.Errorf("rsn_pairwise = %q, want CCMP — TKIP must not be offered", d["rsn_pairwise"])
	}
}

func TestWPA3AndTransitionalDiffer(t *testing.T) {
	t.Parallel()
	only := base()
	only.Security = WPA3
	d := directives(render(t, only))
	if d["wpa_key_mgmt"] != "SAE" || d["ieee80211w"] != "2" {
		t.Errorf("WPA3-only: key_mgmt=%q mfp=%q, want SAE and required", d["wpa_key_mgmt"], d["ieee80211w"])
	}
	if _, ok := d["wpa_psk"]; ok {
		t.Error("WPA3-only wrote a pre-shared key, which SAE does not use")
	}

	both := base()
	both.Security = WPA2WPA3
	d = directives(render(t, both))
	if d["wpa_key_mgmt"] != "WPA-PSK SAE" || d["ieee80211w"] != "1" {
		t.Errorf("transitional: key_mgmt=%q mfp=%q, want both and optional", d["wpa_key_mgmt"], d["ieee80211w"])
	}
	if d["wpa_psk"] == "" {
		t.Error("transitional wrote no pre-shared key, so no WPA2 device could join")
	}
}

func TestAnOpenNetworkIsExplicitlyOpen(t *testing.T) {
	t.Parallel()
	c := base()
	c.Security = Open
	c.Passphrase = ""
	d := directives(render(t, c))
	if d["wpa"] != "0" {
		t.Errorf("wpa = %q, want 0", d["wpa"])
	}
	for _, k := range []string{"wpa_psk", "sae_password", "wpa_key_mgmt"} {
		if _, ok := d[k]; ok {
			t.Errorf("an open network wrote %s", k)
		}
	}
}

// An interface name reaches a command line as well as a file.
func TestInterfaceNamesAreConstrained(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"wlan0; rm -rf /", "wlan0\nx=1", "$(id)", "../etc/passwd", strings.Repeat("a", 20)} {
		c := base()
		c.Interface = name
		if err := c.Validate(); err == nil {
			t.Errorf("interface %q was accepted", name)
		}
	}
	for _, name := range []string{"wlan0", "wlp3s0", "ap-0", "en_1", "phy0.ap"} {
		c := base()
		c.Interface = name
		if err := c.Validate(); err != nil {
			t.Errorf("interface %q was refused: %v", name, err)
		}
	}
}

// The same configuration must render byte-identically every time, or "did
// anything change" is unanswerable — and reconciliation depends on answering it.
func TestRenderingIsStable(t *testing.T) {
	t.Parallel()
	c := base()
	first := render(t, c)
	for range 20 {
		if got := render(t, c); got != first {
			t.Fatalf("rendering is not deterministic:\n%s\n---\n%s", first, got)
		}
	}
}

func TestBandSelection(t *testing.T) {
	t.Parallel()
	// Auto means 2.4 GHz: slower, further, and understood by the printer and
	// the television that somebody installed this product to filter.
	d := directives(render(t, base()))
	if d["hw_mode"] != "g" {
		t.Errorf("auto chose hw_mode %q, want g", d["hw_mode"])
	}

	five := base()
	five.Band = Band5GHz
	d = directives(render(t, five))
	if d["hw_mode"] != "a" {
		t.Errorf("5 GHz chose hw_mode %q, want a", d["hw_mode"])
	}
	// A channel needing radar detection would make the access point take up to
	// a minute to appear and sometimes vanish again.
	if d["channel"] != "36" {
		t.Errorf("5 GHz chose channel %q, want 36 — a channel needing DFS is a hotspot that disappears", d["channel"])
	}

	pinned := base()
	pinned.Band, pinned.Channel = Band2GHz, 11
	if d := directives(render(t, pinned)); d["channel"] != "11" {
		t.Errorf("channel = %q, want the one that was asked for", d["channel"])
	}
}

func TestValidationReportsEveryProblem(t *testing.T) {
	t.Parallel()
	err := Config{SSID: strings.Repeat("x", 40), Passphrase: "short", Country: "GBR", MaxClients: -1}.Validate()
	if err == nil {
		t.Fatal("an invalid configuration was accepted")
	}
	for _, want := range []string{"interface is required", "maximum is 32", "at least 8", "two-letter", "max clients"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error does not mention %q:\n%v", want, err)
		}
	}
}

func TestOptionalSettings(t *testing.T) {
	t.Parallel()
	c := base()
	c.Hidden = true
	c.MaxClients = 12
	c.Bridge = "br-gwdns"
	c.ControlInterface = "/run/gatewaydns/hostapd"
	c.ControlGroup = "gatewaydns"
	d := directives(render(t, c))

	// 2, not 1: a zero-length name is handled by fewer client drivers than a
	// zero-filled one of the right length.
	if d["ignore_broadcast_ssid"] != "2" {
		t.Errorf("ignore_broadcast_ssid = %q, want 2", d["ignore_broadcast_ssid"])
	}
	if d["max_num_sta"] != "12" || d["bridge"] != "br-gwdns" {
		t.Errorf("config = %v", d)
	}
	// Without the group, the control socket is root-owned and an unprivileged
	// interface process reports no clients on a working access point.
	if d["ctrl_interface_group"] != "gatewaydns" {
		t.Errorf("ctrl_interface_group = %q", d["ctrl_interface_group"])
	}
	if d["ieee80211d"] != "1" {
		t.Error("a country code was set without ieee80211d, so the driver may ignore it")
	}
}
