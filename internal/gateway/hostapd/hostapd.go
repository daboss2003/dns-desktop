// Package hostapd builds the configuration that turns a wireless adapter into
// an access point.
//
// It builds text and nothing else: no process is started here and no file is
// written. That is what lets the security-critical half of the Linux gateway be
// tested on any machine, including one with no wireless adapter and no root —
// and the security-critical half is exactly this, for a reason worth stating.
//
// # Why a configuration file is an injection target
//
// hostapd.conf is key=value, one per line, with no quoting and no escaping. A
// value containing a newline is not a value containing a newline; it is a value
// followed by another directive. Both values here — the network's name and its
// passphrase — arrive from a text field in a user interface.
//
//	ssid=MyWiFi
//	wpa=0
//
// is what "MyWiFi\nwpa=0" produces, and it is an OPEN network that reads as
// protected in every screen that shows it. Nobody would notice until somebody
// else was on it.
//
// So neither string is ever written as text:
//
//   - The name goes out as ssid2=<hex>, hostapd's own hexadecimal form, which
//     has no character that could end a line.
//   - For WPA2 the passphrase is never written at all. The 256-bit pairwise
//     master key is derived here — PBKDF2-HMAC-SHA1 over the passphrase and the
//     name, 4096 iterations, which is what IEEE 802.11i specifies — and written
//     as wpa_psk=<64 hex digits>. The passphrase never reaches the file system.
//   - WPA3 has no equivalent: SAE needs the passphrase itself, so sae_password
//     is written as text and [Config.Validate] refuses every character that
//     could matter there, including the '|' that separates its own options.
//
// Rejecting bad input and encoding it unambiguously are two mechanisms for one
// hazard, kept deliberately: the failure mode of the first alone is a network
// with no password on it.
package hostapd

import (
	"crypto/pbkdf2"
	//nolint:gosec // G505: SHA-1 is not a choice here. IEEE 802.11i specifies
	// PBKDF2-HMAC-SHA1 for deriving the pairwise master key, and every Wi-Fi
	// client on earth computes the same thing. Using anything else would
	// produce an access point nothing could join.
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// Security is how the network is protected.
type Security uint8

// The supported modes.
const (
	// WPA2 is WPA2-PSK, and is the default. See [Config.Validate].
	WPA2 Security = iota
	// WPA2WPA3 is transitional mode.
	WPA2WPA3
	// WPA3 is SAE only.
	WPA3
	// Open is no protection.
	Open
)

// Band is the radio band.
type Band uint8

// The bands.
const (
	// BandAuto lets this package choose, which means 2.4 GHz: it is slower and
	// it is understood by every device ever made, including the printer and the
	// television that somebody installed this product to filter. A band those
	// cannot join is a band that does not filter them.
	BandAuto Band = iota
	Band2GHz
	Band5GHz
)

// Config describes one access point.
type Config struct {
	// Interface is the wireless interface to use.
	Interface string
	// Bridge is the bridge to attach the access point to, if any.
	Bridge string
	// SSID is the network name, 1 to 32 octets.
	SSID string
	// Passphrase is 8 to 63 characters, ignored when Security is [Open].
	Passphrase string
	Security   Security
	Band       Band
	// Channel is the radio channel. Zero selects one; see [Config.channel].
	Channel int
	// Country is the two-letter regulatory domain. Empty omits it, which
	// leaves the driver in whatever domain it booted with — usually the most
	// restrictive one, which costs channels and power rather than breaking
	// anything.
	Country string
	// Hidden suppresses the name in beacons. It is offered because people ask
	// and it is not security: the name is still in every association, and
	// hiding it makes client devices probe for the network wherever they go.
	Hidden bool
	// MaxClients bounds associations. Zero means the driver's own limit.
	MaxClients int
	// ControlInterface is where hostapd puts its control socket. Empty omits
	// it, which also gives up knowing which stations are connected.
	ControlInterface string
	// ControlGroup owns that socket, so an unprivileged process can read
	// station state without being root.
	ControlGroup string
}

// Errors from [Config.Validate].
var (
	// ErrUnsafeValue reports a value that could alter the configuration's
	// meaning. It is distinct because it is the one validation failure that is
	// a security finding rather than a typo.
	ErrUnsafeValue = errors.New("hostapd: value contains a character that would change the configuration's meaning")
)

// Validate reports every problem with the configuration rather than the first.
func (c Config) Validate() error {
	var errs []error
	if c.Interface == "" {
		errs = append(errs, errors.New("hostapd: an interface is required"))
	}
	if err := safeName("interface", c.Interface); err != nil {
		errs = append(errs, err)
	}
	if c.Bridge != "" {
		if err := safeName("bridge", c.Bridge); err != nil {
			errs = append(errs, err)
		}
	}
	switch n := len(c.SSID); {
	case n == 0:
		errs = append(errs, errors.New("hostapd: the network needs a name"))
	case n > 32:
		errs = append(errs, fmt.Errorf("hostapd: the name is %d octets and the maximum is 32", n))
	}
	// Checked even though the name is written as hexadecimal. Two mechanisms,
	// because the failure mode of the encoding alone silently going away in a
	// later edit is an open network.
	if i := strings.IndexFunc(c.SSID, unsafeRune); i >= 0 {
		errs = append(errs, fmt.Errorf("%w: the name, at offset %d", ErrUnsafeValue, i))
	}
	if c.Security != Open {
		switch n := len(c.Passphrase); {
		case n < 8:
			errs = append(errs, errors.New("hostapd: the passphrase must be at least 8 characters"))
		case n > 63:
			errs = append(errs, errors.New("hostapd: the passphrase must be at most 63 characters"))
		}
		if i := strings.IndexFunc(c.Passphrase, unsafeRune); i >= 0 {
			errs = append(errs, fmt.Errorf("%w: the passphrase, at offset %d", ErrUnsafeValue, i))
		}
		// SAE writes the passphrase as text and uses '|' to separate its own
		// options, so a passphrase containing one would add options rather than
		// characters.
		if c.Security != WPA2 && strings.ContainsRune(c.Passphrase, '|') {
			errs = append(errs, fmt.Errorf(
				"%w: the passphrase contains '|', which separates options in a WPA3 password", ErrUnsafeValue))
		}
	}
	if c.Country != "" && (len(c.Country) != 2 || !isAlpha(c.Country)) {
		errs = append(errs, fmt.Errorf("hostapd: country %q is not a two-letter code", c.Country))
	}
	if c.MaxClients < 0 {
		errs = append(errs, errors.New("hostapd: max clients must not be negative"))
	}
	if c.Channel < 0 {
		errs = append(errs, errors.New("hostapd: channel must not be negative"))
	}
	return errors.Join(errs...)
}

// unsafeRune reports a character that must never reach a configuration file.
//
// Control characters end lines, and a NUL truncates whatever reads the file
// next. Everything else — spaces, punctuation, emoji in a network name — is
// ordinary and permitted, because refusing it would make the product worse for
// no gain.
func unsafeRune(r rune) bool { return r < 0x20 || r == 0x7f }

// safeName checks an interface name, which reaches a command line as well as a
// file.
func safeName(what, name string) error {
	if name == "" {
		return nil
	}
	if len(name) > 15 {
		return fmt.Errorf("hostapd: %s name %q is longer than an interface name can be", what, name)
	}
	for i, r := range name {
		if !(r == '.' || r == '-' || r == '_' || isAlnum(r)) {
			return fmt.Errorf("%w: %s name %q, at offset %d", ErrUnsafeValue, what, name, i)
		}
	}
	return nil
}

func isAlnum(r rune) bool {
	return (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9')
}

func isAlpha(s string) bool {
	for _, r := range s {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z')) {
			return false
		}
	}
	return true
}

// Render returns the configuration file's contents.
//
// It validates first and refuses rather than escaping on the fly, because a
// renderer that repaired its input would hide the fact that the input needed
// repairing — and the input comes from a form somebody typed into.
func (c Config) Render() (string, error) {
	if err := c.Validate(); err != nil {
		return "", err
	}
	kv := map[string]string{
		"interface": c.Interface,
		"driver":    "nl80211",
		// The name in hexadecimal. There is no character in a hexadecimal
		// string that could end a line, so no name can add a directive.
		"ssid2": `"` + hex.EncodeToString([]byte(c.SSID)) + `"`,
		// Beacons every ~100 ms, and the DTIM and RTS defaults hostapd
		// documents. Written explicitly so that a hostapd whose defaults
		// change does not change this product's behaviour underneath it.
		"beacon_int":      "100",
		"dtim_period":     "2",
		"rts_threshold":   "-1",
		"fragm_threshold": "-1",
		// Management frames from a station are answered only after
		// association, which is hostapd's default and is restated here for the
		// same reason.
		"ap_isolate": "0",
	}
	if c.Bridge != "" {
		kv["bridge"] = c.Bridge
	}
	if c.Country != "" {
		kv["country_code"] = strings.ToUpper(c.Country)
		// Without this the driver may ignore the country code entirely.
		kv["ieee80211d"] = "1"
	}
	if c.Hidden {
		// 2, not 1: 1 sends a zero-length name and 2 sends a name of the right
		// length filled with zeroes, which more client drivers handle.
		kv["ignore_broadcast_ssid"] = "2"
	}
	if c.MaxClients > 0 {
		kv["max_num_sta"] = strconv.Itoa(c.MaxClients)
	}
	if c.ControlInterface != "" {
		kv["ctrl_interface"] = c.ControlInterface
		if c.ControlGroup != "" {
			// So the interface process can read station state without running
			// as root. The socket is root-owned by default, which is why an
			// unprivileged reader would otherwise see nothing and report no
			// clients on a working access point.
			kv["ctrl_interface_group"] = c.ControlGroup
		}
	}

	mode, chans := c.radio()
	kv["hw_mode"] = mode
	kv["channel"] = strconv.Itoa(chans)
	if mode == "a" {
		kv["ieee80211n"] = "1"
		kv["ieee80211ac"] = "1"
		kv["wmm_enabled"] = "1"
	} else {
		kv["ieee80211n"] = "1"
		kv["wmm_enabled"] = "1"
	}

	for k, v := range c.security() {
		kv[k] = v
	}

	keys := make([]string, 0, len(kv))
	for k := range kv {
		keys = append(keys, k)
	}
	// Sorted, so that the same configuration renders byte-identically every
	// time. A file that differed between runs would make "did anything change"
	// unanswerable, and reconciliation depends on answering it.
	sort.Strings(keys)

	var b strings.Builder
	b.WriteString("# Generated by GatewayDNS Desktop. Edits are overwritten.\n")
	for _, k := range keys {
		b.WriteString(k)
		b.WriteByte('=')
		b.WriteString(kv[k])
		b.WriteByte('\n')
	}
	return b.String(), nil
}

// security returns the authentication settings.
func (c Config) security() map[string]string {
	if c.Security == Open {
		return map[string]string{"auth_algs": "1", "wpa": "0"}
	}
	out := map[string]string{
		"auth_algs":    "1", // Open system only: shared-key authentication is WEP.
		"wpa":          "2", // RSN. WPA1 is not offered at all.
		"wpa_pairwise": "CCMP",
		"rsn_pairwise": "CCMP",
	}
	switch c.Security {
	case WPA3:
		out["wpa_key_mgmt"] = "SAE"
		out["ieee80211w"] = "2" // Management frame protection required.
		out["sae_password"] = c.Passphrase
		out["sae_require_mfp"] = "1"
	case WPA2WPA3:
		out["wpa_key_mgmt"] = "WPA-PSK SAE"
		out["ieee80211w"] = "1" // Optional, which is what makes it transitional.
		out["sae_password"] = c.Passphrase
		out["wpa_psk"] = c.psk()
	default:
		out["wpa_key_mgmt"] = "WPA-PSK"
		// The derived key rather than the passphrase, so the passphrase never
		// reaches the file system.
		out["wpa_psk"] = c.psk()
	}
	return out
}

// psk derives the 256-bit pairwise master key.
//
// PBKDF2-HMAC-SHA1 over the passphrase with the network name as the salt and
// 4096 iterations, which is what IEEE 802.11i specifies. SHA-1 is not a choice
// here: it is what the standard says, and every client on earth computes the
// same thing.
func (c Config) psk() string {
	key, err := pbkdf2.Key(sha1.New, c.Passphrase, []byte(c.SSID), 4096, 32)
	if err != nil {
		// pbkdf2.Key fails only on parameters this function does not vary.
		panic("hostapd: deriving the key: " + err.Error())
	}
	return hex.EncodeToString(key)
}

// radio returns the hardware mode and channel.
func (c Config) radio() (string, int) {
	band := c.Band
	if band == BandAuto {
		band = Band2GHz
	}
	if band == Band5GHz {
		ch := c.Channel
		if ch == 0 {
			// 36 is the lowest channel in the lower UNII-1 band, which is
			// permitted indoors in every regulatory domain and needs no radar
			// detection. A channel that needed DFS would make the access point
			// take up to a minute to appear, and sometimes vanish again.
			ch = 36
		}
		return "a", ch
	}
	ch := c.Channel
	if ch == 0 {
		// 6 rather than 1 or 11 only because something has to be chosen; all
		// three are non-overlapping and this package cannot survey the air.
		ch = 6
	}
	return "g", ch
}
