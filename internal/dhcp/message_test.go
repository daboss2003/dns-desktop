package dhcp

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"
)

// discover builds a plausible DHCPDISCOVER, the way a phone sends one.
func discover() *Message {
	m := &Message{
		Op:     BootRequest,
		HType:  HTypeEthernet,
		HLen:   6,
		XID:    0xdeadbeef,
		Secs:   4,
		CHAddr: net.HardwareAddr{0x02, 0x1a, 0x2b, 0x3c, 0x4d, 0x5e},
	}
	m.SetMessageType(Discover)
	m.SetBroadcast(true)
	m.Options.SetString(OptionHostName, "pixel")
	m.Options.SetString(OptionVendorClassID, "android-dhcp-14")
	m.Options.Set(OptionParameterRequestList, []byte{1, 3, 6, 15, 26, 28, 51, 58, 59})
	return m
}

func mustPack(t testing.TB, m *Message) []byte {
	t.Helper()
	b, err := m.Pack()
	if err != nil {
		t.Fatalf("Pack: %v", err)
	}
	return b
}

// A message that survives a round trip unchanged is the baseline property: it
// means the decoder and the encoder agree about every field, which is what lets
// every other test below assert about only the field it is interested in.
func TestRoundTripPreservesEveryField(t *testing.T) {
	t.Parallel()
	in := discover()
	in.Hops = 2
	in.CIAddr = netip.MustParseAddr("192.168.4.20")
	in.GIAddr = netip.MustParseAddr("192.168.4.1")
	in.SName = "boot.example"
	in.File = "pxelinux.0"

	out, err := Unpack(mustPack(t, in))
	if err != nil {
		t.Fatalf("Unpack: %v", err)
	}
	for _, tc := range []struct {
		name      string
		got, want any
	}{
		{"Op", out.Op, in.Op},
		{"HType", out.HType, in.HType},
		{"HLen", out.HLen, in.HLen},
		{"Hops", out.Hops, in.Hops},
		{"XID", out.XID, in.XID},
		{"Secs", out.Secs, in.Secs},
		{"Flags", out.Flags, in.Flags},
		{"CIAddr", out.CIAddr, in.CIAddr},
		{"GIAddr", out.GIAddr, in.GIAddr},
		{"SName", out.SName, in.SName},
		{"File", out.File, in.File},
	} {
		if tc.got != tc.want {
			t.Errorf("%s = %v, want %v", tc.name, tc.got, tc.want)
		}
	}
	if !bytes.Equal(out.CHAddr, in.CHAddr) {
		t.Errorf("CHAddr = %s, want %s", out.CHAddr, in.CHAddr)
	}
	for _, opt := range in.Options {
		got, ok := out.Options.Get(opt.Code)
		if !ok {
			t.Errorf("option %s was lost", opt.Code)
			continue
		}
		if !bytes.Equal(got, opt.Data) {
			t.Errorf("option %s = %v, want %v", opt.Code, got, opt.Data)
		}
	}
}

// The encoding must be byte-stable, or a round-trip test proves only that the
// decoder is consistent with itself.
func TestEncodingIsStable(t *testing.T) {
	t.Parallel()
	first := mustPack(t, discover())
	again, err := Unpack(first)
	if err != nil {
		t.Fatal(err)
	}
	if second := mustPack(t, again); !bytes.Equal(first, second) {
		t.Errorf("re-encoding produced different octets:\n first: %x\nsecond: %x", first, second)
	}
}

// RFC 951 relay agents expect a 300-octet BOOTP message and some drop anything
// shorter — silently, which is the part that costs a day.
func TestMessagesArePaddedToTheBOOTPMinimum(t *testing.T) {
	t.Parallel()
	m := &Message{Op: BootRequest, HType: HTypeEthernet, HLen: 6}
	m.SetMessageType(Discover)
	b := mustPack(t, m)
	if len(b) < PadTo {
		t.Errorf("encoded to %d octets, want at least %d", len(b), PadTo)
	}
	// The padding must be legal option data, so a receiver that keeps parsing
	// past the terminator sees pad octets rather than a truncated option.
	end := bytes.IndexByte(b[MinLen:], byte(OptionEnd))
	if end < 0 {
		t.Fatal("no end option")
	}
	for i, c := range b[MinLen+end+1:] {
		if c != byte(OptionPad) {
			t.Fatalf("padding octet %d is %#x, want a pad option", i, c)
		}
	}
}

// RFC 3396: an option over 255 octets is split across several instances of the
// same code and concatenated by the receiver. Without it, a long domain search
// list is truncated at a point that depends on the data — so it works in
// testing and fails on one network.
func TestLongOptionsSplitAndRejoin(t *testing.T) {
	t.Parallel()
	long := bytes.Repeat([]byte("abcdefgh"), 100) // 800 octets, four fragments
	in := discover()
	in.Options.Set(OptionDomainSearch, long)

	wire := mustPack(t, in)
	// On the wire it really is split: no single option may declare more than
	// 255 octets, because the length field is one octet.
	var fragments int
	for i := MinLen; i < len(wire); {
		code := OptionCode(wire[i])
		if code == OptionEnd {
			break
		}
		if code == OptionPad {
			i++
			continue
		}
		n := int(wire[i+1])
		if code == OptionDomainSearch {
			fragments++
			if n > 255 {
				t.Fatalf("fragment declares %d octets", n)
			}
		}
		i += 2 + n
	}
	if fragments < 2 {
		t.Errorf("a %d-octet option was written as %d fragment(s); it cannot fit in one", len(long), fragments)
	}

	out, err := Unpack(wire)
	if err != nil {
		t.Fatal(err)
	}
	got, ok := out.Options.Get(OptionDomainSearch)
	if !ok {
		t.Fatal("the option did not survive the round trip")
	}
	if !bytes.Equal(got, long) {
		t.Errorf("rejoined to %d octets, want %d", len(got), len(long))
	}
	// And a caller sees one option, not four.
	var count int
	for _, o := range out.Options {
		if o.Code == OptionDomainSearch {
			count++
		}
	}
	if count != 1 {
		t.Errorf("caller sees %d instances of the option, want 1", count)
	}
}

// RFC 2131 section 4.1 option overload: the sname and file fields carry options
// too, in the order options, file, sname.
func TestOptionOverloadIsParsedInTheRightOrder(t *testing.T) {
	t.Parallel()
	// Hand-built, because the encoder never produces overloaded messages — only
	// servers short of room do, and this parser has to read theirs.
	b := make([]byte, HeaderLen+4)
	b[0], b[1], b[2] = byte(BootRequest), byte(HTypeEthernet), 6
	binary.BigEndian.PutUint32(b[HeaderLen:], MagicCookie)

	// sname holds "sname-part", file holds "file-part", both under code 200,
	// which RFC 3396 concatenates in the order file then sname.
	copy(b[44:], []byte{200, 10, 's', 'n', 'a', 'm', 'e', '-', 'p', 'a', 'r', 't', byte(OptionEnd)})
	copy(b[44+snameLen:], []byte{200, 9, 'f', 'i', 'l', 'e', '-', 'p', 'a', 'r', 't', byte(OptionEnd)})

	b = append(b,
		byte(OptionMessageType), 1, byte(Discover),
		byte(OptionOverload), 1, overloadFile|overloadSName,
		200, 5, 'o', 'p', 't', '-', 'p',
		byte(OptionEnd),
	)

	m, err := Unpack(b)
	if err != nil {
		t.Fatalf("Unpack: %v", err)
	}
	got, ok := m.Options.Get(200)
	if !ok {
		t.Fatal("the overloaded option was not found")
	}
	if want := "opt-pfile-partsname-part"; string(got) != want {
		t.Errorf("concatenated to %q, want %q — RFC 2131 section 4.1 orders them options, file, sname", got, want)
	}
	// The fields that were overloaded must not also be read as text: the bytes
	// there are options, and rendering them as a boot file name would put
	// binary into a log line.
	if m.SName != "" || m.File != "" {
		t.Errorf("SName = %q, File = %q; both were overloaded and must read as empty", m.SName, m.File)
	}
}

// A client that cannot yet receive unicast sets bit 15 of flags. A server that
// ignores it works with almost every device and never works with one, which is
// among the hardest DHCP faults to diagnose because the server logs a reply.
func TestBroadcastFlagSurvives(t *testing.T) {
	t.Parallel()
	m := discover()
	if !m.Broadcast() {
		t.Fatal("the flag was not set")
	}
	out, err := Unpack(mustPack(t, m))
	if err != nil {
		t.Fatal(err)
	}
	if !out.Broadcast() {
		t.Error("the broadcast flag was lost in a round trip")
	}
	// And a reply carries it, because the reply is the message that has to be
	// broadcast.
	if !out.Reply(Offer).Broadcast() {
		t.Error("Reply dropped the broadcast flag; the offer would be unicast to a client that cannot receive one")
	}
	out.SetBroadcast(false)
	if out.Broadcast() || out.Flags != 0 {
		t.Errorf("clearing the flag left flags = %#04x", out.Flags)
	}
}

// RFC 2131 section 4.3.1 binds a lease to the client identifier when there is
// one and to the hardware address otherwise. A machine that dual boots sends
// one hardware address and two client identifiers; keying on the hardware
// address alone hands the second system the first one's lease and hostname.
func TestClientKeyPrefersTheClientIdentifier(t *testing.T) {
	t.Parallel()
	hw := discover()
	withID := discover()
	withID.Options.Set(OptionClientID, []byte{0xff, 1, 2, 3, 4})

	if hw.ClientKey() == withID.ClientKey() {
		t.Error("a client identifier did not change the lease key")
	}
	// Two clients with the same identifier and different hardware addresses are
	// the same client.
	other := discover()
	other.CHAddr = net.HardwareAddr{0x02, 0, 0, 0, 0, 0x99}
	other.Options.Set(OptionClientID, []byte{0xff, 1, 2, 3, 4})
	if other.ClientKey() != withID.ClientKey() {
		t.Error("the same client identifier on a different NIC produced a different key")
	}
	// A client identifier whose bytes happen to equal a hardware address must
	// not collide with that hardware address.
	collide := discover()
	collide.Options.Set(OptionClientID, []byte(hw.CHAddr))
	if collide.ClientKey() == hw.ClientKey() {
		t.Error("a client identifier collided with a hardware address of the same bytes")
	}
}

// The three kinds of DHCPREQUEST are answered differently, and a server that
// confused them would answer another server's client or hand a renewing client
// a second address.
func TestRequestKindFollowsRFC2131Section432(t *testing.T) {
	t.Parallel()
	server := netip.MustParseAddr("192.168.4.1")
	wanted := netip.MustParseAddr("192.168.4.20")

	build := func(f func(*Message)) *Message {
		m := discover()
		m.SetMessageType(Request)
		f(m)
		return m
	}
	for _, tc := range []struct {
		name string
		m    *Message
		want RequestKind
	}{
		{"selecting", build(func(m *Message) {
			m.Options.SetAddr(OptionServerID, server)
			m.Options.SetAddr(OptionRequestedIP, wanted)
		}), RequestSelecting},
		{"init-reboot", build(func(m *Message) {
			m.Options.SetAddr(OptionRequestedIP, wanted)
		}), RequestInitReboot},
		{"renewing", build(func(m *Message) {
			m.CIAddr = wanted
		}), RequestRenewing},
		{"neither", build(func(m *Message) {}), RequestUnknown},
		{"not a request", discover(), RequestUnknown},
	} {
		if got := tc.m.RequestKind(); got != tc.want {
			t.Errorf("%s: RequestKind = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// A hostname is the one field in this product whose contents an unauthenticated
// stranger on the network chooses, and it is displayed to the person deciding
// what to block.
func TestHostNamesAreSanitised(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct{ in, want string }{
		{"pixel", "pixel"},
		{"living-room\x00junk", "living-room"},
		{"line\r\nbreak", "linebreak"},
		{"\x1b[31mred", "[31mred"},
		{strings.Repeat("a", 200), strings.Repeat("a", 63)},
		{"  spaced  ", "spaced"},
	} {
		m := discover()
		m.Options.SetString(OptionHostName, tc.in)
		if got := m.HostName(); got != tc.want {
			t.Errorf("HostName(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// RFC 4702 carries a name too, in DNS wire form when the E flag is set. It is
// where a Windows machine's name arrives from.
func TestHostNameFallsBackToTheFQDNOption(t *testing.T) {
	t.Parallel()
	m := discover()
	m.Options.Delete(OptionHostName)
	// flags=0x04 (E), rcode1, rcode2, then \x07desktop\x05local\x00.
	m.Options.Set(OptionClientFQDN, append([]byte{0x04, 0, 0},
		append([]byte{7}, append([]byte("desktop"), append([]byte{5}, append([]byte("local"), 0)...)...)...)...))
	if got := m.HostName(); got != "desktop.local" {
		t.Errorf("HostName = %q, want %q", got, "desktop.local")
	}

	// Without the E flag the name is plain text.
	m.Options.Set(OptionClientFQDN, append([]byte{0x00, 0, 0}, []byte("laptop.local")...))
	if got := m.HostName(); got != "laptop.local" {
		t.Errorf("plain-text FQDN = %q, want %q", got, "laptop.local")
	}

	// A compression pointer is not followed: there is no message here to point
	// into, so the only safe thing is to stop.
	m.Options.Set(OptionClientFQDN, []byte{0x04, 0, 0, 0xc0, 0x0c})
	if got := m.HostName(); got != "" {
		t.Errorf("a compression pointer yielded %q, want empty", got)
	}
}

// Unpack is reachable from anyone who can broadcast to port 67. No input may
// panic, and every refusal must be distinguishable — a short packet is a scan,
// a bad cookie is something that is not DHCP at all.
func TestMalformedInputIsRefusedNotFatal(t *testing.T) {
	t.Parallel()
	good := mustPack(t, discover())

	for _, tc := range []struct {
		name string
		in   []byte
		want error
	}{
		{"empty", nil, ErrShortMessage},
		{"one octet", []byte{1}, ErrShortMessage},
		{"header without cookie", make([]byte, HeaderLen), ErrShortMessage},
		{"header with wrong cookie", make([]byte, MinLen), ErrBadCookie},
		{"too long", make([]byte, MaxMessageLen+1), ErrTooLong},
	} {
		_, err := Unpack(tc.in)
		if !errors.Is(err, tc.want) {
			t.Errorf("%s: err = %v, want %v", tc.name, err, tc.want)
		}
	}

	// Every truncation of a valid message either decodes or is refused, and
	// none of them panics. Truncation is what a lossy relay produces, and it is
	// the cheapest thing for an attacker to try.
	for i := range good {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("Unpack panicked on the first %d octets of a valid message: %v", i, r)
				}
			}()
			_, _ = Unpack(good[:i])
		}()
	}

	// So does corrupting any single octet.
	for i := range good {
		corrupt := append([]byte(nil), good...)
		corrupt[i] ^= 0xff
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("Unpack panicked with octet %d corrupted: %v", i, r)
				}
			}()
			_, _ = Unpack(corrupt)
		}()
	}
}

// HLen is the sender's claim about its own address length. A client claiming
// more than the field holds is broken or probing, and the extra octets are not
// there to be read.
func TestOversizedHardwareLengthIsClamped(t *testing.T) {
	t.Parallel()
	b := make([]byte, MinLen)
	b[0], b[1], b[2] = byte(BootRequest), byte(HTypeEthernet), 0xff
	binary.BigEndian.PutUint32(b[HeaderLen:], MagicCookie)
	b = append(b, byte(OptionMessageType), 1, byte(Discover), byte(OptionEnd))

	m, err := Unpack(b)
	if err != nil {
		t.Fatalf("Unpack: %v", err)
	}
	if len(m.CHAddr) > chaddrLen {
		t.Errorf("read %d octets of hardware address from a %d-octet field", len(m.CHAddr), chaddrLen)
	}
	// And the message cannot be re-encoded with the bogus length, rather than
	// being encoded into something that overruns the field.
	if _, err := m.Pack(); err == nil {
		t.Error("a message claiming hlen=255 re-encoded without complaint")
	}
}

// Unpack must not retain the caller's buffer: a server reuses one receive
// buffer for every packet, and an option that changed value when the next
// packet arrived would be a bug visible only under load.
func TestUnpackDoesNotAliasTheCallersBuffer(t *testing.T) {
	t.Parallel()
	buf := mustPack(t, discover())
	m, err := Unpack(buf)
	if err != nil {
		t.Fatal(err)
	}
	name := m.HostName()
	hw := append(net.HardwareAddr(nil), m.CHAddr...)

	for i := range buf {
		buf[i] = 0xaa
	}
	if got := m.HostName(); got != name {
		t.Errorf("host name changed to %q when the receive buffer was reused; it was %q", got, name)
	}
	if !bytes.Equal(m.CHAddr, hw) {
		t.Errorf("hardware address changed to %s when the receive buffer was reused", m.CHAddr)
	}
}

func TestOptionAccessors(t *testing.T) {
	t.Parallel()
	var o Options
	o.SetAddr(OptionServerID, netip.MustParseAddr("192.168.4.1"))
	o.SetAddrs(OptionDNSServer, []netip.Addr{
		netip.MustParseAddr("192.168.4.1"), netip.MustParseAddr("9.9.9.9"),
	})
	o.SetDuration(OptionLeaseTime, 2*time.Hour)
	o.SetUint16(OptionMaxMessageSize, 1500)

	if a, ok := o.Addr(OptionServerID); !ok || a.String() != "192.168.4.1" {
		t.Errorf("Addr = %v, %v", a, ok)
	}
	if as, ok := o.Addrs(OptionDNSServer); !ok || len(as) != 2 {
		t.Errorf("Addrs = %v, %v", as, ok)
	}
	if d, ok := o.Duration(OptionLeaseTime); !ok || d != 2*time.Hour {
		t.Errorf("Duration = %v, %v", d, ok)
	}
	if v, ok := o.Uint16(OptionMaxMessageSize); !ok || v != 1500 {
		t.Errorf("Uint16 = %v, %v", v, ok)
	}

	// A wrong-length field is not a shorter value. Guessing at the missing
	// octet is how a server hands out an address on the wrong network.
	o.Set(OptionServerID, []byte{192, 168, 4})
	if _, ok := o.Addr(OptionServerID); ok {
		t.Error("a three-octet address option was accepted")
	}
	o.Set(OptionDNSServer, []byte{192, 168, 4, 1, 9})
	if _, ok := o.Addrs(OptionDNSServer); ok {
		t.Error("an address list of a non-multiple-of-four length was accepted")
	}

	o.Delete(OptionServerID)
	if o.Has(OptionServerID) {
		t.Error("Delete left the option behind")
	}
}

// The infinite lease of RFC 2131 section 3.3 must survive as a sentinel, not
// as 136 years — a caller comparing against a wall clock would otherwise get an
// answer that is right until 2106.
func TestInfiniteLeaseRoundTrips(t *testing.T) {
	t.Parallel()
	var o Options
	o.SetDuration(OptionLeaseTime, Infinite)
	if v, _ := o.Uint32(OptionLeaseTime); v != infiniteSeconds {
		t.Errorf("encoded as %d, want %d", v, uint32(infiniteSeconds))
	}
	if d, ok := o.Duration(OptionLeaseTime); !ok || d != Infinite {
		t.Errorf("decoded as %v, want Infinite", d)
	}
	// And an over-long duration clamps to infinite rather than wrapping, which
	// would turn a very long lease into a very short one and produce a
	// network-wide re-request storm.
	o.SetDuration(OptionLeaseTime, 200*365*24*time.Hour)
	if d, _ := o.Duration(OptionLeaseTime); d != Infinite {
		t.Errorf("a two-hundred-year lease became %v", d)
	}
	o.SetDuration(OptionLeaseTime, -time.Hour)
	if v, _ := o.Uint32(OptionLeaseTime); v != 0 {
		t.Errorf("a negative lease encoded as %d", v)
	}
}

// A relay uses option 82 to decide which port to send the reply out of. RFC
// 3046 section 2.1.1 requires the server to echo it unchanged; dropping it
// means the reply arrives nowhere.
func TestReplyEchoesRelayAgentInformation(t *testing.T) {
	t.Parallel()
	m := discover()
	m.GIAddr = netip.MustParseAddr("10.0.0.1")
	circuit := []byte{1, 4, 'e', 't', 'h', '0'}
	m.Options.Set(OptionRelayAgentInfo, circuit)

	r := m.Reply(Offer)
	got, ok := r.Options.Get(OptionRelayAgentInfo)
	if !ok {
		t.Fatal("the relay agent option was not echoed")
	}
	if !bytes.Equal(got, circuit) {
		t.Errorf("echoed %v, want %v unchanged", got, circuit)
	}
	if r.GIAddr != m.GIAddr {
		t.Errorf("GIAddr = %v, want the relay's %v — the reply goes back to the relay", r.GIAddr, m.GIAddr)
	}
	if r.Op != BootReply {
		t.Errorf("Op = %v, want BootReply", r.Op)
	}
	if r.XID != m.XID {
		t.Error("the transaction identifier was not echoed; the client would discard the reply")
	}
}

// A client asking for a reply too small to hold a lease is asking for something
// unusable, so the floor is the RFC 2131 minimum.
func TestMaxSizeHasAFloor(t *testing.T) {
	t.Parallel()
	m := discover()
	if got := m.MaxSize(); got != DefaultMaxSize {
		t.Errorf("with no option 57, MaxSize = %d, want %d", got, DefaultMaxSize)
	}
	m.Options.SetUint16(OptionMaxMessageSize, 100)
	if got := m.MaxSize(); got != DefaultMaxSize {
		t.Errorf("MaxSize = %d for a client asking 100, want the %d floor", got, DefaultMaxSize)
	}
	m.Options.SetUint16(OptionMaxMessageSize, 1500)
	if got := m.MaxSize(); got != 1500 {
		t.Errorf("MaxSize = %d, want 1500", got)
	}
}

// Pad and End inside the option list are structural, not data. Emitting one
// from the list would terminate the message early and discard everything after.
func TestStructuralOptionsAreNotEmitted(t *testing.T) {
	t.Parallel()
	m := discover()
	m.Options = append(Options{{Code: OptionEnd}}, m.Options...)
	m.Options = append(m.Options, Option{Code: OptionPad})

	out, err := Unpack(mustPack(t, m))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := out.MessageType(); !ok {
		t.Error("an End option in the list truncated the message: the message type was lost")
	}
	if _, ok := out.Options.Get(OptionHostName); !ok {
		t.Error("options after a structural code were dropped")
	}
}

// A message with no option 53 is BOOTP, not DHCP. A BOOTP client will not
// understand a DHCP reply, so answering one as though it were DHCP is worse
// than not answering.
func TestBootpIsDistinguishable(t *testing.T) {
	t.Parallel()
	m := &Message{Op: BootRequest, HType: HTypeEthernet, HLen: 6}
	out, err := Unpack(mustPack(t, m))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := out.MessageType(); ok {
		t.Error("a message with no option 53 reported a DHCP message type")
	}
	if !strings.HasPrefix(out.String(), "BOOTP") {
		t.Errorf("String = %q, want it to say BOOTP", out.String())
	}
}

func TestOversizedFixedFieldsAreRefused(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		m    *Message
	}{
		{"sname", &Message{SName: strings.Repeat("a", snameLen)}},
		{"file", &Message{File: strings.Repeat("a", fileLen)}},
		{"chaddr", &Message{CHAddr: make(net.HardwareAddr, chaddrLen+1)}},
	} {
		if _, err := tc.m.Pack(); err == nil {
			t.Errorf("%s: an oversized field encoded without complaint", tc.name)
		}
	}
}

func FuzzUnpack(f *testing.F) {
	f.Add(mustPack(f, discover()))
	f.Add(make([]byte, MinLen))
	f.Add([]byte{})

	long := discover()
	long.Options.Set(OptionDomainSearch, bytes.Repeat([]byte("x"), 700))
	f.Add(mustPack(f, long))

	f.Fuzz(func(t *testing.T, b []byte) {
		m, err := Unpack(b)
		if err != nil {
			return
		}
		// Anything that decodes must re-encode and decode again to the same
		// thing. A decoder that accepts what its encoder cannot produce is a
		// decoder that has invented a field value.
		out, err := m.Pack()
		if err != nil {
			// Only the field-length checks may refuse, and only for a message
			// whose lengths Unpack clamped.
			if m.HLen <= chaddrLen && len(m.SName) < snameLen && len(m.File) < fileLen {
				t.Fatalf("a decoded message would not re-encode: %v", err)
			}
			return
		}
		again, err := Unpack(out)
		if err != nil {
			t.Fatalf("a re-encoded message would not decode: %v", err)
		}
		if again.XID != m.XID || again.Op != m.Op || again.CIAddr != m.CIAddr {
			t.Errorf("round trip changed the message: %v then %v", m, again)
		}
		if t1, ok1 := m.MessageType(); ok1 {
			if t2, ok2 := again.MessageType(); !ok2 || t1 != t2 {
				t.Errorf("message type %v became %v (%v)", t1, t2, ok2)
			}
		}
	})
}
