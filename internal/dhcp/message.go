package dhcp

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
)

// Wire layout constants, RFC 951 section 3 as reinterpreted by RFC 2131
// section 2.
const (
	// HeaderLen is the fixed part: op, htype, hlen, hops, xid, secs, flags,
	// ciaddr, yiaddr, siaddr, giaddr, chaddr, sname, file.
	HeaderLen = 236
	// MagicCookie is 99.130.83.99, RFC 2132 section 2. It is what tells a
	// receiver that what follows is DHCP options rather than BOOTP vendor data.
	MagicCookie = 0x63825363
	// MinLen is the shortest message this package will decode: the header plus
	// the cookie. Anything shorter cannot carry a message type, so it cannot be
	// a DHCP message at all.
	MinLen = HeaderLen + 4

	// PadTo is the length every encoded message is padded to.
	//
	// Not from RFC 2131, which sets no minimum. It is from RFC 951, whose relay
	// agents expect a 300-octet BOOTP message, and there are still relays and
	// embedded stacks that drop anything shorter — silently, which is the
	// expensive part. Twenty-odd octets of padding is a cheap way not to be
	// the DHCP server that "does not work with that one switch".
	PadTo = 300

	// DefaultMaxSize is the largest reply to send when the client did not say
	// (option 57). RFC 2131 section 2 requires every host to accept a 576-octet
	// IP datagram; less the IP and UDP headers, that leaves 548 octets of DHCP.
	DefaultMaxSize = 576 - 20 - 8

	chaddrLen = 16
	snameLen  = 64
	fileLen   = 128
)

// Errors returned by [Unpack]. They are distinguishable because a server counts
// them separately: a short packet is a scan or a broken client, a bad cookie is
// something that is not DHCP at all arriving on port 67, and telling them apart
// is the difference between a diagnosis and a mystery.
var (
	// ErrShortMessage reports a message shorter than [MinLen].
	ErrShortMessage = errors.New("dhcp: message is shorter than the fixed header and cookie")
	// ErrBadCookie reports a message whose magic cookie is not RFC 2132's.
	ErrBadCookie = errors.New("dhcp: magic cookie is not 99.130.83.99")
	// ErrTooLong reports a message beyond [MaxMessageLen].
	ErrTooLong = errors.New("dhcp: message is implausibly long")
)

// MaxMessageLen bounds what [Unpack] will look at.
//
// A DHCP message arrives in one UDP datagram, so it cannot exceed 65507 octets
// however hostile the sender. The bound is here anyway because Unpack is
// reachable from anyone who can send a broadcast to port 67, and a parser whose
// only limit is the caller's buffer is a parser whose limit is whatever the
// caller forgot.
const MaxMessageLen = 65507

// Message is one DHCPv4 message.
//
// Address fields are [netip.Addr] rather than [net.IP] because a DHCPv4 address
// is exactly four octets and netip.Addr cannot be silently the wrong length,
// cannot alias a caller's buffer, and compares with ==. An unset address is the
// zero Addr, which encodes as 0.0.0.0 — the same thing the wire format means by
// it.
type Message struct {
	// Op is the direction: [BootRequest] or [BootReply].
	Op OpCode
	// HType and HLen describe CHAddr. They are held rather than derived so that
	// a decoded message re-encodes to the same octets, which is what makes
	// round-trip testing meaningful.
	HType HType
	HLen  uint8
	// Hops is incremented by each relay agent.
	Hops uint8
	// XID is the client's transaction identifier. A reply that does not echo it
	// is not an answer to this exchange, and matching on it is the client's
	// only defence against an off-path forgery.
	XID uint32
	// Secs is how long the client has been trying, in seconds. Relay agents use
	// it to decide when to step in.
	Secs uint16
	// Flags carries the broadcast bit; see [Message.Broadcast].
	Flags uint16

	// CIAddr is the client's current address, and is set ONLY when the client
	// already has one and can receive unicast on it — RFC 2131 section 4.1.
	// It is how a RENEWING request is told from an INIT-REBOOT one.
	CIAddr netip.Addr
	// YIAddr is "your" address: the one the server is assigning.
	YIAddr netip.Addr
	// SIAddr is the next server in a boot sequence, not this server. The
	// server's own identity is option 54, and confusing the two is a
	// long-standing way to make PXE clients unbootable.
	SIAddr netip.Addr
	// GIAddr is the relay agent that forwarded this message, and is what a
	// reply is sent back to. Non-zero means the client is not on our link.
	GIAddr netip.Addr

	// CHAddr is the client hardware address, HLen octets of it.
	CHAddr net.HardwareAddr
	// SName and File are BOOTP fields, usually empty. They may instead carry
	// options; see option 52.
	SName string
	File  string

	// Options is the option list, RFC 3396 concatenation already applied.
	Options Options
}

// Unpack decodes a message from b.
//
// b is not retained: every field that needs storage gets a copy, so the caller
// may reuse the receive buffer as soon as this returns. That costs a few
// allocations per message — against one message per device per lease period,
// which is nothing — and removes the failure where an option's value changes
// underneath a lease record because the next packet landed in the same array.
func Unpack(b []byte) (*Message, error) {
	switch {
	case len(b) < MinLen:
		return nil, fmt.Errorf("%w: %d octets, want at least %d", ErrShortMessage, len(b), MinLen)
	case len(b) > MaxMessageLen:
		return nil, fmt.Errorf("%w: %d octets", ErrTooLong, len(b))
	}
	if binary.BigEndian.Uint32(b[HeaderLen:HeaderLen+4]) != MagicCookie {
		return nil, ErrBadCookie
	}

	m := &Message{
		Op:    OpCode(b[0]),
		HType: HType(b[1]),
		HLen:  b[2],
		Hops:  b[3],
		XID:   binary.BigEndian.Uint32(b[4:8]),
		Secs:  binary.BigEndian.Uint16(b[8:10]),
		Flags: binary.BigEndian.Uint16(b[10:12]),
	}
	m.CIAddr = netip.AddrFrom4([4]byte(b[12:16]))
	m.YIAddr = netip.AddrFrom4([4]byte(b[16:20]))
	m.SIAddr = netip.AddrFrom4([4]byte(b[20:24]))
	m.GIAddr = netip.AddrFrom4([4]byte(b[24:28]))

	// HLen is the sender's claim about its own address length and is clamped,
	// not trusted. RFC 2131 gives the field 16 octets; a client claiming more
	// is either broken or probing, and either way the extra octets are not
	// there to be read.
	n := int(m.HLen)
	if n > chaddrLen {
		n = chaddrLen
	}
	if n > 0 {
		m.CHAddr = append(net.HardwareAddr(nil), b[28:28+n]...)
	}

	sname := b[44 : 44+snameLen]
	file := b[44+snameLen : 44+snameLen+fileLen]

	var overload uint8
	m.Options, overload = parseOptions(b[HeaderLen+4:], nil)

	// RFC 2131 section 4.1: when option 52 is present the file field is parsed
	// first and the sname field second, and options found there extend the
	// list. The order is normative because a code appearing in more than one
	// area is concatenated in that order.
	if overload&overloadFile != 0 {
		m.Options, _ = parseOptions(file, m.Options)
		file = nil
	}
	if overload&overloadSName != 0 {
		m.Options, _ = parseOptions(sname, m.Options)
		sname = nil
	}
	m.SName = trimNUL(sname)
	m.File = trimNUL(file)
	return m, nil
}

func trimNUL(b []byte) string {
	if i := indexByte(b, 0); i >= 0 {
		b = b[:i]
	}
	return string(b)
}

func indexByte(b []byte, c byte) int {
	for i := range b {
		if b[i] == c {
			return i
		}
	}
	return -1
}

// Pack encodes the message.
func (m *Message) Pack() ([]byte, error) { return m.AppendTo(nil) }

// AppendTo encodes the message onto b and returns the extended slice.
//
// Appending into a caller's buffer rather than allocating is the same shape the
// engine's dnsmsg encoder uses, and for the same reason: a server answering on
// a socket has a buffer already and should not need a new one per reply.
func (m *Message) AppendTo(b []byte) ([]byte, error) {
	if m.HLen > chaddrLen {
		return nil, fmt.Errorf("dhcp: hlen %d exceeds the %d-octet chaddr field", m.HLen, chaddrLen)
	}
	if len(m.CHAddr) > chaddrLen {
		return nil, fmt.Errorf("dhcp: hardware address is %d octets, want at most %d", len(m.CHAddr), chaddrLen)
	}
	if len(m.SName) >= snameLen {
		return nil, fmt.Errorf("dhcp: sname is %d octets, want under %d", len(m.SName), snameLen)
	}
	if len(m.File) >= fileLen {
		return nil, fmt.Errorf("dhcp: file is %d octets, want under %d", len(m.File), fileLen)
	}

	start := len(b)
	b = append(b, byte(m.Op), byte(m.HType), m.HLen, m.Hops)
	b = binary.BigEndian.AppendUint32(b, m.XID)
	b = binary.BigEndian.AppendUint16(b, m.Secs)
	b = binary.BigEndian.AppendUint16(b, m.Flags)
	for _, a := range [...]netip.Addr{m.CIAddr, m.YIAddr, m.SIAddr, m.GIAddr} {
		b = appendAddr(b, a)
	}

	b = append(b, m.CHAddr...)
	b = append(b, make([]byte, chaddrLen-len(m.CHAddr))...)
	b = appendFixed(b, m.SName, snameLen)
	b = appendFixed(b, m.File, fileLen)

	b = binary.BigEndian.AppendUint32(b, MagicCookie)
	b = m.Options.appendTo(b)

	// Pad to the BOOTP minimum. The padding is OptionPad rather than zero
	// octets so that a receiver parsing past the terminator — some do — sees
	// something legal rather than a truncated option.
	for len(b)-start < PadTo {
		b = append(b, byte(OptionPad))
	}
	return b, nil
}

func appendAddr(b []byte, a netip.Addr) []byte {
	if !a.Is4() {
		// Includes the zero Addr, which is what an unset field means, and any
		// IPv6 address, which has no representation here. Writing four zero
		// octets is what the wire format calls "no address"; writing a
		// truncation of an IPv6 address would be a different address.
		return append(b, 0, 0, 0, 0)
	}
	v := a.As4()
	return append(b, v[:]...)
}

func appendFixed(b []byte, s string, n int) []byte {
	b = append(b, s...)
	return append(b, make([]byte, n-len(s))...)
}

// MessageType returns option 53.
//
// A message with no option 53 is BOOTP, not DHCP, and returns false. That
// distinction is worth keeping: a BOOTP client will not understand a DHCP
// reply, and answering one as though it were DHCP is worse than not answering.
func (m *Message) MessageType() (MessageType, bool) {
	v, ok := m.Options.Uint8(OptionMessageType)
	return MessageType(v), ok
}

// SetMessageType writes option 53.
func (m *Message) SetMessageType(t MessageType) { m.Options.SetUint8(OptionMessageType, uint8(t)) }

// Broadcast reports whether the client asked for a broadcast reply.
//
// RFC 2131 section 4.1: a client that cannot yet receive unicast — because it
// has no address configured, and some stacks will not accept a frame for an
// address they do not hold — sets bit 15 of flags. A server that ignores this
// works with most clients and mysteriously never works with one particular
// device, which is among the hardest DHCP faults to diagnose from the server
// side because the server's log says it replied.
func (m *Message) Broadcast() bool { return m.Flags&0x8000 != 0 }

// SetBroadcast sets or clears the broadcast flag.
func (m *Message) SetBroadcast(v bool) {
	if v {
		m.Flags |= 0x8000
		return
	}
	m.Flags &^= 0x8000
}

// ClientKey is the identity a lease binds to.
//
// RFC 2131 section 4.3.1 is explicit: the server uses the client identifier
// (option 61) when the client sends one, and the hardware address otherwise. It
// matters because they are not always the same — a machine that dual boots
// sends one hardware address and two client identifiers, and a server keying on
// the hardware address alone hands the second operating system the first one's
// lease along with its hostname.
//
// The returned string is opaque and is for map keys and comparison, not for
// display. It is prefixed by kind so that a client identifier whose bytes
// happen to equal a hardware address cannot collide with it.
func (m *Message) ClientKey() string {
	if id, ok := m.Options.Get(OptionClientID); ok && len(id) > 0 {
		return "id:" + string(id)
	}
	return "hw:" + string(m.CHAddr)
}

// HardwareAddr returns the client hardware address, or nil.
func (m *Message) HardwareAddr() net.HardwareAddr { return m.CHAddr }

// HostName returns the name the client offered for itself, from option 12 or
// from the FQDN option of RFC 4702, or "".
//
// It is a hint and nothing more. The name is chosen by the device, is not
// unique, is not verified, and is displayed to a person — so a caller must
// treat it as untrusted text, not as an identifier. [SanitiseName] is here for
// exactly that reason.
func (m *Message) HostName() string {
	if s, ok := m.Options.String(OptionHostName); ok && s != "" {
		return SanitiseName(s)
	}
	// RFC 4702 section 2: flags, RCODE1, RCODE2, then the name. The name is in
	// DNS wire form when the E flag (bit 2) is set and plain text otherwise.
	if b, ok := m.Options.Get(OptionClientFQDN); ok && len(b) > 3 {
		if b[0]&0x04 != 0 {
			return SanitiseName(decodeDNSName(b[3:]))
		}
		return SanitiseName(strings.TrimRight(string(b[3:]), "\x00"))
	}
	return ""
}

// decodeDNSName renders an uncompressed DNS wire name as dotted text.
//
// No compression pointers are followed. RFC 4702 section 2 has the FQDN option
// carry an uncompressed name, and a pointer here would be a pointer into a
// message this function cannot see — the only thing to do with one is stop.
func decodeDNSName(b []byte) string {
	var sb strings.Builder
	for i := 0; i < len(b); {
		n := int(b[i])
		if n == 0 {
			break
		}
		if n&0xc0 != 0 || i+1+n > len(b) {
			break
		}
		if sb.Len() > 0 {
			sb.WriteByte('.')
		}
		sb.Write(b[i+1 : i+1+n])
		i += 1 + n
	}
	return sb.String()
}

// SanitiseName makes a client-supplied name safe to store and display.
//
// The name in option 12 is whatever the device's owner typed into a settings
// screen, and it is going into a device list, a log line and a JSON document.
// So: control characters are dropped, the length is bounded, and the result is
// truncated at the first NUL. This is not paranoia about DHCP specifically —
// it is that a hostname is the one field in this product that an unauthenticated
// stranger on the network chooses the contents of, and it is displayed to the
// person deciding what to block.
func SanitiseName(s string) string {
	const maxName = 63 // RFC 1035 section 2.3.4, one label.
	var sb strings.Builder
	for _, r := range s {
		if sb.Len() >= maxName {
			break
		}
		switch {
		case r == 0:
			return sb.String()
		case r < 0x20 || r == 0x7f:
			continue
		default:
			sb.WriteRune(r)
		}
	}
	return strings.TrimSpace(sb.String())
}

// RequestKind classifies a DHCPREQUEST by RFC 2131 section 4.3.2.
//
// The three kinds are answered differently, and the difference is not
// cosmetic: a SELECTING request names one server and every other server must
// drop its offer, while a RENEWING request arrives unicast with the client's
// address in ciaddr and must not be answered with a new address. Returns
// [RequestUnknown] for any other message type.
func (m *Message) RequestKind() RequestKind {
	if t, ok := m.MessageType(); !ok || t != Request {
		return RequestUnknown
	}
	_, hasServer := m.Options.Addr(OptionServerID)
	_, hasRequested := m.Options.Addr(OptionRequestedIP)
	switch {
	case hasServer && hasRequested:
		return RequestSelecting
	case !hasServer && hasRequested:
		return RequestInitReboot
	case !hasServer && !hasRequested && m.CIAddr.Is4() && !m.CIAddr.IsUnspecified():
		return RequestRenewing
	default:
		return RequestUnknown
	}
}

// MaxSize is the largest reply this client will accept.
//
// Option 57 when the client sent one, [DefaultMaxSize] otherwise. A value below
// the RFC 2131 minimum is raised to it: a client asking for a 100-octet reply
// is asking for something that cannot hold a lease, and honouring it would
// produce a message no client could use.
func (m *Message) MaxSize() int {
	v, ok := m.Options.Uint16(OptionMaxMessageSize)
	if !ok || int(v) < DefaultMaxSize {
		return DefaultMaxSize
	}
	if int(v) > MaxMessageLen {
		return MaxMessageLen
	}
	return int(v)
}

// Reply builds the skeleton of a reply to m.
//
// It carries over exactly what RFC 2131 section 4.3 requires and nothing else:
// the transaction identifier, the hardware address, the relay address, and the
// broadcast flag. Everything else is the caller's to fill in, because
// everything else is a policy decision.
//
// The relay agent information option (82) is echoed back unchanged, which RFC
// 3046 section 2.1.1 requires — the relay uses it to decide which port to send
// the reply out of, and dropping it means the reply arrives nowhere.
func (m *Message) Reply(t MessageType) *Message {
	r := &Message{
		Op:     BootReply,
		HType:  m.HType,
		HLen:   m.HLen,
		XID:    m.XID,
		Flags:  m.Flags,
		GIAddr: m.GIAddr,
		CHAddr: m.CHAddr,
	}
	r.SetMessageType(t)
	if relay, ok := m.Options.Get(OptionRelayAgentInfo); ok {
		r.Options.Set(OptionRelayAgentInfo, relay)
	}
	return r
}

// String renders the message for a log line.
func (m *Message) String() string {
	t, ok := m.MessageType()
	kind := "BOOTP"
	if ok {
		kind = t.String()
	}
	var sb strings.Builder
	fmt.Fprintf(&sb, "%s xid=%#08x chaddr=%s", kind, m.XID, m.CHAddr)
	if m.CIAddr.Is4() && !m.CIAddr.IsUnspecified() {
		fmt.Fprintf(&sb, " ciaddr=%s", m.CIAddr)
	}
	if m.YIAddr.Is4() && !m.YIAddr.IsUnspecified() {
		fmt.Fprintf(&sb, " yiaddr=%s", m.YIAddr)
	}
	if m.GIAddr.Is4() && !m.GIAddr.IsUnspecified() {
		fmt.Fprintf(&sb, " giaddr=%s", m.GIAddr)
	}
	if n := m.HostName(); n != "" {
		fmt.Fprintf(&sb, " host=%q", n)
	}
	return sb.String()
}
