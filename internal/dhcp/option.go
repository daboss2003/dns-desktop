package dhcp

import (
	"encoding/binary"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

// OptionCode identifies an option, RFC 2132.
//
// Only the codes this product reads or writes are named. An unnamed code is not
// an error and is carried through unchanged: a DHCP network routinely carries
// vendor options for devices nobody here has heard of, and dropping them would
// break exactly the device that needed one.
type OptionCode uint8

const (
	// OptionPad is a single octet with no length and no data, used to align
	// what follows (RFC 2132 section 3.1).
	OptionPad OptionCode = 0
	// OptionSubnetMask is RFC 2132 section 3.3.
	OptionSubnetMask OptionCode = 1
	// OptionRouter is the default gateway list, RFC 2132 section 3.5. The
	// first entry is the one that matters.
	OptionRouter OptionCode = 3
	// OptionDNSServer is RFC 2132 section 3.8, and is the entire point of this
	// product: it is how a device is told to ask us.
	OptionDNSServer OptionCode = 6
	// OptionHostName is RFC 2132 section 3.14, and is where a phone's name in
	// the device list comes from.
	OptionHostName OptionCode = 12
	// OptionDomainName is RFC 2132 section 3.17.
	OptionDomainName OptionCode = 15
	// OptionInterfaceMTU is RFC 2132 section 3.13.
	OptionInterfaceMTU OptionCode = 26
	// OptionBroadcastAddress is RFC 2132 section 3.16.
	OptionBroadcastAddress OptionCode = 28
	// OptionNTPServer is RFC 2132 section 8.3.
	OptionNTPServer OptionCode = 42
	// OptionVendorSpecific is RFC 2132 section 8.4.
	OptionVendorSpecific OptionCode = 43
	// OptionNetBIOSNameServer is RFC 2132 section 8.5.
	OptionNetBIOSNameServer OptionCode = 44
	// OptionRequestedIP is what a client asks for, RFC 2132 section 9.1. It is
	// a request and not an assertion: honouring it blindly is how one device
	// takes another's address.
	OptionRequestedIP OptionCode = 50
	// OptionLeaseTime is RFC 2132 section 9.2.
	OptionLeaseTime OptionCode = 51
	// OptionOverload says the sname and file fields carry options too, RFC 2132
	// section 9.3.
	OptionOverload OptionCode = 52
	// OptionMessageType is RFC 2132 section 9.6, the option that makes a BOOTP
	// message a DHCP one.
	OptionMessageType OptionCode = 53
	// OptionServerID is RFC 2132 section 9.7. A client uses it to tell servers
	// apart, so it must be an address the client can reach us on.
	OptionServerID OptionCode = 54
	// OptionParameterRequestList is the client saying which options it wants,
	// RFC 2132 section 9.8. Sending options it did not ask for is permitted and
	// is how a client that asks for nothing still gets a DNS server.
	OptionParameterRequestList OptionCode = 55
	// OptionMessage carries a human-readable explanation of a NAK, RFC 2132
	// section 9.9. Most clients log it, which makes it the only channel this
	// server has for telling a person why their device will not connect.
	OptionMessage OptionCode = 56
	// OptionMaxMessageSize is the largest message a client will accept, RFC
	// 2132 section 9.10.
	OptionMaxMessageSize OptionCode = 57
	// OptionRenewalTime is T1, RFC 2132 section 9.11.
	OptionRenewalTime OptionCode = 58
	// OptionRebindingTime is T2, RFC 2132 section 9.12.
	OptionRebindingTime OptionCode = 59
	// OptionVendorClassID is RFC 2132 section 9.13, and is a useful hint about
	// what a device IS — "android-dhcp-14", "MSFT 5.0", "dhcpcd-9.4.1" — when
	// it did not send a hostname.
	OptionVendorClassID OptionCode = 60
	// OptionClientID is RFC 2132 section 9.14. When present it, and not the
	// hardware address, is the client's identity for lease binding (RFC 2131
	// section 4.3.1).
	OptionClientID OptionCode = 61
	// OptionUserClass is RFC 3004.
	OptionUserClass OptionCode = 77
	// OptionClientFQDN is RFC 4702, another place a name arrives from.
	OptionClientFQDN OptionCode = 81
	// OptionRelayAgentInfo is RFC 3046. A relay adds it on the way in and a
	// server must echo it back unchanged on the way out.
	OptionRelayAgentInfo OptionCode = 82
	// OptionClientArch is RFC 4578, for network boot.
	OptionClientArch OptionCode = 93
	// OptionDomainSearch is RFC 3397.
	OptionDomainSearch OptionCode = 119
	// OptionClasslessStaticRoute is RFC 3442. When a client requests both this
	// and option 33, the RFC says it must ignore option 33 — which is why this
	// package does not implement 33 at all.
	OptionClasslessStaticRoute OptionCode = 121
	// OptionPrivateClasslessStaticRoute is the pre-standard code 249 that
	// Windows used before RFC 3442 was assigned 121, and which Windows DHCP
	// clients still request.
	OptionPrivateClasslessStaticRoute OptionCode = 249
	// OptionEnd terminates the option list. It has no length and no data.
	OptionEnd OptionCode = 255
)

var optionNames = map[OptionCode]string{
	OptionPad:                         "Pad",
	OptionSubnetMask:                  "SubnetMask",
	OptionRouter:                      "Router",
	OptionDNSServer:                   "DNSServer",
	OptionHostName:                    "HostName",
	OptionDomainName:                  "DomainName",
	OptionInterfaceMTU:                "InterfaceMTU",
	OptionBroadcastAddress:            "BroadcastAddress",
	OptionNTPServer:                   "NTPServer",
	OptionVendorSpecific:              "VendorSpecific",
	OptionNetBIOSNameServer:           "NetBIOSNameServer",
	OptionRequestedIP:                 "RequestedIP",
	OptionLeaseTime:                   "LeaseTime",
	OptionOverload:                    "Overload",
	OptionMessageType:                 "MessageType",
	OptionServerID:                    "ServerID",
	OptionParameterRequestList:        "ParameterRequestList",
	OptionMessage:                     "Message",
	OptionMaxMessageSize:              "MaxMessageSize",
	OptionRenewalTime:                 "RenewalTime",
	OptionRebindingTime:               "RebindingTime",
	OptionVendorClassID:               "VendorClassID",
	OptionClientID:                    "ClientID",
	OptionUserClass:                   "UserClass",
	OptionClientFQDN:                  "ClientFQDN",
	OptionRelayAgentInfo:              "RelayAgentInfo",
	OptionClientArch:                  "ClientArch",
	OptionDomainSearch:                "DomainSearch",
	OptionClasslessStaticRoute:        "ClasslessStaticRoute",
	OptionPrivateClasslessStaticRoute: "PrivateClasslessStaticRoute",
	OptionEnd:                         "End",
}

func (c OptionCode) String() string {
	if n, ok := optionNames[c]; ok {
		return n
	}
	return "Option" + strconv.Itoa(int(c))
}

// Overload flags, RFC 2132 section 9.3.
const (
	overloadFile  = 1
	overloadSName = 2
)

// Option is one type-length-value.
//
// Data is owned by the Option: [Unpack] copies out of the receive buffer, so a
// caller may reuse that buffer the moment Unpack returns. This costs one
// allocation per option and removes a class of bug — an option quietly changing
// value because the next packet landed in the same array — that is invisible in
// testing and reproducible only under load.
type Option struct {
	Code OptionCode
	Data []byte
}

// Options is an option list in wire order.
//
// A list, not a map. Duplicate codes are legal and mean different things in
// different places: RFC 3396 splits one long option across several instances to
// be concatenated, while a relay may legitimately append its own. A map would
// silently pick one and lose the rest, and the loss would be of the LAST
// fragment of a long option, which is to say of the end of somebody's domain
// search list.
//
// [Unpack] has already applied RFC 3396, so a decoded list holds at most one
// entry per code and a caller may use [Options.Get] without thinking about it.
type Options []Option

// Get returns the data for code, and whether it was present.
//
// A linear scan, deliberately. An option list is a handful of entries and this
// is not on any hot path — a DHCP exchange happens once per device per lease
// period, against a DNS query path that runs thousands of times a second.
func (o Options) Get(code OptionCode) ([]byte, bool) {
	for _, opt := range o {
		if opt.Code == code {
			return opt.Data, true
		}
	}
	return nil, false
}

// Has reports whether code is present, regardless of its value.
func (o Options) Has(code OptionCode) bool {
	_, ok := o.Get(code)
	return ok
}

// Set replaces the option with this code, or appends it.
func (o *Options) Set(code OptionCode, data []byte) {
	for i := range *o {
		if (*o)[i].Code == code {
			(*o)[i].Data = data
			return
		}
	}
	*o = append(*o, Option{Code: code, Data: data})
}

// Delete removes every option with this code.
func (o *Options) Delete(code OptionCode) {
	out := (*o)[:0]
	for _, opt := range *o {
		if opt.Code != code {
			out = append(out, opt)
		}
	}
	*o = out
}

// Uint8 reads a one-octet option.
func (o Options) Uint8(code OptionCode) (uint8, bool) {
	b, ok := o.Get(code)
	if !ok || len(b) != 1 {
		return 0, false
	}
	return b[0], true
}

// Uint16 reads a two-octet option.
func (o Options) Uint16(code OptionCode) (uint16, bool) {
	b, ok := o.Get(code)
	if !ok || len(b) != 2 {
		return 0, false
	}
	return binary.BigEndian.Uint16(b), true
}

// Uint32 reads a four-octet option.
func (o Options) Uint32(code OptionCode) (uint32, bool) {
	b, ok := o.Get(code)
	if !ok || len(b) != 4 {
		return 0, false
	}
	return binary.BigEndian.Uint32(b), true
}

// Addr reads a single IPv4 address option.
//
// The length must be exactly four. A four-octet field carrying three octets is
// not a shorter address, it is a malformed message, and guessing at the missing
// octet is how a server hands out an address on the wrong network.
func (o Options) Addr(code OptionCode) (netip.Addr, bool) {
	b, ok := o.Get(code)
	if !ok || len(b) != 4 {
		return netip.Addr{}, false
	}
	return netip.AddrFrom4([4]byte(b)), true
}

// Addrs reads a list-of-addresses option, such as option 6.
//
// A length that is not a multiple of four is rejected whole rather than
// truncated to the addresses that did fit: the remainder is evidence that the
// sender and this parser disagree about the format, and continuing on that
// basis is how a malformed option becomes a plausible wrong answer.
func (o Options) Addrs(code OptionCode) ([]netip.Addr, bool) {
	b, ok := o.Get(code)
	if !ok || len(b) == 0 || len(b)%4 != 0 {
		return nil, false
	}
	out := make([]netip.Addr, 0, len(b)/4)
	for i := 0; i < len(b); i += 4 {
		out = append(out, netip.AddrFrom4([4]byte(b[i:i+4])))
	}
	return out, true
}

// Duration reads a four-octet seconds option, such as the lease time.
//
// 0xffffffff is the infinite lease of RFC 2131 section 3.3, and is returned as
// [Infinite] rather than as 136 years — a caller comparing against a wall clock
// would otherwise get an answer that is right until 2106.
func (o Options) Duration(code OptionCode) (time.Duration, bool) {
	v, ok := o.Uint32(code)
	if !ok {
		return 0, false
	}
	if v == infiniteSeconds {
		return Infinite, true
	}
	return time.Duration(v) * time.Second, true
}

// String reads a text option, trimming the trailing NULs that several clients
// append and that would otherwise end up in a device name in the UI.
func (o Options) String(code OptionCode) (string, bool) {
	b, ok := o.Get(code)
	if !ok {
		return "", false
	}
	return strings.TrimRight(string(b), "\x00"), true
}

// SetUint8 writes a one-octet option. It and the SetUint16, SetUint32, SetAddr,
// SetAddrs, SetDuration and SetString below are the writing halves of the
// readers above.
func (o *Options) SetUint8(code OptionCode, v uint8) { o.Set(code, []byte{v}) }

// SetUint16 writes a two-octet option.
func (o *Options) SetUint16(code OptionCode, v uint16) {
	o.Set(code, binary.BigEndian.AppendUint16(nil, v))
}

// SetUint32 writes a four-octet option.
func (o *Options) SetUint32(code OptionCode, v uint32) {
	o.Set(code, binary.BigEndian.AppendUint32(nil, v))
}

// SetAddr writes a single IPv4 address option. A non-IPv4 address is dropped
// rather than written as something else: DHCPv4 has no encoding for one, and a
// truncated or mapped form would be read by the client as a different address.
func (o *Options) SetAddr(code OptionCode, a netip.Addr) {
	if !a.Is4() {
		return
	}
	b := a.As4()
	o.Set(code, b[:])
}

// SetAddrs writes a list-of-addresses option.
func (o *Options) SetAddrs(code OptionCode, addrs []netip.Addr) {
	buf := make([]byte, 0, 4*len(addrs))
	for _, a := range addrs {
		if !a.Is4() {
			continue
		}
		b := a.As4()
		buf = append(buf, b[:]...)
	}
	if len(buf) == 0 {
		return
	}
	o.Set(code, buf)
}

// SetDuration writes a seconds option, clamping to what the field can hold.
//
// A negative duration is written as zero and anything past the 32-bit range as
// infinite. Wrapping would turn a very long lease into a very short one, which
// is the direction that produces a network-wide re-request storm.
func (o *Options) SetDuration(code OptionCode, d time.Duration) {
	switch {
	case d == Infinite || d.Seconds() >= infiniteSeconds:
		o.SetUint32(code, infiniteSeconds)
	case d <= 0:
		o.SetUint32(code, 0)
	default:
		o.SetUint32(code, uint32(d.Seconds()))
	}
}

// SetString writes a text option.
func (o *Options) SetString(code OptionCode, s string) { o.Set(code, []byte(s)) }

// infiniteSeconds is the all-ones lease time of RFC 2131 section 3.3.
const infiniteSeconds = 0xffffffff

// Infinite is a lease that never expires.
//
// It is a sentinel and not a very large duration, so that code comparing
// against it does not have to pick a threshold. [Options.SetDuration] writes it
// as the all-ones value RFC 2131 section 3.3 defines.
const Infinite = time.Duration(1<<63 - 1)

// appendTo writes the options and the terminator into b.
//
// RFC 3396: an option whose data exceeds 255 octets is emitted as several
// instances of the same code, each holding a fragment, which the receiver
// concatenates. Without this a long domain search list or a large vendor blob
// would be silently truncated to 255 octets — and truncated at a point that
// depends on the data, so it would work in testing and fail on one network.
func (o Options) appendTo(b []byte) []byte {
	for _, opt := range o {
		switch opt.Code {
		case OptionPad, OptionEnd:
			// Structural codes. Emitting one from the list would terminate the
			// message early, discarding every option after it.
			continue
		}
		data := opt.Data
		for {
			n := min(len(data), 255)
			b = append(b, byte(opt.Code), byte(n))
			b = append(b, data[:n]...)
			data = data[n:]
			if len(data) == 0 {
				break
			}
		}
	}
	return append(b, byte(OptionEnd))
}

// parseOptions appends the options in b to out, stopping at OptionEnd.
//
// It returns the overload flags it saw, because RFC 2131 section 4.1 requires
// the file and sname fields to be parsed only when option 52 says to, and only
// after the options field itself.
//
// Malformed input ends the list rather than failing the message. A truncated
// final option is what a slightly-wrong client or a lossy relay produces, and
// the options before it are still good; refusing the whole message would drop a
// client that is otherwise working, with nothing in the log but "malformed".
func parseOptions(b []byte, out Options) (Options, uint8) {
	var overload uint8
	for i := 0; i < len(b); {
		code := OptionCode(b[i])
		switch code {
		case OptionPad:
			i++
			continue
		case OptionEnd:
			return out, overload
		}
		// Every remaining code is type-length-value, so a length octet must
		// exist and its data must fit in what is left.
		if i+1 >= len(b) {
			return out, overload
		}
		n := int(b[i+1])
		if i+2+n > len(b) {
			return out, overload
		}
		data := b[i+2 : i+2+n]
		i += 2 + n

		if code == OptionOverload && n == 1 {
			overload = data[0]
		}
		// RFC 3396 concatenation. Appending to an option already in the list is
		// what makes a split option arrive whole, and is why a caller never has
		// to know the encoding exists.
		if prev := indexOf(out, code); prev >= 0 {
			out[prev].Data = append(out[prev].Data, data...)
			continue
		}
		// Copied, not aliased: the caller owns the receive buffer and will
		// reuse it for the next packet.
		out = append(out, Option{Code: code, Data: append([]byte(nil), data...)})
	}
	return out, overload
}

func indexOf(o Options, code OptionCode) int {
	for i := range o {
		if o[i].Code == code {
			return i
		}
	}
	return -1
}
