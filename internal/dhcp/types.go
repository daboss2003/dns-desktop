package dhcp

import "strconv"

// OpCode is the message operation, RFC 951 section 3.
//
// It says which direction a message is travelling and nothing else. The kind of
// DHCP message it is — DISCOVER, OFFER, REQUEST — is option 53, because DHCP
// was retrofitted onto BOOTP and had no header field left to put it in.
type OpCode uint8

const (
	// BootRequest is a message from a client to a server.
	BootRequest OpCode = 1
	// BootReply is a message from a server to a client.
	BootReply OpCode = 2
)

func (o OpCode) String() string {
	switch o {
	case BootRequest:
		return "BOOTREQUEST"
	case BootReply:
		return "BOOTREPLY"
	default:
		return "OP" + strconv.Itoa(int(o))
	}
}

// HType is the hardware address type, from the ARP hardware type registry that
// RFC 951 section 3 borrows.
type HType uint8

const (
	// HTypeEthernet is 10 Mb Ethernet, which in practice means every wired and
	// wireless client this software will ever meet. The name is a fossil.
	HTypeEthernet HType = 1
	// HTypeIEEE802 is token ring.
	HTypeIEEE802 HType = 6
	// HTypeARCNET is ARCNET.
	HTypeARCNET HType = 7
	// HTypeFrameRelay is Frame Relay.
	HTypeFrameRelay HType = 15
	// HTypeATM is asynchronous transfer mode.
	HTypeATM HType = 16
	// HTypeInfiniBand is InfiniBand.
	HTypeInfiniBand HType = 32
)

func (h HType) String() string {
	switch h {
	case HTypeEthernet:
		return "Ethernet"
	case HTypeIEEE802:
		return "IEEE802"
	case HTypeARCNET:
		return "ARCNET"
	case HTypeFrameRelay:
		return "FrameRelay"
	case HTypeATM:
		return "ATM"
	case HTypeInfiniBand:
		return "InfiniBand"
	default:
		return "HTYPE" + strconv.Itoa(int(h))
	}
}

// MessageType is the value of option 53, RFC 2131 section 3.1 and RFC 2132
// section 9.6. It is what makes a BOOTP message a DHCP message.
type MessageType uint8

const (
	// Discover is a client looking for any server (RFC 2131 section 3.1).
	Discover MessageType = 1
	// Offer is a server offering an address.
	Offer MessageType = 2
	// Request is a client accepting one server's offer, renewing a lease, or
	// verifying an address it already believes it has. The three are told apart
	// by which of server identifier, requested address and ciaddr are set —
	// see [Message.RequestKind], because getting that wrong is how a renewal
	// becomes a second address.
	Request MessageType = 3
	// Decline is a client reporting that the address it was given is already in
	// use by somebody else (RFC 2131 section 3.1 item 5).
	Decline MessageType = 4
	// Ack is a server confirming a lease.
	Ack MessageType = 5
	// Nak is a server refusing one, usually because the client asked for an
	// address that is not valid on the network it has moved to.
	Nak MessageType = 6
	// Release is a client giving up a lease early.
	Release MessageType = 7
	// Inform is a client that already has an address by other means asking only
	// for configuration — which for this product is the interesting case: a
	// device with a static address still wants to be told a DNS server.
	Inform MessageType = 8
	// ForceRenew is RFC 3203, a server telling a client to renew now.
	ForceRenew MessageType = 9
)

func (t MessageType) String() string {
	switch t {
	case Discover:
		return "DISCOVER"
	case Offer:
		return "OFFER"
	case Request:
		return "REQUEST"
	case Decline:
		return "DECLINE"
	case Ack:
		return "ACK"
	case Nak:
		return "NAK"
	case Release:
		return "RELEASE"
	case Inform:
		return "INFORM"
	case ForceRenew:
		return "FORCERENEW"
	default:
		return "MSGTYPE" + strconv.Itoa(int(t))
	}
}

// RequestKind distinguishes the three things a DHCPREQUEST can mean.
//
// RFC 2131 section 4.3.2 defines them by which fields are populated, and they
// are answered differently: a selecting request must be ignored by every server
// whose identifier it does not name, and a renewing request arrives unicast
// with no server identifier at all. A server that treated them alike would
// answer another server's client, or would allocate a second address to a
// client that was only renewing its first.
type RequestKind uint8

const (
	// RequestUnknown is a REQUEST whose fields match none of the shapes below,
	// which RFC 2131 does not define and which this package does not guess at.
	RequestUnknown RequestKind = iota
	// RequestSelecting names a server identifier and a requested address: the
	// client is accepting one server's OFFER and telling every other server to
	// drop its reservation.
	RequestSelecting
	// RequestInitReboot has a requested address and no server identifier: the
	// client remembers an address and is asking whether it is still valid here.
	RequestInitReboot
	// RequestRenewing has neither, and carries the client's address in ciaddr.
	// It arrives unicast to the server that granted the lease.
	RequestRenewing
)

func (k RequestKind) String() string {
	switch k {
	case RequestSelecting:
		return "SELECTING"
	case RequestInitReboot:
		return "INIT-REBOOT"
	case RequestRenewing:
		return "RENEWING"
	default:
		return "UNKNOWN"
	}
}
