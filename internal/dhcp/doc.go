// Package dhcp encodes and decodes DHCPv4 messages, and serves them.
//
// It exists because GatewayDNS Desktop needs a device table. Per-device policy
// is the headline feature — "no social media on the kids' tablets" — and a
// device has to be identified before a policy can be applied to it. DHCP is
// where a device tells you its hardware address, its hostname and its vendor
// class, all in the first packet it ever sends, before it has an address to be
// identified by. Reading somebody else's lease file gives you the same facts
// late, in a format that is not a contract, from a process that may not be
// running.
//
// # Why this is not a dependency
//
// This module may take dependencies; the engine may not. So the question here
// is not "are we allowed" but "is it worth it", and for a wire format this
// small and this old the answer is no. The whole of RFC 2131 is a 236-octet
// fixed header, a four-octet magic cookie and a type-length-value list. What
// makes a DHCP server correct is not the parsing, it is the allocation policy,
// the conflict detection and the lease store — none of which a codec library
// supplies. What a dependency would supply is a second opinion about
// [netip.Addr] versus [net.IP], and an attack surface on the one port on this
// machine that answers a broadcast from anybody on the network.
//
// # The wire format
//
// A message is the BOOTP header of RFC 951, reinterpreted by RFC 2131 section
// 2, followed by options in the encoding of RFC 2132. The header is fixed at
// 236 octets and is followed by the magic cookie 99.130.83.99, so the shortest
// legal message this package will decode is 240 octets. Messages are padded on
// encode to 300 octets, which is not in RFC 2131 but is what BOOTP relay agents
// of RFC 951 vintage expect, and a relay that drops short messages drops them
// silently.
//
// Three parts of the format regularly surprise people, and this package handles
// all three rather than pretending they do not exist:
//
//   - RFC 3396 long options. An option carrying more than 255 octets is split
//     across several instances of the same code, and a receiver must
//     concatenate them in order. [Unpack] concatenates, so a caller never sees a
//     split option; [Message.Pack] splits, so a caller never has to.
//   - RFC 2131 section 4.1 option overload. Option 52 says that the otherwise
//     unused sname and file fields carry options too, which is how a server
//     fits more into a message than the options field alone allows. They are
//     parsed in the order the RFC gives: options, then file, then sname.
//   - The BROADCAST flag. A client that does not yet have an address cannot
//     receive a unicast reply on every stack, so RFC 2131 section 4.1 has it
//     set bit 15 of flags to ask for a broadcast. Ignoring it is the classic
//     reason one particular device on a network never gets a lease.
//
// # Robustness
//
// Everything here parses input from anybody who can send a broadcast to port
// 67, which on a network this software exists to serve means every device on
// it, including the compromised one. So: no panic is reachable from any input,
// every length is checked against the remaining buffer before it is used, and
// no field's declared length is trusted to allocate with. [Unpack] copies what
// it keeps, so a caller may reuse the receive buffer immediately, and it never
// holds a reference into it.
//
// Decoding is deliberately permissive and validation is deliberately separate.
// A message with an unknown opcode, an implausible hardware type or an option
// the server has never heard of decodes fine; what to do about that is a policy
// question for the server, which has context this layer does not. Refusing at
// the codec would mean a client that sets one odd field disappears with no
// record of why.
package dhcp
