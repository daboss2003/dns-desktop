# 0002. A DHCP server of our own

- Status: Accepted
- Date: 2026-08-30
- Deciders: GatewayDNS maintainers

## Context

Per-device policy is the product's headline feature, and a device has to be
identified before a policy can be applied to it. DHCP is the one moment a device
states its hardware address, its hostname and its vendor class — in the first
packet it ever sends, before it has an address to be identified by.

The alternatives were to run `dnsmasq` or the platform's own DHCP server and
read its lease file, or to take a Go DHCP library as a dependency.

## Decision

**GatewayDNS Desktop implements DHCPv4 itself, in `internal/dhcp`.**

## Why

Against a lease file: the facts arrive late, in a format that is not a contract,
from a process that may not be running. `dnsmasq` writes a lease when the lease
is granted, so the device table learns about a device after it is already
resolving — and the first queries from a new device, which are exactly the ones
somebody watching a screen is looking at, are attributed to nobody. The format
is undocumented and differs between `dnsmasq`, `bootpd` and ISC. And it makes a
package this product must not have a hard dependency: a Debian package that
pulls in `dnsmasq` conflicts with the `dnsmasq` the user's router image already
runs.

Against a library: this module may take dependencies, so the question is whether
one is worth it. RFC 2131 is a 236-octet header, a magic cookie and a
type-length-value list; the whole codec is under a thousand lines. What makes a
DHCP server correct is not the parsing — it is the allocation policy, the
conflict detection and the lease store, none of which a codec library supplies.
What a dependency does supply is an attack surface on the one port on this
machine that answers a broadcast from anybody on the network.

The decisive argument is the third one. The lease pool is not generic: it exists
to keep a device on the same address across reconnects, because per-device policy
is applied by source address on the DNS path and a device whose address changes
on every reconnect is a device whose rules keep coming off. That is a product
requirement expressed as an allocation strategy, and no library implements it
because no library knows about it.

## Consequences

- Port 67 is ours, and conflicts with whatever else wants it. The application
  has to detect that and say so.
- Every part of RFC 2131 that is usually skipped has to be handled here: long
  options (RFC 3396), option overload, the broadcast flag. All three are
  implemented and tested, because each of them is a device that silently never
  joins the network.
- The codec parses input from anyone who can broadcast on the local network, so
  it is fuzzed in CI and no panic is reachable from any input.
