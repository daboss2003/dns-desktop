# 0007. On Windows, creating Wi-Fi and knowing who is on it are alternatives

- Status: Accepted
- Date: 2026-08-30
- Deciders: GatewayDNS maintainers

## Context

Windows can create a Wi-Fi network and it can let this application own the
addressing. It cannot do both, and the reason is structural rather than an
implementation gap.

The Mobile Hotspot is the only way a program can bring up an access point on
Windows. Underneath it is Internet Connection Sharing, which arrives as one
unit: the access point, a DHCP allocator, address translation, and a DNS proxy
on the private interface. The proxy binds port 53 there, so this product's
resolver cannot; clients are filtered only by the proxy forwarding to whatever
resolver the machine itself is configured with. That works — pointing the
machine at our own resolver filters every client — but every query then arrives
from the proxy. All the devices look like one client.

`New-NetNat` translates and nothing else, so our own DHCP server hands out the
addresses and names our own resolver as theirs. Queries arrive from the devices
that made them and per-device policy works in full. But `New-NetNat` cannot
create an access point, and it needs Hyper-V, which Home editions cannot
install.

## Decision

**Both are offered, as [SharingPlatform] and [SharingManaged], and the product
says what each costs rather than choosing.**

Under platform sharing, the device list is built from `GetTetheringClients`,
which reports each connected station's hardware address and host names. So there
is still a list of devices — what is missing is the ability to attribute a query
to one of them.

## Why

The temptation is to pick one and present it as "how it works on Windows". Both
versions of that are wrong in a way a user meets rather than reads about.

Picking the hotspot means a household that came for "no social media on the
kids' tablet" gets a filtered network where that rule cannot be expressed, and
discovers it after setting one up. Picking `New-NetNat` means "create a Wi-Fi
hotspot" is missing from the most used desktop operating system, on the edition
most people have, for a reason nothing in the interface explains.

There is a third option — bind our resolver to loopback and let the ICS proxy
forward to it — and it is worse than it looks. It buys nothing that pointing the
machine's own resolver setting at us does not, and it makes the identity loss
permanent rather than a property of one arrangement.

## Consequences

- The interface must present a choice at the point where somebody turns sharing
  on, with the cost of each stated in a sentence, rather than a single button
  whose behaviour depends on the edition of Windows underneath.
- Per-device policy is silently absent under platform sharing, so it must not be
  silent: a device's rules screen has to say why they will not apply, at the
  moment somebody tries to set one.
- Managed sharing is refused while this build cannot block IPv6 on Windows,
  unless the operator explicitly allows IPv6 through. "We did not configure
  IPv6" is not "IPv6 does not happen", and a gateway that leaks v6 while its v4
  counters look healthy is the failure mode least acceptable here.
- Cutting a device off, and enforcing DNS, are both filters at the forwarding
  layer. A Windows Firewall rule naming a remote address does NOT do it — the
  firewall's filters never see forwarded traffic — so implementing either with
  `netsh advfirewall` would ship a control that looks right and does nothing.
  Until those filters land, both capabilities report themselves absent with that
  reason attached.
