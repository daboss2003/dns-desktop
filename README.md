# GatewayDNS Desktop

A desktop application that turns a laptop into a filtering DNS gateway for the
devices around it: it manages a Wi-Fi hotspot, hands out DHCP leases, configures
NAT and firewall rules, and presents a user interface for the devices and the
policies applied to them.

It is one of three consumers of [GatewayDNS Core][core], the engine. The other
two are anyone embedding the library directly, and [gatewaydnsd][daemon], the
headless server daemon.

[core]: https://github.com/gatewaydns/gatewaydns
[daemon]: https://github.com/gatewaydns/gatewaydnsd

## Status

**Milestone 12 is in progress.** What exists and is tested:

| Package | What it does | Coverage |
| --- | --- | --- |
| `internal/dhcp` | DHCPv4 codec, lease pool and server. RFC 2131/2132, including the parts usually skipped: long options (RFC 3396), option overload, the broadcast flag. Fuzzed in CI. | 86% |
| `internal/device` | The device table: identity, per-device profiles, the address-to-device index the DNS path reads without a lock. | 88% |
| `internal/gateway` | The portable gateway interface: three sharing models, capability reporting with reasons, interface enumeration. | 76% |

Not yet: bringing a gateway up on any platform, the user interface, the
privileged helper, and packaging. See [Delivery](#delivery).

## Architecture

```
                    ┌──────────────────────────────┐
                    │  cmd/gatewaydns-desktop      │
                    └───────────────┬──────────────┘
                                    │
      ┌──────────────┬──────────────┼──────────────┬──────────────┐
      ▼              ▼              ▼              ▼              ▼
  ┌────────┐   ┌──────────┐   ┌──────────┐   ┌─────────┐   ┌──────────┐
  │  ui    │   │  device  │   │   dhcp   │   │ gateway │   │  state   │
  │ (SPA + │   │  table   │   │  server  │   │ (Linux, │   │ (on-disk │
  │  HTTP) │   │          │   │          │   │  macOS) │   │  config) │
  └────┬───┘   └─────┬────┘   └─────┬────┘   └────┬────┘   └──────────┘
       │             │              │             │
       └─────────────┴──────┬───────┴─────────────┘
                            ▼
              ┌───────────────────────────┐
              │  github.com/gatewaydns/   │
              │  gatewaydns  (the engine) │
              │  imported, never modified │
              └───────────────────────────┘
```

The dependency direction is one way and enforced by the module graph: the engine
has no `require` block at all, so it cannot import anything here without an edit
CI rejects. See [ADR 0001][adr1] in the engine repository.

Three joins matter:

- **DHCP feeds the device table.** `dhcp.ServerOptions.OnBound` fires on the
  acknowledgement — the one moment a device volunteers a hardware address, a
  name and a vendor class in a single packet.
- **The device table feeds the engine.** `gatewaydns.Options.Identify` runs
  before the middleware chain and before anything is recorded, so the policy
  decision, the metrics and the query log all get one answer to "who asked
  this". `Options.Devices` then says what that identity means.
- **The gateway is asked what it can do before it is asked to do anything.**
  Every refusal names a capability and gives a reason a person can act on.

The decisions behind those are recorded in [docs/adr](docs/adr).

## Platforms

GatewayDNS Desktop is a filtering resolver on every platform, and that part
needs nothing from the operating system: point a device at this machine and it
is filtered. What differs is how devices come to be pointed at it.

| | Linux | macOS | Windows |
| --- | --- | --- | --- |
| Resolve and filter for devices pointed here | Yes | Yes | Yes |
| Device table and per-device policy | Yes | Yes | Yes |
| Create an access point | hostapd | No¹ | Mobile Hotspot |
| Share a connection (NAT) | nftables/iptables | pfctl | ICS / `New-NetNat` |
| Run our own DHCP, and so know devices fully | Yes | Yes | Yes² |
| Capture DNS from a device that hardcodes a resolver | Redirect | Redirect | Enforce³ |
| Block one device from the network | Yes | Yes | Yes |

1. macOS has no supported interface for a program to bring up a Wi-Fi access
   point. Internet Sharing does exactly what this product wants and is a
   preference pane a person turns on; what a program may do is notice that they
   have.
2. Only when we also own the NAT. The Mobile Hotspot brings its own DHCP server
   and its own DNS proxy, and that proxy collapses every client to one source
   address — which destroys per-device policy. See [ADR 0004][adr4].
3. Windows has no user-mode destination rewrite; the whole WFP action set is
   block, permit and three callout forms. It captures DNS by refusing every
   other resolver rather than by rewriting, which reaches the same policy
   outcome by a route a user can notice. Never a silent default. See
   [ADR 0004][adr4].

None of the three capture DNS over HTTPS to a hardcoded address, and a perfect
redirect on Linux would not either.

## Delivery

Milestone 12 is too large for one change, so it ships in slices, each of which
ends with something that runs.

| # | Slice | Done when |
| --- | --- | --- |
| 12.1 | DHCPv4 codec | Round-trips, fuzzes clean, handles long options and overload. **Done** |
| 12.2 | Lease pool | A reconnecting device keeps its address; reservations, declines and expiry behave. **Done** |
| 12.3 | DHCP server | The protocol as a pure function; refusals follow RFC 2131 §4.3.2. **Done** |
| 12.4 | Device table | Identity survives a restart; a reused address inherits nothing. **Done** |
| 12.5 | Gateway interface | Three sharing models, capabilities with reasons, contract tests. **Done** |
| 12.6 | Linux gateway | hostapd, nftables, journalled bring-up, reconciliation after a crash. |
| 12.7 | Windows gateway | Mobile Hotspot, `New-NetNat`, WFP enforcement, firewall blocking. |
| 12.8 | macOS gateway | pfctl sharing and redirect, Internet Sharing detection. |
| 12.9 | Privileged helper | A tiny audited command surface with peer-credential checks. |
| 12.10 | HTTP API and UI | The embedded single-page application, live updates, loopback authentication. |
| 12.11 | Packaging | `.app` bundle, `.deb`/`.rpm`, MSI, autostart, release automation. |

## Building

```sh
make build      # a static binary
make test-race  # the tests under the race detector
make fuzz       # the wire codecs, briefly
```

During development this module resolves the engine through a `replace`
directive pointing at `../gatewaydns`. Clone both side by side. `make
release-check` fails if that directive is still present, and so does CI on a
tag.

[adr1]: https://github.com/gatewaydns/gatewaydns/blob/main/docs/adr/0001-two-products-one-dependency-boundary.md
[adr4]: docs/adr/0004-dns-capture-differs-by-platform.md

## Licence

Apache-2.0. See [LICENSE](LICENSE).
