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
| `internal/gateway` | The portable gateway interface, capability reporting, interface enumeration on Linux and macOS, an honest refusal on Windows. | 75% |

Not yet: bringing a gateway up (hostapd, nftables, pfctl), the user interface,
the privileged helper, and packaging. See [Delivery](#delivery).

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

## Delivery

Milestone 12 is too large for one change, so it ships in slices, each of which
ends with something that runs.

| # | Slice | Done when |
| --- | --- | --- |
| 12.1 | DHCPv4 codec | Round-trips, fuzzes clean, handles long options and overload. **Done** |
| 12.2 | Lease pool | A reconnecting device keeps its address; reservations, declines and expiry behave. **Done** |
| 12.3 | DHCP server | The protocol as a pure function; refusals follow RFC 2131 §4.3.2. **Done** |
| 12.4 | Device table | Identity survives a restart; a reused address inherits nothing. **Done** |
| 12.5 | Gateway interface | Capabilities, enumeration, honest refusals, contract tests. **Done** |
| 12.6 | Linux gateway | hostapd, nftables, journalled bring-up, reconciliation after a crash. |
| 12.7 | macOS gateway | pfctl sharing and DNS redirect, Internet Sharing detection. |
| 12.8 | Privileged helper | A tiny audited command surface over a unix socket with peer-credential checks. |
| 12.9 | HTTP API and UI | The embedded single-page application, live updates, loopback authentication. |
| 12.10 | Packaging | `.app` bundle, `.deb`/`.rpm`, autostart, release automation. |

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

## Licence

Apache-2.0. See [LICENSE](LICENSE).
