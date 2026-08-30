# GatewayDNS Desktop

A desktop application that turns a laptop into a filtering DNS gateway for the
devices around it: it manages a Wi-Fi hotspot, hands out DHCP leases, configures
NAT and firewall rules, and presents a user interface for the devices and the
policies applied to them.

It is one of three consumers of [GatewayDNS Core][core], the engine. The other
two are anyone embedding the library directly, and [gatewaydnsd][daemon], the
headless server daemon.

[core]: https://github.com/daboss2003/dns
[daemon]: https://github.com/daboss2003/dnsd

## Status

**It runs.** A window, a menu-bar item, and a filtering resolver behind both.

```console
$ make build && ./gatewaydns-desktop
```

What works today: the resolver with DNS-over-TLS upstreams and blocklists; a
device table that names every device that asks and remembers it across
restarts; per-device pause; a query log; and the dashboard that shows all of it.
`-headless` runs the same application with no window, and `make build-headless`
produces a `CGO_ENABLED=0` static binary for a Raspberry Pi or a container.

| Package | What it does | Coverage |
| --- | --- | --- |
| `internal/app` | The product with no interface attached: resolver, devices, policy, gateway lifecycle, state. | 51% |
| `internal/ui` | The embedded interface and its HTTP surface. No build step, no bundler. | |
| `internal/dhcp` | DHCPv4 codec, lease pool and server. RFC 2131/2132, fuzzed in CI. | 86% |
| `internal/device` | Device identity, per-device policy, the address index the DNS path reads without a lock. | 88% |
| `internal/gateway` | Three sharing models, capability reporting with reasons, interface enumeration. | 76% |

Not yet: bringing a gateway up on any platform, wiring the DHCP server into the
application, and packaging. See [Delivery](#delivery).

## Architecture

```
        ┌──────────────────────────────────────────────┐
        │  cmd/gatewaydns-desktop                      │
        │  ┌────────────────┐    ┌──────────────────┐  │
        │  │ menu-bar item  │    │  native window   │  │
        │  │ (primary)      │    │  (on demand)     │  │
        │  └───────┬────────┘    └────────┬─────────┘  │
        └──────────┼──────────────────────┼────────────┘
                   │                      │ HTTP, loopback
                   │              ┌───────▼────────┐
                   │              │  internal/ui   │
                   │              │  embedded SPA  │
                   │              └───────┬────────┘
                   └──────────┬───────────┘
                              ▼
                   ┌─────────────────────┐
                   │    internal/app     │  the product, no UI
                   └──────────┬──────────┘
          ┌──────────┬────────┴────┬──────────────┐
          ▼          ▼             ▼              ▼
      ┌────────┐ ┌────────┐  ┌──────────┐  ┌───────────┐
      │ device │ │  dhcp  │  │ gateway  │  │ the engine│
      │ table  │ │ server │  │ (per OS) │  │ (imported)│
      └────────┘ └────────┘  └──────────┘  └───────────┘
```

The dependency direction is one way and enforced by the module graph: the engine
has no `require` block at all, so it cannot import anything here without an edit
CI rejects. See [ADR 0001][adr1] in the engine repository.

The window talks to its own process over HTTP, which looks like indirection in
one binary and is what makes one interface serve two deployments: the same
screens work pointed at a [`gatewaydnsd`][daemon] on a server. See
[ADR 0006][adr6].

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
| Create an access point | hostapd | No¹ | Mobile Hotspot⁴ |
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

4. And creating it costs per-device policy. The Mobile Hotspot is Internet
   Connection Sharing underneath, which brings its own DHCP and its own DNS
   proxy, so every query arrives from the proxy and all devices look like one
   client. `New-NetNat` keeps identity and cannot create Wi-Fi. Both are
   offered; the product says what each costs. See [ADR 0007][adr7].

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
| 12.6 | Linux gateway | hostapd, nftables, journalled bring-up, reconciliation after a crash. **Done** |
| 12.7 | Windows gateway | Mobile Hotspot, `New-NetNat`, journalled bring-up. **Done**, less the forwarding-layer filters |
| 12.8 | macOS gateway | pfctl sharing and redirect, Internet Sharing detection. |
| 12.9 | Wired end to end | The app starts and stops the gateway, runs the DHCP server, and has a Network screen. **Done** |
| 12.12 | Privileged helper | A tiny audited command surface with peer-credential checks, so the whole application need not be root. |
| 12.10 | Desktop shell and interface | A native window, a menu-bar item, the embedded dashboard. **Done** |
| 12.11 | Packaging | `.app` bundle, `.deb`/`.rpm`, MSI, autostart, release automation. |

## Building

```sh
make build           # the desktop application for this platform
make run             # build it and open the window
make build-headless  # a CGO-free static binary with no window
make test-race       # the tests under the race detector
make fuzz            # the wire codecs, briefly
```

The desktop build links against the platform's own webview: system frameworks
on macOS, `libwebkit2gtk-4.1-dev` on Linux, the WebView2 runtime on Windows
(present on Windows 11, installable on 10). The headless build needs none of
them and cross-compiles to every target.

This module depends on the engine by version, like any other dependency, so it
builds on its own with nothing else checked out.

To develop the two together, check them out side by side and add a `go.work`
naming both — it is deliberately not committed, because a workspace in a
repository silently overrides every collaborator's module resolution:

```sh
go work init ./dns ./dnsd ./dns-desktop
```

[adr1]: https://github.com/daboss2003/dns/blob/main/docs/adr/0001-two-products-one-dependency-boundary.md
[adr4]: docs/adr/0004-dns-capture-differs-by-platform.md
[adr6]: docs/adr/0006-a-desktop-application-not-a-local-server.md
[adr7]: docs/adr/0007-windows-trades-wifi-against-identity.md

## Licence

Apache-2.0. See [LICENSE](LICENSE).
