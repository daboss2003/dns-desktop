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

**Not started.** This repository exists so that the three-way boundary is real
from the start. Work begins at milestone 12 of the [engine's roadmap][core],
after the daemon.

## Scope

This application owns everything the engine deliberately does not: Wi-Fi
adapters, DHCP, NAT, firewall rules, device management, packaging and the user
interface. It contains **no DNS logic** — all of that comes from the engine,
consumed as an ordinary versioned dependency.

Each supported platform implements the same interface, so the application code
above it is platform-agnostic.

## Licence

Apache-2.0. See [LICENSE](LICENSE).
