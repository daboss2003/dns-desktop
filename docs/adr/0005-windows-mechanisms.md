# 0005. The Windows mechanisms, and which of them are real

- Status: Accepted
- Date: 2026-08-30
- Deciders: GatewayDNS maintainers

## Context

An earlier draft reported Windows as capable of nothing, on the assumption that
a gateway means hostapd plus our own DHCP plus our own firewall rules. That is a
Linux shape, and judging Windows by it produced a product that told the majority
of desktop users it was not for them.

Correcting that needed facts rather than confidence, because the Windows
networking surface is full of mechanisms that look right in documentation and
do not do what the name suggests. This ADR records what was actually verified
against Microsoft's documentation, so that the implementation slice is not spent
re-discovering it — and so that the three findings which contradict the obvious
approach are written down before somebody takes the obvious approach.

## Decision

**The Windows gateway is built from three independent pieces, chosen as
follows.** Each is recorded here with the caveat that decided it.

### Access point: `NetworkOperatorTetheringManager` (WinRT)

The Mobile Hotspot API. Confirmed present and complete:
`GetTetheringCapabilityFromConnectionProfile`, `CreateFromConnectionProfile`,
`ConfigureAccessPointAsync`, `StartTetheringAsync`, `GetTetheringClients` — the
last returning a MAC address and host names per client, which is a real device
source on a platform where the hotspot owns DHCP.

Reachable from CGO-free Go through `combase.dll` and vtable dispatch. Three
constraints that are not obvious:

- The manager is declared `ThreadingModel.Both` and is **not** agile. It must be
  created on a thread pinned with `runtime.LockOSThread` and every call made on
  that same thread, including the async poll loop. Stashing the pointer and
  calling it from an arbitrary goroutine is a latent crash.
- `AuthenticationKind` does not exist before Windows 11 24H2. On the actual
  target — Windows 10 22H2 and Windows 11 23H2 — the only configurable fields
  are SSID, passphrase and band, and the authentication is whatever the system
  picks. Configuring security is not on the table, so the product must not offer
  a control for it on this platform.
- The documentation says the `wiFiControl` device capability must be declared in
  an app manifest, which would mean MSIX packaging. Unpackaged PowerShell and
  C++ tools demonstrably drive the same API, and Microsoft's own guidance says
  unpackaged applications do not declare capabilities. **This is unresolved**,
  and it is the single highest-value thing to measure on a real machine before
  building on it. Microsoft documents the exact runtime test:
  `GetTetheringCapabilityFromConnectionProfile` returns
  `DisabledBySystemCapability` when the capability is missing.

`TetheringOperationStatus` — `WiFiDeviceOff`, `NetworkLimitedConnectivity`,
`AlreadyOn`, `RadioRestriction`, `BandInterference` and the rest — is the whole
diagnostic surface of this API, and belongs in the capability report rather than
being collapsed into a failure.

### NAT: prefer `New-NetNat`, fall back to Internet Connection Sharing

`New-NetNat` leaves DHCP and DNS to us, so the device table keeps the full
identity a lease exchange carries. It requires Hyper-V, **which cannot be
installed on Home editions**, is limited to one NAT network per host — Docker,
WSL or the Hyper-V default switch may already hold it — and is documented by
Microsoft only under Windows Server monikers despite being present on client
Windows. So it is preferred where it works and probed for rather than assumed.

Internet Connection Sharing is the fallback and carries three costs worth
knowing before choosing it:

- Its DNS proxy binds port 53 on the private interface, so our resolver cannot.
  Binding loopback and letting ICS forward to us collapses every client to one
  source address, **which destroys per-device policy entirely**. That cost is
  larger than the interception it would buy.
- `EnableSharing` triggers a documented user consent prompt, which a background
  service has nowhere to display.
- `EnableSharing` turns on Internet Connection Firewall on the shared connection
  as a side effect, and `DisableSharing` is documented as not undoing it. Our
  reconciliation cannot fully restore the machine with `DisableSharing` alone.
  It also silently disables whatever else was being shared.

`INetConnection` inherits `IUnknown`, not `IDispatch`, so the `IDispatch`-only
interop route does not cover it; `get_NetConnectionProps` is the way through.

### Blocking a device, and capturing DNS: user-mode WFP

Both are `FwpmFilterAdd0` against `FWPM_LAYER_IPFORWARD_V4`, through
`fwpuclnt.dll`, with no driver and no CGO.

**A Windows Firewall rule does not do this.** The firewall authors its filters
at the layers that see sockets on this machine; forwarded traffic never reaches
them, and bypassing firewall rules through a shared connection has been intended
behaviour since Windows 10. Implementing "pause the internet for this device"
with `netsh advfirewall` ships a feature that looks right in the interface and
does nothing at all. This is the finding most likely to be re-introduced by
somebody reaching for the obvious tool.

Two details that decide whether the filters work: the forwarding layer offers
`IP_SOURCE_ADDRESS` and not `IP_REMOTE_ADDRESS`, and a session opened with
`FWPM_SESSION_FLAG_DYNAMIC` has its filters removed automatically when the
process ends — which is the crash-cleanup story, and a far better one than
Linux's, where rules survive a kill and must be journalled and reconciled.

## Consequences

- Windows is a first-class platform with one permanent gap: it captures DNS by
  refusing other resolvers rather than by rewriting. See ADR 0004.
- `SetIpInterfaceEntry` and `CreateUnicastIpAddressEntry` are absent from
  `golang.org/x/sys/windows` and must be called through a lazy DLL binding.
- Two things must be measured on real hardware before the implementation slice
  commits to them: whether the tethering API works from an unpackaged process,
  and whether `New-NetNat` is usable on a machine without Hyper-V. Both have a
  documented runtime probe, so both belong in `Capabilities` rather than in an
  assumption.
