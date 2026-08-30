# 0001. Capabilities are part of the gateway interface

- Status: Accepted
- Date: 2026-08-30
- Deciders: GatewayDNS maintainers

## Context

GatewayDNS Desktop turns a machine into a filtering gateway. Doing that means
creating a Wi-Fi access point, routing and masquerading a subnet, redirecting
DNS, and cutting individual devices off — and the platforms differ so much in
what they permit that the differences cannot be hidden.

Linux can do all of it, given an adapter whose driver supports AP mode and one
of `nft` or `iptables`. macOS can do almost none of it: there is no supported
interface for a program to bring up an access point, and Internet Sharing —
which does exactly what this product wants — is a preference pane that a person
turns on. Windows has neither today.

The obvious design is a `Gateway` interface with a method per feature and
implementations that return "not supported" from the ones they lack.

## Decision

**A platform states what it can do before anything is attempted, and every
refusal names a capability and gives a reason a person can read.**

`Gateway.Capabilities` returns the set that is available, a reason for every one
that is not, and a marker for the absences a person could act on.

## Why

A `Gateway` that only refuses at the point of use produces two failures.

The first is a user interface that discovers what it can do by trying and
failing. A "create a hotspot" button that returns an error when pressed is worse
than one greyed out with an explanation, and the interface cannot grey it out
without asking first.

The second is worse: an application that cannot tell a missing feature from a
broken one. "Not supported" and "the driver rejected the netlink attribute" both
arrive as errors, and only one of them is worth retrying, reporting, or telling
the user to buy hardware for.

The reasons are the load-bearing part. "You cannot create a hotspot" has at
least four causes with four different actions:

- there is no wireless adapter — buy one;
- the adapter's driver has no AP mode — buy a different one;
- the only adapter is carrying the connection being shared — share a wired
  connection instead;
- the platform will never support it — stop waiting.

A greyed-out control with no explanation turns every one of those into a support
question that cannot be answered remotely. So `Capabilities.Reasons` is not
optional, `Capabilities.Fixable` separates advice from a fact of life, and the
JSON form is a list of capabilities with reasons rather than a bit set the front
end would have to interpret.

`Config.Required` and `CheckCapabilities` follow from the same decision: a
configuration a platform cannot satisfy is refused in one place, naming every
missing capability, rather than partway through bring-up with whatever error the
fifth step produced.

## Consequences

- macOS ships as a real implementation of the part it can do, and says clearly
  what it cannot. It is not a stub and not a lie.
- Adding a capability means adding it to the enumeration, which forces every
  platform to answer for it — including with "no, because".
- A capability check is a second thing to keep in step with the implementation.
  The contract test requires every unavailable capability to carry a reason, so
  the cheap failure mode — adding a capability and forgetting to explain its
  absence — fails the build rather than shipping a silent control.
