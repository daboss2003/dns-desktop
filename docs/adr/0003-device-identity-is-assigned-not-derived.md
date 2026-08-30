# 0003. Device identity is assigned, not derived

- Status: Accepted
- Date: 2026-08-30
- Deciders: GatewayDNS maintainers

## Context

A rule is set on a device. A DNS query carries an address. Something has to join
the two, and it has to keep them joined across reconnects, address changes and
restarts — because a rule that comes off by itself is worse than no rule, and
the user's description of the failure is "the parental controls stopped working
and I don't know when".

The obvious key is the hardware address.

## Decision

**A device has an opaque identifier of this application's own making. Hardware
address, hostname and current address are observations that point at it.**

When a device does arrive as a stranger, a person can merge the two records.

## Why

Every observable signal is unstable in a different way.

A **hardware address** is randomised by default on current iOS and Android. The
randomisation is per-network and persistent, which is why keying on it works at
all — a phone keeps one address on this network — but a device reset, a "forget
this network", or one of the rotating modes produces a new one, and the same
phone arrives as a stranger. A key derived from it takes every rule with it when
it changes.

A **hostname** is whatever somebody typed into a settings screen. It is not
unique, it is not stable, and it is chosen by the device rather than by us.

An **address** is ours to assign and stable while a lease holds — which is what
the lease pool works to preserve — but not across a re-addressing, and on a
network where somebody else runs DHCP it is not ours at all.

Assigning the identity separates the thing rules are attached to from the things
that change. The observations attach and detach; the identity does not.

The merge capability is the honest part. No automatic scheme is reliable, and a
product that pretended otherwise would leave a household with two entries for
one phone and no way to fix it. Saying so in the design is better than
discovering it in the field.

## Consequences

- Two records for one device is a normal state that the interface must present
  and offer to merge, not an error.
- Identity is persisted, and the persisted state includes the address mappings.
  A table that relearned addresses after a restart would apply the default
  profile to every device on the network for the first queries after every
  restart, which is a filtering product briefly not filtering.
- An address freed by one device must identify nobody until another claims it.
  Both the lease pool and the device table enforce that separately, because a
  stale mapping in either would hand the next device the previous one's rules.
- The engine needed a seam for this. `resolver.Options.Identify` runs before the
  middleware chain and before anything is recorded, so the policy decision, the
  metrics and the query log all get one answer to "who asked this". A middleware
  could not have done it: the chain takes `resolver.Client` by value, so a
  middleware informs what runs after it and nothing before — including the code
  that records the query.
