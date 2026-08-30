# 0004. DNS capture is two capabilities, not one

- Status: Accepted
- Date: 2026-08-30
- Deciders: GatewayDNS maintainers

## Context

A filtering resolver only filters devices that ask it. Most devices ask whoever
DHCP told them to, and this product's own DHCP server tells them to ask us. The
gap is the device that ignores that and asks a resolver it was built with — a
streaming stick with `8.8.8.8` compiled in is the canonical case, and it is
exactly the device somebody installs this product to control.

On Linux the answer is `iptables -j REDIRECT` or its nftables equivalent: the
device believes it is talking to `8.8.8.8`, the packet arrives here, and it gets
a filtered answer. Nothing breaks and the device never knows.

Windows has no equivalent, and the search for one is worth recording so nobody
repeats it. The complete set of Windows Filtering Platform actions is block,
permit, and three callout forms — there is no rewrite action. Redirection is a
side effect only a kernel-mode callout driver can produce, which means an EV
certificate, Microsoft attestation signing and a per-release signing pipeline
for a desktop application. And it would not even work: the redirect layers are
ALE layers, which see sockets on this machine and never see forwarded traffic.
Windows has no PREROUTING. `netsh interface portproxy` is TCP only, and DNS is
mostly UDP.

## Decision

**Redirecting DNS and enforcing DNS are separate capabilities.
`CapDNSRedirect` rewrites; `CapDNSEnforce` blocks everything else.**

Windows implements `CapDNSEnforce` through user-mode WFP block filters at
`FWPM_LAYER_IPFORWARD_V4`, reachable from a CGO-free Go program through
`fwpuclnt.dll`. Linux implements both. Neither is switched on by default.

## Why

Modelling them as one capability forces a false choice: either Windows reports
that it cannot capture DNS at all — which is what an earlier draft did, and
which is wrong, because blocking the alternative resolvers achieves the same
policy outcome — or it claims a capability whose behaviour differs from every
other platform's in a way a user would notice immediately.

That difference is the whole reason for two names. A device with a hardcoded
resolver meets a redirect and is filtered silently. It meets enforcement and
either falls back to the resolver DHCP gave it — the good case, and the common
one — or stops resolving and appears broken. The second outcome is a support
call, so switching enforcement on is a decision an operator takes deliberately
with the consequence written next to the control, and `Status.DNSCapture` names
which mechanism is actually in force.

## Consequences

- Windows is not second-class for DNS capture. It captures by refusing rather
  than by rewriting, and the product says which.
- Enforcement is never a silent default on any platform, including the ones that
  could also redirect. Two mechanisms with visibly different failure modes must
  not be chosen for the user.
- Neither mechanism touches DNS over HTTPS to a hardcoded address. That is worth
  stating plainly rather than implying, because a perfect redirect on Linux does
  not solve it either: the answer to DoH is a blocklist entry for the resolver's
  own hostname and, for the hardcoded-address case, a firewall rule — not
  anything in this package.
