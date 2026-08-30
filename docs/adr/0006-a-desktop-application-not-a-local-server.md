# 0006. A desktop application, not a local server

- Status: Accepted, supersedes an earlier decision
- Date: 2026-08-30
- Deciders: GatewayDNS maintainers

## Context

The first plan for this product's interface was: one static binary serving an
embedded page on loopback, and the user's browser is the window. It was chosen
for engineering properties — `CGO_ENABLED=0`, one file, cross-compiles to eight
targets from one machine, no second toolchain.

Those are real advantages and they were the wrong thing to optimise. The product
is called Desktop. A tab at `http://127.0.0.1:8080` has no dock icon, does not
appear when you Alt-Tab, has no menu bar, does not start when you double-click
anything and does not stop when you quit it. Every one of those is what a person
means by "a desktop app", and none of them was on the list the decision was made
against.

## Decision

**GatewayDNS Desktop is a native window and a menu-bar item in one process.**

The window is an operating-system webview — WKWebView, WebKitGTK, WebView2 —
hosting the same embedded interface. The menu-bar item is the primary surface.
A `nogui` build tag produces the previous arrangement for machines with no
display.

## Why

The window is a webview rather than a native toolkit because the interface is a
dashboard: tables of devices, a live list of queries, counters. That is what
HTML is good at, and rebuilding it in a Go GUI toolkit would be several times
the work for a worse result. Using the platform's own webview rather than
bundling a browser engine keeps the download small and the rendering native.

**The menu-bar item is primary and the window is on demand.** A filtering
gateway runs continuously and is looked at rarely; what somebody needs at hand
is "is it on", "pause it", "show me". A window that had to stay open for the
resolver to work would be a resolver that stops when you tidy your desktop, so
closing the window hides it and quitting is a deliberate choice from the menu —
because on this product, quitting means the network stops being filtered.

**The interface still talks to its own process over HTTP.** That looks like
indirection when the window is in the same binary, and it is what makes one
interface serve two deployments: the same screens work pointed at a
`gatewaydnsd` on a server. A private binding between the window and the
application would have made the remote case a second interface to write and
keep in step.

## Consequences

- The desktop build needs CGO and links against the platform's webview: system
  frameworks on macOS, WebKitGTK on Linux, the WebView2 runtime on Windows.
  That is an ordinary cost for a desktop application and it is confined to the
  shell — the engine keeps its empty dependency graph, and `-tags nogui` keeps a
  `CGO_ENABLED=0` static binary for a Raspberry Pi or a container.
- Cross-compiling every target from one machine is over for the GUI build. CI
  builds it natively on each platform, which it already does now that Windows is
  in the test matrix.
- **A constraint discovered by experiment, and the reason this is one process:**
  on macOS both a menu-bar item and a webview want to be `NSApplication` and own
  the main thread. They coexist in exactly one order — the tray started in its
  external-loop mode, which returns, and then the webview owning the run loop.
  `systray.Run` deadlocks. The main thread is locked for the shell's lifetime
  and every webview call is dispatched onto it.
- The credential is injected into the page before the first script runs. It is
  never in the address bar, never in a cookie — a cookie on `127.0.0.1` is sent
  to every other service on `127.0.0.1` whatever port it listens on — and never
  on a command line, where on Linux any local user can read it from `/proc`. The
  headless build has no window to inject into, so it writes the token to a file
  only its own user can read, and logs the path rather than the token.
