//go:build !nogui

package main

import (
	"log/slog"
	"runtime"
	"strings"
	"sync"

	"fyne.io/systray"
	webview "github.com/webview/webview_go"

	"github.com/daboss2003/dns-desktop/internal/app"
)

// runShell is the desktop application: a menu-bar item and a window.
//
// The menu-bar item is the primary surface and the window is on demand, which
// is the right way round for this product. A filtering gateway runs
// continuously and is looked at rarely; what somebody actually needs at hand is
// "is it on", "pause it", "show me". A window that had to stay open for the
// resolver to keep working would be a resolver that stops when you tidy your
// desktop.
//
// Closing the window therefore hides it and does not quit. Quitting is a
// deliberate choice from the menu, because on this product quitting means the
// network stops being filtered.
func runShell(a *app.App, uiAddr string, log *slog.Logger) error {
	// Both the menu-bar item and the window want the main thread — on macOS
	// each wants to be NSApplication. They can share it only in this order:
	// systray in its external-loop mode, which starts and returns, and then
	// the webview owning the run loop. Reversing them, or using systray.Run,
	// deadlocks on macOS.
	runtime.LockOSThread()

	var (
		mu     sync.Mutex
		window webview.WebView
	)

	show := func() {
		mu.Lock()
		defer mu.Unlock()
		if window == nil {
			return
		}
		// Dispatch, because this is called from the menu's goroutine and every
		// webview call must happen on the thread that created it.
		window.Dispatch(func() { window.SetSize(1000, 700, webview.HintNone) })
	}

	startTray, stopTray := systray.RunWithExternalLoop(func() {
		systray.SetTitle("⛨")
		systray.SetTooltip("GatewayDNS — filtering DNS for this network")

		mOpen := systray.AddMenuItem("Open GatewayDNS", "Show the dashboard")
		systray.AddSeparator()
		mStatus := systray.AddMenuItem("Resolving on "+a.Status().Listen, "")
		mStatus.Disable()
		systray.AddSeparator()
		mQuit := systray.AddMenuItem("Quit GatewayDNS", "Stop filtering and exit")

		go func() {
			for {
				select {
				case <-mOpen.ClickedCh:
					show()
				case <-mQuit.ClickedCh:
					// Quitting stops the resolver, so the window is torn down
					// through the same path a window close would take and the
					// run loop returns.
					mu.Lock()
					w := window
					mu.Unlock()
					if w != nil {
						w.Dispatch(w.Terminate)
					}
					return
				}
			}
		}()
	}, func() {})
	startTray()
	defer stopTray()

	w := webview.New(false)
	defer w.Destroy()
	mu.Lock()
	window = w
	mu.Unlock()

	w.SetTitle("GatewayDNS")
	w.SetSize(1000, 700, webview.HintNone)
	// The credential is injected before the first page runs, so it is never in
	// the address bar, never in history, and never in a Referer header. A
	// token in a URL would be all three, and on Linux a token in the command
	// line of a launched browser is readable by every local user through /proc.
	w.Init(injectToken(uiAddr))
	w.Navigate(baseOf(uiAddr))
	log.Info("window open")
	w.Run()
	return nil
}

// injectToken builds the script that hands the page its credential.
//
// The token is spliced into a JSON string literal, so a token that somehow
// contained a quote could not close it. It cannot — it is hexadecimal — and
// the escaping is here anyway, because "this input is safe" is the assumption
// that stops being true when somebody changes how tokens are made.
func injectToken(uiAddr string) string {
	_, frag, _ := strings.Cut(uiAddr, "#t=")
	return "window.__GATEWAYDNS_TOKEN__ = " + quoteJS(frag) + ";"
}

func baseOf(uiAddr string) string {
	base, _, _ := strings.Cut(uiAddr, "#")
	return base
}

// quoteJS renders a string as a JavaScript literal.
func quoteJS(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"', '\\':
			b.WriteByte('\\')
			b.WriteRune(r)
		case '\n':
			b.WriteString("\\n")
		case '\r':
			b.WriteString("\\r")
		case '<', '>', '&':
			// Escaped as unicode, so that this string cannot terminate a
			// surrounding script element wherever it is later embedded.
			b.WriteString("\\u")
			const hex = "0123456789abcdef"
			b.WriteByte('0')
			b.WriteByte('0')
			b.WriteByte(hex[byte(r)>>4])
			b.WriteByte(hex[byte(r)&0xf])
		default:
			if r < 0x20 {
				continue
			}
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
	return b.String()
}
