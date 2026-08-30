//go:build nogui

package main

import (
	"log/slog"

	"github.com/gatewaydns/gatewaydns-desktop/internal/app"
)

// runShell has no window in this build.
//
// The nogui tag exists so that a build for a machine with no display — a
// Raspberry Pi, a container, a CI runner — needs neither a webview library nor
// CGO, and stays a single static binary. It is the same application; only the
// shell is missing, so -headless is implied rather than refused.
func runShell(a *app.App, uiAddr string, log *slog.Logger) error {
	log.Info("built without a window; running headless",
		slog.String("interface", baseOfAddr(uiAddr)))
	return runHeadless(a, make(chan error), log)
}

func baseOfAddr(s string) string {
	for i := range s {
		if s[i] == '#' {
			return s[:i]
		}
	}
	return s
}
