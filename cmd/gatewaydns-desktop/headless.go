package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/daboss2003/dns-desktop/internal/app"
)

// runHeadless waits for a signal, which is what a service manager sends.
func runHeadless(a *app.App, served <-chan error, log *slog.Logger) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	select {
	case err := <-served:
		return err
	case <-ctx.Done():
	}
	log.Info("shutting down")
	// Queries already accepted are finished before the process leaves, because
	// dropping them turns a routine restart into a visible failure on every
	// device behind the resolver.
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return a.Shutdown(shutdownCtx)
}
