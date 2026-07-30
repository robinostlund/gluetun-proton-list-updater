package engine

import (
	"context"
	"fmt"

	"github.com/robinostlund/gluetun-proton-list-updater/internal/gluetunapi"
)

// setTunnelStatus starts or stops Gluetun's VPN loop on request.
//
// Stopping is safe from being undone behind the operator's back: evaluate treats a
// stopped tunnel as a deliberate decision and never starts it, so the tunnel stays down
// until it is started again here.
func (e *Engine) setTunnelStatus(ctx context.Context, status string) (err error) {
	if status != gluetunapi.StatusRunning && status != gluetunapi.StatusStopped {
		return fmt.Errorf("vpn status must be %q or %q, not %q",
			gluetunapi.StatusRunning, gluetunapi.StatusStopped, status)
	}

	e.setActivity(fmt.Sprintf("asking gluetun to %s the tunnel", verbFor(status)))
	defer func() {
		e.setActivity("")
		e.publish()
	}()

	outcome, err := e.gluetun.SetStatus(ctx, status)
	if err != nil {
		e.logger.Error("could not change the tunnel state", "status", status, "error", err)
		return err
	}
	e.logger.Info("changed the tunnel state", "status", status, "outcome", outcome)

	// A stop invalidates what we knew about where the tunnel was, and a start means the
	// selection may have changed; refresh rather than leaving stale values on display.
	e.checkGluetun(ctx)
	return nil
}

// setDNSStatus starts or stops Gluetun's DNS-over-TLS resolver.
func (e *Engine) setDNSStatus(ctx context.Context, status string) (err error) {
	if status != gluetunapi.StatusRunning && status != gluetunapi.StatusStopped {
		return fmt.Errorf("dns status must be %q or %q, not %q",
			gluetunapi.StatusRunning, gluetunapi.StatusStopped, status)
	}

	e.setActivity(fmt.Sprintf("asking gluetun to %s its dns resolver", verbFor(status)))
	defer func() {
		e.setActivity("")
		e.publish()
	}()

	outcome, err := e.gluetun.SetDNSStatus(ctx, status)
	if err != nil {
		e.logger.Error("could not change the dns resolver state", "status", status, "error", err)
		return err
	}
	e.logger.Info("changed the dns resolver state", "status", status, "outcome", outcome)

	e.checkGluetun(ctx)
	return nil
}

func verbFor(status string) string {
	if status == gluetunapi.StatusStopped {
		return "stop"
	}
	return "start"
}
