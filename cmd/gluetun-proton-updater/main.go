// Command gluetun-proton-updater keeps a Gluetun container connected to the
// least utilised ProtonVPN server.
//
// It runs as a sidecar: it fetches Proton's server list, writes Gluetun's
// servers.json, measures latency to Proton's entry nodes, ranks servers by
// utilisation and latency, and moves the tunnel onto the winner through
// Gluetun's control server. A web dashboard exposes the same actions manually.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/robinostlund/gluetun-proton-list-updater/internal/config"
	"github.com/robinostlund/gluetun-proton-list-updater/internal/dashboard"
	"github.com/robinostlund/gluetun-proton-list-updater/internal/engine"
	"github.com/robinostlund/gluetun-proton-list-updater/internal/gluetunapi"
	"github.com/robinostlund/gluetun-proton-list-updater/internal/logbuf"
	"github.com/robinostlund/gluetun-proton-list-updater/internal/preflight"
	"github.com/robinostlund/gluetun-proton-list-updater/internal/proton"
)

// version is overridden at build time with -ldflags "-X main.version=...".
var version = "dev"

func main() {
	if err := run(); err != nil {
		// The logger may not exist yet when configuration fails, so this one
		// message goes straight to stderr.
		fmt.Fprintf(os.Stderr, "fatal: %s\n", err)
		os.Exit(1)
	}
}

func run() (err error) {
	cfg, err := config.Load()
	if err != nil {
		return err
	}

	logs := logbuf.NewBuffer(500)
	logger := newLogger(cfg, logs)
	slog.SetDefault(logger)

	logger.Info("gluetun proton list updater starting",
		"version", version,
		"state_dir", cfg.StateDir,
		"gluetun", cfg.Gluetun.BaseURL,
		"servers_file", cfg.Servers.FilePath)

	// Fail fast on unwritable directories. Without this the tool runs, logs a
	// warning per attempt and never writes servers.json - the one file that
	// makes it useful - which is a very easy failure to miss.
	checks := []preflight.Check{{
		Path:    cfg.StateDir,
		Purpose: "STATE_DIR: Proton session, cached server list, switch history",
		Hint: "Without it the Proton session cannot be persisted, so every restart re-authenticates - " +
			"and Proton rate-limits logins.",
	}}
	if cfg.Servers.WriteMode != config.WriteModeNone {
		// Both layouts are checked: which one Gluetun uses is detected at
		// runtime, and on a fresh volume the tool writes both.
		hint := "Gluetun creates this directory owned by root, so a container running as a " +
			"non-root user cannot replace files in it."
		checks = append(checks,
			preflight.Check{
				Path:    preflight.ServersDir(cfg.Servers.FilePath),
				Purpose: "GLUETUN_SERVERS_FILE directory: Gluetun's legacy servers.json location",
				Hint:    hint,
			},
			preflight.Check{
				Path:    cfg.Servers.DirPath,
				Purpose: "GLUETUN_SERVERS_DIR: Gluetun's per-provider servers directory",
				Hint:    hint,
			},
		)
	}
	if err := preflight.Verify(checks...); err != nil {
		return err
	}

	codeProvider, manual, err := newCodeProvider(cfg, logger)
	if err != nil {
		return err
	}

	protonClient, err := proton.New(proton.Options{
		BaseURL:      cfg.Proton.APIBaseURL,
		AppVersion:   cfg.Proton.AppVersion,
		UserAgent:    cfg.Proton.UserAgent,
		Timeout:      cfg.Proton.RequestTimeout,
		Username:     cfg.Proton.Username,
		Password:     cfg.Proton.Password,
		CodeProvider: codeProvider,
		SessionStore: proton.NewFileSessionStore(engine.SessionPath(cfg.StateDir)),
		Logger:       logger.With("component", "proton"),
	})
	if err != nil {
		return err
	}

	gluetunClient := gluetunapi.New(gluetunapi.Options{
		BaseURL:         cfg.Gluetun.BaseURL,
		APIKey:          cfg.Gluetun.APIKey,
		Username:        cfg.Gluetun.Username,
		Password:        cfg.Gluetun.Password,
		Timeout:         cfg.Gluetun.RequestTimeout,
		MutationTimeout: cfg.Gluetun.MutationTimeout,
	})

	core, err := engine.New(engine.Options{
		Config:  cfg,
		Logger:  logger.With("component", "engine"),
		Version: version,
		Proton:  protonClient,
		Gluetun: gluetunClient,
		Manual:  manual,
	})
	if err != nil {
		return err
	}

	// SIGTERM from `docker stop` and SIGINT from a terminal both mean the same
	// thing: finish what you are doing and exit.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	errs := make(chan error, 2)

	go func() {
		errs <- core.Run(ctx)
	}()

	if cfg.Dashboard.Enabled {
		server := dashboard.New(core, dashboard.Options{
			Address:  cfg.Dashboard.Address,
			Username: cfg.Dashboard.Username,
			Password: cfg.Dashboard.Password,
			Logger:   logger.With("component", "dashboard"),
			Logs:     logs,
		})
		go func() {
			errs <- server.Run(ctx)
		}()
	} else {
		logger.Info("dashboard disabled")
	}

	// The first error wins; a nil error means that component exited cleanly
	// because the context was cancelled.
	err = <-errs
	stop()

	// Give the remaining component a moment to unwind before returning.
	select {
	case second := <-errs:
		if err == nil {
			err = second
		}
	case <-time.After(6 * time.Second):
	}

	// Deliberately no logout on the way out.
	//
	// Logging out invalidates the refresh token and deletes the stored session, so
	// every restart would have to authenticate again - defeating the whole point of
	// persisting it, and walking straight into Proton's login rate limits for
	// anyone who restarts the container a few times in a row. Long-lived sessions
	// are how Proton's own clients behave; a stale one costs nothing.
	if err != nil && !errors.Is(err, context.Canceled) {
		return err
	}
	logger.Info("stopped cleanly")
	return nil
}

// newLogger builds the structured logger, teeing records into the ring buffer
// the dashboard reads.
func newLogger(cfg config.Config, logs *logbuf.Buffer) *slog.Logger {
	options := &slog.HandlerOptions{Level: cfg.LogLevel}

	var base slog.Handler
	if cfg.LogFormat == "json" {
		base = slog.NewJSONHandler(os.Stdout, options)
	} else {
		base = slog.NewTextHandler(os.Stdout, options)
	}
	return slog.New(logbuf.NewHandler(base, logs))
}

// newCodeProvider decides how two-factor codes are obtained.
//
// A configured secret means fully unattended operation. Without one, the
// dashboard is the only way in, so a manual provider is wired up and the login
// waits for a human when Proton asks for a code.
func newCodeProvider(cfg config.Config, logger *slog.Logger) (
	provider proton.CodeProvider, manual *proton.ManualCodeProvider, err error,
) {
	if cfg.Proton.TOTPSecret != "" {
		secretProvider, err := proton.NewSecretCodeProvider(cfg.Proton.TOTPSecret)
		if err != nil {
			return nil, nil, err
		}
		logger.Info("two-factor authentication will use the configured TOTP secret")
		return secretProvider, nil, nil
	}

	manual = proton.NewManualCodeProvider(10 * time.Minute)
	return manual, manual, nil
}
