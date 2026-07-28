// Package dashboard serves the web UI and its JSON API.
//
// The UI is a single embedded page with no build step and no external requests,
// so the container stays self-contained and works on an air-gapped network.
// Live updates use server-sent events, which need no client library and
// reconnect on their own.
package dashboard

import (
	"context"
	"crypto/subtle"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/robinostlund/gluetun-proton-list-updater/internal/engine"
	"github.com/robinostlund/gluetun-proton-list-updater/internal/logbuf"
)

//go:embed assets
var assetsFS embed.FS

// Controller is the slice of the engine the dashboard is allowed to drive.
// Depending on an interface rather than *engine.Engine keeps the UI honest
// about what it can do and makes it trivial to test.
type Controller interface {
	Snapshot() engine.Snapshot
	Subscribe() (updates <-chan struct{}, cancel func())
	RefreshList(ctx context.Context) error
	RefreshLoads(ctx context.Context) error
	ProbeLatency(ctx context.Context) error
	Evaluate(ctx context.Context) error
	SwitchToBest(ctx context.Context) error
	SwitchTo(ctx context.Context, hostname string) error
	WriteServersFile(ctx context.Context) error
	SetAutoSwitch(ctx context.Context, enabled bool) error
	SubmitTOTP(code string) bool
	Healthy() (healthy bool, reason string)
}

// Options configures a Server.
type Options struct {
	Address  string
	Username string
	Password string
	Logger   *slog.Logger
	Logs     *logbuf.Buffer
}

// Server is the dashboard HTTP server.
type Server struct {
	controller Controller
	opts       Options
	logger     *slog.Logger
	http       *http.Server
}

// New builds the dashboard server.
func New(controller Controller, opts Options) *Server {
	logger := opts.Logger
	if logger == nil {
		logger = slog.Default()
	}

	server := &Server{controller: controller, opts: opts, logger: logger}
	server.http = &http.Server{
		Addr:    opts.Address,
		Handler: server.routes(),
		// No write timeout: the SSE stream is deliberately long-lived.
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	return server
}

// Run serves until ctx is cancelled, then shuts down gracefully.
func (s *Server) Run(ctx context.Context) (err error) {
	errs := make(chan error, 1)
	go func() {
		s.logger.Info("dashboard listening", "address", s.opts.Address,
			"auth", s.opts.Username != "")
		if err := s.http.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errs <- err
			return
		}
		errs <- nil
	}()

	select {
	case err = <-errs:
		return err
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := s.http.Shutdown(shutdownCtx); err != nil {
			s.logger.Warn("dashboard shutdown was not clean", "error", err)
		}
		return nil
	}
}

func (s *Server) routes() http.Handler {
	mux := http.NewServeMux()

	// Health endpoints stay unauthenticated so Docker's health check works
	// without embedding credentials in the compose file.
	mux.HandleFunc("GET /healthz", s.handleHealth)
	mux.HandleFunc("GET /readyz", s.handleHealth)

	protected := http.NewServeMux()
	protected.Handle("GET /", s.handleStatic())
	protected.HandleFunc("GET /api/state", s.handleState)
	protected.HandleFunc("GET /api/events", s.handleEvents)
	protected.HandleFunc("GET /api/logs", s.handleLogs)
	protected.HandleFunc("POST /api/refresh", s.command("refresh", s.controller.RefreshList))
	protected.HandleFunc("POST /api/loads", s.command("loads", s.controller.RefreshLoads))
	protected.HandleFunc("POST /api/probe", s.command("probe", s.controller.ProbeLatency))
	protected.HandleFunc("POST /api/evaluate", s.command("evaluate", s.controller.Evaluate))
	protected.HandleFunc("POST /api/reconnect", s.command("reconnect", s.controller.SwitchToBest))
	protected.HandleFunc("POST /api/servers/write", s.command("write servers file", s.controller.WriteServersFile))
	protected.HandleFunc("POST /api/switch", s.handleSwitch)
	protected.HandleFunc("POST /api/auto-switch", s.handleAutoSwitch)
	protected.HandleFunc("POST /api/totp", s.handleTOTP)

	mux.Handle("/", s.withAuth(protected))
	return mux
}

// withAuth applies HTTP basic auth when credentials are configured.
func (s *Server) withAuth(next http.Handler) http.Handler {
	if s.opts.Username == "" {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		username, password, ok := r.BasicAuth()
		// Constant-time comparison keeps the check free of timing side
		// channels, which costs nothing here.
		userMatch := subtle.ConstantTimeCompare([]byte(username), []byte(s.opts.Username)) == 1
		passMatch := subtle.ConstantTimeCompare([]byte(password), []byte(s.opts.Password)) == 1
		if !ok || !userMatch || !passMatch {
			w.Header().Set("WWW-Authenticate", `Basic realm="gluetun proton updater"`)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) handleStatic() http.Handler {
	sub, err := fs.Sub(assetsFS, "assets")
	if err != nil {
		// Only reachable if the embed directive and directory disagree, which
		// is a build-time mistake.
		panic("dashboard: embedded assets missing: " + err.Error())
	}
	fileServer := http.FileServer(http.FS(sub))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The page is regenerated from live data on every load, so caching it
		// only creates confusion after an upgrade.
		w.Header().Set("Cache-Control", "no-store")
		fileServer.ServeHTTP(w, r)
	})
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	healthy, reason := s.controller.Healthy()
	status := http.StatusOK
	if !healthy {
		status = http.StatusServiceUnavailable
	}
	writeJSON(w, status, map[string]any{"healthy": healthy, "reason": reason})
}

func (s *Server) handleState(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.controller.Snapshot())
}

func (s *Server) handleLogs(w http.ResponseWriter, r *http.Request) {
	limit := 200
	if raw := r.URL.Query().Get("limit"); raw != "" {
		if parsed, err := strconv.Atoi(raw); err == nil && parsed > 0 {
			limit = parsed
		}
	}
	if s.opts.Logs == nil {
		writeJSON(w, http.StatusOK, []logbuf.Record{})
		return
	}
	writeJSON(w, http.StatusOK, s.opts.Logs.Records(limit))
}

// handleEvents streams snapshots as server-sent events.
func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Connection", "keep-alive")
	// Disable proxy buffering, which would otherwise hold events back until the
	// buffer fills.
	w.Header().Set("X-Accel-Buffering", "no")

	updates, cancel := s.controller.Subscribe()
	defer cancel()

	send := func() bool {
		payload, err := json.Marshal(s.controller.Snapshot())
		if err != nil {
			s.logger.Warn("could not encode snapshot for event stream", "error", err)
			return true
		}
		if _, err := fmt.Fprintf(w, "data: %s\n\n", payload); err != nil {
			return false
		}
		flusher.Flush()
		return true
	}

	if !send() {
		return
	}

	// A slow heartbeat keeps intermediaries from closing an idle connection and
	// lets the browser notice a dead stream.
	heartbeat := time.NewTicker(25 * time.Second)
	defer heartbeat.Stop()
	// Coalesce bursts: many small snapshot changes during a switch would
	// otherwise flood the browser.
	throttle := time.NewTicker(500 * time.Millisecond)
	defer throttle.Stop()

	pending := false
	for {
		select {
		case <-r.Context().Done():
			return
		case _, open := <-updates:
			if !open {
				return
			}
			pending = true
		case <-throttle.C:
			if pending {
				pending = false
				if !send() {
					return
				}
			}
		case <-heartbeat.C:
			if _, err := io.WriteString(w, ": ping\n\n"); err != nil {
				return
			}
			flusher.Flush()
		}
	}
}

// command adapts a no-argument engine action to an HTTP handler.
func (s *Server) command(name string, action func(ctx context.Context) error) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := action(r.Context()); err != nil {
			s.logger.Warn("dashboard command failed", "command", name, "error", err)
			writeJSON(w, http.StatusBadGateway, map[string]any{"ok": false, "error": err.Error()})
			return
		}
		writeJSON(w, http.StatusAccepted, map[string]any{"ok": true, "command": name})
	}
}

func (s *Server) handleSwitch(w http.ResponseWriter, r *http.Request) {
	var request struct {
		Hostname string `json:"hostname"`
	}
	if err := decodeJSON(r, &request); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	if request.Hostname == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "hostname is required"})
		return
	}

	// Switching waits for verification, which can take the better part of a
	// minute; the browser is told to be patient by the UI, not by a shorter
	// timeout here.
	if err := s.controller.SwitchTo(r.Context(), request.Hostname); err != nil {
		s.logger.Warn("dashboard switch failed", "hostname", request.Hostname, "error", err)
		writeJSON(w, http.StatusBadGateway, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "hostname": request.Hostname})
}

func (s *Server) handleAutoSwitch(w http.ResponseWriter, r *http.Request) {
	var request struct {
		Enabled bool `json:"enabled"`
	}
	if err := decodeJSON(r, &request); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	if err := s.controller.SetAutoSwitch(r.Context(), request.Enabled); err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "enabled": request.Enabled})
}

func (s *Server) handleTOTP(w http.ResponseWriter, r *http.Request) {
	var request struct {
		Code string `json:"code"`
	}
	if err := decodeJSON(r, &request); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	if !s.controller.SubmitTOTP(request.Code) {
		writeJSON(w, http.StatusConflict, map[string]any{
			"ok":    false,
			"error": "no login is waiting for a two-factor code right now",
		})
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]any{"ok": true})
}

func decodeJSON(r *http.Request, value any) (err error) {
	defer func() { _ = r.Body.Close() }()
	decoder := json.NewDecoder(io.LimitReader(r.Body, 64<<10))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return fmt.Errorf("invalid request body: %w", err)
	}
	return nil
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	_ = encoder.Encode(value)
}
