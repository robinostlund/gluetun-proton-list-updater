// Package logbuf keeps the most recent log records in memory so the dashboard
// can show what the tool has been doing without the operator needing to reach
// for `docker logs`.
package logbuf

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"
)

// Record is one captured log line.
type Record struct {
	Time    time.Time      `json:"time"`
	Level   string         `json:"level"`
	Message string         `json:"message"`
	Attrs   map[string]any `json:"attrs,omitempty"`
}

// Buffer is a fixed-size ring of records, safe for concurrent use.
type Buffer struct {
	mu      sync.RWMutex
	records []Record
	next    int
	filled  bool
}

// NewBuffer returns a Buffer holding at most size records.
func NewBuffer(size int) *Buffer {
	if size < 1 {
		size = 200
	}
	return &Buffer{records: make([]Record, size)}
}

// Append adds a record, overwriting the oldest one when full.
func (b *Buffer) Append(record Record) {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.records[b.next] = record
	b.next = (b.next + 1) % len(b.records)
	if b.next == 0 {
		b.filled = true
	}
}

// Reset discards every buffered record.
//
// Only the in-memory ring is affected; records already written to the container's
// own log stream are untouched, which is deliberate - this clears the dashboard's
// view, not the audit trail.
func (b *Buffer) Reset() {
	b.mu.Lock()
	defer b.mu.Unlock()

	// Overwrite rather than reallocate, so the slot the reader indexes into never
	// holds a stale record.
	clear(b.records)
	b.next = 0
	b.filled = false
}

// Records returns up to limit records, newest first.
func (b *Buffer) Records(limit int) (records []Record) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	count := b.next
	if b.filled {
		count = len(b.records)
	}
	if limit > 0 && limit < count {
		count = limit
	}

	records = make([]Record, 0, count)
	for i := range count {
		// Walk backwards from the most recently written slot.
		index := (b.next - 1 - i + len(b.records)*2) % len(b.records)
		records = append(records, b.records[index])
	}
	return records
}

// Handler is a slog.Handler that writes to a Buffer as well as to a wrapped
// handler, so records reach both the container log and the dashboard.
type Handler struct {
	inner  slog.Handler
	buffer *Buffer
	attrs  []slog.Attr
	groups []string
}

// NewHandler wraps inner so every record it receives is also captured.
func NewHandler(inner slog.Handler, buffer *Buffer) *Handler {
	return &Handler{inner: inner, buffer: buffer}
}

// Enabled implements slog.Handler.
func (h *Handler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.inner.Enabled(ctx, level)
}

// Handle implements slog.Handler.
func (h *Handler) Handle(ctx context.Context, record slog.Record) (err error) {
	attrs := make(map[string]any, record.NumAttrs()+len(h.attrs))
	for _, attr := range h.attrs {
		attrs[attr.Key] = attr.Value.Resolve().Any()
	}
	record.Attrs(func(attr slog.Attr) bool {
		attrs[attr.Key] = attr.Value.Resolve().Any()
		return true
	})
	// Values are rendered to strings so the dashboard's JSON encoding never
	// fails on an exotic attribute type.
	stringified := make(map[string]any, len(attrs))
	for key, value := range attrs {
		stringified[key] = fmt.Sprint(value)
	}

	h.buffer.Append(Record{
		Time:    record.Time,
		Level:   record.Level.String(),
		Message: record.Message,
		Attrs:   stringified,
	})
	return h.inner.Handle(ctx, record)
}

// WithAttrs implements slog.Handler.
func (h *Handler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &Handler{
		inner:  h.inner.WithAttrs(attrs),
		buffer: h.buffer,
		attrs:  append(append([]slog.Attr{}, h.attrs...), attrs...),
		groups: h.groups,
	}
}

// WithGroup implements slog.Handler.
func (h *Handler) WithGroup(name string) slog.Handler {
	return &Handler{
		inner:  h.inner.WithGroup(name),
		buffer: h.buffer,
		attrs:  h.attrs,
		groups: append(append([]string{}, h.groups...), name),
	}
}
