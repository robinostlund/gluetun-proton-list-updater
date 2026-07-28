package logbuf

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"
)

func TestBufferReturnsNewestFirst(t *testing.T) {
	t.Parallel()

	buffer := NewBuffer(5)
	for _, message := range []string{"one", "two", "three"} {
		buffer.Append(Record{Time: time.Now(), Message: message})
	}

	records := buffer.Records(0)
	if len(records) != 3 {
		t.Fatalf("got %d records, want 3", len(records))
	}
	if records[0].Message != "three" || records[2].Message != "one" {
		t.Errorf("order = %q, %q, %q; want newest first",
			records[0].Message, records[1].Message, records[2].Message)
	}
}

func TestBufferWrapsAndDropsOldest(t *testing.T) {
	t.Parallel()

	buffer := NewBuffer(3)
	for _, message := range []string{"a", "b", "c", "d", "e"} {
		buffer.Append(Record{Message: message})
	}

	records := buffer.Records(0)
	if len(records) != 3 {
		t.Fatalf("got %d records, want 3", len(records))
	}
	if records[0].Message != "e" || records[1].Message != "d" || records[2].Message != "c" {
		t.Errorf("records = %+v, want e, d, c", records)
	}
}

func TestBufferRespectsLimit(t *testing.T) {
	t.Parallel()

	buffer := NewBuffer(10)
	for i := range 8 {
		buffer.Append(Record{Message: string(rune('a' + i))})
	}

	if got := len(buffer.Records(3)); got != 3 {
		t.Errorf("Records(3) returned %d entries", got)
	}
	if got := len(buffer.Records(100)); got != 8 {
		t.Errorf("Records(100) returned %d entries, want all 8", got)
	}
}

func TestBufferEmpty(t *testing.T) {
	t.Parallel()

	buffer := NewBuffer(4)
	if got := len(buffer.Records(0)); got != 0 {
		t.Errorf("an empty buffer returned %d records", got)
	}
}

// The handler must forward to the wrapped handler as well as capture, so log
// lines still reach the container log.
func TestHandlerCapturesAndForwards(t *testing.T) {
	t.Parallel()

	buffer := NewBuffer(10)
	var forwarded int
	counting := &countingHandler{count: &forwarded}

	logger := slog.New(NewHandler(counting, buffer))
	logger.With("component", "test").Info("hello", "hostname", "se-01", "load", 42)

	records := buffer.Records(0)
	if len(records) != 1 {
		t.Fatalf("got %d records, want 1", len(records))
	}
	record := records[0]
	if record.Message != "hello" || record.Level != "INFO" {
		t.Errorf("record = %+v", record)
	}
	// Attributes from both With and the call site must be present, rendered as
	// strings so JSON encoding can never fail on an exotic type.
	for key, want := range map[string]string{"component": "test", "hostname": "se-01", "load": "42"} {
		if got := record.Attrs[key]; got != want {
			t.Errorf("attr %q = %v, want %q", key, got, want)
		}
	}
	if forwarded != 1 {
		t.Errorf("forwarded %d records to the inner handler, want 1", forwarded)
	}
}

func TestHandlerRespectsLevel(t *testing.T) {
	t.Parallel()

	buffer := NewBuffer(10)
	inner := slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelWarn})
	logger := slog.New(NewHandler(inner, buffer))

	logger.Debug("filtered out")
	logger.Warn("kept")

	records := buffer.Records(0)
	if len(records) != 1 || records[0].Message != "kept" {
		t.Errorf("records = %+v, want only the warning", records)
	}
}

func TestHandlerWithGroup(t *testing.T) {
	t.Parallel()

	buffer := NewBuffer(10)
	logger := slog.New(NewHandler(slog.NewTextHandler(io.Discard, nil), buffer))
	logger.WithGroup("proton").Info("grouped", "key", "value")

	if len(buffer.Records(0)) != 1 {
		t.Error("a grouped logger should still capture records")
	}
}

type countingHandler struct {
	count *int
	attrs []slog.Attr
}

func (h *countingHandler) Enabled(context.Context, slog.Level) bool { return true }

func (h *countingHandler) Handle(context.Context, slog.Record) error {
	*h.count++
	return nil
}

func (h *countingHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &countingHandler{count: h.count, attrs: append(h.attrs, attrs...)}
}

func (h *countingHandler) WithGroup(string) slog.Handler { return h }
