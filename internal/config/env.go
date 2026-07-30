package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// reader collects values from the environment and accumulates errors so a
// misconfigured container reports every problem at once instead of failing one
// variable at a time across restarts.
type reader struct {
	errs []error
}

func (r *reader) errorf(format string, args ...any) {
	r.errs = append(r.errs, fmt.Errorf(format, args...))
}

// lookup returns the value of key, supporting two indirections used by
// container runtimes:
//
//	KEY_FILE=/run/secrets/key  reads the value from that file
//	KEY_SECRET=name            reads /run/secrets/name
//
// Values read from files are trimmed of surrounding whitespace, since editors
// and `echo` habitually add a trailing newline.
func (r *reader) lookup(key string) (value string, isSet bool) {
	if path := os.Getenv(key + "_FILE"); path != "" {
		return r.readFile(key+"_FILE", path)
	}
	if name := os.Getenv(key + "_SECRET"); name != "" {
		return r.readFile(key+"_SECRET", filepath.Join("/run/secrets", name))
	}
	value, isSet = os.LookupEnv(key)
	if !isSet {
		return "", false
	}
	// An explicitly empty variable is treated as unset so that
	// `KEY=` in a compose file falls back to the default.
	value = strings.TrimSpace(value)
	return value, value != ""
}

func (r *reader) readFile(key, path string) (value string, isSet bool) {
	data, err := os.ReadFile(path) //nolint:gosec // path is operator-provided by design
	if err != nil {
		r.errorf("%s: reading %s: %w", key, path, err)
		return "", false
	}
	value = strings.TrimSpace(string(data))
	if value == "" {
		r.errorf("%s: file %s is empty", key, path)
		return "", false
	}
	return value, true
}

func (r *reader) str(key, defaultValue string) string {
	if value, isSet := r.lookup(key); isSet {
		return value
	}
	return defaultValue
}

func (r *reader) required(key string) string {
	if value, isSet := r.lookup(key); isSet {
		return value
	}
	r.errorf("%s is required", key)
	return ""
}

func (r *reader) boolean(key string, defaultValue bool) bool {
	value, isSet := r.lookup(key)
	if !isSet {
		return defaultValue
	}
	switch strings.ToLower(value) {
	case "true", "yes", "on", "1":
		return true
	case "false", "no", "off", "0":
		return false
	default:
		r.errorf("%s: %q is not a boolean (use true or false)", key, value)
		return defaultValue
	}
}

func (r *reader) duration(key string, defaultValue time.Duration) time.Duration {
	value, isSet := r.lookup(key)
	if !isSet {
		return defaultValue
	}
	duration, err := time.ParseDuration(value)
	if err != nil {
		r.errorf("%s: %q is not a duration (e.g. 30s, 15m, 12h)", key, value)
		return defaultValue
	}
	if duration < 0 {
		r.errorf("%s: %q must not be negative", key, value)
		return defaultValue
	}
	return duration
}

func (r *reader) integer(key string, defaultValue int) int {
	value, isSet := r.lookup(key)
	if !isSet {
		return defaultValue
	}
	parsed, err := strconv.Atoi(value)
	if err != nil {
		r.errorf("%s: %q is not an integer", key, value)
		return defaultValue
	}
	return parsed
}

func (r *reader) float(key string, defaultValue float64) float64 {
	value, isSet := r.lookup(key)
	if !isSet {
		return defaultValue
	}
	parsed, err := strconv.ParseFloat(value, 64)
	if err != nil {
		r.errorf("%s: %q is not a number", key, value)
		return defaultValue
	}
	return parsed
}

// csv splits a comma-separated list, dropping empty elements. Returns nil when
// unset so callers can distinguish "not configured" from "configured empty".
func (r *reader) csv(key string) []string {
	value, isSet := r.lookup(key)
	if !isSet {
		return nil
	}
	fields := strings.Split(value, ",")
	list := make([]string, 0, len(fields))
	for _, field := range fields {
		if field = strings.TrimSpace(field); field != "" {
			list = append(list, field)
		}
	}
	return list
}

// choice reads a value restricted to a fixed set of options.
func (r *reader) choice(key, defaultValue string, options ...string) string {
	value, isSet := r.lookup(key)
	if !isSet {
		return defaultValue
	}
	value = strings.ToLower(value)
	for _, option := range options {
		if value == option {
			return value
		}
	}
	r.errorf("%s: %q is not one of %s", key, value, strings.Join(options, ", "))
	return defaultValue
}

// byteRate reads a transfer rate in bytes per second.
//
// Rates are written the way people say them - "1MB", "500KB", "2.5MiB" - because a
// threshold in bare bytes is unreadable and easy to get wrong by three orders of
// magnitude. A bare number is accepted as bytes per second.
//
// Both conventions are supported: KB/MB/GB are powers of ten, KiB/MiB/GiB powers of
// two, matching how each is normally defined. The "/s" is optional and ignored,
// since a rate is the only thing this can mean.
func (r *reader) byteRate(key string, defaultValue uint64) uint64 {
	value, isSet := r.lookup(key)
	if !isSet {
		return defaultValue
	}

	parsed, err := parseByteRate(value)
	if err != nil {
		r.errorf("%s: %q is not a transfer rate (e.g. 1MB, 500KB, 2MiB, or bytes per second)", key, value)
		return defaultValue
	}
	return parsed
}

// byteRateUnits is ordered longest-suffix-first, so "MiB" is matched before "B"
// and "KB" before "B".
var byteRateUnits = []struct {
	suffix string
	scale  float64
}{
	{"KIB", 1 << 10}, {"MIB", 1 << 20}, {"GIB", 1 << 30}, {"TIB", 1 << 40},
	{"KB", 1e3}, {"MB", 1e6}, {"GB", 1e9}, {"TB", 1e12},
	{"K", 1e3}, {"M", 1e6}, {"G", 1e9}, {"T", 1e12},
	{"B", 1},
}

func parseByteRate(value string) (bytesPerSecond uint64, err error) {
	text := strings.ToUpper(strings.TrimSpace(value))
	text = strings.TrimSuffix(text, "/S")
	text = strings.TrimSuffix(text, "PS")
	text = strings.TrimSpace(text)
	if text == "" {
		return 0, fmt.Errorf("empty rate")
	}

	scale := 1.0
	for _, unit := range byteRateUnits {
		if len(text) > len(unit.suffix) && strings.HasSuffix(text, unit.suffix) {
			scale = unit.scale
			text = strings.TrimSpace(strings.TrimSuffix(text, unit.suffix))
			break
		}
	}

	amount, err := strconv.ParseFloat(text, 64)
	if err != nil {
		return 0, fmt.Errorf("%q is not a number", text)
	}
	if amount < 0 {
		return 0, fmt.Errorf("must not be negative")
	}
	return uint64(amount * scale), nil
}
