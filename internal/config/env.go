package config

import (
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Variable is one configuration setting as it was actually resolved.
//
// Recorded while parsing rather than described afterwards, which is the only way the list
// cannot drift: a variable that is read is a variable that appears, and a new one appears
// without anybody remembering to add it anywhere. The dashboard's settings panel used to be
// a hand-maintained list of about half of them.
type Variable struct {
	Name string `json:"name"`
	// Value is the resolved value, formatted for display. For secrets it is never the
	// value itself - see Secret.
	Value string `json:"value"`
	// Configured distinguishes a value that was set from one that fell back to its
	// default, which is the difference between "this is what I asked for" and "this is
	// what happens when I do not ask".
	Configured bool `json:"configured"`
	// Secret marks a variable whose value must never leave the process. Value then says
	// only whether it is set, because that much is diagnostic and the rest is not.
	Secret bool `json:"secret,omitempty"`
}

// secretVariables are the variables whose values are never reported.
//
// A denylist rather than a heuristic on the name: "password" and "key" would catch these
// but also catch WIREGUARD_PRIVATE_KEY-shaped names this tool does not read, and missing
// one is a credential leak rather than a cosmetic bug. Anything added here is safe; the
// test that every variable is displayed is what stops one being forgotten.
var secretVariables = map[string]bool{
	"PROTON_PASSWORD":     true,
	"PROTON_TOTP_SECRET":  true,
	"GLUETUN_API_KEY":     true,
	"GLUETUN_PASSWORD":    true,
	"QBITTORRENT_API_KEY": true,
	"DASHBOARD_PASSWORD":  true,
}

// reader collects values from the environment and accumulates errors so a
// misconfigured container reports every problem at once instead of failing one
// variable at a time across restarts.
type reader struct {
	errs []error
	// variables is every setting read, in the order it was read. That order groups them
	// by subject already, because config.go reads them a section at a time.
	variables []Variable
}

// record notes how a variable resolved, for the settings panel.
func (r *reader) record(name, value string, configured bool) {
	if secretVariables[name] {
		// Whether a credential is set is worth knowing and safe to say. Its length is
		// not: that narrows a guess.
		value = "not set"
		if configured {
			value = "set"
		}
		r.variables = append(r.variables, Variable{
			Name: name, Value: value, Configured: configured, Secret: true,
		})
		return
	}
	if value == "" {
		value = "(empty)"
	}
	r.variables = append(r.variables, Variable{Name: name, Value: value, Configured: configured})
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
	value, isSet := r.lookup(key)
	if !isSet {
		value = defaultValue
	}
	r.record(key, value, isSet)
	return value
}

func (r *reader) required(key string) string {
	value, isSet := r.lookup(key)
	r.record(key, value, isSet)
	if !isSet {
		r.errorf("%s is required", key)
		return ""
	}
	return value
}

func (r *reader) boolean(key string, defaultValue bool) bool {
	value, isSet := r.lookup(key)
	if !isSet {
		r.record(key, strconv.FormatBool(defaultValue), false)
		return defaultValue
	}
	switch strings.ToLower(value) {
	case "true", "yes", "on", "1":
		r.record(key, "true", true)
		return true
	case "false", "no", "off", "0":
		r.record(key, "false", true)
		return false
	default:
		r.errorf("%s: %q is not a boolean (use true or false)", key, value)
		r.record(key, strconv.FormatBool(defaultValue), false)
		return defaultValue
	}
}

func (r *reader) duration(key string, defaultValue time.Duration) (resolved time.Duration) {
	// Recorded on every path, including the invalid ones, where the value that takes
	// effect is the default rather than what was written.
	configured := false
	defer func() { r.record(key, resolved.String(), configured) }()

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
	configured = true
	return duration
}

func (r *reader) integer(key string, defaultValue int) (resolved int) {
	configured := false
	defer func() { r.record(key, strconv.Itoa(resolved), configured) }()

	value, isSet := r.lookup(key)
	if !isSet {
		return defaultValue
	}
	parsed, err := strconv.Atoi(value)
	if err != nil {
		r.errorf("%s: %q is not an integer", key, value)
		return defaultValue
	}
	configured = true
	return parsed
}

func (r *reader) float(key string, defaultValue float64) (resolved float64) {
	configured := false
	defer func() {
		r.record(key, strconv.FormatFloat(resolved, 'f', -1, 64), configured)
	}()

	value, isSet := r.lookup(key)
	if !isSet {
		return defaultValue
	}
	parsed, err := strconv.ParseFloat(value, 64)
	if err != nil {
		r.errorf("%s: %q is not a number", key, value)
		return defaultValue
	}
	// ParseFloat accepts "nan" and "inf", and neither survives a range check: NaN
	// compares false against everything, so a "must not be negative" guard passes it
	// through, and it then poisons every arithmetic result it touches. A NaN scoring
	// weight would make every score NaN and the ranking meaningless, silently.
	if math.IsNaN(parsed) || math.IsInf(parsed, 0) {
		r.errorf("%s: %q is not a finite number", key, value)
		return defaultValue
	}
	configured = true
	return parsed
}

// csv splits a comma-separated list, dropping empty elements. Returns nil when
// unset so callers can distinguish "not configured" from "configured empty".
func (r *reader) csv(key string) (list []string) {
	// "(any)" rather than "(empty)" for an unset list: these are filters, and not
	// restricting something is different from restricting it to nothing.
	configured := false
	defer func() {
		shown := "(any)"
		if len(list) > 0 {
			shown = strings.Join(list, ", ")
		}
		r.record(key, shown, configured)
	}()

	value, isSet := r.lookup(key)
	if !isSet {
		return nil
	}
	configured = true
	fields := strings.Split(value, ",")
	list = make([]string, 0, len(fields))
	for _, field := range fields {
		if field = strings.TrimSpace(field); field != "" {
			list = append(list, field)
		}
	}
	return list
}

// choice reads a value restricted to a fixed set of options.
func (r *reader) choice(key, defaultValue string, options ...string) (resolved string) {
	configured := false
	defer func() { r.record(key, resolved, configured) }()

	value, isSet := r.lookup(key)
	if !isSet {
		return defaultValue
	}
	value = strings.ToLower(value)
	for _, option := range options {
		if value == option {
			configured = true
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
func (r *reader) byteRate(key string, defaultValue uint64) (resolved uint64) {
	// Shown the way it was written rather than in bytes: "2 MB/s" is the threshold an
	// operator set, and "2000000" is arithmetic they would have to do to recognise it.
	configured := false
	defer func() {
		shown := "not a trigger"
		if resolved > 0 {
			shown = formatByteRate(resolved)
		}
		r.record(key, shown, configured)
	}()

	value, isSet := r.lookup(key)
	if !isSet {
		return defaultValue
	}

	parsed, err := parseByteRate(value)
	if err != nil {
		r.errorf("%s: %q is not a transfer rate (e.g. 1MB, 500KB, 2MiB, or bytes per second)", key, value)
		return defaultValue
	}
	configured = true
	return parsed
}

// formatByteRate renders a rate the way it is written in configuration.
func formatByteRate(bytesPerSecond uint64) string {
	const unit = 1000
	if bytesPerSecond < unit {
		return fmt.Sprintf("%d B/s", bytesPerSecond)
	}
	value := float64(bytesPerSecond)
	for _, suffix := range []string{"kB/s", "MB/s", "GB/s", "TB/s"} {
		value /= unit
		if value < unit {
			return fmt.Sprintf("%.3g %s", value, suffix)
		}
	}
	return fmt.Sprintf("%.3g PB/s", value/unit)
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
	// "nan" and "inf" parse cleanly and then defeat every range check below, because
	// NaN compares false against everything. Left in, a NaN threshold would never be
	// exceeded and an Inf one could never be reached - so the protection this setting
	// exists to provide would be silently switched off by a typo.
	if math.IsNaN(amount) || math.IsInf(amount, 0) {
		return 0, fmt.Errorf("%q is not a finite number", text)
	}
	if amount < 0 {
		return 0, fmt.Errorf("must not be negative")
	}

	// Converting an out-of-range float to an integer is undefined in Go, so the range
	// has to be checked before the conversion rather than after.
	total := amount * scale
	if total > math.MaxUint64 {
		return 0, fmt.Errorf("%q is too large to be a transfer rate", value)
	}
	return uint64(total), nil
}
