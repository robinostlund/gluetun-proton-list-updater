package engine

import (
	"context"
	"fmt"
	"strconv"
	"strings"
)

// Rates are carried through this package in **bits per second**, as uint64.
//
// One unit, converted once, at the boundary where a source is read. Every source reports
// something different - qBittorrent's Web API answers in bytes per second, a network
// interface counter is bytes, and a future Gluetun route would be whatever Gluetun chooses -
// so the choice is between converting at the edge or carrying the unit around with the value
// and getting it wrong somewhere. Bits because that is what a link speed is quoted in, so it
// is also what the thresholds are written in and what the dashboard displays: nothing between
// the source adapter and the screen multiplies by anything.
//
// Volumes are the exception and stay in bytes: "412 GB downloaded" is a volume, and nobody
// measures data in bits.

// bitsPerByte is the only place the conversion appears.
const bitsPerByte = 8

// bitsFromBytes converts a byte rate reported by a source into the canonical unit.
func bitsFromBytes(bytesPerSecond uint64) uint64 { return bytesPerSecond * bitsPerByte }

// rateReading is what a source reports for one moment.
type rateReading struct {
	// Download and Upload are bits per second.
	Download uint64
	Upload   uint64
	// DownloadedBytes and UploadedBytes are the source's cumulative counters, in bytes, or
	// zero when the source has none. Volumes are attributed by difference between readings,
	// so a source without counters simply contributes no volume.
	DownloadedBytes uint64
	UploadedBytes   uint64
}

// rateSource is something that can say how fast traffic is flowing.
//
// An interface with one implementation today, existing so a second can be added without
// touching anything that consumes the readings. Gluetun is the expected second: it sits in
// the network namespace the traffic actually crosses, so its numbers would cover everything
// through the tunnel rather than one torrent client's share - which makes it the better
// source, and the reason the list is ordered rather than a single field.
//
// Gluetun exposes no such route today. Its control server has no throughput endpoint and it
// never reads the byte counters in its own namespace, so this cannot be implemented against
// it yet; the seam is here so that it is a new file and a line in the list when it can be.
type rateSource interface {
	// name identifies the source in logs and on the dashboard, because "which of these
	// answered?" is otherwise unanswerable.
	name() string
	// read returns the current rates, or an error if the source cannot be reached.
	read(ctx context.Context) (reading rateReading, err error)
}

// readRates asks each source in order and returns the first answer.
//
// Order is priority: the first source that answers wins, and the others are not consulted.
// Every failure is returned alongside so a caller can report why a preferred source was
// skipped rather than silently using a fallback.
func readRates(ctx context.Context, sources []rateSource) (
	reading rateReading, source string, failures []error,
) {
	for _, candidate := range sources {
		reading, err := candidate.read(ctx)
		if err == nil {
			return reading, candidate.name(), failures
		}
		failures = append(failures, fmt.Errorf("%s: %w", candidate.name(), err))
	}
	return rateReading{}, "", failures
}

// formatRate renders a rate in bits per second, scaling to the unit that fits.
func formatRate(bitsPerSecond uint64) string {
	const step = 1000
	if bitsPerSecond < step {
		return fmt.Sprintf("%d bit/s", bitsPerSecond)
	}
	value := float64(bitsPerSecond)
	for _, unit := range []string{"kbit/s", "Mbit/s", "Gbit/s", "Tbit/s"} {
		value /= step
		if value < step {
			return trimZero(value) + " " + unit
		}
	}
	return trimZero(value/step) + " Pbit/s"
}

// trimZero drops a trailing ".0", so a rate reads "16 Mbit/s" rather than "16.0 Mbit/s".
func trimZero(value float64) string {
	return strings.TrimSuffix(strconv.FormatFloat(value, 'f', 1, 64), ".0")
}

// formatBytes renders a volume. Deliberately unlike formatRate: logging a total as a rate
// states a measurement that was never taken, and the two differ by a unit and a factor of
// eight.
func formatBytes(total uint64) string {
	const step = 1000
	if total < step {
		return fmt.Sprintf("%d B", total)
	}
	value := float64(total)
	for _, unit := range []string{"kB", "MB", "GB", "TB"} {
		value /= step
		if value < step {
			return trimZero(value) + " " + unit
		}
	}
	return trimZero(value/step) + " PB"
}
