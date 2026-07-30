// Package latency measures the round-trip time to Proton entry servers.
//
// The probe is a plain TCP connect to the entry IP, timed from dial to
// established. That deliberately avoids ICMP: raw sockets need NET_RAW, which
// many container setups do not grant, and Proton entry nodes accept TCP 443 on
// every server for OpenVPN over TCP. The number measured is therefore the same
// path a real handshake takes.
//
// One caveat is worth knowing: the measurement is taken from wherever this
// process runs. Run the sidecar on a normal Docker network, not inside
// Gluetun's network namespace, or every measurement is taken through the
// existing tunnel and means nothing.
package latency

import (
	"context"
	"net"
	"net/netip"
	"sort"
	"sync"
	"time"
)

// Result is a single server's measurement.
type Result struct {
	// RTT is the best (lowest) round trip of the samples taken. The minimum is
	// used rather than the mean because it is the least polluted by scheduler
	// noise and transient queueing.
	RTT time.Duration
	// Err is set when every sample failed. RTT is then zero.
	Err error
	// MeasuredAt is when the probe completed.
	MeasuredAt time.Time
	// Samples is how many attempts succeeded.
	Samples int
}

// OK reports whether the measurement produced a usable round trip.
func (r Result) OK() bool { return r.Err == nil && r.RTT > 0 }

// Options configures a Prober.
type Options struct {
	Port        int
	Samples     int
	Timeout     time.Duration
	Concurrency int
	// SmoothingFactor is the weight of a new measurement in the exponentially
	// weighted moving average (0 < f <= 1). 1 discards history entirely.
	// Smoothing matters because a single unlucky probe should not be able to
	// trigger a reconnect.
	SmoothingFactor float64
	// Dial overrides the dialer. Used by tests.
	Dial func(ctx context.Context, address string) (net.Conn, error)
}

// Prober measures and remembers round-trip times.
type Prober struct {
	opts Options

	mu      sync.RWMutex
	history map[string]Result // keyed by IP string
}

// New builds a Prober, applying defaults for anything left unset.
func New(opts Options) *Prober {
	if opts.Port == 0 {
		opts.Port = 443
	}
	if opts.Samples < 1 {
		opts.Samples = 3
	}
	if opts.Timeout <= 0 {
		opts.Timeout = 2 * time.Second
	}
	if opts.Concurrency < 1 {
		opts.Concurrency = 16
	}
	if opts.SmoothingFactor <= 0 || opts.SmoothingFactor > 1 {
		opts.SmoothingFactor = 0.5
	}
	if opts.Dial == nil {
		opts.Dial = func(ctx context.Context, address string) (net.Conn, error) {
			var dialer net.Dialer
			return dialer.DialContext(ctx, "tcp", address)
		}
	}
	return &Prober{opts: opts, history: make(map[string]Result)}
}

// Probe measures every address concurrently and returns the smoothed results,
// keyed by address string.
//
// Probing is bounded by Concurrency, and the whole run respects ctx: a shutdown
// during a 600-server sweep returns promptly with whatever completed.
func (p *Prober) Probe(ctx context.Context, addresses []netip.Addr) (results map[string]Result) {
	results = make(map[string]Result, len(addresses))
	if len(addresses) == 0 {
		return results
	}

	type measurement struct {
		key    string
		result Result
	}

	jobs := make(chan netip.Addr)
	measurements := make(chan measurement, len(addresses))

	var workers sync.WaitGroup
	for range min(p.opts.Concurrency, len(addresses)) {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for address := range jobs {
				measurements <- measurement{
					key:    address.String(),
					result: p.probeOne(ctx, address),
				}
			}
		}()
	}

	go func() {
		defer close(jobs)
		for _, address := range addresses {
			select {
			case jobs <- address:
			case <-ctx.Done():
				return
			}
		}
	}()

	go func() {
		workers.Wait()
		close(measurements)
	}()

	for m := range measurements {
		results[m.key] = p.record(m.key, m.result)
	}
	return results
}

// probeOne dials the address up to Samples times and keeps the fastest success.
func (p *Prober) probeOne(ctx context.Context, address netip.Addr) (result Result) {
	target := net.JoinHostPort(address.String(), itoa(p.opts.Port))
	best := time.Duration(0)
	successes := 0
	var lastErr error

	for range p.opts.Samples {
		if ctx.Err() != nil {
			break
		}

		dialCtx, cancel := context.WithTimeout(ctx, p.opts.Timeout)
		start := time.Now()
		conn, err := p.opts.Dial(dialCtx, target)
		elapsed := time.Since(start)
		cancel()

		if err != nil {
			lastErr = err
			continue
		}
		_ = conn.Close()

		successes++
		if best == 0 || elapsed < best {
			best = elapsed
		}
	}

	if successes == 0 {
		return Result{Err: orUnreachable(lastErr), MeasuredAt: time.Now()}
	}
	return Result{RTT: best, MeasuredAt: time.Now(), Samples: successes}
}

// record blends a new measurement into the stored history.
//
// A failed probe does not erase a previous good measurement; it is kept as-is
// but reported as failed, so one flaky sweep cannot make every server look
// equally unknown.
func (p *Prober) record(key string, fresh Result) (blended Result) {
	p.mu.Lock()
	defer p.mu.Unlock()

	previous, hadPrevious := p.history[key]
	switch {
	case !fresh.OK() && hadPrevious && previous.OK():
		blended = Result{
			RTT:        previous.RTT,
			Err:        fresh.Err,
			MeasuredAt: fresh.MeasuredAt,
			Samples:    previous.Samples,
		}
	case !fresh.OK():
		blended = fresh
	case hadPrevious && previous.OK():
		factor := p.opts.SmoothingFactor
		smoothed := time.Duration(factor*float64(fresh.RTT) + (1-factor)*float64(previous.RTT))
		blended = Result{RTT: smoothed, MeasuredAt: fresh.MeasuredAt, Samples: fresh.Samples}
	default:
		blended = fresh
	}

	p.history[key] = blended
	return blended
}

// Results returns a copy of everything measured so far.
func (p *Prober) Results() (results map[string]Result) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	results = make(map[string]Result, len(p.history))
	for key, result := range p.history {
		results[key] = result
	}
	return results
}

// Lookup returns the stored measurement for one address.
func (p *Prober) Lookup(address netip.Addr) (result Result, found bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	result, found = p.history[address.String()]
	return result, found
}

// Forget drops measurements for addresses that are no longer in the catalog, so
// the history cannot grow without bound over a long-lived container.
func (p *Prober) Forget(keep []netip.Addr) (removed int) {
	keepSet := make(map[string]struct{}, len(keep))
	for _, address := range keep {
		keepSet[address.String()] = struct{}{}
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	for key := range p.history {
		if _, wanted := keepSet[key]; !wanted {
			delete(p.history, key)
			removed++
		}
	}
	return removed
}

// Summary describes the current measurement set, for the dashboard.
type Summary struct {
	Measured int           `json:"measured"`
	Failed   int           `json:"failed"`
	Best     time.Duration `json:"best_ns"`
	Median   time.Duration `json:"median_ns"`
	Worst    time.Duration `json:"worst_ns"`
	// LastRun is the newest measurement timestamp, zero before anything is probed.
	//
	// The summary had no timestamp of its own, so the dashboard read an absent field and
	// showed "never" for ever, and the next-sweep countdown was computed from the last
	// *evaluation* instead - a different clock entirely.
	LastRun time.Time `json:"last_run"`
}

// Summarize computes aggregate statistics over the stored measurements.
func (p *Prober) Summarize() (summary Summary) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	rtts := make([]time.Duration, 0, len(p.history))
	for _, result := range p.history {
		if result.Err != nil {
			summary.Failed++
		}
		if result.MeasuredAt.After(summary.LastRun) {
			summary.LastRun = result.MeasuredAt
		}
		if result.RTT > 0 {
			rtts = append(rtts, result.RTT)
		}
	}
	if len(rtts) == 0 {
		return summary
	}

	sort.Slice(rtts, func(i, j int) bool { return rtts[i] < rtts[j] })
	summary.Measured = len(rtts)
	summary.Best = rtts[0]
	summary.Worst = rtts[len(rtts)-1]
	summary.Median = rtts[len(rtts)/2]
	return summary
}

func itoa(value int) string {
	if value == 0 {
		return "0"
	}
	digits := [6]byte{}
	index := len(digits)
	for value > 0 {
		index--
		digits[index] = byte('0' + value%10)
		value /= 10
	}
	return string(digits[index:])
}

// Record stores a measurement directly. It exists for tests and for seeding a
// prober from persisted data; normal operation goes through Probe.
func (p *Prober) Record(address netip.Addr, rtt time.Duration) {
	p.record(address.String(), Result{RTT: rtt, MeasuredAt: time.Now(), Samples: 1})
}
