package latency

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"
)

// fakeConn is the minimum net.Conn a probe touches: it is closed immediately.
type fakeConn struct{ net.Conn }

func (fakeConn) Close() error { return nil }

func TestProbeMeasuresAndKeepsTheFastestSample(t *testing.T) {
	t.Parallel()

	var calls atomic.Int32
	delays := []time.Duration{30 * time.Millisecond, 5 * time.Millisecond, 20 * time.Millisecond}

	prober := New(Options{
		Samples: 3,
		Dial: func(ctx context.Context, address string) (net.Conn, error) {
			index := int(calls.Add(1)) - 1
			time.Sleep(delays[index%len(delays)])
			return fakeConn{}, nil
		},
	})

	results := prober.Probe(context.Background(), []netip.Addr{netip.MustParseAddr("10.0.0.1")})
	result := results["10.0.0.1"]

	if !result.OK() {
		t.Fatalf("probe failed: %v", result.Err)
	}
	// The minimum of the three samples is around 5ms; allow generous slack for
	// slow CI machines.
	if result.RTT > 20*time.Millisecond {
		t.Errorf("RTT = %s, expected the fastest sample (~5ms)", result.RTT)
	}
	if result.Samples != 3 {
		t.Errorf("Samples = %d, want 3", result.Samples)
	}
}

func TestProbeRecordsFailure(t *testing.T) {
	t.Parallel()

	wantErr := errors.New("connection refused")
	prober := New(Options{
		Samples: 2,
		Dial: func(ctx context.Context, address string) (net.Conn, error) {
			return nil, wantErr
		},
	})

	results := prober.Probe(context.Background(), []netip.Addr{netip.MustParseAddr("10.0.0.1")})
	result := results["10.0.0.1"]

	if result.OK() {
		t.Fatal("expected the probe to fail")
	}
	if !errors.Is(result.Err, wantErr) {
		t.Errorf("Err = %v, want %v", result.Err, wantErr)
	}
}

// One bad sweep must not erase a known-good measurement, or a transient network
// blip would make every server look equally unknown and could trigger a switch.
func TestProbeKeepsPreviousRTTAfterAFailure(t *testing.T) {
	t.Parallel()

	fail := false
	prober := New(Options{
		Samples:         1,
		SmoothingFactor: 1,
		Dial: func(ctx context.Context, address string) (net.Conn, error) {
			if fail {
				return nil, errors.New("down")
			}
			time.Sleep(5 * time.Millisecond)
			return fakeConn{}, nil
		},
	})

	address := netip.MustParseAddr("10.0.0.1")
	good := prober.Probe(context.Background(), []netip.Addr{address})["10.0.0.1"]
	if !good.OK() {
		t.Fatal("first probe should succeed")
	}

	fail = true
	after := prober.Probe(context.Background(), []netip.Addr{address})["10.0.0.1"]
	if after.Err == nil {
		t.Error("the failure should be reported")
	}
	if after.RTT != good.RTT {
		t.Errorf("RTT = %s, want the previous %s to be retained", after.RTT, good.RTT)
	}
}

func TestProbeSmoothsAcrossRuns(t *testing.T) {
	t.Parallel()

	// Deterministic fake timings are impossible with a real clock, so this test
	// checks the blending arithmetic through record directly.
	prober := New(Options{SmoothingFactor: 0.5})
	prober.record("10.0.0.1", Result{RTT: 100 * time.Millisecond, Samples: 1})
	blended := prober.record("10.0.0.1", Result{RTT: 200 * time.Millisecond, Samples: 1})

	if blended.RTT != 150*time.Millisecond {
		t.Errorf("RTT = %s, want 150ms (0.5*200 + 0.5*100)", blended.RTT)
	}
}

func TestProbeRespectsContextCancellation(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	prober := New(Options{
		Samples: 3,
		Dial: func(ctx context.Context, address string) (net.Conn, error) {
			return nil, ctx.Err()
		},
	})

	addresses := make([]netip.Addr, 0, 50)
	for i := range 50 {
		addresses = append(addresses, netip.MustParseAddr("10.0.0."+itoa(i+1)))
	}

	done := make(chan struct{})
	go func() {
		prober.Probe(ctx, addresses)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Probe did not return promptly after cancellation")
	}
}

func TestForgetDropsStaleAddresses(t *testing.T) {
	t.Parallel()

	prober := New(Options{})
	prober.record("10.0.0.1", Result{RTT: time.Millisecond})
	prober.record("10.0.0.2", Result{RTT: time.Millisecond})

	removed := prober.Forget([]netip.Addr{netip.MustParseAddr("10.0.0.1")})
	if removed != 1 {
		t.Errorf("removed = %d, want 1", removed)
	}
	if _, found := prober.Lookup(netip.MustParseAddr("10.0.0.2")); found {
		t.Error("10.0.0.2 should have been forgotten")
	}
	if _, found := prober.Lookup(netip.MustParseAddr("10.0.0.1")); !found {
		t.Error("10.0.0.1 should have been kept")
	}
}

func TestSummarize(t *testing.T) {
	t.Parallel()

	prober := New(Options{})
	prober.record("10.0.0.1", Result{RTT: 10 * time.Millisecond})
	prober.record("10.0.0.2", Result{RTT: 20 * time.Millisecond})
	prober.record("10.0.0.3", Result{RTT: 30 * time.Millisecond})
	prober.record("10.0.0.4", Result{Err: ErrUnreachable})

	summary := prober.Summarize()
	switch {
	case summary.Measured != 3:
		t.Errorf("Measured = %d, want 3", summary.Measured)
	case summary.Failed != 1:
		t.Errorf("Failed = %d, want 1", summary.Failed)
	case summary.Best != 10*time.Millisecond:
		t.Errorf("Best = %s, want 10ms", summary.Best)
	case summary.Median != 20*time.Millisecond:
		t.Errorf("Median = %s, want 20ms", summary.Median)
	case summary.Worst != 30*time.Millisecond:
		t.Errorf("Worst = %s, want 30ms", summary.Worst)
	}
}

// The probe targets a real TCP port, so this checks the whole path against a
// local listener rather than a fake dialer.
func TestProbeAgainstRealListener(t *testing.T) {
	t.Parallel()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			_ = conn.Close()
		}
	}()

	port := listener.Addr().(*net.TCPAddr).Port
	prober := New(Options{Port: port, Samples: 2, Timeout: time.Second})

	results := prober.Probe(context.Background(), []netip.Addr{netip.MustParseAddr("127.0.0.1")})
	if !results["127.0.0.1"].OK() {
		t.Fatalf("probe against a live listener failed: %v", results["127.0.0.1"].Err)
	}
}

func TestItoa(t *testing.T) {
	t.Parallel()
	for input, want := range map[int]string{0: "0", 7: "7", 443: "443", 65535: "65535"} {
		if got := itoa(input); got != want {
			t.Errorf("itoa(%d) = %q, want %q", input, got, want)
		}
	}
}
