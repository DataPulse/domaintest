package main

import (
	"context"
	"errors"
	"os/exec"
	"sync"
	"testing"
	"time"
)

// countingRunner records how many executions overlap.
type countingRunner struct {
	mu      sync.Mutex
	cur     int
	peak    int
	total   int
	release chan struct{} // closed to let calls finish
}

func (c *countingRunner) Run(ctx context.Context, name string, args ...string) ([]byte, []byte, error) {
	c.mu.Lock()
	c.cur++
	c.total++
	if c.cur > c.peak {
		c.peak = c.cur
	}
	c.mu.Unlock()
	<-c.release
	c.mu.Lock()
	c.cur--
	c.mu.Unlock()
	return nil, nil, nil
}

func TestLimitRunner(t *testing.T) {
	check(t, "zero is unlimited", limitRunner(execRunner{}, 0), Runner(execRunner{}))
	check(t, "negative is unlimited", limitRunner(execRunner{}, -1), Runner(execRunner{}))

	inner := &countingRunner{release: make(chan struct{})}
	limited := limitRunner(inner, 3)
	const calls = 12
	var wg sync.WaitGroup
	for i := 0; i < calls; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _, _ = limited.Run(context.Background(), "dog", "x")
		}()
	}
	// Let the callers pile up against the cap, then release them.
	time.Sleep(100 * time.Millisecond)
	inner.mu.Lock()
	peak := inner.peak
	inner.mu.Unlock()
	check(t, "cap respected while contended", peak, 3)
	close(inner.release)
	wg.Wait()

	inner.mu.Lock()
	defer inner.mu.Unlock()
	check(t, "every call ran", inner.total, calls)
	check(t, "cap never exceeded", inner.peak <= 3, true)
}

// A caller whose budget expires while queueing gets a timeout, not a hang.
func TestLimitRunner_ContextEndsWhileWaiting(t *testing.T) {
	inner := &countingRunner{release: make(chan struct{})}
	limited := limitRunner(inner, 1)
	go func() { _, _, _ = limited.Run(context.Background(), "dog", "holder") }()
	time.Sleep(50 * time.Millisecond)

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, _, err := limited.Run(ctx, "dog", "waiter")
	check(t, "gives up", errors.Is(err, context.DeadlineExceeded), true)
	check(t, "reported as a timeout", isTimeout(ctx, err), true)
	check(t, "promptly", time.Since(start) < time.Second, true)
	close(inner.release)
}

// The slot is returned even when the wrapped runner fails, so one bad tool
// invocation cannot leak capacity.
func TestLimitRunner_ReleasesOnError(t *testing.T) {
	failing := newFakeRunner()
	failing.on("dog", []string{"x"}, fakeCall{err: errFake})
	limited := limitRunner(failing, 1)
	for i := 0; i < 3; i++ {
		if _, _, err := limited.Run(context.Background(), "dog", "x"); err == nil {
			t.Fatal("expected the wrapped error")
		}
	}
}

func TestCappedBuffer(t *testing.T) {
	b := &cappedBuffer{max: 5}
	n, err := b.Write([]byte("abc"))
	check(t, "first write", []any{n, err}, []any{3, nil})
	n, err = b.Write([]byte("defgh"))
	check(t, "accepted in full", []any{n, err}, []any{5, nil})
	check(t, "kept up to the cap", string(b.Bytes()), "abcde")
	_, _ = b.Write([]byte("more"))
	check(t, "nothing past the cap", string(b.Bytes()), "abcde")
}

// A tool that writes far more than the cap still finishes normally.
func TestExecRunner_OutputIsCapped(t *testing.T) {
	out, _, err := execRunner{}.Run(context.Background(), "sh", "-c", "head -c 3000000 /dev/zero")
	check(t, "ran", err, nil)
	check(t, "capped", len(out), maxToolOutput)
}

// A tool killed at its deadline whose child still holds the output pipe
// (the shape of a wrapper script around a DNS tool) must not hold Run past the
// deadline until that child exits: WaitDelay bounds the wait.
func TestExecRunner_KilledToolWithLivingChild(t *testing.T) {
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("no sh")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, _, err = execRunner{}.Run(ctx, sh, "-c", "sleep 10 & wait")
	if took := time.Since(start); took > 200*time.Millisecond+toolWaitDelay+time.Second {
		t.Errorf("Run returned after %v; the orphan held it past the deadline", took)
	}
	if !isTimeout(ctx, err) {
		t.Errorf("err = %v, want a timeout", err)
	}
}
