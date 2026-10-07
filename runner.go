package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"time"
)

// Runner executes an external tool. It is an interface so tests can feed
// captured tool output without touching the network.
type Runner interface {
	// Run executes name with args under ctx and returns stdout, stderr and
	// the process error (nil on exit 0). A context deadline kills the
	// process; callers should check ctx.Err() to distinguish a timeout
	// from a tool failure.
	Run(ctx context.Context, name string, args ...string) (stdout, stderr []byte, err error)
}

// execRunner is the production Runner backed by os/exec.
type execRunner struct{}

func (execRunner) Run(ctx context.Context, name string, args ...string) ([]byte, []byte, error) {
	if ctx == nil {
		return nil, nil, errors.New("runner: nil context")
	}
	cmd := exec.CommandContext(ctx, name, args...)
	// Killing the tool at the deadline does not end Run while anything
	// else still holds its output pipes open (a child the tool started, or
	// a wrapper's orphan): Wait would block until that writer exits. Bound
	// the wait so the run deadline holds whatever the tool does.
	cmd.WaitDelay = toolWaitDelay
	stdout, stderr := &cappedBuffer{max: maxToolOutput}, &cappedBuffer{max: maxToolOutput}
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	err := cmd.Run()
	if ctxErr := ctx.Err(); ctxErr != nil {
		return stdout.Bytes(), stderr.Bytes(), fmt.Errorf("%s: %w", name, ctxErr)
	}
	return stdout.Bytes(), stderr.Bytes(), err
}

// toolWaitDelay is how long Run waits for a killed tool's pipes to close.
const toolWaitDelay = 500 * time.Millisecond

// maxToolOutput bounds what is kept of one tool's stdout or stderr. The
// largest real output, a dig +trace or a nameserver audit, is tens of
// kilobytes; a tool that runs away (or a quicprobe stderr echoing a
// hostile server) cannot fill memory or the report.
const maxToolOutput = 1 << 20

// cappedBuffer keeps the first max bytes written to it and discards the
// rest, while still accepting every write so the process is not killed by
// a broken pipe.
type cappedBuffer struct {
	buf bytes.Buffer
	max int
}

func (b *cappedBuffer) Write(p []byte) (int, error) {
	if room := b.max - b.buf.Len(); room > 0 {
		b.buf.Write(p[:min(len(p), room)])
	}
	return len(p), nil
}

func (b *cappedBuffer) Bytes() []byte { return b.buf.Bytes() }

// isTimeout reports whether err (or ctx) indicates the tool was cut off by
// its deadline.
func isTimeout(ctx context.Context, err error) bool {
	if ctx != nil && errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return true
	}
	return errors.Is(err, context.DeadlineExceeded)
}

// requireTool resolves an executable on PATH (or an explicit path) and
// returns a usage-level error suitable for exit code 2 when it is missing.
func requireTool(explicit, name string) (string, error) {
	candidate := name
	if explicit != "" {
		candidate = explicit
	}
	path, err := exec.LookPath(candidate)
	if err != nil {
		return "", fmt.Errorf("required tool %q not found: %w", candidate, err)
	}
	return path, nil
}

// limitedRunner caps how many external DNS tools run at once. One run
// makes about 45 dog invocations and can have 18 or more in flight; when
// each was a delv validating DNSSEC in its own process, several runs at
// once on a small host missed their deadlines through scheduling delay
// alone, with the resolver still idle. The cap bounds the fan-out inside a run so callers
// keep their own parallelism.
type limitedRunner struct {
	inner Runner
	sem   chan struct{}
}

// limitRunner wraps r to allow at most n concurrent executions. n <= 0
// means unlimited, and returns r unchanged.
func limitRunner(r Runner, n int) Runner {
	if n <= 0 {
		return r
	}
	return &limitedRunner{inner: r, sem: make(chan struct{}, n)}
}

func (l *limitedRunner) Run(ctx context.Context, name string, args ...string) ([]byte, []byte, error) {
	select {
	case l.sem <- struct{}{}:
		defer func() { <-l.sem }()
	case <-ctx.Done():
		// Waiting for a slot is bounded by the caller's budget, so a
		// saturated host degrades to timeouts rather than queueing forever.
		return nil, nil, fmt.Errorf("%s: %w", name, ctx.Err())
	}
	return l.inner.Run(ctx, name, args...)
}
