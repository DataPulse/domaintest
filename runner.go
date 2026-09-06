package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
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
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	if ctxErr := ctx.Err(); ctxErr != nil {
		return stdout.Bytes(), stderr.Bytes(), fmt.Errorf("%s: %w", name, ctxErr)
	}
	return stdout.Bytes(), stderr.Bytes(), err
}

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
