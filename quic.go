package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

// QUICResult mirrors quicprobe's JSON output. Family and target IP are
// dropped from the report because the enclosing address entry carries them.
type QUICResult struct {
	Supported   bool   `json:"supported"`
	ALPN        string `json:"alpn,omitempty"`
	TLSVersion  string `json:"tls_version,omitempty"`
	ServerAddr  string `json:"server_addr,omitempty"`
	Family      string `json:"-"`
	TargetIP    string `json:"-"`
	HandshakeMs int64  `json:"handshake_ms"`
	Error       string `json:"error,omitempty"`
}

// UnmarshalJSON accepts the full quicprobe object (including the fields we
// hide on output).
func (q *QUICResult) UnmarshalJSON(b []byte) error {
	var raw struct {
		Supported   bool   `json:"supported"`
		ALPN        string `json:"alpn"`
		TLSVersion  string `json:"tls_version"`
		ServerAddr  string `json:"server_addr"`
		Family      string `json:"family"`
		TargetIP    string `json:"target_ip"`
		HandshakeMs int64  `json:"handshake_ms"`
		Error       string `json:"error"`
	}
	if err := json.Unmarshal(b, &raw); err != nil {
		return err
	}
	*q = QUICResult(raw)
	return nil
}

const quicprobeName = "quicprobe"

// findQuicprobe locates the quicprobe binary: explicit path, then $PATH,
// then ../quicprobe/quicprobe relative to the executable and to the cwd.
func findQuicprobe(explicit string) (string, error) {
	if explicit != "" {
		return requireTool(explicit, quicprobeName)
	}
	if p, err := exec.LookPath(quicprobeName); err == nil {
		return p, nil
	}
	var tried []string
	for _, dir := range candidateDirs() {
		p := filepath.Join(dir, "..", quicprobeName, quicprobeName)
		tried = append(tried, p)
		if isExecutable(p) {
			return p, nil
		}
	}
	return "", fmt.Errorf("quicprobe not found on PATH or at %s (use -quicprobe)", strings.Join(tried, ", "))
}

func candidateDirs() []string {
	var dirs []string
	if exe, err := os.Executable(); err == nil {
		if real, err := filepath.EvalSymlinks(exe); err == nil {
			exe = real
		}
		dirs = append(dirs, filepath.Dir(exe))
	}
	if cwd, err := os.Getwd(); err == nil {
		dirs = append(dirs, cwd)
	}
	return dirs
}

func isExecutable(p string) bool {
	st, err := os.Stat(p)
	return err == nil && !st.IsDir() && st.Mode()&0o111 != 0
}

// quicArgs builds argv for one quicprobe run against a specific address.
func quicArgs(host string, ip netip.Addr, timeoutSec int) []string {
	return []string{"-ip", ip.String(), "-t", strconv.Itoa(maxInt(1, timeoutSec)), host}
}

// probeQUIC runs quicprobe for host at ip and parses its JSON.
func probeQUIC(ctx context.Context, r Runner, path, host string, ip netip.Addr, timeoutSec int) QUICResult {
	stdout, stderr, err := r.Run(ctx, path, quicArgs(host, ip, timeoutSec)...)
	if isTimeout(ctx, err) {
		return QUICResult{Error: "quicprobe timed out"}
	}
	if err != nil {
		return QUICResult{Error: fmt.Sprintf("quicprobe: %v: %s", err, strings.TrimSpace(string(stderr)))}
	}
	return parseQUIC(stdout)
}

func parseQUIC(out []byte) QUICResult {
	var q QUICResult
	if len(strings.TrimSpace(string(out))) == 0 {
		return QUICResult{Error: "quicprobe produced no output"}
	}
	if err := json.Unmarshal(out, &q); err != nil {
		return QUICResult{Error: "quicprobe output not JSON: " + firstLine(string(out))}
	}
	return q
}
