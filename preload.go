package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

// preloadFetcher queries the HSTS preload list; replaceable in tests.
var preloadFetcher = fetchPreloadStatus

// fetchPreloadStatus asks hstspreload.org whether domain is on the
// Chromium HSTS preload list. Statuses seen: preloaded, unknown, pending,
// rejected.
func fetchPreloadStatus(ctx context.Context, domain string, timeout time.Duration) (string, error) {
	client := &http.Client{Timeout: timeout, Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}}}
	u := "https://hstspreload.org/api/v2/status?domain=" + url.QueryEscape(domain)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return "", err
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("HTTP %d from hstspreload.org", resp.StatusCode)
	}
	var body struct {
		Status string `json:"status"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 16<<10)).Decode(&body); err != nil {
		return "", err
	}
	if body.Status == "" {
		return "", errors.New("no status in hstspreload.org reply")
	}
	return body.Status, nil
}

// parsePEMCerts decodes every CERTIFICATE block in b.
func parsePEMCerts(b []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	for {
		var block *pem.Block
		block, b = pem.Decode(b)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		certs = append(certs, c)
	}
	if len(certs) == 0 {
		return nil, errors.New("no CERTIFICATE blocks")
	}
	return certs, nil
}
