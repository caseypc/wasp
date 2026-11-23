package engine

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/caseypc/wasp/internal/config"
	dnsprobe "github.com/caseypc/wasp/internal/modules/dns"
	httpprobe "github.com/caseypc/wasp/internal/modules/http"
	tlsprobe "github.com/caseypc/wasp/internal/modules/tls"
	"github.com/caseypc/wasp/internal/network"
	"github.com/caseypc/wasp/pkg/report"
	"math"
	"net/url"
	"strings"
	"sync"
	"time"
)

var SupportedModules = map[string]bool{"tls": true, "http": true, "dns": true}

type Options struct {
	Version string
}

func Scan(ctx context.Context, cfg config.Config, options Options) (report.Report, error) {
	target, err := network.ParseTarget(cfg.Target.URL)
	if err != nil {
		return report.Report{}, fmt.Errorf("invalid target: %w", err)
	}
	if !network.InScope(target.URL, cfg.Scope) {
		return report.Report{}, fmt.Errorf("%w: target does not match configured scope", network.ErrScopeDenied)
	}
	for _, module := range cfg.Modules {
		if !SupportedModules[module] {
			return report.Report{}, fmt.Errorf("module %q is not implemented in this release", module)
		}
	}
	if cfg.Profile != "passive" {
		return report.Report{}, errors.New("active profile is not implemented; passive scan only")
	}
	if options.Version == "" {
		options.Version = "dev"
	}
	started := time.Now().UTC()
	ctx, cancel := withTimeout(ctx, cfg.Limits.TotalTimeout)
	defer cancel()
	client := network.NewClient(
		cfg.Scope, nil, durationOr(cfg.Limits.RequestTimeout, config.DefaultTimeout),
		cfg.Limits.MaxRedirects, cfg.Limits.MaxRequests, cfg.Limits.MaxResponseBytes,
	)
	r := report.Report{
		SchemaVersion: report.SchemaVersion, ScanID: scanID(), EngineVersion: options.Version,
		PolicyVersion: defaultString(cfg.Policy.ID, "default-v1"),
		Target:        report.Target{Input: target.Input, CanonicalURL: target.URL.String(), Hostname: target.Host},
		StartedAt:     started, Status: "completed",
		Observations: []report.Observation{}, Evaluations: []report.Evaluation{},
		Findings: []report.Finding{}, Diagnostics: []report.Diagnostic{},
		Score: report.Score{Status: "not_applicable"},
	}
	type result struct {
		module string
		probe  string
		status report.Status
		value  map[string]any
		err    error
	}
	jobs := make(chan string)
	results := make(chan result, len(cfg.Modules))
	concurrency := cfg.Limits.Concurrency
	if concurrency < 1 {
		concurrency = config.DefaultConcurrency
	}
	if concurrency > len(cfg.Modules) && len(cfg.Modules) > 0 {
		concurrency = len(cfg.Modules)
	}
	var workers sync.WaitGroup
	for i := 0; i < concurrency; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for module := range jobs {
				results <- collect(ctx, module, target, client)
			}
		}()
	}
	go func() {
		for _, module := range cfg.Modules {
			jobs <- module
		}
		close(jobs)
		workers.Wait()
		close(results)
	}()
	collected := make(map[string]result)
	for res := range results {
		collected[res.module] = res
	}
	for _, module := range cfg.Modules {
		res := collected[module]
		if res.err != nil {
			code := "probe_error"
			if errors.Is(res.err, network.ErrScopeDenied) {
				code = "scope_denied"
			} else if errors.Is(res.err, context.DeadlineExceeded) || errors.Is(ctx.Err(), context.DeadlineExceeded) {
				code = "timeout"
			} else if errors.Is(res.err, network.ErrRequestLimit) {
				code = "request_limit"
			}
			message := "probe could not collect evidence"
			if code == "scope_denied" {
				message = "network operation was denied by scope policy"
			} else if code == "timeout" {
				message = "probe exceeded its configured deadline"
			} else if code == "request_limit" {
				message = "configured network request budget was reached"
			}
			r.Diagnostics = append(r.Diagnostics, report.Diagnostic{
				ModuleID: module, ProbeID: res.probe, Code: code, Message: message, Retryable: code == "timeout",
			})
			r.Status = "partial"
			continue
		}
		id := "obs-" + module + "-" + res.probe
		r.Observations = append(r.Observations, report.Observation{
			ID: id, ModuleID: module, ProbeID: res.probe, Resource: target.URL.Host,
			ObservedAt: started, Status: defaultStatus(res.status), Source: "scoped_network",
			Confidence: "observed", Data: res.value,
		})
	}
	evaluate(&r, cfg, target.URL)
	r.CompletedAt = time.Now().UTC()
	r.Coverage = coverage(r.Evaluations)
	score(&r, cfg.Policy.MinimumScoreCoverage)
	if ctx.Err() != nil {
		r.Status = "partial"
		if len(r.Diagnostics) == 0 {
			r.Diagnostics = append(r.Diagnostics, report.Diagnostic{
				ModuleID: "engine", ProbeID: "scheduler", Code: "cancelled",
				Message: "scan ended before all probes completed", Retryable: true,
			})
		}
	}
	r.Sort()
	for _, d := range r.Diagnostics {
		if d.Code == "scope_denied" {
			return r, fmt.Errorf("%w: network operation denied", network.ErrScopeDenied)
		}
	}
	return r, nil
}
func collect(ctx context.Context, module string, target network.Target, client *network.Client) (res struct {
	module string
	probe  string
	status report.Status
	value  map[string]any
	err    error
}) {
	res.module = module
	res.status = report.StatusPass
	switch module {
	case "dns":
		res.probe = "dns.addresses"
		value, err := (dnsprobe.Probe{Client: client}).Collect(ctx, target.Host)
		if err != nil {
			res.err = err
			return
		}
		addresses := make([]string, 0, len(value.Addresses))
		for _, ip := range value.Addresses {
			addresses = append(addresses, ip.String())
		}
		res.value = map[string]any{"addresses": addresses, "source": "system_resolver"}
	case "tls":
		res.probe = "tls.certificate"
		if target.URL.Scheme != "https" {
			res.status = report.StatusNotApplicable
			res.value = map[string]any{"reason": "target uses HTTP"}
			return
		}
		value, err := (tlsprobe.Probe{Client: client}).Collect(ctx, target.Host, target.Port)
		if err != nil {
			res.err = err
			return
		}
		res.value = map[string]any{
			"subject": value.Subject, "issuer": value.Issuer, "sans": value.SANs,
			"serial_number": value.SerialNumber, "sha256_fingerprint": value.SHA256Fingerprint,
			"not_before": value.NotBefore.Format(time.RFC3339), "not_after": value.NotAfter.Format(time.RFC3339),
			"signature_algorithm": value.SignatureAlgorithm, "public_key_algorithm": value.PublicKeyAlgorithm,
			"public_key_bits": value.PublicKeyBits, "tls_version": value.TLSVersion,
			"cipher_suite": value.CipherSuite, "chain_length": value.ChainLength,
			"chain_verified": value.ChainVerified, "verification_error": value.VerificationError,
			"expired": value.Expired,
		}
	case "http":
		res.probe = "http.response"
		value, err := (httpprobe.Probe{Client: client}).Collect(ctx, target.URL)
		if err != nil {
			res.err = err
			return
		}
		res.value = map[string]any{
			"status_code": value.StatusCode, "status": value.Status, "http_version": value.HTTPVersion,
			"duration_ms": value.DurationMS, "headers": value.Headers, "redirects": value.Redirects,
			"final_url": value.FinalURL, "body_bytes": value.BodyBytes, "hsts": value.HSTS,
		}
	}
	return
}
func defaultStatus(status report.Status) report.Status {
	if status == "" {
		return report.StatusPass
	}
	return status
}
func evaluate(r *report.Report, cfg config.Config, target *url.URL) {
	observations := make(map[string]report.Observation)
	for _, obs := range r.Observations {
		observations[obs.ModuleID] = obs
	}
	hasModule := func(module string) bool {
		for _, candidate := range cfg.Modules {
			if candidate == module {
				return true
			}
		}
		return false
	}
	if hasModule("tls") {
		applicable := target.Scheme == "https"
		evaluation := report.Evaluation{RuleID: "TLS-CERT-001", Resource: target.Host, Applicable: applicable, Status: report.StatusNotApplicable}
		if applicable {
			if obs, ok := observations["tls"]; ok {
				evaluation.Status = report.StatusPass
				evaluation.ObservationIDs = []string{obs.ID}
				if expired, _ := obs.Data["expired"].(bool); expired {
					evaluation.Status = report.StatusFail
					r.Findings = append(r.Findings, report.Finding{
						FindingID: report.StableFindingID("TLS-CERT-001", target.Host), RuleID: "TLS-CERT-001",
						Severity: "critical", Resource: target.Host, Title: "TLS certificate is expired",
						Description:    "The server presented a certificate whose validity period has ended.",
						Evidence:       map[string]any{"summary": "The certificate validity period has ended."},
						ObservationIDs: []string{obs.ID}, Remediation: "Renew and deploy a valid certificate.",
						References: []string{"https://datatracker.ietf.org/doc/html/rfc5280"},
					})
				}
			} else {
				evaluation.Status = report.StatusUnknown
			}
		}
		r.Evaluations = append(r.Evaluations, evaluation)
	}
	if hasModule("http") {
		applicable := target.Scheme == "https"
		evaluation := report.Evaluation{RuleID: "HTTP-HEADER-001", Resource: target.Host, Applicable: applicable, Status: report.StatusNotApplicable}
		if applicable {
			if obs, ok := observations["http"]; ok {
				evaluation.Status = report.StatusFail
				evaluation.ObservationIDs = []string{obs.ID}
				hsts, _ := obs.Data["hsts"].(string)
				if strings.TrimSpace(hsts) != "" {
					evaluation.Status = report.StatusPass
				} else {
					r.Findings = append(r.Findings, report.Finding{
						FindingID: report.StableFindingID("HTTP-HEADER-001", target.Host), RuleID: "HTTP-HEADER-001",
						Severity: "medium", Resource: target.Host, Title: "HTTP Strict Transport Security is missing",
						Description:    "The HTTPS response did not include a Strict-Transport-Security header.",
						Evidence:       map[string]any{"summary": "The HTTPS response did not include a Strict-Transport-Security header."},
						ObservationIDs: []string{obs.ID}, Remediation: "Configure a suitable Strict-Transport-Security header after verifying HTTPS deployment.",
						References: []string{"https://datatracker.ietf.org/doc/html/rfc6797"},
					})
				}
			} else {
				evaluation.Status = report.StatusUnknown
			}
		}
		r.Evaluations = append(r.Evaluations, evaluation)
	}
}
func coverage(evaluations []report.Evaluation) report.Coverage {
	c := report.Coverage{}
	for _, evaluation := range evaluations {
		if !evaluation.Applicable {
			continue
		}
		c.Planned++
		if evaluation.Status == report.StatusPass || evaluation.Status == report.StatusFail {
			c.Evaluable++
		}
	}
	if c.Planned > 0 {
		c.Fraction = float64(c.Evaluable) / float64(c.Planned)
	}
	return c
}
func score(r *report.Report, minimum float64) {
	if r.Coverage.Planned == 0 {
		r.Score.Status = "not_applicable"
		return
	}
	if r.Coverage.Fraction < minimum {
		r.Score.Status = "insufficient_evidence"
		return
	}
	weights := map[string]float64{"TLS-CERT-001": 30, "HTTP-HEADER-001": 30}
	var weight, failed float64
	for _, evaluation := range r.Evaluations {
		if !evaluation.Applicable || (evaluation.Status != report.StatusPass && evaluation.Status != report.StatusFail) {
			continue
		}
		w := weights[evaluation.RuleID]
		weight += w
		if evaluation.Status == report.StatusFail {
			failed += w
		}
	}
	if weight == 0 {
		r.Score.Status = "not_applicable"
		return
	}
	value := int(math.Round(100 * (1 - failed/weight)))
	r.Score = report.Score{Value: &value, Status: "scored"}
}
func withTimeout(ctx context.Context, raw string) (context.Context, context.CancelFunc) {
	if duration, err := time.ParseDuration(raw); err == nil && duration > 0 {
		return context.WithTimeout(ctx, duration)
	}
	return context.WithTimeout(ctx, config.DefaultTotalTimeoutSpan)
}
func durationOr(raw string, fallback time.Duration) time.Duration {
	if duration, err := time.ParseDuration(raw); err == nil && duration > 0 {
		return duration
	}
	return fallback
}
func defaultString(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}
func scanID() string {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return hex.EncodeToString([]byte(time.Now().UTC().Format(time.RFC3339Nano)))
	}
	raw[6] = (raw[6] & 0x0f) | 0x40
	raw[8] = (raw[8] & 0x3f) | 0x80
	hexID := hex.EncodeToString(raw[:])
	return fmt.Sprintf("%s-%s-%s-%s-%s", hexID[:8], hexID[8:12], hexID[12:16], hexID[16:20], hexID[20:])
}
