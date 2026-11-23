package output

import (
	"github.com/caseypc/wasp/pkg/report"
	"strings"
	"testing"
	"time"
)

func TestPartialReportPreservesOutcomes(t *testing.T) {
	now := time.Date(2026, 11, 20, 15, 2, 14, 0, time.FixedZone("offset", -6*60*60))
	r := report.Report{EngineVersion: "test-build", Target: report.Target{Input: "example.com", CanonicalURL: "https://example.com:443"}, StartedAt: now, CompletedAt: now.Add(312 * time.Millisecond), Status: "partial", Score: report.Score{Status: "insufficient_evidence"}}
	for _, status := range []report.Status{report.StatusUnknown, report.StatusError, report.StatusNotRun, report.StatusNotApplicable} {
		r.Evaluations = append(r.Evaluations, report.Evaluation{RuleID: "RULE-" + string(status), Status: status})
	}
	got := string(RenderTerminal(r, false, "OK", "BAD"))
	for _, want := range []string{"v.test-build", "Duration: 312ms", "2026-11-20T21:02:14Z", "Score: n/a (insufficient_evidence)", "[UNKNOWN]", "[ERROR]", "[NOT_RUN]", "[NOT_APPLICABLE]", "None reported", "0 passed, 0 failed, 1 unknown, 1 error, 1 not run, 1 not applicable"} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in %s", want, got)
		}
	}
	if strings.Contains(got, "✔") || strings.Contains(got, "\x1b") {
		t.Fatalf("partial empty report asserted success or used ANSI: %s", got)
	}
}

func TestTerminalEvidenceAndRemediation(t *testing.T) {
	score := 50
	r := report.Report{EngineVersion: "0.1.0", Score: report.Score{Value: &score, Status: "scored"},
		Evaluations: []report.Evaluation{{RuleID: "HTTP-HEADER-001", Status: report.StatusFail}, {RuleID: "TLS-CERT-001", Status: report.StatusPass}},
		Findings:    []report.Finding{{RuleID: "HTTP-HEADER-001", Severity: "medium", Title: "Missing HSTS", Description: "No HSTS", Remediation: "Configure HSTS"}},
		Observations: []report.Observation{
			{ModuleID: "http", Data: map[string]any{"status": 200, "headers": map[string][]string{"Server": {"fixture"}, "Content-Type": {"text/html"}}}},
			{ModuleID: "tls", Data: map[string]any{"subject": "example.com", "tls_version": "TLS 1.3"}},
			{ModuleID: "dns", Data: map[string]any{"addresses": []string{"93.184.216.34"}}},
		},
		Diagnostics: []report.Diagnostic{{ModuleID: "http", ProbeID: "response", Code: "fixture", Message: "Unavailable"}},
	}
	got := string(RenderTerminal(r, false, "OK", "BAD"))
	for _, want := range []string{"[BAD] HTTP-HEADER-001", "[OK] TLS-CERT-001", "[MEDIUM]", "Fix: Configure HSTS", "50/100", "HTTP RESPONSE", "TLS CONNECTION & CERTIFICATE", "DNS RECORDS", "http/response: fixture: Unavailable"} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in %s", want, got)
		}
	}
	if strings.Index(got, "Content-Type:") > strings.Index(got, "Server:") {
		t.Fatal("headers not sorted")
	}
	if string(RenderTerminal(r, false, "OK", "BAD")) != got {
		t.Fatal("unstable output")
	}
}

func TestBannerUsesVersion(t *testing.T) {
	for _, style := range []string{"normal", "short", "text"} {
		got := Banner(style, "dev-custom")
		if !strings.Contains(got, "dev-custom") || strings.Contains(got, "0.1.0") {
			t.Fatal(got)
		}
	}
}
