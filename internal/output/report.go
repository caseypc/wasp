package output

import (
	"bytes"
	"fmt"
	"net"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/caseypc/wasp/pkg/report"
)

func RenderTerminal(r report.Report, color bool, passLabel, failLabel string) []byte {
	var b bytes.Buffer
	pass := func(text string) string { return paintColor(color, ansiGreen, text) }
	fail := func(text string) string { return paintColor(color, ansiRed, text) }
	warn := func(text string) string { return paintColor(color, ansiYellow, text) }

	fmt.Fprintln(&b, Banner("short", r.EngineVersion))
	fmt.Fprintf(&b, "[!] Target: %s -> %s\n", r.Target.Input, r.Target.CanonicalURL)
	fmt.Fprintf(&b, "[*] Started: %s\n[*] Stopped: %s | Duration: %dms\n", r.StartedAt.UTC().Format(time.RFC3339), r.CompletedAt.UTC().Format(time.RFC3339), r.CompletedAt.Sub(r.StartedAt).Milliseconds())
	score := "n/a"
	if r.Score.Value != nil {
		score = fmt.Sprintf("%d/100", *r.Score.Value)
	}
	counts := map[report.Status]int{}
	for _, evaluation := range r.Evaluations {
		counts[evaluation.Status]++
	}
	fmt.Fprintf(&b, "\n[!] SUMMARY\n  ├─ Status: %s\n  ├─ Rules: %d passed, %d failed, %d unknown, %d error, %d not run, %d not applicable\n", r.Status, counts[report.StatusPass], counts[report.StatusFail], counts[report.StatusUnknown], counts[report.StatusError], counts[report.StatusNotRun], counts[report.StatusNotApplicable])
	fmt.Fprintf(&b, "  ├─ Score: %s (%s)\n  └─ Coverage: %.0f%% (%d/%d)\n", score, r.Score.Status, r.Coverage.Fraction*100, r.Coverage.Evaluable, r.Coverage.Planned)
	fmt.Fprintln(&b, "\n[!] RULE EVALUATIONS")
	for _, evaluation := range r.Evaluations {
		label := strings.ToUpper(string(evaluation.Status))
		if evaluation.Status == report.StatusPass {
			label = pass(passLabel)
		}
		if evaluation.Status == report.StatusFail {
			label = fail(failLabel)
		}
		fmt.Fprintf(&b, "  [%s] %s  %s\n", label, evaluation.RuleID, evaluation.Resource)
	}
	if len(r.Evaluations) == 0 {
		fmt.Fprintln(&b, "  None evaluated")
	}

	fmt.Fprintf(&b, "\n[!] OBSERVATIONS (%d)\n", len(r.Observations))
	if len(r.Observations) == 0 {
		fmt.Fprintln(&b, "  None")
	}
	for _, observation := range r.Observations {
		level := "warn"
		switch observation.Status {
		case report.StatusPass:
			level = "pass"
		case report.StatusFail, report.StatusError:
			level = "fail"
		}
		label := "WARN"
		if level == "pass" {
			label = passLabel
		} else if level == "fail" {
			label = failLabel
		}
		fmt.Fprintf(&b, "  %s %s/%s: %s\n", FormatStatus(level, label, color), observation.ModuleID, observation.ProbeID, observation.Status)
	}

	fmt.Fprintf(&b, "\n[!] FINDINGS (%d)\n", len(r.Findings))
	if len(r.Findings) == 0 {
		fmt.Fprintln(&b, "  None reported")
	}
	for _, finding := range r.Findings {
		fmt.Fprintf(&b, "  %s [%s] %s: %s\n", fail("✖ "+failLabel), strings.ToUpper(finding.Severity), finding.RuleID, finding.Title)
		fmt.Fprintf(&b, "    ├─ Detail: %s\n", finding.Description)
		if finding.Remediation != "" {
			fmt.Fprintf(&b, "    └─ Fix: %s\n", finding.Remediation)
		}
	}

	fmt.Fprintf(&b, "\n[!] DIAGNOSTICS (%d)\n", len(r.Diagnostics))
	if len(r.Diagnostics) == 0 {
		fmt.Fprintln(&b, "  None reported")
	}
	for _, diagnostic := range r.Diagnostics {
		fmt.Fprintf(&b, "  %s %s/%s: %s: %s\n", warn("⚠ WARN"), diagnostic.ModuleID, diagnostic.ProbeID, diagnostic.Code, diagnostic.Message)
	}

	fmt.Fprintln(&b, "\n[!] EVIDENCE")
	fmt.Fprintf(&b, "\nURL: %s\nHOST: %s Port: %s\n", r.Target.CanonicalURL, r.Target.Hostname, targetPort(r.Target.CanonicalURL))

	for _, observation := range r.Observations {
		switch observation.ModuleID {
		case "http":
			fmt.Fprintln(&b, "\n[!] HTTP RESPONSE")
			if value, ok := observation.Data["status"]; ok {
				fmt.Fprintf(&b, "  status: %v\n", value)
			}
			if value, ok := observation.Data["http_version"]; ok {
				fmt.Fprintf(&b, "  version: %v\n", value)
			}
			if headers := headerValues(observation.Data["headers"]); len(headers) > 0 {
				fmt.Fprintln(&b, "  Headers:")
				keys := make([]string, 0, len(headers))
				for key := range headers {
					keys = append(keys, key)
				}
				sort.Strings(keys)
				for _, key := range keys {
					fmt.Fprintf(&b, "    %s: %v\n", key, headers[key])
				}
			}
		case "tls":
			fmt.Fprintln(&b, "\n[!] TLS CONNECTION & CERTIFICATE")
			for _, key := range []string{
				"subject", "issuer", "expired", "not_before", "not_after", "serial_number",
				"sha256_fingerprint", "signature_algorithm", "public_key_algorithm", "tls_version",
				"cipher_suite", "chain_verified", "verification_error",
			} {
				if value, ok := observation.Data[key]; ok {
					fmt.Fprintf(&b, "  %s: %v\n", key, value)
				}
			}
		case "dns":
			fmt.Fprintln(&b, "\n[!] DNS RECORDS")
			if value, ok := observation.Data["addresses"]; ok {
				fmt.Fprintf(&b, "  A/AAAA addresses: %v\n", value)
			}
		}
	}
	fmt.Fprintf(&b, "\n[-] %s\n", Banner("text", r.EngineVersion))
	return b.Bytes()
}

func FormatStatus(level, label string, color bool) string {
	switch level {
	case "pass":
		return paintColor(color, ansiBold+ansiGreen, "✔ "+label)
	case "fail":
		return paintColor(color, ansiBold+ansiRed, "✖ "+label)
	default:
		return paintColor(color, ansiBold+ansiYellow, "⚠ "+label)
	}
}

func paintColor(enabled bool, code, text string) string {
	if !enabled {
		return text
	}
	return paint(code, text)
}

func headerValues(value any) map[string]any {
	switch headers := value.(type) {
	case map[string]any:
		return headers
	case map[string][]string:
		values := make(map[string]any, len(headers))
		for key, entries := range headers {
			values[key] = entries
		}
		return values
	default:
		return nil
	}
}

func targetPort(rawURL string) string {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return "unknown"
	}
	if port := parsed.Port(); port != "" {
		return port
	}
	if parsed.Scheme == "https" {
		return "443"
	}
	if parsed.Scheme == "http" {
		return "80"
	}
	_, port, err := net.SplitHostPort(parsed.Host)
	if err == nil {
		return port
	}
	return "unknown"
}
