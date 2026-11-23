package engine

import (
	"github.com/caseypc/wasp/internal/config"
	"github.com/caseypc/wasp/pkg/report"
	"net/url"
	"testing"
	"time"
)

func TestRulesNeverPassMissingEvidenceAndScoreOnlyEvaluableRules(t *testing.T) {
	u, _ := url.Parse("https://example.com:443")
	cfg := config.Defaults(u.String())
	r := report.Report{
		Observations: []report.Observation{},
		Evaluations:  []report.Evaluation{},
		Findings:     []report.Finding{},
	}
	evaluate(&r, cfg, u)
	if len(r.Evaluations) != 2 || r.Evaluations[0].Status != report.StatusUnknown || r.Evaluations[1].Status != report.StatusUnknown {
		t.Fatalf("missing evidence evaluations = %#v", r.Evaluations)
	}
	r.Coverage = coverage(r.Evaluations)
	score(&r, 0.8)
	if r.Score.Value != nil || r.Score.Status != "insufficient_evidence" {
		t.Fatalf("score with no evidence = %#v", r.Score)
	}
}
func TestExpiredCertificateProducesStableFinding(t *testing.T) {
	u, _ := url.Parse("https://example.com:443")
	cfg := config.Defaults(u.String())
	r := report.Report{
		Observations: []report.Observation{{
			ID: "obs-tls", ModuleID: "tls", ObservedAt: time.Unix(1, 0).UTC(), Data: map[string]any{"expired": true},
		}},
		Findings: []report.Finding{},
	}
	evaluate(&r, cfg, u)
	if len(r.Findings) != 1 || r.Findings[0].RuleID != "TLS-CERT-001" {
		t.Fatalf("expired cert finding = %#v", r.Findings)
	}
	if r.Findings[0].FindingID != report.StableFindingID("TLS-CERT-001", "example.com:443") {
		t.Fatalf("finding ID is unstable: %q", r.Findings[0].FindingID)
	}
}
