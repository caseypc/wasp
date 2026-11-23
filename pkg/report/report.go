package report

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"time"
)

const SchemaVersion = "1.0.0"

type Status string

const (
	StatusPass          Status = "pass"
	StatusFail          Status = "fail"
	StatusUnknown       Status = "unknown"
	StatusNotApplicable Status = "not_applicable"
	StatusNotRun        Status = "not_run"
	StatusError         Status = "error"
)

type Target struct {
	Input        string `json:"input"`
	CanonicalURL string `json:"canonical_url"`
	Hostname     string `json:"hostname"`
}
type Observation struct {
	ID         string         `json:"id"`
	ModuleID   string         `json:"module_id,omitempty"`
	ProbeID    string         `json:"probe_id"`
	Resource   string         `json:"resource"`
	ObservedAt time.Time      `json:"observed_at"`
	Status     Status         `json:"status,omitempty"`
	Source     string         `json:"source,omitempty"`
	Confidence string         `json:"confidence,omitempty"`
	Data       map[string]any `json:"data"`
}
type Evaluation struct {
	RuleID         string   `json:"rule_id"`
	Resource       string   `json:"resource"`
	Applicable     bool     `json:"applicable"`
	Status         Status   `json:"status"`
	ObservationIDs []string `json:"observation_ids,omitempty"`
}
type Finding struct {
	FindingID      string         `json:"finding_id"`
	RuleID         string         `json:"rule_id"`
	Severity       string         `json:"severity"`
	Resource       string         `json:"resource"`
	Title          string         `json:"title"`
	Description    string         `json:"description"`
	Evidence       map[string]any `json:"evidence,omitempty"`
	ObservationIDs []string       `json:"observation_ids,omitempty"`
	Remediation    string         `json:"remediation"`
	References     []string       `json:"references"`
}
type Diagnostic struct {
	ModuleID  string `json:"module_id,omitempty"`
	ProbeID   string `json:"probe_id,omitempty"`
	Code      string `json:"code"`
	Message   string `json:"message"`
	Retryable bool   `json:"retryable,omitempty"`
}
type Coverage struct {
	Fraction  float64 `json:"fraction"`
	Planned   int     `json:"planned"`
	Evaluable int     `json:"evaluable"`
}
type Score struct {
	Value  *int   `json:"value"`
	Status string `json:"status"`
}
type Report struct {
	SchemaVersion string        `json:"schema_version"`
	ScanID        string        `json:"scan_id"`
	EngineVersion string        `json:"engine_version"`
	PolicyVersion string        `json:"policy_version"`
	Target        Target        `json:"target"`
	StartedAt     time.Time     `json:"started_at"`
	CompletedAt   time.Time     `json:"completed_at"`
	Status        string        `json:"status"`
	Observations  []Observation `json:"observations"`
	Evaluations   []Evaluation  `json:"evaluations"`
	Findings      []Finding     `json:"findings"`
	Diagnostics   []Diagnostic  `json:"diagnostics"`
	Coverage      Coverage      `json:"coverage"`
	Score         Score         `json:"score"`
}

func StableFindingID(ruleID, resource string) string {
	sum := sha256.Sum256([]byte(ruleID + "\x00" + resource))
	return ruleID + "-" + hex.EncodeToString(sum[:8])
}
func (r *Report) Sort() {
	sort.Slice(r.Observations, func(i, j int) bool {
		if r.Observations[i].ModuleID != r.Observations[j].ModuleID {
			return r.Observations[i].ModuleID < r.Observations[j].ModuleID
		}
		if r.Observations[i].ProbeID != r.Observations[j].ProbeID {
			return r.Observations[i].ProbeID < r.Observations[j].ProbeID
		}
		if r.Observations[i].Resource != r.Observations[j].Resource {
			return r.Observations[i].Resource < r.Observations[j].Resource
		}
		return r.Observations[i].ID < r.Observations[j].ID
	})
	sort.Slice(r.Evaluations, func(i, j int) bool {
		if r.Evaluations[i].RuleID != r.Evaluations[j].RuleID {
			return r.Evaluations[i].RuleID < r.Evaluations[j].RuleID
		}
		return r.Evaluations[i].Resource < r.Evaluations[j].Resource
	})
	sort.Slice(r.Findings, func(i, j int) bool {
		if r.Findings[i].RuleID != r.Findings[j].RuleID {
			return r.Findings[i].RuleID < r.Findings[j].RuleID
		}
		if r.Findings[i].Resource != r.Findings[j].Resource {
			return r.Findings[i].Resource < r.Findings[j].Resource
		}
		return r.Findings[i].FindingID < r.Findings[j].FindingID
	})
	sort.Slice(r.Diagnostics, func(i, j int) bool {
		if r.Diagnostics[i].ModuleID != r.Diagnostics[j].ModuleID {
			return r.Diagnostics[i].ModuleID < r.Diagnostics[j].ModuleID
		}
		if r.Diagnostics[i].ProbeID != r.Diagnostics[j].ProbeID {
			return r.Diagnostics[i].ProbeID < r.Diagnostics[j].ProbeID
		}
		return r.Diagnostics[i].Code < r.Diagnostics[j].Code
	})
}
func (r Report) WriteJSON(w io.Writer) error {
	r.Sort()
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(r); err != nil {
		return fmt.Errorf("encode report: %w", err)
	}
	return nil
}
func (r Report) JSON() ([]byte, error) {
	var buf bytes.Buffer
	if err := r.WriteJSON(&buf); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
