package report

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func TestGeneratedReportMatchesBothSchemaCopies(t *testing.T) {
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	r := Report{
		SchemaVersion: SchemaVersion, ScanID: "e7d7b5e0-7cc6-4a57-a398-4ac5090662fa", EngineVersion: "test", PolicyVersion: "default-v1",
		Target:    Target{Input: "example.com", CanonicalURL: "https://example.com:443", Hostname: "example.com"},
		StartedAt: now, CompletedAt: now, Status: "completed",
		Observations: []Observation{}, Evaluations: []Evaluation{}, Findings: []Finding{}, Diagnostics: []Diagnostic{},
		Coverage: Coverage{}, Score: Score{Status: "not_applicable"},
	}
	raw, err := r.JSON()
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateJSON(raw); err != nil {
		t.Fatalf("embedded schema rejected report: %v", err)
	}
	canonical, err := os.ReadFile(filepath.Join("..", "..", "schemas", "report.v1.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	var embeddedValue, canonicalValue any
	if err := json.Unmarshal([]byte(schema), &embeddedValue); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(canonical, &canonicalValue); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(embeddedValue, canonicalValue) {
		t.Fatal("pkg and published report schemas differ")
	}
}
func TestSchemaRejectsUnknownAndInvalidStatus(t *testing.T) {
	valid := []byte(`{"schema_version":"1.0.0","scan_id":"e7d7b5e0-7cc6-4a57-a398-4ac5090662fa","engine_version":"x","policy_version":"x","target":{"input":"x","canonical_url":"https://example.com","hostname":"example.com"},"started_at":"2026-01-02T03:04:05Z","completed_at":"2026-01-02T03:04:05Z","status":"completed","observations":[],"evaluations":[],"findings":[],"diagnostics":[],"coverage":{"fraction":0,"planned":0,"evaluable":0},"score":{"value":null,"status":"not_applicable"}}`)
	if err := ValidateJSON(valid); err != nil {
		t.Fatalf("valid report rejected: %v", err)
	}
	var value map[string]any
	if err := json.Unmarshal(valid, &value); err != nil {
		t.Fatal(err)
	}
	value["extra"] = true
	invalid, _ := json.Marshal(value)
	if err := ValidateJSON(invalid); err == nil {
		t.Fatal("unknown property accepted")
	}
	value["extra"] = false
	value["status"] = "complete"
	invalid, _ = json.Marshal(value)
	if err := ValidateJSON(invalid); err == nil {
		t.Fatal("invalid report status accepted")
	}
	if err := ValidateJSON(append(valid, []byte(` {}`)...)); err == nil {
		t.Fatal("multiple JSON values accepted")
	}
}
