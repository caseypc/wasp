package config

import (
	"encoding/json"
	"github.com/santhosh-tekuri/jsonschema/v6"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseExampleAndValidateAgainstPublishedSchema(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "examples", "wasp.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	instance, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	schemaData, err := os.ReadFile(filepath.Join("..", "..", "schemas", "config.v1.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	compiler := jsonschema.NewCompiler()
	var schemaDocument any
	if err := json.Unmarshal(schemaData, &schemaDocument); err != nil {
		t.Fatal(err)
	}
	if err := compiler.AddResource("config.json", schemaDocument); err != nil {
		t.Fatal(err)
	}
	schema, err := compiler.Compile("config.json")
	if err != nil {
		t.Fatal(err)
	}
	var value any
	if err := json.Unmarshal(instance, &value); err != nil {
		t.Fatal(err)
	}
	if err := schema.Validate(value); err != nil {
		t.Fatalf("example does not match published schema: %v", err)
	}
}
func TestParseRejectsUnknownKeysAndMalformedPolicy(t *testing.T) {
	base := `schema_version: "1"
profile: passive
target: {url: https://example.com}
scope: {include_hosts: [example.com]}
unexpected: true
`
	if _, err := Parse([]byte(base)); err == nil {
		t.Fatal("unknown configuration key accepted")
	}
	base = `schema_version: "1"
profile: passive
target: {url: https://example.com}
scope: {include_hosts: [example.com]}
policy: {minimum_score_coverage: 1.1}
`
	if _, err := Parse([]byte(base)); err == nil {
		t.Fatal("invalid policy value accepted")
	}
}
func TestParseRejectsYAMLAliasesAndOversizedInput(t *testing.T) {
	aliased := []byte(`schema_version: "1"
profile: passive
target: {url: https://example.com}
scope: {include_hosts: [example.com]}
value: &v true
other: *v
`)
	if _, err := Parse(aliased); err == nil {
		t.Fatal("YAML alias accepted")
	}
	if _, err := Parse([]byte(strings.Repeat("x", (1<<20)+1))); err == nil {
		t.Fatal("oversized configuration accepted")
	}
}
