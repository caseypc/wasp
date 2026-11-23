package report

//go:generate cp ../../schemas/report.v1.schema.json report.v1.schema.json

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"
	"io"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

//go:embed report.v1.schema.json
var schema string

func ValidateJSON(data []byte) error {
	compiler := jsonschema.NewCompiler()
	var schemaDocument any
	if err := json.Unmarshal([]byte(schema), &schemaDocument); err != nil {
		return fmt.Errorf("decode report schema: %w", err)
	}
	if err := compiler.AddResource("report.schema.json", schemaDocument); err != nil {
		return fmt.Errorf("load report schema: %w", err)
	}
	compiled, err := compiler.Compile("report.schema.json")
	if err != nil {
		return fmt.Errorf("compile report schema: %w", err)
	}
	var value any
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&value); err != nil {
		return fmt.Errorf("decode report JSON: %w", err)
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		if err == nil {
			return fmt.Errorf("decode report JSON: multiple JSON values")
		}
		return fmt.Errorf("decode report JSON: %w", err)
	}
	if err := compiled.Validate(value); err != nil {
		return fmt.Errorf("report does not match schema: %w", err)
	}
	return nil
}
