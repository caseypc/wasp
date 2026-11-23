package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/santhosh-tekuri/jsonschema/v6"
	"gopkg.in/yaml.v3"
)

const SchemaVersion = "1"

var KnownModules = map[string]bool{
	"tls": true, "http": true, "dns": true, "email": true,
	"domain": true, "network": true, "discovery": true,
}

type Config struct {
	SchemaVersion string        `yaml:"schema_version" json:"schema_version"`
	Profile       string        `yaml:"profile" json:"profile"`
	Target        Target        `yaml:"target" json:"target"`
	Scope         Scope         `yaml:"scope" json:"scope"`
	Modules       []string      `yaml:"modules,omitempty" json:"modules,omitempty"`
	Limits        Limits        `yaml:"limits,omitempty" json:"limits,omitempty"`
	Policy        Policy        `yaml:"policy,omitempty" json:"policy,omitempty"`
	Email         Email         `yaml:"email,omitempty" json:"email,omitempty"`
	Providers     Providers     `yaml:"providers,omitempty" json:"providers,omitempty"`
	Report        Report        `yaml:"report,omitempty" json:"report,omitempty"`
	Authorization Authorization `yaml:"authorization,omitempty" json:"authorization,omitempty"`
	Active        Active        `yaml:"active,omitempty" json:"active,omitempty"`
}
type Target struct {
	URL string `yaml:"url" json:"url"`
}
type Scope struct {
	IncludeHosts           []string `yaml:"include_hosts" json:"include_hosts"`
	IncludeSubdomains      bool     `yaml:"include_subdomains,omitempty" json:"include_subdomains,omitempty"`
	AllowedSchemes         []string `yaml:"allowed_schemes,omitempty" json:"allowed_schemes,omitempty"`
	AllowedPorts           []int    `yaml:"allowed_ports,omitempty" json:"allowed_ports,omitempty"`
	FollowInScopeRedirects bool     `yaml:"follow_in_scope_redirects,omitempty" json:"follow_in_scope_redirects,omitempty"`
}
type Limits struct {
	Concurrency      int    `yaml:"concurrency,omitempty" json:"concurrency,omitempty"`
	TotalTimeout     string `yaml:"total_timeout,omitempty" json:"total_timeout,omitempty"`
	RequestTimeout   string `yaml:"request_timeout,omitempty" json:"request_timeout,omitempty"`
	MaxRequests      int    `yaml:"max_requests,omitempty" json:"max_requests,omitempty"`
	MaxRedirects     int    `yaml:"max_redirects,omitempty" json:"max_redirects,omitempty"`
	MaxResponseBytes int64  `yaml:"max_response_bytes,omitempty" json:"max_response_bytes,omitempty"`
}
type Policy struct {
	ID                    string  `yaml:"id,omitempty" json:"id,omitempty"`
	MinimumScoreCoverage  float64 `yaml:"minimum_score_coverage,omitempty" json:"minimum_score_coverage,omitempty"`
	CertExpiryWarningDays int     `yaml:"cert_expiry_warning_days,omitempty" json:"cert_expiry_warning_days,omitempty"`
	FailOn                string  `yaml:"fail_on,omitempty" json:"fail_on,omitempty"`
}
type Email struct {
	DKIMSelectors []string `yaml:"dkim_selectors,omitempty" json:"dkim_selectors,omitempty"`
}
type Providers struct {
	GeoIP string `yaml:"geoip,omitempty" json:"geoip,omitempty"`
	ASN   string `yaml:"asn,omitempty" json:"asn,omitempty"`
	RDAP  string `yaml:"rdap,omitempty" json:"rdap,omitempty"`
}
type Report struct {
	Format          string `yaml:"format,omitempty" json:"format,omitempty"`
	RedactSensitive *bool  `yaml:"redact_sensitive,omitempty" json:"redact_sensitive,omitempty"`
}
type Authorization struct {
	Acknowledged bool `yaml:"acknowledged,omitempty" json:"acknowledged,omitempty"`
}
type Active struct {
	AllowedPorts        []int `yaml:"allowed_ports,omitempty" json:"allowed_ports,omitempty"`
	MaxHosts            int   `yaml:"max_hosts,omitempty" json:"max_hosts,omitempty"`
	MaxConnections      int   `yaml:"max_connections,omitempty" json:"max_connections,omitempty"`
	MaxPacketsPerSecond int   `yaml:"max_packets_per_second,omitempty" json:"max_packets_per_second,omitempty"`
}

func Defaults(target string) Config {
	return Config{
		SchemaVersion: SchemaVersion,
		Profile:       "passive",
		Target:        Target{URL: target},
		Scope: Scope{
			IncludeHosts:           []string{target},
			AllowedSchemes:         []string{"https"},
			AllowedPorts:           []int{443},
			FollowInScopeRedirects: true,
		},
		Modules: []string{"tls", "http", "dns"},
		Limits: Limits{
			Concurrency: DefaultConcurrency, TotalTimeout: DefaultTotalTimeout, RequestTimeout: DefaultRequestTimeout,
			MaxRequests: DefaultMaxRequests, MaxRedirects: DefaultMaxRedirects, MaxResponseBytes: DefaultMaxResponseBytes,
		},
		Policy:    Policy{ID: "default-v1", MinimumScoreCoverage: DefaultMinimumCoverage, CertExpiryWarningDays: DefaultCertWarningDays, FailOn: "none"},
		Providers: Providers{GeoIP: "disabled", ASN: "disabled", RDAP: "disabled"},
		Report:    Report{Format: "terminal", RedactSensitive: boolPtr(true)},
	}
}
func boolPtr(v bool) *bool { return &v }
func LoadFile(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("read config: %w", err)
	}
	return Parse(data)
}
func Parse(data []byte) (Config, error) {
	if len(data) > 1<<20 {
		return Config{}, errors.New("configuration exceeds 1 MiB limit")
	}
	var document yaml.Node
	if err := yaml.Unmarshal(data, &document); err != nil {
		return Config{}, fmt.Errorf("decode config: %w", err)
	}
	count := 0
	var visit func(*yaml.Node) error
	visit = func(node *yaml.Node) error {
		count++
		if count > 20000 {
			return errors.New("configuration contains too many YAML nodes")
		}
		if node.Kind == yaml.AliasNode {
			return errors.New("YAML aliases are not allowed")
		}
		for _, child := range node.Content {
			if err := visit(child); err != nil {
				return err
			}
		}
		return nil
	}
	if err := visit(&document); err != nil {
		return Config{}, err
	}
	var cfg Config
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&cfg); err != nil {
		return Config{}, fmt.Errorf("decode config: %w", err)
	}
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return Config{}, errors.New("config must contain exactly one YAML document")
	}
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	cfg.ApplyDefaults()
	raw, err := json.Marshal(cfg)
	if err != nil {
		return Config{}, fmt.Errorf("encode config for schema validation: %w", err)
	}
	if err := ValidateJSONSchema(raw, configSchema); err != nil {
		return Config{}, fmt.Errorf("config schema validation: %w", err)
	}
	return cfg, nil
}
func (c *Config) ApplyDefaults() {
	if c.Modules == nil {
		c.Modules = []string{"tls", "http", "dns"}
	}
	if c.Limits.Concurrency == 0 {
		c.Limits.Concurrency = DefaultConcurrency
	}
	if c.Limits.TotalTimeout == "" {
		c.Limits.TotalTimeout = DefaultTotalTimeout
	}
	if c.Limits.RequestTimeout == "" {
		c.Limits.RequestTimeout = DefaultRequestTimeout
	}
	if c.Limits.MaxRequests == 0 {
		c.Limits.MaxRequests = DefaultMaxRequests
	}
	if c.Limits.MaxResponseBytes == 0 {
		c.Limits.MaxResponseBytes = DefaultMaxResponseBytes
	}
	if c.Policy.ID == "" {
		c.Policy.ID = "default-v1"
	}
	if c.Policy.MinimumScoreCoverage == 0 {
		c.Policy.MinimumScoreCoverage = DefaultMinimumCoverage
	}
	if c.Policy.CertExpiryWarningDays == 0 {
		c.Policy.CertExpiryWarningDays = DefaultCertWarningDays
	}
	if c.Policy.FailOn == "" {
		c.Policy.FailOn = "none"
	}
	if c.Report.Format == "" {
		c.Report.Format = "terminal"
	}
	if c.Report.RedactSensitive == nil {
		c.Report.RedactSensitive = boolPtr(true)
	}
	if c.Providers.GeoIP == "" {
		c.Providers.GeoIP = "disabled"
	}
	if c.Providers.ASN == "" {
		c.Providers.ASN = "disabled"
	}
	if c.Providers.RDAP == "" {
		c.Providers.RDAP = "disabled"
	}
	if len(c.Scope.AllowedSchemes) == 0 || len(c.Scope.AllowedPorts) == 0 {
		raw := strings.TrimSpace(c.Target.URL)
		if !strings.Contains(raw, "://") {
			raw = "https://" + raw
		}
		if target, err := url.Parse(raw); err == nil && target.Hostname() != "" {
			port := target.Port()
			if port == "" {
				if target.Scheme == "http" {
					port = "80"
				} else {
					port = "443"
				}
			}
			if len(c.Scope.AllowedSchemes) == 0 {
				c.Scope.AllowedSchemes = []string{target.Scheme}
			}
			if len(c.Scope.AllowedPorts) == 0 {
				if parsed, err := strconv.Atoi(port); err == nil {
					c.Scope.AllowedPorts = []int{parsed}
				}
			}
		}
	}
}
func (c Config) Validate() error {
	if c.SchemaVersion != SchemaVersion {
		return fmt.Errorf("schema_version must be %q", SchemaVersion)
	}
	if c.Profile != "passive" && c.Profile != "active" {
		return errors.New("profile must be passive or active")
	}
	if strings.TrimSpace(c.Target.URL) == "" {
		return errors.New("target.url is required")
	}
	if len(c.Scope.IncludeHosts) == 0 {
		return errors.New("scope.include_hosts must not be empty")
	}
	for _, module := range c.Modules {
		if !KnownModules[module] {
			return fmt.Errorf("unknown module %q", module)
		}
	}
	if duplicate(c.Modules) {
		return errors.New("modules must not contain duplicates")
	}
	if c.Limits.Concurrency < 0 || c.Limits.Concurrency > 64 {
		return errors.New("limits.concurrency must be between 1 and 64 when set")
	}
	if c.Limits.MaxRequests < 0 || c.Limits.MaxRequests > 10000 {
		return errors.New("limits.max_requests must be between 1 and 10000 when set")
	}
	if c.Limits.MaxRedirects < 0 || c.Limits.MaxRedirects > 20 {
		return errors.New("limits.max_redirects must be between 0 and 20")
	}
	if c.Limits.MaxResponseBytes < 0 || c.Limits.MaxResponseBytes > 10*1024*1024 {
		return errors.New("limits.max_response_bytes must be between 1024 and 10485760 when set")
	}
	for name, value := range map[string]string{"total_timeout": c.Limits.TotalTimeout, "request_timeout": c.Limits.RequestTimeout} {
		if value != "" {
			d, err := time.ParseDuration(value)
			if err != nil || d <= 0 {
				return fmt.Errorf("limits.%s must be a positive duration", name)
			}
		}
	}
	if c.Policy.MinimumScoreCoverage < 0 || c.Policy.MinimumScoreCoverage > 1 {
		return errors.New("policy.minimum_score_coverage must be between 0 and 1")
	}
	if c.Policy.CertExpiryWarningDays < 0 || c.Policy.CertExpiryWarningDays > 365 {
		return errors.New("policy.cert_expiry_warning_days must be between 1 and 365 when set")
	}
	if c.Policy.FailOn != "" && !oneOf(c.Policy.FailOn, "none", "low", "medium", "high", "critical") {
		return errors.New("policy.fail_on must be none, low, medium, high, or critical")
	}
	if c.Report.Format != "" && !oneOf(c.Report.Format, "terminal", "json", "sarif") {
		return errors.New("report.format must be terminal, json, or sarif")
	}
	if c.Providers.RDAP != "" && !oneOf(c.Providers.RDAP, "enabled", "disabled") {
		return errors.New("providers.rdap must be enabled or disabled")
	}
	if c.Profile == "active" && !c.Authorization.Acknowledged {
		return errors.New("active profile requires authorization.acknowledged: true")
	}
	return nil
}
func ValidateJSONSchema(data []byte, schema string) error {
	compiler := jsonschema.NewCompiler()
	var schemaDocument any
	if err := json.Unmarshal([]byte(schema), &schemaDocument); err != nil {
		return err
	}
	if err := compiler.AddResource("schema.json", schemaDocument); err != nil {
		return err
	}
	compiled, err := compiler.Compile("schema.json")
	if err != nil {
		return err
	}
	var value any
	if err := json.Unmarshal(data, &value); err != nil {
		return err
	}
	return compiled.Validate(value)
}
func duplicate(values []string) bool {
	seen := make(map[string]bool, len(values))
	for _, value := range values {
		if seen[value] {
			return true
		}
		seen[value] = true
	}
	return false
}
func oneOf(value string, allowed ...string) bool {
	for _, candidate := range allowed {
		if value == candidate {
			return true
		}
	}
	return false
}

const configSchema = `{
 "$schema":"https://json-schema.org/draft/2020-12/schema","type":"object","additionalProperties":false,
 "required":["schema_version","profile","target","scope"],
 "properties":{
  "schema_version":{"const":"1"},
  "profile":{"enum":["passive","active"]},
  "target":{"type":"object","additionalProperties":false,"required":["url"],"properties":{"url":{"type":"string","minLength":1}}},
  "scope":{"type":"object","additionalProperties":false,"required":["include_hosts"],"properties":{
   "include_hosts":{"type":"array","minItems":1,"items":{"type":"string"}},
   "include_subdomains":{"type":"boolean"},
   "allowed_schemes":{"type":"array","items":{"enum":["http","https"]}},
   "allowed_ports":{"type":"array","items":{"type":"integer","minimum":1,"maximum":65535}},
   "follow_in_scope_redirects":{"type":"boolean"}}},
  "modules":{"type":"array","uniqueItems":true,"items":{"enum":["tls","http","dns","email","domain","network","discovery"]}},
  "limits":{"type":"object","additionalProperties":false,"properties":{
   "concurrency":{"type":"integer","minimum":1,"maximum":64},"total_timeout":{"type":"string"},
   "request_timeout":{"type":"string"},"max_requests":{"type":"integer","minimum":1,"maximum":10000},
   "max_redirects":{"type":"integer","minimum":0,"maximum":20},"max_response_bytes":{"type":"integer","minimum":1024,"maximum":10485760}}},
  "policy":{"type":"object","additionalProperties":false,"properties":{
   "id":{"type":"string"},"minimum_score_coverage":{"type":"number","minimum":0,"maximum":1},
   "cert_expiry_warning_days":{"type":"integer","minimum":1,"maximum":365},
   "fail_on":{"enum":["none","low","medium","high","critical"]}}},
  "email":{"type":"object","additionalProperties":false,"properties":{"dkim_selectors":{"type":"array","items":{"type":"string"}}}},
  "providers":{"type":"object","additionalProperties":false,"properties":{
   "geoip":{"type":"string"},"asn":{"type":"string"},"rdap":{"enum":["enabled","disabled"]}}},
  "report":{"type":"object","additionalProperties":false,"properties":{
   "format":{"enum":["terminal","json","sarif"]},"redact_sensitive":{"type":"boolean"}}},
  "authorization":{"type":"object","additionalProperties":false,"properties":{"acknowledged":{"type":"boolean"}}},
  "active":{"type":"object","additionalProperties":false,"properties":{
   "allowed_ports":{"type":"array","items":{"type":"integer","minimum":1,"maximum":65535}},
   "max_hosts":{"type":"integer","minimum":1},"max_connections":{"type":"integer","minimum":1},
   "max_packets_per_second":{"type":"integer","minimum":1}}}},
 "allOf":[{"if":{"properties":{"profile":{"const":"active"}},"required":["profile"]},"then":{"required":["active","authorization"]}}]
}`
