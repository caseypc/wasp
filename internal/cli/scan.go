package cli

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/caseypc/wasp/internal/config"
	"github.com/caseypc/wasp/internal/engine"
	"github.com/caseypc/wasp/internal/network"
	"github.com/caseypc/wasp/internal/output"
	"github.com/caseypc/wasp/pkg/report"
	"github.com/spf13/cobra"
)

func newScanCommand() *cobra.Command {
	var configPath, modulesFlag, formatFlag, outputPath, failOn, timeout string
	var concurrency int
	var minimumCoverage float64
	var force bool
	cmd := &cobra.Command{
		Use:   "scan <target>",
		Short: "Run a bounded passive audit of a scoped public target",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			target, err := network.ParseTarget(args[0])
			if err != nil {
				if errors.Is(err, network.ErrScopeDenied) {
					return deniedError(err)
				}
				return usageError(err)
			}
			var cfg config.Config
			if configPath != "" {
				cfg, err = config.LoadFile(configPath)
				if err != nil {
					return usageError(err)
				}
				cfg.Target.URL = target.URL.String()
			} else {
				cfg = config.Defaults(target.URL.String())
				cfg.Scope.IncludeHosts = []string{target.Host}
				cfg.Scope.AllowedSchemes = []string{target.URL.Scheme}
				port, parseErr := network.ParsePort(target.Port)
				if parseErr != nil {
					return usageError(parseErr)
				}
				cfg.Scope.AllowedPorts = []int{port}
			}
			if modulesFlag != "" {
				cfg.Modules, err = supportedModuleList(modulesFlag)
				if err != nil {
					return usageError(err)
				}
			}
			for _, module := range cfg.Modules {
				if !engine.SupportedModules[module] {
					return usageError(fmt.Errorf("module %q is not implemented; available scan modules: tls,http,dns", module))
				}
			}
			if concurrency < 0 || concurrency > 64 {
				return usageError(errors.New("--concurrency must be between 1 and 64"))
			}
			if concurrency > 0 {
				cfg.Limits.Concurrency = concurrency
			}
			if timeout != "" {
				d, parseErr := time.ParseDuration(timeout)
				if parseErr != nil || d <= 0 {
					return usageError(errors.New("--timeout must be a positive duration"))
				}
				cfg.Limits.TotalTimeout = timeout
			}
			if cmd.Flags().Changed("min-coverage") {
				if minimumCoverage < 0 || minimumCoverage > 1 {
					return usageError(errors.New("--min-coverage must be between 0 and 1"))
				}
				cfg.Policy.MinimumScoreCoverage = minimumCoverage
			}
			if failOn != "" {
				if !oneOf(failOn, "none", "low", "medium", "high", "critical") {
					return usageError(errors.New("--fail-on must be none, low, medium, high, or critical"))
				}
				cfg.Policy.FailOn = failOn
			}
			if formatFlag == "" {
				formatFlag = cfg.Report.Format
			}
			if formatFlag == "" {
				formatFlag = "terminal"
			}
			if formatFlag == "sarif" {
				return usageError(errors.New("SARIF output is planned for M3 and is not implemented"))
			}
			if !oneOf(formatFlag, "terminal", "json") {
				return usageError(errors.New("format must be terminal or json"))
			}
			ctx := cmd.Context()
			if ctx == nil {
				ctx = context.Background()
			}
			fmt.Fprintf(cmd.ErrOrStderr(), "[!] Target: %s -> %s\n[!] Modules: %s | Mode: %s\n", args[0], target.URL.String(), strings.Join(cfg.Modules, ","), cfg.Profile)
			result, err := engine.Scan(ctx, cfg, engine.Options{Version: config.Version})
			scopeDenied := false
			if err != nil {
				if errors.Is(err, network.ErrScopeDenied) {
					scopeDenied = true
				} else {
					return usageError(err)
				}
			}
			printModuleStatuses(cmd, cfg.Modules, result)
			for _, diagnostic := range result.Diagnostics {
				fmt.Fprintf(cmd.ErrOrStderr(), "%s/%s: %s: %s\n", diagnostic.ModuleID, diagnostic.ProbeID, diagnostic.Code, diagnostic.Message)
			}
			var outputBytes []byte
			if formatFlag == "json" {
				outputBytes, err = result.JSON()
				if err != nil {
					return runtimeError(err)
				}
				if err := report.ValidateJSON(outputBytes); err != nil {
					return runtimeError(fmt.Errorf("generated report failed schema validation: %w", err))
				}
			} else {
				color := output.SupportsColor(cmd.OutOrStdout()) && (outputPath == "" || outputPath == "-")
				outputBytes = output.RenderTerminal(result, color, config.PassLabel(), config.FailLabel())
			}
			if outputPath == "" {
				outputPath = "-"
			}
			if outputPath == "-" {
				if _, err := cmd.OutOrStdout().Write(outputBytes); err != nil {
					return runtimeError(err)
				}
			} else if err := writeNewFile(outputPath, outputBytes, force); err != nil {
				return usageError(err)
			}
			if scopeDenied {
				return deniedError(errors.New("network operation denied by scope policy"))
			}
			if len(result.Diagnostics) > 0 || result.Coverage.Fraction < cfg.Policy.MinimumScoreCoverage {
				return runtimeError(errors.New("scan completed with operational errors or insufficient coverage"))
			}
			if findingGate(result.Findings, cfg.Policy.FailOn) {
				return exitError{code: 1, err: errors.New("findings met the configured severity gate")}
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "Configuration file")
	cmd.Flags().StringVar(&modulesFlag, "modules", "", "Comma-separated modules (tls,http,dns)")
	cmd.Flags().StringVar(&formatFlag, "format", "", "Report format: terminal or json")
	cmd.Flags().StringVar(&outputPath, "output", "-", "Output path or - for stdout")
	cmd.Flags().StringVar(&failOn, "fail-on", "", "Findings threshold: none, low, medium, high, critical")
	cmd.Flags().Float64Var(&minimumCoverage, "min-coverage", 0, "Minimum evaluable rule coverage [0,1]")
	cmd.Flags().IntVar(&concurrency, "concurrency", 0, "Maximum concurrent probes (1-64)")
	cmd.Flags().StringVar(&timeout, "timeout", "", "Total scan timeout")
	cmd.Flags().BoolVar(&force, "force", false, "Atomically replace an existing output file")
	_ = cmd.Flags().Set("output", "-")
	cmd.Flags().Lookup("output").DefValue = "-"
	return cmd
}

func printModuleStatuses(cmd *cobra.Command, modules []string, result report.Report) {
	color := output.SupportsColor(cmd.ErrOrStderr())
	for _, module := range modules {
		level := "fail"
		hasDiagnostic := false
		for _, diagnostic := range result.Diagnostics {
			if diagnostic.ModuleID == module {
				hasDiagnostic = true
				break
			}
		}
		if !hasDiagnostic {
			for _, observation := range result.Observations {
				if observation.ModuleID != module {
					continue
				}
				switch observation.Status {
				case report.StatusPass:
					level = "pass"
				case report.StatusFail, report.StatusError:
					level = "fail"
				default:
					level = "warn"
				}
				break
			}
		}
		var status string
		switch level {
		case "pass":
			status = output.FormatStatus(level, config.PassLabel(), color)
		case "fail":
			status = output.FormatStatus(level, config.FailLabel(), color)
		default:
			status = output.FormatStatus(level, "WARN", color)
		}
		fmt.Fprintf(cmd.ErrOrStderr(), "Scanning module %s... [%s]\n", module, status)
	}
}
func findingGate(findings []report.Finding, threshold string) bool {
	rank := map[string]int{"none": 5, "low": 1, "medium": 2, "high": 3, "critical": 4}
	minimum := rank[threshold]
	if minimum == 0 || minimum >= 5 {
		return false
	}
	for _, finding := range findings {
		if rank[finding.Severity] >= minimum {
			return true
		}
	}
	return false
}
func oneOf(value string, options ...string) bool {
	for _, option := range options {
		if value == option {
			return true
		}
	}
	return false
}
