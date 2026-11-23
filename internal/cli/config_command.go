package cli

import (
	"fmt"
	"github.com/caseypc/wasp/internal/config"
	"github.com/caseypc/wasp/internal/network"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
	"os"
	"path/filepath"
)

func newConfigCommand() *cobra.Command {
	cmd := &cobra.Command{Use: "config", Short: "Create or validate WASP configuration", Args: cobra.NoArgs}
	initCmd := &cobra.Command{
		Use: "init", Short: "Write a starter configuration", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			path, _ := cmd.Flags().GetString("output")
			targetInput, _ := cmd.Flags().GetString("target")
			target, err := network.ParseTarget(targetInput)
			if err != nil {
				return usageError(err)
			}
			cfg := config.Defaults(target.URL.String())
			cfg.Scope.IncludeHosts = []string{target.Host}
			cfg.Scope.AllowedSchemes = []string{target.URL.Scheme}
			if port, err := network.ParsePort(target.Port); err == nil {
				cfg.Scope.AllowedPorts = []int{port}
			}
			data, err := yaml.Marshal(cfg)
			if err != nil {
				return fmt.Errorf("encode config: %w", err)
			}
			if err := writeNewFile(path, data, false); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Wrote %s\n", path)
			return nil
		},
	}
	initCmd.Flags().String("output", ".wasp.yaml", "Output configuration path")
	initCmd.Flags().String("target", "https://example.com", "Initial in-scope target")
	cmd.AddCommand(initCmd)
	validate := &cobra.Command{
		Use: "validate", Short: "Validate a YAML configuration", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			path, _ := cmd.Flags().GetString("file")
			if _, err := config.LoadFile(path); err != nil {
				return usageError(err)
			}
			fmt.Fprintln(cmd.OutOrStdout(), "configuration is valid")
			return nil
		},
	}
	validate.Flags().String("file", ".wasp.yaml", "Configuration file")
	cmd.AddCommand(validate)
	return cmd
}
func writeNewFile(path string, data []byte, force bool) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".wasp-tmp-*")
	if err != nil {
		return fmt.Errorf("create temporary output: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return fmt.Errorf("set output permissions: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("write output: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("sync output: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close output: %w", err)
	}
	if force {
		if err := os.Rename(tmpName, path); err != nil {
			return fmt.Errorf("replace output %q: %w", path, err)
		}
		return nil
	}
	if err := os.Link(tmpName, path); err != nil {
		if os.IsExist(err) {
			return fmt.Errorf("output %q already exists (use --force to replace)", path)
		}
		return fmt.Errorf("install output %q: %w", path, err)
	}
	return nil
}
