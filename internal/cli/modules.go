package cli

import (
	"fmt"
	"github.com/caseypc/wasp/internal/engine"
	"github.com/spf13/cobra"
	"strings"
)

type moduleInfo struct {
	id, description, status string
}

var moduleCatalog = []moduleInfo{
	{"tls", "Passive HTTPS certificate and negotiated TLS inspection.", "implemented"},
	{"http", "Passive HTTP response and HSTS inspection.", "implemented"},
	{"dns", "Scoped public A/AAAA resolution.", "implemented"},
	{"email", "SPF, DMARC, and configured DKIM selectors.", "planned"},
	{"domain", "RDAP registration evidence.", "planned"},
	{"network", "Passive IP metadata; active probes are deferred.", "planned"},
	{"discovery", "Explicitly supplied, in-scope hostname evidence.", "planned"},
}

func newModulesCommand() *cobra.Command {
	cmd := &cobra.Command{Use: "modules", Short: "List available WASP modules", Args: cobra.NoArgs}
	cmd.AddCommand(&cobra.Command{
		Use:   "list",
		Short: "List modules and implementation status",
		Args:  cobra.NoArgs,
		Run: func(cmd *cobra.Command, args []string) {
			for _, module := range moduleCatalog {
				fmt.Fprintf(cmd.OutOrStdout(), "%-12s %-11s %s\n", module.id, module.status, module.description)
			}
		},
	})
	cmd.AddCommand(&cobra.Command{
		Use:   "show <module>",
		Short: "Show module capabilities",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			for _, module := range moduleCatalog {
				if module.id == args[0] {
					fmt.Fprintf(cmd.OutOrStdout(), "%s (%s)\n%s\n", module.id, module.status, module.description)
					return nil
				}
			}
			return fmt.Errorf("unknown module %q", args[0])
		},
	})
	_ = engine.SupportedModules
	return cmd
}
func supportedModuleList(input string) ([]string, error) {
	modules := strings.Split(input, ",")
	seen := make(map[string]bool)
	for i := range modules {
		modules[i] = strings.TrimSpace(modules[i])
		if modules[i] == "" {
			return nil, fmt.Errorf("module list contains an empty name")
		}
		if !engine.SupportedModules[modules[i]] {
			return nil, fmt.Errorf("module %q is not implemented in this release", modules[i])
		}
		if seen[modules[i]] {
			return nil, fmt.Errorf("module %q is repeated", modules[i])
		}
		seen[modules[i]] = true
	}
	return modules, nil
}
