package cli

import (
	"fmt"
	"github.com/spf13/cobra"
)

type ruleInfo struct {
	id, module, severity, title, remediation string
}

var ruleCatalog = []ruleInfo{
	{"TLS-CERT-001", "tls", "critical", "TLS certificate is expired", "Renew and deploy a valid certificate."},
	{"HTTP-HEADER-001", "http", "medium", "HTTP Strict Transport Security is missing", "Configure a suitable Strict-Transport-Security header after verifying HTTPS deployment."},
}

func newRulesCommand() *cobra.Command {
	cmd := &cobra.Command{Use: "rules", Short: "Inspect the versioned rule catalog", Args: cobra.NoArgs}
	list := &cobra.Command{
		Use: "list", Short: "List implemented rules", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			module, _ := cmd.Flags().GetString("module")
			for _, rule := range ruleCatalog {
				if module == "" || rule.module == module {
					fmt.Fprintf(cmd.OutOrStdout(), "%-20s %-8s %-9s %s\n", rule.id, rule.module, rule.severity, rule.title)
				}
			}
			return nil
		},
	}
	list.Flags().String("module", "", "Filter rules by module")
	cmd.AddCommand(list)
	cmd.AddCommand(&cobra.Command{
		Use: "show <rule-id>", Short: "Show rule remediation", Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			for _, rule := range ruleCatalog {
				if rule.id == args[0] {
					fmt.Fprintf(cmd.OutOrStdout(), "%s (%s, %s)\n%s\nRemediation: %s\n", rule.id, rule.module, rule.severity, rule.title, rule.remediation)
					return nil
				}
			}
			return fmt.Errorf("unknown rule %q", args[0])
		},
	})
	return cmd
}
