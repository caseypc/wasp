package cli

import (
	"fmt"
	"github.com/caseypc/wasp/internal/config"
	"github.com/caseypc/wasp/internal/output"
	"github.com/caseypc/wasp/pkg/report"
	"github.com/spf13/cobra"
)

func newVersionCommand() *cobra.Command {
	var banner string
	cmd := &cobra.Command{
		Use: "version", Short: "Print version and build metadata", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if !oneOf(banner, "normal", "short", "text") {
				return usageError(fmt.Errorf("--banner must be normal, short, or text"))
			}
			_, err := fmt.Fprintf(cmd.OutOrStdout(), "%s\nCommit: %s | Built: %s | Report schema: %s\n", output.Banner(banner, config.Version), config.Commit, config.BuildDate, report.SchemaVersion)
			return err
		},
	}
	cmd.Flags().StringVar(&banner, "banner", "normal", "Banner style: normal, short, or text")
	return cmd
}
