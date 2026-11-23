package cli

import (
	"fmt"
	"github.com/caseypc/wasp/pkg/report"
	"github.com/spf13/cobra"
	"os"
)

func newReportCommand() *cobra.Command {
	cmd := &cobra.Command{Use: "report", Short: "Validate a WASP JSON report", Args: cobra.NoArgs}
	cmd.AddCommand(&cobra.Command{
		Use: "validate", Short: "Validate a JSON report against schema v1", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			path, _ := cmd.Flags().GetString("file")
			data, err := os.ReadFile(path)
			if err != nil {
				return usageError(fmt.Errorf("read report: %w", err))
			}
			if len(data) > 10*1024*1024 {
				return usageError(fmt.Errorf("report exceeds 10 MiB validation limit"))
			}
			if err := report.ValidateJSON(data); err != nil {
				return usageError(err)
			}
			fmt.Fprintln(cmd.OutOrStdout(), "report is valid")
			return nil
		},
	})
	cmd.Commands()[0].Flags().String("file", "", "Report JSON file")
	_ = cmd.Commands()[0].MarkFlagRequired("file")
	return cmd
}
