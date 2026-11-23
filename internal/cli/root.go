package cli

import (
	"errors"
	"fmt"
	"github.com/spf13/cobra"
	"os"
)

type exitError struct {
	code int
	err  error
}

func (e exitError) Error() string { return e.err.Error() }
func (e exitError) Unwrap() error { return e.err }
func Execute() int {
	root := NewRootCommand()
	if err := root.Execute(); err != nil {
		var coded exitError
		if errors.As(err, &coded) {
			fmt.Fprintln(os.Stderr, err)
			return coded.code
		}
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	return 0
}
func NewRootCommand() *cobra.Command {
	root := &cobra.Command{
		Use:           "wasp",
		Short:         "Website Audit & Security Profiler",
		Long:          "WASP performs bounded, passive security audits of explicitly scoped public web targets.",
		SilenceErrors: true,
		SilenceUsage:  false,
	}
	root.SetHelpCommand(&cobra.Command{Use: "help [command]", Hidden: true})
	root.AddCommand(newScanCommand(), newModulesCommand(), newRulesCommand(), newConfigCommand(), newReportCommand(), newVersionCommand())
	root.CompletionOptions.DisableDefaultCmd = false
	return root
}
func usageError(err error) error   { return exitError{code: 2, err: err} }
func runtimeError(err error) error { return exitError{code: 3, err: err} }
func deniedError(err error) error  { return exitError{code: 4, err: err} }
