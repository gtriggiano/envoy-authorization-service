// Package cmd provides the command-line interface for the Envoy Authorization Service
// using the Cobra framework. It defines the root command and subcommands for starting
// the server and utility operations.
package cmd

import (
	"errors"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/gtriggiano/envoy-authorization-service/pkg/version"
)

// rootCmd is the base command for the CLI. Subcommands are registered via their init() hooks.
//
// Cobra's own error and usage printing is disabled for the whole command tree: Execute
// prints every error exactly once on stderr, and usage is only shown for flag and
// argument mistakes (see flagError), never for runtime failures such as an unreadable
// configuration file.
var rootCmd = &cobra.Command{
	Use:           "envoy-authorization-service",
	Short:         "External authorization service implementing the Envoy ext_authz gRPC API",
	Version:       version.Get().String(),
	SilenceErrors: true,
	SilenceUsage:  true,
}

func init() {
	rootCmd.SetVersionTemplate("{{.Name}} {{.Version}}\n")
	rootCmd.SetFlagErrorFunc(flagError)
}

// flagError appends the command usage to flag parsing errors so a mistyped flag still
// tells the user what the command accepts.
func flagError(cmd *cobra.Command, err error) error {
	return fmt.Errorf("%w\n\n%s", err, cmd.UsageString())
}

// reportedError marks an error that has already been shown to the user (logged or
// printed by the command itself) so Execute does not print it a second time.
type reportedError struct{ err error }

func (e reportedError) Error() string { return e.err.Error() }
func (e reportedError) Unwrap() error { return e.err }

// reported wraps err so that Execute exits with a failure status without printing it again.
func reported(err error) error {
	if err == nil {
		return nil
	}
	return reportedError{err: err}
}

// Execute runs the root Cobra command, prints any error that has not been reported yet
// on stderr and returns it. This is the main entry point called from main.go.
func Execute() error {
	err := rootCmd.Execute()
	if err == nil {
		return nil
	}
	var already reportedError
	if !errors.As(err, &already) {
		fmt.Fprintf(rootCmd.ErrOrStderr(), "Error: %v\n", err)
	}
	return err
}
