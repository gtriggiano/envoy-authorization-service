// Package cmd provides the command-line interface for the Contour Authorization Server
// using the Cobra framework. It defines the root command and subcommands for starting
// the server and utility operations.
package cmd

import "github.com/spf13/cobra"

// rootCmd is the base command for the CLI. Subcommands are registered via their init() hooks.
var rootCmd = &cobra.Command{
	Use:   "contour-authserver",
	Short: "External authorization server for Project Contour",
}

// Execute runs the root Cobra command and returns any error encountered during execution.
// This is the main entry point called from main.go.
func Execute() error {
	return rootCmd.Execute()
}
