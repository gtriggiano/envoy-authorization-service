// Package main serves as the entry point for the Envoy Authorization Service.
// It initializes the CLI and delegates execution to the cmd package.
package main

import (
	"os"

	"github.com/gtriggiano/envoy-authorization-service/cmd"
)

// main is the application entry point. It invokes the root Cobra command, which prints
// any error on stderr, and exits with a non-zero status code when it fails.
func main() {
	if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}
}
