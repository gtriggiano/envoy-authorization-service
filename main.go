// Package main serves as the entry point for the Contour Authorization Server.
// It initializes the CLI and delegates execution to the cmd package.
package main

import (
	"os"

	"github.com/gtriggiano/envoy-authorization-service/cmd"
)

// main is the application entry point. It invokes the root Cobra command and exits
// with a non-zero status code if command execution fails.
func main() {
	if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}
}
