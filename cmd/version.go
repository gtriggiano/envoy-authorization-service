package cmd

import (
	"encoding/json"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/gtriggiano/envoy-authorization-service/pkg/version"
)

var versionOutput string

// init registers the version subcommand and its flags.
func init() {
	rootCmd.AddCommand(versionCmd)
	versionCmd.Flags().StringVarP(&versionOutput, "output", "o", "text", `Output format: "text", "short" (version only) or "json"`)
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the version, commit and build information of this binary",
	Long: `Print the version, commit and build information of this binary.

Release builds carry the release version, the commit they were built from and the
build time. Binaries built with a plain "go build" report "dev" as version and take the
commit from the Git metadata embedded by the Go toolchain, with a "-dirty" suffix when
the working tree had uncommitted changes.`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, _ []string) error {
		info := version.Get()
		switch versionOutput {
		case "text":
			fmt.Fprintf(cmd.OutOrStdout(), "%s %s\n", rootCmd.Name(), info)
		case "short":
			fmt.Fprintln(cmd.OutOrStdout(), info.Version)
		case "json":
			enc := json.NewEncoder(cmd.OutOrStdout())
			enc.SetIndent("", "  ")
			return enc.Encode(struct {
				Version   string `json:"version"`
				Commit    string `json:"commit"`
				BuildDate string `json:"buildDate"`
				GoVersion string `json:"goVersion"`
				Platform  string `json:"platform"`
			}(info))
		default:
			return fmt.Errorf("unknown output format %q (expected \"text\", \"short\" or \"json\")", versionOutput)
		}
		return nil
	},
}
