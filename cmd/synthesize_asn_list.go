package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/gtriggiano/envoy-authorization-service/pkg/asnlist"
)

var (
	asnListFile          string
	asnListFileOverwrite bool
)

// init registers the synthesize-asn-list subcommand and associated flags.
func init() {
	rootCmd.AddCommand(synthesizeASNListCmd)
	synthesizeASNListCmd.Flags().StringVar(&asnListFile, "file", "", "Path to the ASN list file")
	synthesizeASNListCmd.Flags().BoolVar(&asnListFileOverwrite, "overwrite", false, "Overwrite the ASN list file with the synthesized output, otherwise prints to stdout")
}

var synthesizeASNListCmd = &cobra.Command{
	Use:   "synthesize-asn-list",
	Short: "Remove duplicate ASN entries from a file",
	RunE: func(_ *cobra.Command, _ []string) error {
		if asnListFile == "" {
			return fmt.Errorf("flag \"file\" is required")
		}

		fileInfo, err := os.Stat(asnListFile)
		if err != nil {
			return fmt.Errorf("could not stat file %s: %w", asnListFile, err)
		}

		data, err := os.ReadFile(asnListFile)
		if err != nil {
			return fmt.Errorf("could not read file %s: %w", asnListFile, err)
		}

		output := asnlist.Format(asnlist.Synthesize(asnlist.Parse(string(data))).NewList)

		if asnListFileOverwrite {
			if err := os.WriteFile(asnListFile, []byte(output), fileInfo.Mode()); err != nil {
				return fmt.Errorf("could not overwrite file %s: %w", asnListFile, err)
			}
			return nil
		}

		fmt.Println(output)

		return nil
	},
}
