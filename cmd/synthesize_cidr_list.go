package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/gtriggiano/envoy-authorization-service/pkg/cidrlist"
)

var (
	cidrListFile          string
	cidrListFileOverwrite bool
)

// init registers the synthesize-cidr-list subcommand and its flags.
func init() {
	rootCmd.AddCommand(synthesizeCIDRListCmd)
	synthesizeCIDRListCmd.Flags().StringVar(&cidrListFile, "file", "", "Path to the CIDR list file")
	synthesizeCIDRListCmd.Flags().BoolVar(&cidrListFileOverwrite, "overwrite", false, "Overwrite the CIDR list file with the synthesized output, otherwise prints to stdout")
}

var synthesizeCIDRListCmd = &cobra.Command{
	Use:   "synthesize-cidr-list",
	Short: "Remove redundant CIDRs from a list file",
	RunE: func(_ *cobra.Command, _ []string) error {
		if cidrListFile == "" {
			return fmt.Errorf("flag \"file\" is required")
		}

		fileInfo, err := os.Stat(cidrListFile)
		if err != nil {
			return fmt.Errorf("could not stat file %s: %w", cidrListFile, err)
		}

		data, err := os.ReadFile(cidrListFile)
		if err != nil {
			return fmt.Errorf("could not read file %s: %w", cidrListFile, err)
		}

		output := cidrlist.Format(cidrlist.Synthesize(cidrlist.Parse(string(data))).NewList)

		if cidrListFileOverwrite {
			if err := os.WriteFile(cidrListFile, []byte(output), fileInfo.Mode()); err != nil {
				return fmt.Errorf("write file %s: %w", cidrListFile, err)
			}
			return nil
		}

		fmt.Println(output)

		return nil
	},
}
