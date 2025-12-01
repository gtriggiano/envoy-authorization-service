package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/gtriggiano/envoy-authorization-service/pkg/match/geofence_match"
)

var (
	geojsonFile string
)

// init registers the validate-geojson subcommand and its flags.
func init() {
	rootCmd.AddCommand(validateGeoJSONCmd)
	validateGeoJSONCmd.Flags().StringVar(&geojsonFile, "file", "", "Path to the GeoJSON file to validate")
}

var validateGeoJSONCmd = &cobra.Command{
	Use:   "validate-geojson",
	Short: "Validate a GeoJSON file for use with the geofence-match controller",
	Long: `Validate a GeoJSON file to ensure it can be used with the geofence-match controller.

The command checks that:
- The file is valid JSON and follows GeoJSON FeatureCollection format
- Each feature has a "name" property
- Each feature has a Polygon or MultiPolygon geometry
- All polygons are closed (first and last points match)
- All coordinates are valid GPS coordinates (lat: -90 to 90, lon: -180 to 180)
- Feature names are unique`,
	RunE: func(_ *cobra.Command, _ []string) error {
		if geojsonFile == "" {
			return fmt.Errorf("flag \"file\" is required")
		}

		if _, err := os.Stat(geojsonFile); err != nil {
			return fmt.Errorf("could not stat file %s: %w", geojsonFile, err)
		}

		names, err := geofence_match.GetPolygonNames(geojsonFile)
		if err != nil {
			return fmt.Errorf("validation failed: %w", err)
		}

		fmt.Printf("✓ GeoJSON file is valid\n")
		fmt.Printf("  Polygons found: %d\n", len(names))
		for _, name := range names {
			fmt.Printf("    - %s\n", name)
		}

		return nil
	},
}
