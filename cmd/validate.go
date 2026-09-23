package cmd

import (
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/spf13/cobra"
	"go.uber.org/zap"

	"github.com/gtriggiano/envoy-authorization-service/pkg/config"
	"github.com/gtriggiano/envoy-authorization-service/pkg/controller"
	"github.com/gtriggiano/envoy-authorization-service/pkg/runtime"
)

var (
	validateCfgFile string
	validateOffline bool
)

// init registers the validate subcommand and its flags.
func init() {
	rootCmd.AddCommand(validateCmd)
	validateCmd.Flags().StringVar(&validateCfgFile, "config", "config.yaml", "Path to the configuration file")
	validateCmd.Flags().BoolVar(&validateOffline, "offline", false, "Do not use the deployment environment: skip database connections and report missing credential and data files as warnings")
}

var validateCmd = &cobra.Command{
	Use:   "validate",
	Short: "Validate a configuration file without starting the server",
	Long: `Validate a configuration file exactly as "start" would load it, then exit.

The command expands environment references, rejects unknown keys, checks every
top-level field and the authorization policy, and builds every enabled controller:
list files are parsed, MaxMind databases opened, GeoJSON validated, database
settings checked and, unless --offline is given, databases are connected to.

With --offline the deployment environment is assumed to be unavailable: no network
connection is attempted, and credential or data files that cannot be found are
reported as warnings instead of errors. Everything else is still checked, which
makes the flag suitable for CI pipelines validating ConfigMaps before rollout.

The exit status is 0 when the configuration is valid and 1 otherwise.`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, _ []string) error {
		mode := controller.BuildModeValidate
		if validateOffline {
			mode = controller.BuildModeValidateOffline
		}
		result, err := validateConfiguration(context.Background(), validateCfgFile, mode)
		if err != nil {
			fmt.Fprintf(cmd.ErrOrStderr(), "✗ configuration is invalid: %v\n", err)
			return reported(err)
		}
		result.print(cmd.OutOrStdout())
		return nil
	},
}

// validationResult summarises a successful validation.
type validationResult struct {
	path                string
	offline             bool
	analysisControllers []string
	matchControllers    []string
	skipped             int
	policy              string
	policyBypass        bool
	clientIPSources     []string
	warnings            []string
}

// validateConfiguration loads the configuration and builds every enabled controller in
// the given mode, returning a summary or the first error encountered.
func validateConfiguration(parent context.Context, path string, mode controller.BuildMode) (*validationResult, error) {
	cfg, err := config.Load(path)
	if err != nil {
		return nil, err
	}

	diagnostics := &controller.Diagnostics{}
	ctx, cancel := context.WithCancel(controller.WithDiagnostics(controller.WithBuildMode(parent, mode), diagnostics))
	defer cancel() // releases databases, MaxMind readers and other controller resources

	logger := zap.NewNop()
	analysisControllers, err := controller.BuildAnalysisControllers(ctx, logger, cfg.AnalysisControllers)
	if err != nil {
		return nil, err
	}
	matchControllers, err := controller.BuildMatchControllers(ctx, logger, cfg.MatchControllers)
	if err != nil {
		return nil, err
	}

	result := &validationResult{
		path:            path,
		offline:         mode.Offline(),
		policy:          strings.TrimSpace(cfg.AuthorizationPolicy),
		policyBypass:    cfg.AuthorizationPolicyBypass,
		clientIPSources: runtime.NewClientIPResolver(cfg.ClientIP).Sources(),
		warnings:        diagnostics.Warnings(),
	}
	for _, c := range analysisControllers {
		result.analysisControllers = append(result.analysisControllers, fmt.Sprintf("%s (%s)", c.Name(), c.Kind()))
	}
	for _, c := range matchControllers {
		result.matchControllers = append(result.matchControllers, fmt.Sprintf("%s (%s)", c.Name(), c.Kind()))
	}
	enabled := 0
	for _, c := range append(append([]config.ControllerConfig{}, cfg.AnalysisControllers...), cfg.MatchControllers...) {
		if c.IsEnabled() {
			enabled++
		}
	}
	result.skipped = enabled - len(analysisControllers) - len(matchControllers)
	return result, nil
}

func (r *validationResult) print(w io.Writer) {
	fmt.Fprintf(w, "✓ configuration is valid: %s\n", r.path)
	if r.offline {
		fmt.Fprintf(w, "  mode: offline (no database connections; missing credential and data files reported as warnings)\n")
	}
	fmt.Fprintf(w, "  analysis controllers: %s\n", joinOrNone(r.analysisControllers))
	fmt.Fprintf(w, "  match controllers: %s\n", joinOrNone(r.matchControllers))
	if r.skipped > 0 {
		fmt.Fprintf(w, "  controllers not fully built (offline): %d\n", r.skipped)
	}
	if r.policy == "" {
		fmt.Fprintf(w, "  authorization policy: (empty: every request is allowed)\n")
	} else {
		fmt.Fprintf(w, "  authorization policy: %s\n", r.policy)
	}
	if r.policyBypass {
		fmt.Fprintf(w, "  authorization policy bypass: enabled (denied requests are allowed)\n")
	}
	fmt.Fprintf(w, "  client IP sources: %s\n", strings.Join(r.clientIPSources, ", "))
	if len(r.warnings) > 0 {
		fmt.Fprintf(w, "  warnings:\n")
		for _, warning := range r.warnings {
			fmt.Fprintf(w, "    - %s\n", warning)
		}
	}
}

func joinOrNone(items []string) string {
	if len(items) == 0 {
		return "(none)"
	}
	return strings.Join(items, ", ")
}
