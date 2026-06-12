package internal

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/GoCodeAlone/workflow-plugin-compute-container/container"
)

func RunManagedRuntimeCLI(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if stdout == nil {
		stdout = io.Discard
	}
	if stderr == nil {
		stderr = io.Discard
	}
	if len(args) == 0 || args[0] != "managed-runtime" {
		_, _ = fmt.Fprintln(stderr, "usage: managed-runtime <install|doctor|uninstall|reinstall> [flags]")
		return 2
	}
	if len(args) < 2 {
		_, _ = fmt.Fprintln(stderr, "managed-runtime subcommand is required")
		return 2
	}
	command := args[1]
	cfg, ok := parseManagedRuntimeCLIFlags(command, args[2:], stderr)
	if !ok {
		return 2
	}
	installer, err := cfg.installer()
	if err != nil {
		_, _ = fmt.Fprintln(stderr, err)
		return 1
	}
	var result any
	switch command {
	case "install":
		result, err = installer.Install(ctx, cfg.installRequest())
	case "doctor":
		result, err = installer.Doctor(ctx, cfg.doctorRequest())
	case "uninstall":
		result, err = installer.Uninstall(ctx, container.ManagedRuntimeUninstallRequest{BundleID: cfg.BundleID})
	case "reinstall":
		result, err = installer.Reinstall(ctx, cfg.installRequest())
	default:
		_, _ = fmt.Fprintf(stderr, "unknown managed-runtime subcommand %q\n", command)
		return 2
	}
	if err != nil {
		_, _ = fmt.Fprintln(stderr, err)
		return 1
	}
	if err := json.NewEncoder(stdout).Encode(result); err != nil {
		_, _ = fmt.Fprintln(stderr, err)
		return 1
	}
	return 0
}

type managedRuntimeCLIConfig struct {
	CatalogPath string
	InstallRoot string
	BundleID    string
	TargetOS    string
	TargetArch  string
}

func parseManagedRuntimeCLIFlags(command string, args []string, stderr io.Writer) (managedRuntimeCLIConfig, bool) {
	fs := flag.NewFlagSet("managed-runtime "+command, flag.ContinueOnError)
	fs.SetOutput(stderr)
	cfg := managedRuntimeCLIConfig{}
	fs.StringVar(&cfg.CatalogPath, "catalog", "", "managed runtime bundle catalog path")
	fs.StringVar(&cfg.InstallRoot, "install-root", "", "agent-managed install root")
	fs.StringVar(&cfg.BundleID, "bundle-id", "", "managed runtime bundle id")
	fs.StringVar(&cfg.TargetOS, "target-os", "", "target operating system")
	fs.StringVar(&cfg.TargetArch, "target-arch", "", "target architecture")
	if err := fs.Parse(args); err != nil {
		return managedRuntimeCLIConfig{}, false
	}
	if cfg.CatalogPath == "" || cfg.InstallRoot == "" || cfg.BundleID == "" {
		_, _ = fmt.Fprintln(stderr, "--catalog, --install-root, and --bundle-id are required")
		return managedRuntimeCLIConfig{}, false
	}
	if command != "uninstall" && (cfg.TargetOS == "" || cfg.TargetArch == "") {
		_, _ = fmt.Fprintln(stderr, "--target-os and --target-arch are required")
		return managedRuntimeCLIConfig{}, false
	}
	return cfg, true
}

func (c managedRuntimeCLIConfig) installer() (container.ManagedRuntimeBundleInstaller, error) {
	content, err := os.ReadFile(c.CatalogPath)
	if err != nil {
		return container.ManagedRuntimeBundleInstaller{}, fmt.Errorf("read managed runtime catalog: %w", err)
	}
	var catalog container.ManagedRuntimeBundleCatalog
	if err := json.Unmarshal(content, &catalog); err != nil {
		return container.ManagedRuntimeBundleInstaller{}, fmt.Errorf("decode managed runtime catalog: %w", err)
	}
	return container.ManagedRuntimeBundleInstaller{
		Catalog:     catalog,
		InstallRoot: c.InstallRoot,
	}, nil
}

func (c managedRuntimeCLIConfig) installRequest() container.ManagedRuntimeInstallRequest {
	return container.ManagedRuntimeInstallRequest{
		BundleID:   c.BundleID,
		TargetOS:   c.TargetOS,
		TargetArch: c.TargetArch,
	}
}

func (c managedRuntimeCLIConfig) doctorRequest() container.ManagedRuntimeDoctorRequest {
	return container.ManagedRuntimeDoctorRequest{
		BundleID:   c.BundleID,
		TargetOS:   c.TargetOS,
		TargetArch: c.TargetArch,
	}
}
