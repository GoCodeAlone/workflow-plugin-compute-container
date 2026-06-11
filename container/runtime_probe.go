package container

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"time"

	core "github.com/GoCodeAlone/workflow-plugin-compute-core/protocol"
)

const (
	defaultConformanceProfile  = "distroless-static-v1"
	defaultConformanceCommand  = "/usr/local/bin/wfcompute-sandbox-probe"
	defaultConformanceImageRef = "gcr.io/distroless/static-debian13@sha256:3592aa8171c77482f62bbc4164e6a2d141c6122554ace66e5cc910cadb961ff0"
)

type RuntimeCommandResult struct {
	Stdout []byte
	Stderr []byte
}

type RuntimeCommandRunner interface {
	LookPath(name string) (string, error)
	Run(ctx context.Context, name string, args ...string) (RuntimeCommandResult, error)
}

type ExecRuntimeCommandRunner struct{}

func (ExecRuntimeCommandRunner) LookPath(name string) (string, error) {
	return exec.LookPath(name)
}

func (ExecRuntimeCommandRunner) Run(ctx context.Context, name string, args ...string) (RuntimeCommandResult, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	stdout, err := cmd.Output()
	result := RuntimeCommandResult{Stdout: stdout}
	if err != nil {
		if exitErr := (&exec.ExitError{}); errors.As(err, &exitErr) {
			result.Stderr = exitErr.Stderr
		}
		return result, err
	}
	return result, nil
}

type RuntimeBackendProbeOptions struct {
	BackendID            string
	Family               core.RuntimeBackendFamily
	Tool                 core.ContainerRuntimeTool
	Command              string
	VersionArgs          []string
	ConformanceImage     string
	ConformanceCommand   []string
	ConformanceWorkspace string
	RuntimeScopeArgs     []string
	IsolationMode        core.RuntimeIsolationMode
	InstallBurden        core.RuntimeInstallBurden
	RuntimeProfiles      []core.RuntimeProfile
	ConformanceProfiles  []string
	ManagedBundle        *core.ManagedRuntimeBundleDescriptor
	GeneratedAt          time.Time
}

type RuntimeBackendProbe struct {
	Options RuntimeBackendProbeOptions
	Runner  RuntimeCommandRunner
}

type ManagedRuntimeInstallation struct {
	Bundle      core.ManagedRuntimeBundleDescriptor
	Root        string
	CommandPath string
}

func NewManagedContainerdRuntimeInstallation(bundle core.ManagedRuntimeBundleDescriptor, root string) (ManagedRuntimeInstallation, error) {
	root = strings.TrimSpace(root)
	if root == "" {
		return ManagedRuntimeInstallation{}, errors.New("managed runtime root is required")
	}
	root, err := filepath.Abs(root)
	if err != nil {
		return ManagedRuntimeInstallation{}, err
	}
	return ManagedRuntimeInstallation{
		Bundle:      bundle,
		Root:        root,
		CommandPath: filepath.Join(root, "bin", "nerdctl"),
	}, nil
}

func DockerCompatibleRuntimeProbes(runner RuntimeCommandRunner, generatedAt time.Time) []RuntimeBackendProbe {
	if runner == nil {
		runner = ExecRuntimeCommandRunner{}
	}
	profiles := []core.RuntimeProfile{core.RuntimeProfileSandboxedOCI, core.RuntimeProfileContainerBuild}
	return []RuntimeBackendProbe{
		{
			Options: RuntimeBackendProbeOptions{
				BackendID:           "podman-rootless",
				Family:              core.RuntimeBackendFamilyPodman,
				Tool:                core.ContainerRuntimePodman,
				Command:             "podman",
				VersionArgs:         []string{"version", "--format", "{{.Client.Version}}"},
				ConformanceImage:    defaultRuntimeConformanceImage(),
				ConformanceCommand:  []string{defaultConformanceCommand},
				IsolationMode:       core.RuntimeIsolationUserNamespace,
				InstallBurden:       core.RuntimeInstallSystemInstalled,
				RuntimeProfiles:     profiles,
				ConformanceProfiles: []string{defaultConformanceProfile},
				GeneratedAt:         generatedAt,
			},
			Runner: runner,
		},
		{
			Options: RuntimeBackendProbeOptions{
				BackendID:           "docker-desktop",
				Family:              core.RuntimeBackendFamilyDocker,
				Tool:                core.ContainerRuntimeDocker,
				Command:             "docker",
				VersionArgs:         []string{"version", "--format", "{{.Client.Version}}"},
				ConformanceImage:    defaultRuntimeConformanceImage(),
				ConformanceCommand:  []string{defaultConformanceCommand},
				IsolationMode:       core.RuntimeIsolationVMBackedContainer,
				InstallBurden:       core.RuntimeInstallDesktopManaged,
				RuntimeProfiles:     profiles,
				ConformanceProfiles: []string{defaultConformanceProfile},
				GeneratedAt:         generatedAt,
			},
			Runner: runner,
		},
		{
			Options: RuntimeBackendProbeOptions{
				BackendID:           "nerdctl-containerd",
				Family:              core.RuntimeBackendFamilyNerdctl,
				Tool:                core.ContainerRuntimeNerdctl,
				Command:             "nerdctl",
				VersionArgs:         []string{"version", "--format", "{{.Client.Version}}"},
				ConformanceImage:    defaultRuntimeConformanceImage(),
				ConformanceCommand:  []string{defaultConformanceCommand},
				IsolationMode:       core.RuntimeIsolationSharedKernelContainer,
				InstallBurden:       core.RuntimeInstallSystemInstalled,
				RuntimeProfiles:     profiles,
				ConformanceProfiles: []string{defaultConformanceProfile},
				GeneratedAt:         generatedAt,
			},
			Runner: runner,
		},
	}
}

func ManagedContainerdRuntimeProbe(installation *ManagedRuntimeInstallation, runner RuntimeCommandRunner, generatedAt time.Time) RuntimeBackendProbe {
	if runner == nil {
		runner = ExecRuntimeCommandRunner{}
	}
	profiles := []core.RuntimeProfile{core.RuntimeProfileSandboxedOCI, core.RuntimeProfileContainerBuild}
	backendID := "managed-containerd"
	command := ""
	var bundle *core.ManagedRuntimeBundleDescriptor
	if installation != nil {
		bundle = &installation.Bundle
		command = installation.CommandPath
	}
	if bundle != nil && bundle.BundleID != "" {
		backendID = bundle.BundleID
	}
	profile := defaultConformanceProfile
	if bundle != nil && bundle.ConformanceProfile != "" {
		profile = bundle.ConformanceProfile
	}
	return RuntimeBackendProbe{
		Options: RuntimeBackendProbeOptions{
			BackendID:           backendID,
			Family:              core.RuntimeBackendFamilyContainerd,
			Tool:                core.ContainerRuntimeNerdctl,
			Command:             command,
			VersionArgs:         []string{"version", "--format", "{{.Client.Version}}"},
			ConformanceImage:    defaultRuntimeConformanceImage(),
			ConformanceCommand:  []string{defaultConformanceCommand},
			RuntimeScopeArgs:    ManagedRuntimeScopeArgs(backendID, profile),
			IsolationMode:       core.RuntimeIsolationUserNamespace,
			InstallBurden:       core.RuntimeInstallBundled,
			RuntimeProfiles:     profiles,
			ConformanceProfiles: []string{profile},
			ManagedBundle:       bundle,
			GeneratedAt:         generatedAt,
		},
		Runner: runner,
	}
}

func ManagedContainerdRuntimeProbes(catalog ManagedRuntimeBundleCatalog, installRoot string, runner RuntimeCommandRunner, generatedAt time.Time) []RuntimeBackendProbe {
	if strings.TrimSpace(installRoot) == "" {
		return nil
	}
	if generatedAt.IsZero() {
		generatedAt = time.Now().UTC()
	}
	probes := make([]RuntimeBackendProbe, 0, len(catalog.Bundles))
	for _, candidate := range catalog.Bundles {
		bundle, err := catalog.BundleForTarget(candidate.BundleID, runtime.GOOS, runtime.GOARCH, generatedAt)
		if err != nil {
			continue
		}
		installation, err := NewManagedContainerdRuntimeInstallation(bundle, filepath.Join(installRoot, bundle.BundleID))
		if err != nil {
			continue
		}
		probes = append(probes, ManagedContainerdRuntimeProbe(&installation, runner, generatedAt))
	}
	return probes
}

func ManagedRuntimeScopeArgs(parts ...string) []string {
	return []string{"--namespace", ManagedRuntimeScopeName(parts...)}
}

func ManagedRuntimeScopeName(parts ...string) string {
	digest := digestForRuntimeClaim(append(parts, "scope")...)
	return "wfcompute-" + digest[7:23]
}

func (p RuntimeBackendProbe) Probe(ctx context.Context) core.RuntimeBackendReport {
	opts := p.Options.withDefaults()
	runner := p.Runner
	if runner == nil {
		runner = ExecRuntimeCommandRunner{}
	}
	report := core.RuntimeBackendReport{
		ProtocolVersion:     core.Version,
		BackendID:           opts.BackendID,
		Family:              opts.Family,
		Tool:                opts.Tool,
		OS:                  runtime.GOOS,
		Arch:                runtime.GOARCH,
		Status:              core.RuntimeBackendUnsupported,
		IsolationMode:       opts.IsolationMode,
		InstallBurden:       opts.InstallBurden,
		RuntimeProfiles:     slices.Clone(opts.RuntimeProfiles),
		ConformanceProfiles: slices.Clone(opts.ConformanceProfiles),
		GeneratedAt:         opts.GeneratedAt,
	}
	if opts.InstallBurden == core.RuntimeInstallBundled {
		if opts.ManagedBundle == nil {
			report.Reason = "managed runtime bundle is unavailable"
			return report
		}
		if !filepath.IsAbs(opts.Command) {
			report.Reason = "managed runtime executable is unavailable"
			return report
		}
		if err := opts.ManagedBundle.ValidateAt(opts.GeneratedAt); err != nil {
			report.Status = core.RuntimeBackendDegraded
			report.Reason = redactRuntimeProbeDetail(fmt.Sprintf("managed runtime bundle validation failed: %v", err))
			return report
		}
		report.Bundle = opts.ManagedBundle
		report.Version = opts.ManagedBundle.Version
		if opts.ManagedBundle.Family != "" {
			report.Family = opts.ManagedBundle.Family
		}
		if opts.ManagedBundle.Tool != "" {
			report.Tool = opts.ManagedBundle.Tool
		}
		if opts.ManagedBundle.OS != "" {
			report.OS = opts.ManagedBundle.OS
		}
		if opts.ManagedBundle.Arch != "" {
			report.Arch = opts.ManagedBundle.Arch
		}
	}
	if _, err := runner.LookPath(opts.Command); err != nil {
		report.Reason = "runtime executable is unavailable"
		return report
	}
	versionResult, err := runner.Run(ctx, opts.Command, opts.VersionArgs...)
	if err != nil {
		report.Status = core.RuntimeBackendDegraded
		report.Reason = redactRuntimeProbeDetail(fmt.Sprintf("runtime version probe failed: %v", err))
		return report
	}
	if report.Version == "" {
		report.Version = sanitizeRuntimeVersion(string(versionResult.Stdout))
	}
	workspace, cleanup, err := runtimeBackendConformanceWorkspace(opts)
	if err != nil {
		report.Status = core.RuntimeBackendDegraded
		report.Reason = redactRuntimeProbeDetail(fmt.Sprintf("runtime conformance workspace failed: %v", err))
		return report
	}
	defer cleanup()
	conformanceArgs := append([]string(nil), opts.RuntimeScopeArgs...)
	conformanceArgs = append(conformanceArgs,
		"run",
		"--rm",
		"--network", SandboxNetworkNone,
		"-v", workspace+":/workspace",
		"-w", "/workspace",
		"-e", "WFCOMPUTE_RUNTIME_PROBE=1",
		"--read-only",
		opts.ConformanceImage,
	)
	conformanceArgs = append(conformanceArgs, opts.ConformanceCommand...)
	conformanceResult, err := runner.Run(ctx, opts.Command, conformanceArgs...)
	if err != nil {
		report.Status = core.RuntimeBackendDegraded
		report.Reason = redactRuntimeProbeDetail(fmt.Sprintf("runtime conformance probe failed: %v", err))
		return report
	}
	evidence, err := runtimeBackendConformanceEvidence(conformanceResult.Stdout, report)
	if err != nil {
		report.Status = core.RuntimeBackendDegraded
		report.Reason = redactRuntimeProbeDetail(fmt.Sprintf("runtime conformance evidence incomplete: %v", err))
		return report
	}
	report.Status = core.RuntimeBackendSupported
	report.ExecutorProviders, report.Executors = executorClaimsForRuntimeProfiles(opts.RuntimeProfiles, report.Version)
	report.Evidence = evidence
	return report
}

func (opts RuntimeBackendProbeOptions) withDefaults() RuntimeBackendProbeOptions {
	if opts.GeneratedAt.IsZero() {
		opts.GeneratedAt = time.Now().UTC()
	}
	if opts.VersionArgs == nil {
		opts.VersionArgs = []string{"version"}
	}
	if opts.ConformanceImage == "" {
		opts.ConformanceImage = defaultRuntimeConformanceImage()
	}
	if len(opts.ConformanceCommand) == 0 {
		opts.ConformanceCommand = []string{defaultConformanceCommand}
	}
	if len(opts.ConformanceProfiles) == 0 {
		opts.ConformanceProfiles = []string{defaultConformanceProfile}
	}
	return opts
}

func runtimeBackendConformanceWorkspace(opts RuntimeBackendProbeOptions) (string, func(), error) {
	if configured := strings.TrimSpace(opts.ConformanceWorkspace); configured != "" {
		workspace, err := filepath.Abs(configured)
		if err != nil {
			return "", func() {}, err
		}
		if err := os.MkdirAll(workspace, 0o700); err != nil {
			return "", func() {}, err
		}
		info, err := os.Stat(workspace)
		if err != nil {
			return "", func() {}, err
		}
		if !info.IsDir() {
			return "", func() {}, fmt.Errorf("runtime conformance workspace %q is not a directory", workspace)
		}
		originalMode := info.Mode()
		if err := os.Chmod(workspace, originalMode|0o003); err != nil {
			return "", func() {}, err
		}
		return workspace, func() { _ = os.Chmod(workspace, originalMode) }, nil
	}
	dir, err := os.MkdirTemp("", "wfcompute-runtime-probe-*")
	if err != nil {
		return "", func() {}, err
	}
	if err := os.Chmod(dir, 0o703); err != nil {
		_ = os.RemoveAll(dir)
		return "", func() {}, err
	}
	return dir, func() { _ = os.RemoveAll(dir) }, nil
}

func executorClaimsForRuntimeProfiles(profiles []core.RuntimeProfile, version string) ([]string, []core.ExecutorRef) {
	var providers []string
	var executors []core.ExecutorRef
	for _, profile := range profiles {
		switch profile {
		case core.RuntimeProfileSandboxedOCI:
			providers = append(providers, SandboxedCommandProviderName)
			executors = append(executors, runtimeExecutorRef(SandboxedCommandProviderName, version, "command"))
		case core.RuntimeProfileContainerBuild:
			providers = append(providers, SandboxedContainerBuildProviderName)
			executors = append(executors, runtimeExecutorRef(SandboxedContainerBuildProviderName, version, "container-build"))
		}
	}
	return providers, executors
}

func runtimeExecutorRef(provider, version, salt string) core.ExecutorRef {
	return core.ExecutorRef{
		Provider:              provider,
		Version:               firstNonEmpty(version, "unknown"),
		ExecutionSecurityTier: core.ExecutionSandboxedContainer,
		ProofTier:             core.ProofArtifactHash,
		ImageDigest:           digestForRuntimeClaim(provider, version, salt, "image"),
		RootFSDigest:          digestForRuntimeClaim(provider, version, salt, "rootfs"),
	}
}

func runtimeBackendEvidenceDigest(report core.RuntimeBackendReport) string {
	data, err := json.Marshal(struct {
		BackendID           string                    `json:"backend_id"`
		Family              core.RuntimeBackendFamily `json:"family"`
		Tool                core.ContainerRuntimeTool `json:"tool"`
		Version             string                    `json:"version"`
		RuntimeProfiles     []core.RuntimeProfile     `json:"runtime_profiles"`
		ConformanceProfiles []string                  `json:"conformance_profiles"`
	}{
		BackendID:           report.BackendID,
		Family:              report.Family,
		Tool:                report.Tool,
		Version:             report.Version,
		RuntimeProfiles:     report.RuntimeProfiles,
		ConformanceProfiles: report.ConformanceProfiles,
	})
	if err != nil {
		return digestForRuntimeClaim(report.BackendID, report.Version, "evidence", "fallback")
	}
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func runtimeBackendConformanceEvidence(stdout []byte, report core.RuntimeBackendReport) (core.RuntimeBackendEvidence, error) {
	var evidence core.RuntimeBackendEvidence
	if err := json.Unmarshal(bytes.TrimSpace(stdout), &evidence); err != nil {
		return core.RuntimeBackendEvidence{}, fmt.Errorf("decode evidence JSON: %w", err)
	}
	var missing []string
	if !evidence.Workspace {
		missing = append(missing, "workspace")
	}
	if !evidence.Network {
		missing = append(missing, "network")
	}
	if !evidence.Env {
		missing = append(missing, "env")
	}
	if !evidence.Proof {
		missing = append(missing, "proof")
	}
	if !evidence.Cleanup {
		missing = append(missing, "cleanup")
	}
	if len(missing) != 0 {
		return core.RuntimeBackendEvidence{}, fmt.Errorf("missing %s", strings.Join(missing, ","))
	}
	if evidence.Digest == "" {
		evidence.Digest = runtimeBackendEvidenceDigest(report)
	}
	if len(evidence.Details) == 0 {
		evidence.Details = []string{firstNonEmpty(report.ConformanceProfiles...)}
	}
	if report.InstallBurden == core.RuntimeInstallBundled && report.Bundle != nil {
		expectedScope := "runtime-scope:" + ManagedRuntimeScopeName(report.BackendID, firstNonEmpty(report.ConformanceProfiles...))
		if !slices.Contains(evidence.Details, expectedScope) {
			return core.RuntimeBackendEvidence{}, fmt.Errorf("missing managed runtime scope evidence")
		}
	}
	return evidence, nil
}

func digestForRuntimeClaim(parts ...string) string {
	sum := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func sanitizeRuntimeVersion(value string) string {
	value = strings.TrimSpace(value)
	value = strings.ReplaceAll(value, "\x00", "")
	if value == "" {
		return "unknown"
	}
	fields := strings.Fields(value)
	if len(fields) == 0 {
		return "unknown"
	}
	return fields[0]
}

func redactRuntimeProbeDetail(value string) string {
	lower := strings.ToLower(value)
	for _, marker := range []string{
		"/users/",
		"/home/",
		"\\users\\",
		".sock",
		"token",
		"cookie",
		"secret",
		"password",
		"credential",
		"auth",
		"authentication",
		"unauthorized",
		"authorization",
		"bearer",
	} {
		if strings.Contains(lower, marker) {
			return "runtime probe failed; details redacted"
		}
	}
	value = strings.TrimSpace(strings.ReplaceAll(value, "\x00", ""))
	value = strings.ReplaceAll(value, "\n", " ")
	value = strings.ReplaceAll(value, "\r", " ")
	if value == "" {
		return "runtime probe failed"
	}
	return value
}

func defaultRuntimeConformanceImage() string {
	return defaultConformanceImageRef
}
