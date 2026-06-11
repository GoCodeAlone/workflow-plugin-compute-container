package container

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	core "github.com/GoCodeAlone/workflow-plugin-compute-core/protocol"
)

func TestRuntimeBackendProbeReportsUnsupportedWhenExecutableMissing(t *testing.T) {
	probe := RuntimeBackendProbe{
		Options: podmanProbeOptions([]core.RuntimeProfile{core.RuntimeProfileSandboxedOCI}),
		Runner:  &fakeRuntimeCommandRunner{lookPathErr: exec.ErrNotFound},
	}

	report := probe.Probe(context.Background())

	if report.Status != core.RuntimeBackendUnsupported {
		t.Fatalf("status = %q, want unsupported: %+v", report.Status, report)
	}
	if len(report.ExecutorProviders) != 0 || len(report.Executors) != 0 {
		t.Fatalf("unsupported probe advertised executors: %+v", report)
	}
	if strings.TrimSpace(report.Reason) == "" {
		t.Fatalf("unsupported probe omitted reason: %+v", report)
	}
	if err := report.Validate(); err != nil {
		t.Fatalf("unsupported report invalid: %v", err)
	}
}

func TestDockerCompatibleRuntimeProbeReportsDegradedWhenVersionFails(t *testing.T) {
	probe := RuntimeBackendProbe{
		Options: podmanProbeOptions([]core.RuntimeProfile{core.RuntimeProfileSandboxedOCI}),
		Runner: &fakeRuntimeCommandRunner{
			path: "/usr/bin/podman",
			results: map[string]fakeRuntimeCommandResult{
				"podman version --format {{.Client.Version}}": {err: errors.New("runtime unavailable at /home/example/podman.sock")},
			},
		},
	}

	report := probe.Probe(context.Background())

	if report.Status != core.RuntimeBackendDegraded {
		t.Fatalf("status = %q, want degraded: %+v", report.Status, report)
	}
	if len(report.ExecutorProviders) != 0 || len(report.Executors) != 0 {
		t.Fatalf("degraded version probe advertised executors: %+v", report)
	}
	if strings.Contains(report.Reason, "/home/example") || strings.Contains(report.Reason, "podman.sock") {
		t.Fatalf("reason leaked local runtime detail: %q", report.Reason)
	}
	if err := report.Validate(); err != nil {
		t.Fatalf("degraded report invalid: %v", err)
	}
}

func TestDockerCompatibleRuntimeProbeReportsDegradedWhenConformanceFails(t *testing.T) {
	probe := RuntimeBackendProbe{
		Options: podmanProbeOptions([]core.RuntimeProfile{core.RuntimeProfileSandboxedOCI}),
		Runner: &fakeRuntimeCommandRunner{
			path: "/usr/bin/podman",
			results: map[string]fakeRuntimeCommandResult{
				"podman version --format {{.Client.Version}}": {stdout: "5.0.0\n"},
				defaultRuntimeConformanceCommandKey("podman"): {
					err: errors.New("registry credential token rejected"),
				},
			},
		},
	}

	report := probe.Probe(context.Background())

	if report.Status != core.RuntimeBackendDegraded {
		t.Fatalf("status = %q, want degraded: %+v", report.Status, report)
	}
	if len(report.ExecutorProviders) != 0 || len(report.Executors) != 0 {
		t.Fatalf("degraded conformance probe advertised executors: %+v", report)
	}
	if strings.Contains(report.Reason, "token") || strings.Contains(report.Reason, "credential") {
		t.Fatalf("reason leaked secret-looking detail: %q", report.Reason)
	}
	if err := report.Validate(); err != nil {
		t.Fatalf("degraded report invalid: %v", err)
	}
}

func TestDockerCompatibleRuntimeProbeReportsSupportedProfiles(t *testing.T) {
	probe := RuntimeBackendProbe{
		Options: podmanProbeOptions([]core.RuntimeProfile{
			core.RuntimeProfileSandboxedOCI,
			core.RuntimeProfileContainerBuild,
		}),
		Runner: &fakeRuntimeCommandRunner{
			path: "/usr/bin/podman",
			results: map[string]fakeRuntimeCommandResult{
				"podman version --format {{.Client.Version}}": {stdout: "5.0.0\n"},
				defaultRuntimeConformanceCommandKey("podman"): {
					stdout: validRuntimeEvidenceJSON(),
				},
			},
		},
	}

	report := probe.Probe(context.Background())

	if report.Status != core.RuntimeBackendSupported {
		t.Fatalf("status = %q, want supported: %+v", report.Status, report)
	}
	if !slices.Equal(report.ExecutorProviders, []string{SandboxedCommandProviderName, SandboxedContainerBuildProviderName}) {
		t.Fatalf("executor providers = %+v", report.ExecutorProviders)
	}
	if len(report.Executors) != 2 {
		t.Fatalf("executors = %+v", report.Executors)
	}
	for _, executor := range report.Executors {
		if executor.ExecutionSecurityTier != core.ExecutionSandboxedContainer ||
			executor.ProofTier != core.ProofArtifactHash ||
			executor.ImageDigest == "" ||
			executor.RootFSDigest == "" {
			t.Fatalf("executor missing proof metadata: %+v", executor)
		}
	}
	if !report.Evidence.Workspace || !report.Evidence.Network || !report.Evidence.Env || !report.Evidence.Proof || !report.Evidence.Cleanup {
		t.Fatalf("supported report omitted conformance evidence: %+v", report.Evidence)
	}
	if err := report.Validate(); err != nil {
		t.Fatalf("supported report invalid: %v", err)
	}
}

func TestDockerCompatibleRuntimeProbeRequiresFullEvidencePayload(t *testing.T) {
	probe := RuntimeBackendProbe{
		Options: podmanProbeOptions([]core.RuntimeProfile{core.RuntimeProfileSandboxedOCI}),
		Runner: &fakeRuntimeCommandRunner{
			path: "/usr/bin/podman",
			results: map[string]fakeRuntimeCommandResult{
				"podman version --format {{.Client.Version}}": {stdout: "5.0.0\n"},
				defaultRuntimeConformanceCommandKey("podman"): {
					stdout: `{"workspace":true,"network":true,"env":true,"proof":true}`,
				},
			},
		},
	}

	report := probe.Probe(context.Background())

	if report.Status != core.RuntimeBackendDegraded {
		t.Fatalf("status = %q, want degraded for incomplete evidence: %+v", report.Status, report)
	}
	if len(report.ExecutorProviders) != 0 || len(report.Executors) != 0 {
		t.Fatalf("incomplete evidence advertised executors: %+v", report)
	}
}

func TestDockerCompatibleRuntimeProbeOnlyAdvertisesRequestedProfiles(t *testing.T) {
	probe := RuntimeBackendProbe{
		Options: podmanProbeOptions([]core.RuntimeProfile{core.RuntimeProfileSandboxedOCI}),
		Runner: &fakeRuntimeCommandRunner{
			path: "/usr/bin/podman",
			results: map[string]fakeRuntimeCommandResult{
				"podman version --format {{.Client.Version}}": {stdout: "5.0.0\n"},
				defaultRuntimeConformanceCommandKey("podman"): {
					stdout: validRuntimeEvidenceJSON(),
				},
			},
		},
	}

	report := probe.Probe(context.Background())

	if !slices.Equal(report.ExecutorProviders, []string{SandboxedCommandProviderName}) {
		t.Fatalf("executor providers = %+v", report.ExecutorProviders)
	}
	if len(report.Executors) != 1 || report.Executors[0].Provider != SandboxedCommandProviderName {
		t.Fatalf("executors = %+v", report.Executors)
	}
}

func TestManagedRuntimeBundleCatalogRejectsBlockedStaleOrUnsignedBundle(t *testing.T) {
	catalog := validManagedRuntimeBundleCatalog()
	catalog.BlockedVersions = []string{"v2.3.1"}
	if _, err := catalog.Bundle("managed-containerd-linux-amd64", time.Unix(1_700_000_000, 0).UTC()); err == nil || !strings.Contains(err.Error(), "blocked") {
		t.Fatalf("expected blocked bundle to fail, got %v", err)
	}

	catalog = validManagedRuntimeBundleCatalog()
	catalog.Bundles[0].ValidUntil = time.Unix(1_600_000_000, 0).UTC()
	if _, err := catalog.Bundle("managed-containerd-linux-amd64", time.Unix(1_700_000_000, 0).UTC()); err == nil || !strings.Contains(err.Error(), "valid_until") {
		t.Fatalf("expected stale bundle to fail, got %v", err)
	}

	catalog = validManagedRuntimeBundleCatalog()
	catalog.Bundles[0].SignatureDigest = ""
	if _, err := catalog.Bundle("managed-containerd-linux-amd64", time.Unix(1_700_000_000, 0).UTC()); err == nil || !strings.Contains(err.Error(), "signature") {
		t.Fatalf("expected unsigned bundle to fail, got %v", err)
	}
}

func TestManagedRuntimeBundleCatalogRequiresMatchingTarget(t *testing.T) {
	catalog := validManagedRuntimeBundleCatalog()

	if _, err := catalog.BundleForTarget("managed-containerd-linux-amd64", "windows", "amd64", time.Unix(1_700_000_000, 0).UTC()); err == nil || !strings.Contains(err.Error(), "does not support") {
		t.Fatalf("expected mismatched target to fail, got %v", err)
	}
	if _, err := catalog.BundleForTarget("managed-containerd-linux-amd64", "linux", "amd64", time.Unix(1_700_000_000, 0).UTC()); err != nil {
		t.Fatalf("expected linux/amd64 bundle lookup to pass: %v", err)
	}
}

func TestManagedContainerdRuntimeProbeRequiresBundleBeforeSupport(t *testing.T) {
	probe := ManagedContainerdRuntimeProbe(nil, RuntimeCommandRunner(nil), time.Unix(1_700_000_000, 0).UTC())

	report := probe.Probe(context.Background())

	if report.Status != core.RuntimeBackendUnsupported {
		t.Fatalf("status=%q want unsupported: %+v", report.Status, report)
	}
	if len(report.ExecutorProviders) != 0 || len(report.Executors) != 0 {
		t.Fatalf("missing managed bundle advertised executors: %+v", report)
	}
	if err := report.Validate(); err != nil {
		t.Fatalf("unsupported managed bundle report invalid: %v", err)
	}
}

func TestManagedContainerdRuntimeProbeAttachesBundleAndScopedNamespace(t *testing.T) {
	var calls []string
	bundle := validManagedRuntimeBundleDescriptor()
	installation, err := NewManagedContainerdRuntimeInstallation(bundle, filepath.Join(t.TempDir(), "managed-containerd-linux-amd64"))
	if err != nil {
		t.Fatalf("managed runtime installation: %v", err)
	}
	probe := ManagedContainerdRuntimeProbe(&installation, &fakeRuntimeCommandRunner{
		path:  installation.CommandPath,
		calls: &calls,
		results: map[string]fakeRuntimeCommandResult{
			installation.CommandPath + " version --format {{.Client.Version}}": {stdout: "1.7.7\n"},
			managedRuntimeConformanceCommandKey(installation.CommandPath): {
				stdout: validManagedRuntimeEvidenceJSON(),
			},
		},
	}, time.Unix(1_700_000_000, 0).UTC())

	report := probe.Probe(context.Background())

	if report.Status != core.RuntimeBackendSupported {
		t.Fatalf("status=%q want supported: %+v", report.Status, report)
	}
	if report.InstallBurden != core.RuntimeInstallBundled || report.Bundle == nil {
		t.Fatalf("supported managed report missing bundled descriptor: %+v", report)
	}
	if err := report.ValidateAt(time.Unix(1_700_000_000, 0).UTC()); err != nil {
		t.Fatalf("supported managed report invalid: %v", err)
	}
	for _, call := range calls {
		if strings.HasPrefix(call, installation.CommandPath+" --namespace ") {
			if !strings.Contains(call, "wfcompute-") || strings.Contains(call, "pool") || strings.Contains(call, "worker") {
				t.Fatalf("managed runtime scope is not opaque: %q", call)
			}
			return
		}
	}
	t.Fatalf("managed probe did not use scoped nerdctl args: %+v", calls)
}

func TestManagedContainerdRuntimeProbeRequiresScopedEvidence(t *testing.T) {
	bundle := validManagedRuntimeBundleDescriptor()
	installation, err := NewManagedContainerdRuntimeInstallation(bundle, filepath.Join(t.TempDir(), "managed-containerd-linux-amd64"))
	if err != nil {
		t.Fatalf("managed runtime installation: %v", err)
	}
	probe := ManagedContainerdRuntimeProbe(&installation, &fakeRuntimeCommandRunner{
		path: installation.CommandPath,
		results: map[string]fakeRuntimeCommandResult{
			installation.CommandPath + " version --format {{.Client.Version}}": {stdout: "1.7.7\n"},
			managedRuntimeConformanceCommandKey(installation.CommandPath): {
				stdout: validRuntimeEvidenceJSON(),
			},
		},
	}, time.Unix(1_700_000_000, 0).UTC())

	report := probe.Probe(context.Background())

	if report.Status != core.RuntimeBackendDegraded {
		t.Fatalf("status=%q want degraded without scoped evidence: %+v", report.Status, report)
	}
	if len(report.ExecutorProviders) != 0 || len(report.Executors) != 0 {
		t.Fatalf("managed runtime without scoped evidence advertised executors: %+v", report)
	}
}

func TestManagedContainerdRuntimeProbesRequireInstallRootAndCurrentTarget(t *testing.T) {
	catalog := validManagedRuntimeBundleCatalog()
	if probes := ManagedContainerdRuntimeProbes(catalog, "", &fakeRuntimeCommandRunner{}, time.Unix(1_700_000_000, 0).UTC()); len(probes) != 0 {
		t.Fatalf("managed probes without install root = %+v", probes)
	}
	installRoot := t.TempDir()
	probes := ManagedContainerdRuntimeProbes(catalog, installRoot, &fakeRuntimeCommandRunner{}, time.Unix(1_700_000_000, 0).UTC())
	if runtime.GOOS == "linux" && runtime.GOARCH == "amd64" {
		if len(probes) != 1 || probes[0].Options.BackendID != "managed-containerd-linux-amd64" {
			t.Fatalf("managed probes = %+v", probes)
		}
		if !filepath.IsAbs(probes[0].Options.Command) || !strings.HasPrefix(probes[0].Options.Command, installRoot) {
			t.Fatalf("managed probe command is not rooted in install root: %q", probes[0].Options.Command)
		}
		return
	}
	if len(probes) != 0 {
		t.Fatalf("unexpected managed probes for %s/%s: %+v", runtime.GOOS, runtime.GOARCH, probes)
	}
}

func TestRuntimeBackendProbeRunsConformanceWithWorkspaceEnvAndReadOnlyRoot(t *testing.T) {
	var calls []string
	probe := RuntimeBackendProbe{
		Options: podmanProbeOptions([]core.RuntimeProfile{core.RuntimeProfileSandboxedOCI}),
		Runner: &fakeRuntimeCommandRunner{
			path:  "/usr/bin/podman",
			calls: &calls,
			results: map[string]fakeRuntimeCommandResult{
				"podman version --format {{.Client.Version}}": {stdout: "5.0.0\n"},
				defaultRuntimeConformanceCommandKey("podman"): {
					stdout: validRuntimeEvidenceJSON(),
				},
			},
		},
	}

	report := probe.Probe(context.Background())

	if report.Status != core.RuntimeBackendSupported {
		t.Fatalf("probe status=%q: %+v", report.Status, report)
	}
	for _, call := range calls {
		if strings.HasPrefix(call, "podman run ") {
			for _, want := range []string{
				"--network none",
				"-v /tmp/wfcompute-runtime-probe-test:/workspace",
				"-w /workspace",
				"-e WFCOMPUTE_RUNTIME_PROBE=1",
				"--read-only",
			} {
				if !strings.Contains(call, want) {
					t.Fatalf("conformance command missing %q in %q", want, call)
				}
			}
			return
		}
	}
	t.Fatalf("missing conformance run call: %+v", calls)
}

func TestRuntimeBackendConformanceWorkspaceNormalizesConfiguredPath(t *testing.T) {
	t.Chdir(t.TempDir())

	workspace, cleanup, err := runtimeBackendConformanceWorkspace(RuntimeBackendProbeOptions{
		ConformanceWorkspace: "relative-probe-workspace",
	})
	t.Cleanup(cleanup)
	if err != nil {
		t.Fatalf("conformance workspace: %v", err)
	}
	if !filepath.IsAbs(workspace) {
		t.Fatalf("workspace path is not absolute: %q", workspace)
	}
	info, err := os.Stat(workspace)
	if err != nil {
		t.Fatalf("workspace was not created: %v", err)
	}
	if !info.IsDir() {
		t.Fatalf("workspace is not a directory: %s", workspace)
	}
	if got := info.Mode().Perm(); got&0o003 != 0o003 {
		t.Fatalf("workspace must be writable/traversable by nonroot probe containers, mode=%o", got)
	}
}

func TestRuntimeBackendConformanceWorkspaceRestoresConfiguredPathMode(t *testing.T) {
	workspace := filepath.Join(t.TempDir(), "configured")
	if err := os.Mkdir(workspace, 0o750); err != nil {
		t.Fatalf("mkdir workspace: %v", err)
	}

	_, cleanup, err := runtimeBackendConformanceWorkspace(RuntimeBackendProbeOptions{ConformanceWorkspace: workspace})
	if err != nil {
		t.Fatalf("conformance workspace: %v", err)
	}
	info, err := os.Stat(workspace)
	if err != nil {
		t.Fatalf("workspace stat during probe: %v", err)
	}
	if got := info.Mode().Perm(); got&0o003 != 0o003 {
		t.Fatalf("configured workspace must be writable/traversable during probe, mode=%o", got)
	}
	cleanup()
	info, err = os.Stat(workspace)
	if err != nil {
		t.Fatalf("workspace stat after cleanup: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o750 {
		t.Fatalf("configured workspace mode after cleanup: got %o want 750", got)
	}
}

func TestRuntimeBackendConformanceWorkspaceRejectsFilePath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "workspace-file")
	if err := os.WriteFile(path, []byte("not a dir"), 0o600); err != nil {
		t.Fatalf("write workspace file: %v", err)
	}

	_, _, err := runtimeBackendConformanceWorkspace(RuntimeBackendProbeOptions{ConformanceWorkspace: path})

	if err == nil || !strings.Contains(err.Error(), "not a directory") {
		t.Fatalf("workspace file err = %v", err)
	}
}

func TestRuntimeBackendConformanceWorkspaceTempDirAllowsNonrootContainerWrite(t *testing.T) {
	workspace, cleanup, err := runtimeBackendConformanceWorkspace(RuntimeBackendProbeOptions{})
	t.Cleanup(cleanup)
	if err != nil {
		t.Fatalf("conformance workspace: %v", err)
	}
	info, err := os.Stat(workspace)
	if err != nil {
		t.Fatalf("workspace stat: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o703 {
		t.Fatalf("temp workspace mode: got %o want 703", got)
	}
}

func TestDockerCompatibleRuntimeProbeRealBackends(t *testing.T) {
	if os.Getenv("WORKFLOW_COMPUTE_RUNTIME_PROBE_REAL") != "1" {
		t.Skip("set WORKFLOW_COMPUTE_RUNTIME_PROBE_REAL=1 to run installed runtime probes")
	}
	reports := make([]core.RuntimeBackendReport, 0, 3)
	for _, probe := range DockerCompatibleRuntimeProbes(ExecRuntimeCommandRunner{}, time.Now().UTC()) {
		report := probe.Probe(context.Background())
		if err := report.Validate(); err != nil {
			t.Fatalf("%s report invalid: %v\n%+v", probe.Options.BackendID, err, report)
		}
		if report.Status == core.RuntimeBackendSupported && len(report.ExecutorProviders) == 0 {
			t.Fatalf("%s supported report omitted executor providers: %+v", probe.Options.BackendID, report)
		}
		reports = append(reports, report)
	}
	data, err := json.MarshalIndent(reports, "", "  ")
	if err != nil {
		t.Fatalf("marshal reports: %v", err)
	}
	t.Logf("runtime backend reports:\n%s", data)
}

func podmanProbeOptions(profiles []core.RuntimeProfile) RuntimeBackendProbeOptions {
	return RuntimeBackendProbeOptions{
		BackendID:            "podman-rootless",
		Family:               core.RuntimeBackendFamilyPodman,
		Tool:                 core.ContainerRuntimePodman,
		Command:              "podman",
		VersionArgs:          []string{"version", "--format", "{{.Client.Version}}"},
		ConformanceImage:     defaultConformanceImageRef,
		ConformanceCommand:   []string{defaultConformanceCommand},
		ConformanceWorkspace: "/tmp/wfcompute-runtime-probe-test",
		IsolationMode:        core.RuntimeIsolationUserNamespace,
		InstallBurden:        core.RuntimeInstallSystemInstalled,
		RuntimeProfiles:      profiles,
		ConformanceProfiles:  []string{"distroless-static-v1"},
		GeneratedAt:          time.Unix(1_700_000_000, 0).UTC(),
	}
}

func defaultRuntimeConformanceCommandKey(tool string) string {
	return tool + " run --rm --network none -v /tmp/wfcompute-runtime-probe-test:/workspace -w /workspace -e WFCOMPUTE_RUNTIME_PROBE=1 --read-only " + defaultConformanceImageRef + " " + defaultConformanceCommand
}

func validRuntimeEvidenceJSON() string {
	return `{"workspace":true,"network":true,"env":true,"proof":true,"cleanup":true}`
}

func validManagedRuntimeEvidenceJSON() string {
	return `{"workspace":true,"network":true,"env":true,"proof":true,"cleanup":true,"details":["runtime-scope:wfcompute-06d10e1aef1733a0"]}`
}

func validManagedRuntimeBundleCatalog() ManagedRuntimeBundleCatalog {
	return ManagedRuntimeBundleCatalog{
		ReleaseTag:       "v2.3.1",
		SourceBaseURL:    "https://github.com/containerd/nerdctl/releases/download/v2.3.1",
		GeneratedAt:      time.Unix(1_700_000_000, 0).UTC(),
		MinimumVersion:   "v2.3.1",
		StableSigningKey: "containerd-nerdctl-release",
		Bundles:          []core.ManagedRuntimeBundleDescriptor{validManagedRuntimeBundleDescriptor()},
	}
}

func validManagedRuntimeBundleDescriptor() core.ManagedRuntimeBundleDescriptor {
	return core.ManagedRuntimeBundleDescriptor{
		ProtocolVersion: core.Version,
		BundleID:        "managed-containerd-linux-amd64",
		Family:          core.RuntimeBackendFamilyContainerd,
		Tool:            core.ContainerRuntimeNerdctl,
		Version:         "v2.3.1",
		OS:              "linux",
		Arch:            "amd64",
		ArtifactName:    "nerdctl-full-2.3.1-linux-amd64.tar.gz",
		ArtifactDigest:  "sha256:7a0d8efcf55b10b57d831541266adb9c6ec3d55b44ec041c95f6eb994d1faab9",
		ChecksumName:    "SHA256SUMS",
		ChecksumDigest:  "sha256:8a0586ff11d4d5a5d19d59494a10af8c6d41dd95ca72ff347f62d5288bc5131a",
		SignatureName:   "SHA256SUMS.asc",
		SignatureDigest: "sha256:f87400e0923e22eab251328bd210bb9e8d3bba2b58dbbb84699622474344d68c",
		SignatureIssuer: "containerd/nerdctl release",
		SignatureKeyID:  "containerd-nerdctl-release",
		TrustRootDigest: "sha256:6fad18923304aba73378965a8bac49bf44a3a22da73df42ca6a081c726c36b34",
		SignatureSubject: core.ManagedRuntimeSignatureSubject{
			ArtifactDigest:          "sha256:7a0d8efcf55b10b57d831541266adb9c6ec3d55b44ec041c95f6eb994d1faab9",
			RuntimeFamily:           core.RuntimeBackendFamilyContainerd,
			OS:                      "linux",
			Arch:                    "amd64",
			Version:                 "v2.3.1",
			Channel:                 "stable",
			ConformanceProfile:      "distroless-static-v1",
			ScopedStorePolicyDigest: "sha256:311ab6244d878cf7280a5927f5af6063337ec262e35fd7c84c6579d07591337e",
		},
		ValidUntil: time.Date(2026, 12, 31, 0, 0, 0, 0, time.UTC),
		UpdatePolicy: core.ManagedRuntimeUpdatePolicy{
			Channel:             "stable",
			MinSupportedVersion: "v2.3.1",
		},
		CVEPolicy: core.ManagedRuntimeCVEPolicy{
			PolicyDigest:     "sha256:5bc9d3baf40fe716e68bfc469c53040351288caaaa048650aeadd6320ca6d7c1",
			UpdatedByVersion: "v2.3.1",
		},
		ScopedStore: core.ManagedRuntimeScopedStorePolicy{
			Required:                      true,
			NamespaceStrategy:             "opaque-worker-pool-scope",
			StoreStrategy:                 "workflow-owned-content-store",
			PolicyDigest:                  "sha256:311ab6244d878cf7280a5927f5af6063337ec262e35fd7c84c6579d07591337e",
			CleanupRequired:               true,
			HostGlobalVisibilityForbidden: true,
		},
		SupportedTargets: []core.ManagedRuntimeTarget{{
			OS:   "linux",
			Arch: "amd64",
		}},
		ConformanceProfile: "distroless-static-v1",
		InstallBurden:      core.RuntimeInstallBundled,
	}
}

func managedRuntimeConformanceCommandKey(command string) string {
	digest := digestForRuntimeClaim("managed-containerd-linux-amd64", "distroless-static-v1", "scope")
	return command + " --namespace wfcompute-" + digest[7:23] +
		" run --rm --network none -v /tmp/wfcompute-runtime-probe-test:/workspace -w /workspace -e WFCOMPUTE_RUNTIME_PROBE=1 --read-only " +
		defaultConformanceImageRef + " " + defaultConformanceCommand
}

func TestRuntimeProbeRedactsAuthFailures(t *testing.T) {
	report := RuntimeBackendProbe{
		Options: podmanProbeOptions([]core.RuntimeProfile{core.RuntimeProfileSandboxedOCI}),
		Runner: &fakeRuntimeCommandRunner{
			path: "/usr/bin/podman",
			results: map[string]fakeRuntimeCommandResult{
				"podman version --format {{.Client.Version}}": {err: errors.New("authentication required")},
			},
		},
	}.Probe(context.Background())

	if strings.Contains(strings.ToLower(report.Reason), "auth") {
		t.Fatalf("auth detail not redacted: %q", report.Reason)
	}
	if err := report.Validate(); err != nil {
		t.Fatalf("redacted auth failure report invalid: %v", err)
	}
}

type fakeRuntimeCommandRunner struct {
	path        string
	lookPathErr error
	results     map[string]fakeRuntimeCommandResult
	calls       *[]string
}

type fakeRuntimeCommandResult struct {
	stdout string
	err    error
}

func (r *fakeRuntimeCommandRunner) LookPath(string) (string, error) {
	if r.lookPathErr != nil {
		return "", r.lookPathErr
	}
	return r.path, nil
}

func (r *fakeRuntimeCommandRunner) Run(_ context.Context, name string, args ...string) (RuntimeCommandResult, error) {
	key := strings.Join(append([]string{name}, args...), " ")
	if r.calls != nil {
		*r.calls = append(*r.calls, key)
	}
	result, ok := r.results[key]
	if !ok {
		return RuntimeCommandResult{}, errors.New("unexpected command: " + key)
	}
	return RuntimeCommandResult{Stdout: []byte(result.stdout)}, result.err
}
