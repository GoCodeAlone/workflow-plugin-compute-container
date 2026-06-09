package container

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
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
