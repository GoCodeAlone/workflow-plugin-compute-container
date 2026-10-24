package container

import (
	"strings"
	"testing"

	core "github.com/GoCodeAlone/workflow-plugin-compute-core/protocol"
)

func TestNativeReadOnlyRefusesMissingSwapControlBeforeCreation(t *testing.T) {
	for _, field := range []string{"", `"SwapLimit":false,`} {
		runner := &policyFixtureRunner{info: strings.Replace(supportedDockerControls, `"SwapLimit":true,`, field, 1), volumes: "null"}
		_, err := (DockerSandboxRuntime{ReadOnlyWorkspace: true, Runner: runner}).Run(t.Context(), SandboxRunRequest{Image: "cached", Workspace: t.TempDir(), Limits: core.ResourceLimits{WorkspaceBytes: 4096, MemoryBytes: 64 << 20, CPUPercent: 25}})
		if err == nil {
			t.Fatal("unsupported or missing swap limit evidence admitted creation")
		}
		for _, call := range runner.calls {
			if len(call) > 0 && call[0] == "run" {
				t.Fatal("unsupported swap control reached runtime execution")
			}
		}
	}
}

func TestNativeReadOnlyMemoryBoundsIncludeSwap(t *testing.T) {
	for _, readonly := range []bool{false, true} {
		spec, cleanup, err := (DockerSandboxRuntime{ReadOnlyWorkspace: readonly}).prepareRun(SandboxRunRequest{Image: "cached", Workspace: t.TempDir(), Limits: core.ResourceLimits{WorkspaceBytes: 4096, MemoryBytes: 64 << 20, CPUPercent: 25}})
		defer cleanup()
		if err != nil {
			t.Fatal(err)
		}
		got := dockerArgValue(spec.Args, "--memory-swap")
		if readonly && got != "67108864" {
			t.Fatal("fixed read-only exercise did not bound memory plus swap")
		}
		if !readonly && got != "" {
			t.Fatal("legacy writable command swap behavior changed")
		}
	}
}
