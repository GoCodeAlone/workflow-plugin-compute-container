package container

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"
	"text/template"

	core "github.com/GoCodeAlone/workflow-plugin-compute-core/protocol"
)

// Docker29 may omit empty Config.Volumes. Evaluate the actual production
// template with Docker's strict missing-key behavior, not canned template output.
type optionalVolumesTemplateRunner struct{ config map[string]any }

func (r optionalVolumesTemplateRunner) CombinedOutput(_ context.Context, _ []byte, _ string, args ...string) ([]byte, []byte, error) {
	if len(args) == 3 && args[0] == "info" {
		return []byte(supportedDockerControls), nil, nil
	}
	if len(args) != 5 || args[0] != "image" || args[1] != "inspect" || args[2] != "--format" {
		return nil, nil, errors.New("unexpected preflight command")
	}
	render, err := template.New("actual-docker-format").Option("missingkey=error").Funcs(template.FuncMap{
		"json": func(value any) (string, error) { raw, err := json.Marshal(value); return string(raw), err },
	}).Parse(args[3])
	if err != nil {
		return nil, nil, err
	}
	var out bytes.Buffer
	err = render.Execute(&out, map[string]any{"Config": r.config})
	return out.Bytes(), nil, err
}

func TestNativeReadOnlyOptionalImageVolumes(t *testing.T) {
	for _, tc := range []struct {
		name      string
		config    map[string]any
		wantError bool
	}{
		{"omitted", map[string]any{}, false},
		{"null", map[string]any{"Volumes": nil}, false},
		{"empty", map[string]any{"Volumes": map[string]any{}}, false},
		{"declared", map[string]any{"Volumes": map[string]any{"/private": map[string]any{}}}, true},
		{"malformed", map[string]any{"Volumes": []any{}}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := SandboxRunRequest{Image: "fixed-cached-image", Workspace: t.TempDir(), Limits: core.ResourceLimits{WorkspaceBytes: 4096, MemoryBytes: 64 << 20, CPUPercent: 25}}
			runtime := DockerSandboxRuntime{ReadOnlyWorkspace: true, Runner: optionalVolumesTemplateRunner{config: tc.config}}
			err := runtime.ValidateReadOnlyPolicy(t.Context(), req)
			if (err != nil) != tc.wantError {
				t.Fatalf("preflight error=%v, wantError=%t", err, tc.wantError)
			}
		})
	}
}
