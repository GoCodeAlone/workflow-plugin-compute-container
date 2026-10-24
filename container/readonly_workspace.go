package container

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"
)

// ValidateReadOnlyPolicy is shared by native command and service consumers. It
// does not provision quotas or change engine settings. Unsupported evidence fails.
func (r DockerSandboxRuntime) ValidateReadOnlyPolicy(ctx context.Context, req SandboxRunRequest) error {
	if !r.ReadOnlyWorkspace && !req.ReadOnlyWorkspace {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := validateReadOnlyWorkspaceContext(ctx, req); err != nil {
		return err
	}
	tool := firstNonEmpty(r.Tool, "docker")
	if filepath.Base(tool) != "docker" {
		return errors.New("read-only resource control evidence unsupported for runtime")
	}
	scope, err := validateRuntimeScope(tool, req.RuntimeScope)
	if err != nil {
		return err
	}
	run := func(args ...string) ([]byte, error) {
		out, stderr, err := r.commandRunner().CombinedOutput(ctx, nil, tool, appendRuntimeScopeArgs(scope, args...)...)
		out, _, err = boundRunnerOutput(out, stderr, err, 0)
		return out, controlProcessError(err, "runtime preflight output capture failed")
	}
	out, err := run("info", "--format", "{{json .}}")
	if err != nil {
		return fmt.Errorf("read-only runtime controls unavailable: %w", err)
	}
	var info struct {
		OSType       string
		MemoryLimit  bool
		SwapLimit    bool
		CPUCfsQuota  bool
		CPUCfsPeriod bool
		PidsLimit    bool
	}
	if json.Unmarshal(out, &info) != nil || info.OSType != "linux" || !info.MemoryLimit || !info.SwapLimit || !info.CPUCfsQuota || !info.CPUCfsPeriod || !info.PidsLimit {
		return errors.New("required runtime memory/swap/CPU/PID controls unavailable")
	}
	out, err = run("image", "inspect", "--format", `{{json (index .Config "Volumes")}}`, req.Image)
	if err != nil {
		return fmt.Errorf("read-only local image inspection failed: %w", err)
	}
	var volumes map[string]json.RawMessage
	if json.Unmarshal(out, &volumes) != nil || len(volumes) > 0 {
		return errors.New("read-only image has unsupported writable volumes")
	}
	return nil
}

func validateReadOnlyWorkspace(req SandboxRunRequest) error {
	return validateReadOnlyWorkspaceContext(context.Background(), req)
}

func validateReadOnlyWorkspaceContext(ctx context.Context, req SandboxRunRequest) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if strings.TrimSpace(req.Image) == "" || strings.HasPrefix(req.Image, "-") {
		return errors.New("read-only local image required")
	}
	if req.Limits.WorkspaceBytes <= 0 || req.Limits.MemoryBytes <= 0 || req.Limits.CPUPercent <= 0 {
		return errors.New("read-only workspace requires positive workspace, memory and CPU limits")
	}
	if req.WritableRootFS || req.RunAsRoot || len(req.ExtraTmpfs) > 0 || len(req.AddCapabilities) > 0 {
		return errors.New("read-only workspace rejects writable sandbox overrides")
	}
	for _, mount := range req.DataMounts {
		_, target, err := validateSandboxMount(mount)
		if err != nil {
			return err
		}
		target = path.Clean(filepath.ToSlash(target))
		if !mount.ReadOnly || target == "/" || target == "/workspace" || strings.HasPrefix(target, "/workspace/") {
			return errors.New("read-only workspace rejects writable or shadowing data mount")
		}
	}
	if strings.TrimSpace(req.Workspace) == "" {
		return errors.New("read-only workspace required")
	}
	if err := rejectSymlinkPathComponents(req.Workspace, req.Workspace); err != nil {
		return err
	}
	info, err := os.Lstat(req.Workspace)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return errors.New("read-only workspace must be a directory")
	}
	var total int64
	return filepath.WalkDir(req.Workspace, func(_ string, entry fs.DirEntry, walkErr error) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if walkErr != nil {
			return walkErr
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return errors.New("read-only workspace rejects symlinks")
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		if !info.Mode().IsRegular() {
			return errors.New("read-only workspace rejects special files")
		}
		if info.Size() > req.Limits.WorkspaceBytes-total {
			return errors.New("read-only initial workspace exceeds byte limit")
		}
		total += info.Size()
		return nil
	})
}
