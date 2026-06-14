package container

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	core "github.com/GoCodeAlone/workflow-plugin-compute-core/protocol"
)

type DockerSandboxRuntime struct {
	Tool        string
	RuntimeName string
	Runner      DockerCommandRunner
}

type DockerCommandRunner interface {
	CombinedOutput(ctx context.Context, stdin []byte, name string, args ...string) ([]byte, []byte, error)
}

type ExecDockerCommandRunner struct{}

func (ExecDockerCommandRunner) CombinedOutput(ctx context.Context, stdin []byte, name string, args ...string) ([]byte, []byte, error) {
	return splitOutputContextWithStdin(ctx, stdin, name, args...)
}

type dockerRunSpec struct {
	Tool        string
	RuntimeArgs []string
	Args        []string
	EnvFile     string
}

func (r DockerSandboxRuntime) Available(ctx context.Context) error {
	tool := firstNonEmpty(r.Tool, "docker")
	out, stderr, err := r.commandRunner().CombinedOutput(ctx, nil, tool, "version")
	if err != nil && len(stderr) > 0 {
		return fmt.Errorf("%w: %s", err, strings.TrimSpace(string(stderr)))
	}
	if err != nil && len(out) > 0 {
		return fmt.Errorf("%w: %s", err, strings.TrimSpace(string(out)))
	}
	return err
}

func (r DockerSandboxRuntime) Run(ctx context.Context, req SandboxRunRequest) (SandboxRunResult, error) {
	spec, cleanup, err := r.prepareRun(req)
	if err != nil {
		return SandboxRunResult{}, err
	}
	defer cleanup()
	stdout, stderr, err := r.commandRunner().CombinedOutput(ctx, req.Stdin, spec.Tool, spec.CommandArgs()...)
	exitCode := 0
	if err != nil {
		exitCode = commandExitCode(err)
	}
	if err != nil && len(stderr) > 0 {
		err = fmt.Errorf("%w: %s", err, strings.TrimSpace(string(stderr)))
	} else if err != nil && len(stdout) > 0 {
		err = fmt.Errorf("%w: %s", err, strings.TrimSpace(string(stdout)))
	}
	return SandboxRunResult{
		ExitCode: exitCode,
		Stdout:   stdout,
		Stderr:   stderr,
		ResourceUsage: core.ResourceUsage{
			OutputBytes:    int64(len(stdout) + len(stderr)),
			WorkspaceBytes: DirectorySize(req.Workspace),
		},
	}, err
}

func (r DockerSandboxRuntime) commandRunner() DockerCommandRunner {
	if r.Runner != nil {
		return r.Runner
	}
	return ExecDockerCommandRunner{}
}

func (r DockerSandboxRuntime) prepareRun(req SandboxRunRequest) (dockerRunSpec, func(), error) {
	cleanup := func() {}
	tool := firstNonEmpty(r.Tool, "docker")
	if strings.TrimSpace(req.Workspace) == "" {
		return dockerRunSpec{}, cleanup, errors.New("workspace is required for sandboxed-command")
	}
	workspace, err := filepath.Abs(req.Workspace)
	if err != nil {
		return dockerRunSpec{}, cleanup, fmt.Errorf("resolve workspace: %w", err)
	}
	workspace = filepath.Clean(workspace)
	if req.RunAsRoot {
		restore, err := makeWorkspaceSandboxReadable(workspace)
		if err != nil {
			return dockerRunSpec{}, cleanup, err
		}
		cleanup = restore
	}
	network := sandboxNetwork(req.Network)
	if network == "" {
		return dockerRunSpec{}, cleanup, fmt.Errorf("unsupported sandbox network %q", req.Network)
	}
	args := []string{
		"run",
		"--rm",
		"--network", network,
		"--cap-drop", "ALL",
		"--security-opt", "no-new-privileges",
		"--pids-limit", "256",
		"--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=64m",
	}
	if len(req.Stdin) > 0 {
		args = append(args, "-i")
	}
	if !req.WritableRootFS {
		args = append(args, "--read-only")
	}
	for _, capability := range req.AddCapabilities {
		if err := validateDockerCapability(req, capability); err != nil {
			cleanup()
			return dockerRunSpec{}, cleanup, err
		}
		args = append(args, "--cap-add", capability)
	}
	for _, tmpfs := range req.ExtraTmpfs {
		if err := validateDockerTmpfs(req, tmpfs); err != nil {
			cleanup()
			return dockerRunSpec{}, cleanup, err
		}
		args = append(args, "--tmpfs", tmpfs)
	}
	if !req.RunAsRoot {
		if tool == "podman" {
			args = append(args, "--userns", "keep-id")
		}
		args = append(args, "--user", fmt.Sprintf("%d:%d", os.Getuid(), os.Getgid()))
	}
	if r.RuntimeName != "" {
		args = append(args, "--runtime", r.RuntimeName)
	}
	if req.Limits.MemoryBytes > 0 {
		args = append(args, "--memory", fmt.Sprintf("%d", req.Limits.MemoryBytes))
	}
	if req.Limits.CPUPercent > 0 {
		args = append(args, "--cpus", fmt.Sprintf("%.2f", float64(req.Limits.CPUPercent)/100))
	}
	workingDir, err := sandboxWorkingDir(req.WorkingDir)
	if err != nil {
		cleanup()
		return dockerRunSpec{}, cleanup, err
	}
	args = append(args, "-v", workspace+":/workspace:rw", "-w", workingDir)
	for _, mount := range req.DataMounts {
		hostPath, containerPath, err := validateSandboxMount(mount)
		if err != nil {
			cleanup()
			return dockerRunSpec{}, cleanup, err
		}
		mode := "rw"
		if mount.ReadOnly {
			mode = "ro"
		}
		args = append(args, "-v", hostPath+":"+containerPath+":"+mode)
	}
	envFile, envCleanup, err := writeDockerEnvFile(req.Env)
	if err != nil {
		cleanup()
		return dockerRunSpec{}, cleanup, err
	}
	cleanup = joinCleanup(cleanup, envCleanup)
	if envFile != "" {
		args = append(args, "--env-file", envFile)
	}
	if req.CommandOverridesEntrypoint {
		if len(req.Command) == 0 || strings.TrimSpace(req.Command[0]) == "" {
			cleanup()
			return dockerRunSpec{}, cleanup, errors.New("entrypoint override requires a command")
		}
		args = append(args, "--entrypoint", "")
	}
	args = append(args, req.Image)
	args = append(args, req.Command...)
	runtimeScope, err := validateRuntimeScope(tool, req.RuntimeScope)
	if err != nil {
		cleanup()
		return dockerRunSpec{}, cleanup, err
	}
	return dockerRunSpec{Tool: tool, RuntimeArgs: runtimeScope.Args, Args: args, EnvFile: envFile}, cleanup, nil
}

func (s dockerRunSpec) CommandArgs() []string {
	return appendRuntimeScopeArgs(ContainerRuntimeScope{Args: s.RuntimeArgs}, s.Args...)
}

func sandboxNetwork(value string) string {
	switch value {
	case "", SandboxNetworkNone:
		return SandboxNetworkNone
	case SandboxNetworkBridge:
		return SandboxNetworkBridge
	default:
		if validManagedSandboxNetwork(value) {
			return value
		}
		return ""
	}
}

func validManagedSandboxNetwork(value string) bool {
	if !strings.HasPrefix(value, "wfcompute-") {
		return false
	}
	for _, r := range value {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= 'A' && r <= 'Z':
		case r >= '0' && r <= '9':
		case r == '-' || r == '_' || r == '.':
		default:
			return false
		}
	}
	return true
}

func makeWorkspaceSandboxReadable(workspace string) (func(), error) {
	original, err := chmodSandboxReadableTree(workspace)
	if err != nil {
		return func() {}, err
	}
	return func() {
		for i := len(original) - 1; i >= 0; i-- {
			_ = os.Chmod(original[i].path, original[i].mode)
		}
	}, nil
}

type sandboxPathMode struct {
	path string
	mode os.FileMode
}

func chmodSandboxReadableTree(workspace string) ([]sandboxPathMode, error) {
	var original []sandboxPathMode
	err := filepath.WalkDir(workspace, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		info, err := entry.Info()
		if err != nil {
			return fmt.Errorf("stat sandbox workspace path %s: %w", path, err)
		}
		original = append(original, sandboxPathMode{path: path, mode: info.Mode().Perm()})
		switch {
		case info.Mode().IsDir():
			if err := os.Chmod(path, dockerSandboxReadableDirMode(info.Mode().Perm())); err != nil {
				return fmt.Errorf("chmod sandbox workspace dir %s: %w", path, err)
			}
		case info.Mode().IsRegular():
			if err := os.Chmod(path, dockerSandboxReadableFileMode(info.Mode().Perm())); err != nil {
				return fmt.Errorf("chmod sandbox workspace file %s: %w", path, err)
			}
		}
		return nil
	})
	if err != nil {
		for i := len(original) - 1; i >= 0; i-- {
			_ = os.Chmod(original[i].path, original[i].mode)
		}
		return nil, err
	}
	return original, nil
}

func dockerSandboxReadableDirMode(mode os.FileMode) os.FileMode {
	return (mode | 0o755) & 0o777
}

func dockerSandboxReadableFileMode(mode os.FileMode) os.FileMode {
	if mode&0o111 != 0 {
		return (mode | 0o755) & 0o777
	}
	return (mode | 0o644) & 0o777
}

func joinCleanup(first func(), second func()) func() {
	return func() {
		second()
		first()
	}
}

func validateDockerCapability(req SandboxRunRequest, value string) error {
	if value == "" {
		return errors.New("docker capability cannot be empty")
	}
	for _, r := range value {
		if (r < 'A' || r > 'Z') && (r < '0' || r > '9') && r != '_' {
			return fmt.Errorf("invalid docker capability %q", value)
		}
	}
	if !req.RunAsRoot || !slices.Contains([]string{"CHOWN", "FOWNER"}, value) {
		return fmt.Errorf("docker capability %q is not allowed for this sandbox profile", value)
	}
	return nil
}

func validateDockerTmpfs(req SandboxRunRequest, value string) error {
	if value == "" || !strings.HasPrefix(value, "/") || strings.ContainsAny(value, "\x00\n\r") {
		return fmt.Errorf("invalid docker tmpfs %q", value)
	}
	allowed := []string{"/wfcompute-build:rw,noexec,nosuid,nodev,size=512m"}
	if !req.RunAsRoot || !slices.Contains(allowed, value) {
		return fmt.Errorf("docker tmpfs %q is not allowed for this sandbox profile", value)
	}
	return nil
}

func writeDockerEnvFile(env map[string]string) (string, func(), error) {
	cleanup := func() {}
	if len(env) == 0 {
		return "", cleanup, nil
	}
	file, err := os.CreateTemp("", "wfcompute-sandbox-env-*")
	if err != nil {
		return "", cleanup, fmt.Errorf("create sandbox env file: %w", err)
	}
	path := file.Name()
	cleanup = func() { _ = os.Remove(path) }
	if err := os.Chmod(path, 0o600); err != nil {
		_ = file.Close()
		cleanup()
		return "", func() {}, fmt.Errorf("chmod sandbox env file: %w", err)
	}
	writer := bufio.NewWriter(file)
	keys := make([]string, 0, len(env))
	for key := range env {
		if err := validateDockerEnvName(key); err != nil {
			_ = file.Close()
			cleanup()
			return "", func() {}, err
		}
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		value := env[key]
		if strings.ContainsAny(value, "\x00\r\n") {
			_ = file.Close()
			cleanup()
			return "", func() {}, fmt.Errorf("sandbox env %q contains unsupported newline or NUL", key)
		}
		if _, err := fmt.Fprintf(writer, "%s=%s\n", key, value); err != nil {
			_ = file.Close()
			cleanup()
			return "", func() {}, fmt.Errorf("write sandbox env file: %w", err)
		}
	}
	if err := writer.Flush(); err != nil {
		_ = file.Close()
		cleanup()
		return "", func() {}, fmt.Errorf("flush sandbox env file: %w", err)
	}
	if err := file.Close(); err != nil {
		cleanup()
		return "", func() {}, fmt.Errorf("close sandbox env file: %w", err)
	}
	return path, cleanup, nil
}

func validateDockerEnvName(key string) error {
	if key == "" {
		return errors.New("sandbox env name is required")
	}
	for i, r := range key {
		valid := r == '_' || r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z' || i > 0 && r >= '0' && r <= '9'
		if !valid {
			return fmt.Errorf("sandbox env name %q is invalid", key)
		}
	}
	return nil
}

func validateSandboxMount(mount SandboxMount) (string, string, error) {
	hostPath := strings.TrimSpace(mount.HostPath)
	containerPath := strings.TrimSpace(mount.ContainerPath)
	if hostPath == "" || containerPath == "" {
		return "", "", errors.New("sandbox mount host and container paths are required")
	}
	absHost, err := filepath.Abs(hostPath)
	if err != nil {
		return "", "", fmt.Errorf("resolve sandbox mount: %w", err)
	}
	absHost = filepath.Clean(absHost)
	if mount.RequiredPrefix != "" {
		prefix, err := filepath.Abs(mount.RequiredPrefix)
		if err != nil {
			return "", "", fmt.Errorf("resolve sandbox mount prefix: %w", err)
		}
		prefix = filepath.Clean(prefix)
		rel, err := filepath.Rel(prefix, absHost)
		if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return "", "", fmt.Errorf("sandbox mount %q escapes required prefix", absHost)
		}
	}
	if !strings.HasPrefix(containerPath, "/") || strings.Contains(containerPath, "..") {
		return "", "", fmt.Errorf("sandbox mount container path %q is invalid", containerPath)
	}
	return absHost, filepath.Clean(containerPath), nil
}

func cloneContainerRuntimeScope(scope ContainerRuntimeScope) ContainerRuntimeScope {
	if len(scope.Args) > 0 {
		scope.Args = append([]string(nil), scope.Args...)
	}
	return scope
}

func appendRuntimeScopeArgs(scope ContainerRuntimeScope, args ...string) []string {
	out := append([]string(nil), scope.Args...)
	return append(out, args...)
}

func validateRuntimeScope(tool string, scope ContainerRuntimeScope) (ContainerRuntimeScope, error) {
	if len(scope.Args) == 0 {
		return ContainerRuntimeScope{}, nil
	}
	if tool != "nerdctl" {
		return ContainerRuntimeScope{}, errors.New("runtime scope args are only supported for nerdctl")
	}
	if len(scope.Args) != 2 || scope.Args[0] != "--namespace" || strings.TrimSpace(scope.Args[1]) == "" {
		return ContainerRuntimeScope{}, errors.New("runtime scope must be --namespace <name>")
	}
	namespace := scope.Args[1]
	if strings.ContainsAny(namespace, " \t\r\n/:?&#\\\x00") || strings.HasPrefix(namespace, "-") {
		return ContainerRuntimeScope{}, errors.New("runtime scope namespace is invalid")
	}
	return cloneContainerRuntimeScope(scope), nil
}

func sandboxWorkingDir(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" || value == "." {
		return "/workspace", nil
	}
	if filepath.IsAbs(value) || strings.ContainsAny(value, "\x00\r\n") {
		return "", errors.New("working_dir is invalid")
	}
	cleaned := filepath.Clean(value)
	if cleaned == "." || cleaned == "" {
		return "/workspace", nil
	}
	if cleaned == ".." || strings.HasPrefix(cleaned, ".."+string(filepath.Separator)) {
		return "", errors.New("working_dir escapes workspace")
	}
	return path.Join("/workspace", filepath.ToSlash(cleaned)), nil
}

func combinedOutputContext(ctx context.Context, name string, args ...string) ([]byte, error) {
	return combinedOutputContextWithStdin(ctx, nil, name, args...)
}

func combinedOutputContextWithStdin(ctx context.Context, stdin []byte, name string, args ...string) ([]byte, error) {
	stdout, stderr, err := splitOutputContextWithStdin(ctx, stdin, name, args...)
	return append(stdout, stderr...), err
}

func splitOutputContextWithStdin(ctx context.Context, stdin []byte, name string, args ...string) ([]byte, []byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	if len(stdin) > 0 {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	return stdout.Bytes(), stderr.Bytes(), err
}

func commandExitCode(err error) int {
	if err == nil {
		return 0
	}
	var exitCoder interface{ ExitCode() int }
	if errors.As(err, &exitCoder) {
		return exitCoder.ExitCode()
	}
	return -1
}
