package container

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	core "github.com/GoCodeAlone/workflow-plugin-compute-core/protocol"
)

const (
	SandboxedCommandProviderName        = "sandboxed-command"
	SandboxedCommandOperationRun        = "run-sandboxed-command"
	SandboxedContainerBuildProviderName = "sandboxed-container-build"
	SandboxedContainerBuildOperation    = "build-sandboxed-container"

	SandboxNetworkNone   = "none"
	SandboxNetworkBridge = "bridge"

	SandboxedContainerBuildStateDir     = "/wfcompute-build"
	SandboxedContainerBuildDigestPath   = SandboxedContainerBuildStateDir + "/wfcompute-container-build-digest"
	SandboxedContainerBuildDigestMarker = "WORKFLOW_COMPUTE_BUILD_DIGEST="

	sandboxedContainerBuildDigestFile = ".wfcompute-container-build-digest"
)

type ContainerRuntimeScope struct {
	Args []string
}

type SandboxMount struct {
	HostPath       string
	ContainerPath  string
	ReadOnly       bool
	RequiredPrefix string
}

type SandboxRunRequest struct {
	Image           string
	Command         []string
	RuntimeScope    ContainerRuntimeScope
	Stdin           []byte
	Workspace       string
	WorkingDir      string
	Env             map[string]string
	Network         string
	RuntimeName     string
	RunAsRoot       bool
	WritableRootFS  bool
	AddCapabilities []string
	ExtraTmpfs      []string
	DataMounts      []SandboxMount
	Timeout         time.Duration
	Limits          core.ResourceLimits
}

type SandboxRunResult struct {
	ExitCode      int
	Stdout        []byte
	Stderr        []byte
	ArtifactHash  string
	ResourceUsage core.ResourceUsage
}

type SandboxRuntime interface {
	Available(context.Context) error
	Run(context.Context, SandboxRunRequest) (SandboxRunResult, error)
}

type SandboxedCommandRuntimeInvocation struct {
	Request         core.RuntimeExecutionRequest
	Image           string
	Workspace       string
	Network         string
	Timeout         time.Duration
	TimeoutLimitHit string
}

type SandboxedCommandInvocationOptions struct {
	TaskID          string
	LeaseID         string
	Image           string
	Workspace       string
	Network         string
	Timeout         time.Duration
	TimeoutLimitHit string
	Workload        core.CommandWorkload
	ResolvedEnv     map[string]string
	Limits          core.ResourceLimits
}

type SandboxedCommandRuntime interface {
	RunSandboxedCommand(context.Context, SandboxedCommandRuntimeInvocation) (core.RuntimeExecutionResult, error)
}

type SandboxRuntimeCommandAdapter struct {
	Runtime SandboxRuntime
}

type SandboxedContainerBuildRuntimeInvocation struct {
	Request         core.RuntimeExecutionRequest
	Image           string
	Workspace       string
	Network         string
	Timeout         time.Duration
	TimeoutLimitHit string
}

type SandboxedContainerBuildInvocationOptions struct {
	TaskID          string
	LeaseID         string
	Image           string
	Workspace       string
	Network         string
	Timeout         time.Duration
	TimeoutLimitHit string
	Workload        core.ContainerBuildWorkload
	ResolvedEnv     map[string]string
	Limits          core.ResourceLimits
}

type SandboxedContainerBuildRuntime interface {
	BuildSandboxedContainer(context.Context, SandboxedContainerBuildRuntimeInvocation) (core.RuntimeExecutionResult, error)
}

type SandboxRuntimeContainerBuildAdapter struct {
	Runtime SandboxRuntime
}

type RuntimeAdapterCatalogDocument struct {
	Version                   string                       `json:"version"`
	ProtocolVersion           string                       `json:"protocol_version"`
	Adapters                  []RuntimeAdapterCatalogEntry `json:"adapters"`
	RuntimeBackends           []RuntimeBackendCatalogEntry `json:"runtime_backends,omitempty"`
	HostOwnedResponsibilities []string                     `json:"host_owned_responsibilities"`
}

func (d RuntimeAdapterCatalogDocument) Validate() error {
	var errs []error
	if d.Version == "" {
		errs = append(errs, errors.New("version is required"))
	}
	if d.ProtocolVersion != core.Version {
		errs = append(errs, fmt.Errorf("protocol_version = %q, want %q", d.ProtocolVersion, core.Version))
	}
	if len(d.Adapters) == 0 {
		errs = append(errs, errors.New("at least one adapter is required"))
	}
	for i, adapter := range d.Adapters {
		if err := adapter.Validate(); err != nil {
			errs = append(errs, fmt.Errorf("adapters[%d]: %w", i, err))
		}
	}
	for i, backend := range d.RuntimeBackends {
		if err := backend.Validate(); err != nil {
			errs = append(errs, fmt.Errorf("runtime_backends[%d]: %w", i, err))
		}
	}
	if len(d.HostOwnedResponsibilities) == 0 {
		errs = append(errs, errors.New("host_owned_responsibilities is required"))
	}
	return errors.Join(errs...)
}

type RuntimeAdapterCatalogEntry struct {
	AdapterID           string                      `json:"adapter_id"`
	Operation           string                      `json:"operation"`
	Kinds               []core.RuntimeAdapterKind   `json:"kinds"`
	WorkloadKinds       []core.WorkloadKind         `json:"workload_kinds"`
	RuntimeProfiles     []core.RuntimeProfile       `json:"runtime_profiles"`
	WorkspacePolicy     core.RuntimeWorkspacePolicy `json:"workspace_policy"`
	ConformanceProfiles []string                    `json:"conformance_profiles"`
}

func (e RuntimeAdapterCatalogEntry) Validate() error {
	var errs []error
	if e.AdapterID == "" {
		errs = append(errs, errors.New("adapter_id is required"))
	}
	if e.Operation == "" {
		errs = append(errs, errors.New("operation is required"))
	}
	if len(e.Kinds) == 0 {
		errs = append(errs, errors.New("kinds is required"))
	}
	if len(e.WorkloadKinds) == 0 {
		errs = append(errs, errors.New("workload_kinds is required"))
	}
	if len(e.RuntimeProfiles) == 0 {
		errs = append(errs, errors.New("runtime_profiles is required"))
	}
	if e.WorkspacePolicy == "" {
		errs = append(errs, errors.New("workspace_policy is required"))
	}
	if len(e.ConformanceProfiles) == 0 {
		errs = append(errs, errors.New("conformance_profiles is required"))
	}
	return errors.Join(errs...)
}

func (e RuntimeAdapterCatalogEntry) Contract(descriptor core.RuntimeDescriptor) core.RuntimeAdapterContract {
	if descriptor.Name == "" {
		descriptor.Name = e.AdapterID
	}
	return core.RuntimeAdapterContract{
		ProtocolVersion:     core.Version,
		AdapterID:           e.AdapterID,
		Descriptor:          descriptor,
		Kinds:               slices.Clone(e.Kinds),
		WorkloadKinds:       slices.Clone(e.WorkloadKinds),
		RuntimeProfiles:     slices.Clone(e.RuntimeProfiles),
		WorkspacePolicy:     e.WorkspacePolicy,
		ConformanceProfiles: slices.Clone(e.ConformanceProfiles),
	}
}

type RuntimeBackendCatalogEntry struct {
	BackendID           string                      `json:"backend_id"`
	Families            []core.RuntimeBackendFamily `json:"families"`
	Tools               []core.ContainerRuntimeTool `json:"tools"`
	IsolationModes      []core.RuntimeIsolationMode `json:"isolation_modes"`
	InstallBurdens      []core.RuntimeInstallBurden `json:"install_burdens"`
	RuntimeProfiles     []core.RuntimeProfile       `json:"runtime_profiles"`
	ExecutorProviders   []string                    `json:"executor_providers"`
	ConformanceProfiles []string                    `json:"conformance_profiles"`
}

func (e RuntimeBackendCatalogEntry) Validate() error {
	var errs []error
	if e.BackendID == "" {
		errs = append(errs, errors.New("backend_id is required"))
	}
	if len(e.Families) == 0 {
		errs = append(errs, errors.New("families is required"))
	}
	if len(e.Tools) == 0 {
		errs = append(errs, errors.New("tools is required"))
	}
	if len(e.IsolationModes) == 0 {
		errs = append(errs, errors.New("isolation_modes is required"))
	}
	if len(e.InstallBurdens) == 0 {
		errs = append(errs, errors.New("install_burdens is required"))
	}
	if len(e.RuntimeProfiles) == 0 {
		errs = append(errs, errors.New("runtime_profiles is required"))
	}
	if len(e.ExecutorProviders) == 0 {
		errs = append(errs, errors.New("executor_providers is required"))
	}
	if len(e.ConformanceProfiles) == 0 {
		errs = append(errs, errors.New("conformance_profiles is required"))
	}
	return errors.Join(errs...)
}

func SandboxedCommandContract(descriptor core.RuntimeDescriptor) core.RuntimeAdapterContract {
	if descriptor.Name == "" {
		descriptor.Name = SandboxedCommandProviderName
	}
	return core.RuntimeAdapterContract{
		ProtocolVersion:     core.Version,
		AdapterID:           SandboxedCommandProviderName,
		Descriptor:          descriptor,
		Kinds:               []core.RuntimeAdapterKind{core.RuntimeAdapterExecution},
		WorkloadKinds:       []core.WorkloadKind{core.WorkloadCommand},
		RuntimeProfiles:     []core.RuntimeProfile{core.RuntimeProfileSandboxedOCI},
		WorkspacePolicy:     core.RuntimeWorkspaceRequired,
		ConformanceProfiles: []string{"sandboxed-command-v1"},
	}
}

func SandboxedContainerBuildContract(descriptor core.RuntimeDescriptor) core.RuntimeAdapterContract {
	if descriptor.Name == "" {
		descriptor.Name = SandboxedContainerBuildProviderName
	}
	return core.RuntimeAdapterContract{
		ProtocolVersion:     core.Version,
		AdapterID:           SandboxedContainerBuildProviderName,
		Descriptor:          descriptor,
		Kinds:               []core.RuntimeAdapterKind{core.RuntimeAdapterExecution},
		WorkloadKinds:       []core.WorkloadKind{core.WorkloadContainerBuild},
		RuntimeProfiles:     []core.RuntimeProfile{core.RuntimeProfileContainerBuild},
		WorkspacePolicy:     core.RuntimeWorkspaceRequired,
		ConformanceProfiles: []string{"container-build-v1"},
	}
}

func NewSandboxedCommandInvocation(opts SandboxedCommandInvocationOptions) (SandboxedCommandRuntimeInvocation, error) {
	if strings.TrimSpace(opts.Workspace) == "" {
		return SandboxedCommandRuntimeInvocation{}, errors.New("workspace is required")
	}
	if err := opts.Workload.Validate(); err != nil {
		return SandboxedCommandRuntimeInvocation{}, err
	}
	if len(opts.Workload.Args) == 0 {
		return SandboxedCommandRuntimeInvocation{}, errors.New("command args are required")
	}
	env, err := CommandRuntimeEnv(opts.Workload, opts.ResolvedEnv)
	if err != nil {
		return SandboxedCommandRuntimeInvocation{}, err
	}
	payload := opts.Workload
	payload.Env = nil
	input, err := json.Marshal(payload)
	if err != nil {
		return SandboxedCommandRuntimeInvocation{}, fmt.Errorf("marshal sandboxed-command runtime input: %w", err)
	}
	runtimeReq := core.RuntimeExecutionRequest{
		ProtocolVersion: core.Version,
		TaskID:          opts.TaskID,
		LeaseID:         opts.LeaseID,
		WorkloadKind:    core.WorkloadCommand,
		Operation:       SandboxedCommandOperationRun,
		Input:           input,
		Env:             env,
		Limits:          opts.Limits,
	}
	if err := runtimeReq.Validate(); err != nil {
		return SandboxedCommandRuntimeInvocation{}, err
	}
	return SandboxedCommandRuntimeInvocation{
		Request:         runtimeReq,
		Image:           opts.Image,
		Workspace:       opts.Workspace,
		Network:         firstNonEmpty(opts.Network, SandboxNetworkNone),
		Timeout:         defaultDuration(opts.Timeout, time.Minute),
		TimeoutLimitHit: firstNonEmpty(opts.TimeoutLimitHit, "timeout"),
	}, nil
}

func (a SandboxRuntimeCommandAdapter) RunSandboxedCommand(ctx context.Context, invocation SandboxedCommandRuntimeInvocation) (core.RuntimeExecutionResult, error) {
	if a.Runtime == nil {
		return core.RuntimeExecutionResult{}, errors.New("sandbox runtime is required")
	}
	if err := invocation.Request.Validate(); err != nil {
		return core.RuntimeExecutionResult{}, err
	}
	if invocation.Request.WorkloadKind != core.WorkloadCommand {
		return core.RuntimeExecutionResult{}, fmt.Errorf("workload kind %q is not supported by sandboxed-command runtime", invocation.Request.WorkloadKind)
	}
	var workload core.CommandWorkload
	if len(invocation.Request.Input) == 0 {
		return core.RuntimeExecutionResult{}, errors.New("sandboxed-command runtime input is required")
	}
	if err := json.Unmarshal(invocation.Request.Input, &workload); err != nil {
		return core.RuntimeExecutionResult{}, fmt.Errorf("decode sandboxed-command runtime input: %w", err)
	}
	if err := workload.Validate(); err != nil {
		return core.RuntimeExecutionResult{}, err
	}
	if len(workload.Args) == 0 {
		return core.RuntimeExecutionResult{}, errors.New("command args are required")
	}
	if err := a.Runtime.Available(ctx); err != nil {
		return core.RuntimeExecutionResult{}, fmt.Errorf("sandbox runtime unavailable: %w", err)
	}
	timeout := defaultDuration(invocation.Timeout, time.Minute)
	timeoutLimitHit := firstNonEmpty(invocation.TimeoutLimitHit, "timeout")
	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	started := time.Now().UTC()
	result, err := a.Runtime.Run(runCtx, SandboxRunRequest{
		Image:      invocation.Image,
		Command:    slices.Clone(workload.Args),
		Workspace:  invocation.Workspace,
		WorkingDir: workload.WorkingDirectory,
		Env:        cloneStringMap(invocation.Request.Env),
		Network:    firstNonEmpty(invocation.Network, SandboxNetworkNone),
		Timeout:    timeout,
		Limits:     invocation.Request.Limits,
	})
	finished := time.Now().UTC()
	runResult := core.RuntimeExecutionResult{
		StartedAt:     started,
		FinishedAt:    finished,
		ExitCode:      result.ExitCode,
		Stdout:        result.Stdout,
		Stderr:        result.Stderr,
		ArtifactHash:  result.ArtifactHash,
		ResourceUsage: result.ResourceUsage,
	}
	if runCtx.Err() != nil {
		runResult.ResourceUsage.LimitHit = timeoutLimitHit
		return runResult, fmt.Errorf("sandboxed command timed out after %s: %w", timeout, runCtx.Err())
	}
	if err != nil {
		return runResult, err
	}
	if len(workload.ArtifactAllowlist) > 0 {
		artifactBase, hashErr := commandArtifactBaseDir(invocation.Workspace, workload.WorkingDirectory)
		if hashErr != nil {
			return runResult, hashErr
		}
		artifactHash, hashErr := hashArtifacts(artifactBase, workload.ArtifactAllowlist)
		if hashErr != nil {
			return runResult, hashErr
		}
		runResult.ArtifactHash = artifactHash
		runResult.Artifacts = slices.Clone(workload.ArtifactAllowlist)
	}
	if runResult.ResourceUsage.WorkspaceBytes == 0 && invocation.Workspace != "" {
		runResult.ResourceUsage.WorkspaceBytes = DirectorySize(invocation.Workspace)
	}
	return runResult, nil
}

func NewSandboxedContainerBuildInvocation(opts SandboxedContainerBuildInvocationOptions) (SandboxedContainerBuildRuntimeInvocation, error) {
	if err := opts.Workload.Validate(); err != nil {
		return SandboxedContainerBuildRuntimeInvocation{}, err
	}
	if _, _, err := ResolveContainerBuildPaths(opts.Workspace, opts.Workload); err != nil {
		return SandboxedContainerBuildRuntimeInvocation{}, err
	}
	env, err := ContainerBuildEnv(opts.Workload, opts.ResolvedEnv)
	if err != nil {
		return SandboxedContainerBuildRuntimeInvocation{}, err
	}
	payload := opts.Workload
	payload.Env = nil
	input, err := json.Marshal(payload)
	if err != nil {
		return SandboxedContainerBuildRuntimeInvocation{}, fmt.Errorf("marshal sandboxed-container-build runtime input: %w", err)
	}
	runtimeReq := core.RuntimeExecutionRequest{
		ProtocolVersion: core.Version,
		TaskID:          opts.TaskID,
		LeaseID:         opts.LeaseID,
		WorkloadKind:    core.WorkloadContainerBuild,
		Operation:       SandboxedContainerBuildOperation,
		Input:           input,
		Env:             env,
		Limits:          opts.Limits,
	}
	if err := runtimeReq.Validate(); err != nil {
		return SandboxedContainerBuildRuntimeInvocation{}, err
	}
	return SandboxedContainerBuildRuntimeInvocation{
		Request:         runtimeReq,
		Image:           opts.Image,
		Workspace:       opts.Workspace,
		Network:         firstNonEmpty(opts.Network, SandboxNetworkNone),
		Timeout:         defaultDuration(opts.Timeout, time.Hour),
		TimeoutLimitHit: firstNonEmpty(opts.TimeoutLimitHit, "timeout"),
	}, nil
}

func (a SandboxRuntimeContainerBuildAdapter) BuildSandboxedContainer(ctx context.Context, invocation SandboxedContainerBuildRuntimeInvocation) (core.RuntimeExecutionResult, error) {
	if a.Runtime == nil {
		return core.RuntimeExecutionResult{}, errors.New("sandbox runtime is required")
	}
	if err := invocation.Request.Validate(); err != nil {
		return core.RuntimeExecutionResult{}, err
	}
	if invocation.Request.WorkloadKind != core.WorkloadContainerBuild {
		return core.RuntimeExecutionResult{}, fmt.Errorf("workload kind %q is not supported by sandboxed-container-build runtime", invocation.Request.WorkloadKind)
	}
	var workload core.ContainerBuildWorkload
	if len(invocation.Request.Input) == 0 {
		return core.RuntimeExecutionResult{}, errors.New("sandboxed-container-build runtime input is required")
	}
	if err := json.Unmarshal(invocation.Request.Input, &workload); err != nil {
		return core.RuntimeExecutionResult{}, fmt.Errorf("decode sandboxed-container-build runtime input: %w", err)
	}
	if err := workload.Validate(); err != nil {
		return core.RuntimeExecutionResult{}, err
	}
	_, dockerfile, err := ResolveContainerBuildPaths(invocation.Workspace, workload)
	if err != nil {
		return core.RuntimeExecutionResult{}, err
	}
	if err := a.Runtime.Available(ctx); err != nil {
		return core.RuntimeExecutionResult{}, fmt.Errorf("sandbox runtime unavailable: %w", err)
	}
	timeout := defaultDuration(invocation.Timeout, time.Hour)
	timeoutLimitHit := firstNonEmpty(invocation.TimeoutLimitHit, "timeout")
	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	push := workload.PushTargetRef != ""
	digestPath := filepath.Join(invocation.Workspace, sandboxedContainerBuildDigestFile)
	started := time.Now().UTC()
	runEnv := map[string]string{
		"WORKFLOW_COMPUTE_BUILD_CONTEXT":         CleanContainerPath(workload.ContextDirectory),
		"WORKFLOW_COMPUTE_BUILD_DOCKERFILE":      dockerfile,
		"WORKFLOW_COMPUTE_BUILD_TAG":             firstTag(workload.Tags),
		"WORKFLOW_COMPUTE_BUILD_TAGS":            mustJSON(workload.Tags),
		"WORKFLOW_COMPUTE_BUILD_PULL_TARGET_REF": workload.PullTargetRef,
		"WORKFLOW_COMPUTE_BUILD_PUSH_TARGET_REF": workload.PushTargetRef,
		"WORKFLOW_COMPUTE_BUILD_STATE_DIR":       SandboxedContainerBuildStateDir,
		"WORKFLOW_COMPUTE_BUILD_DIGEST_FILE":     SandboxedContainerBuildDigestPath,
		"WORKFLOW_COMPUTE_BUILD_PUSH":            fmt.Sprintf("%t", push),
	}
	for key, value := range invocation.Request.Env {
		if strings.HasPrefix(key, "WORKFLOW_COMPUTE_BUILD_") {
			return core.RuntimeExecutionResult{}, fmt.Errorf("reserved workflow-compute build env %q", key)
		}
		runEnv[key] = value
	}
	result, err := a.Runtime.Run(runCtx, SandboxRunRequest{
		Image:           invocation.Image,
		Command:         []string{"/usr/local/bin/wfcompute-container-builder"},
		Workspace:       invocation.Workspace,
		WorkingDir:      ".",
		RunAsRoot:       true,
		WritableRootFS:  true,
		AddCapabilities: []string{"CHOWN", "FOWNER"},
		ExtraTmpfs: []string{
			SandboxedContainerBuildStateDir + ":rw,noexec,nosuid,nodev,size=512m",
		},
		Env:     runEnv,
		Network: firstNonEmpty(invocation.Network, SandboxNetworkNone),
		Timeout: timeout,
		Limits:  invocation.Request.Limits,
	})
	finished := time.Now().UTC()
	runResult := core.RuntimeExecutionResult{
		StartedAt:     started,
		FinishedAt:    finished,
		ExitCode:      result.ExitCode,
		Stdout:        result.Stdout,
		Stderr:        result.Stderr,
		ArtifactHash:  result.ArtifactHash,
		ResourceUsage: result.ResourceUsage,
	}
	if runCtx.Err() != nil {
		runResult.ResourceUsage.LimitHit = timeoutLimitHit
		return runResult, fmt.Errorf("sandboxed container build timed out after %s: %w", timeout, runCtx.Err())
	}
	if err != nil {
		return runResult, err
	}
	if !ValidSHA256Digest(runResult.ArtifactHash) {
		if digest := ParseSandboxedContainerBuildDigestMarker(runResult.Stdout); digest != "" {
			runResult.ArtifactHash = digest
		}
	}
	if !ValidSHA256Digest(runResult.ArtifactHash) {
		if digest, readErr := ReadSandboxedContainerBuildDigest(digestPath); readErr == nil {
			runResult.ArtifactHash = digest
		}
	}
	if !ValidSHA256Digest(runResult.ArtifactHash) {
		return runResult, errors.New("sandboxed container build did not produce a sha256 artifact digest")
	}
	if runResult.ResourceUsage.WorkspaceBytes == 0 && invocation.Workspace != "" {
		runResult.ResourceUsage.WorkspaceBytes = DirectorySize(invocation.Workspace)
	}
	return runResult, nil
}

func CommandRuntimeEnv(workload core.CommandWorkload, resolved map[string]string) (map[string]string, error) {
	env := make(map[string]string, len(workload.Env))
	for _, ref := range workload.Env {
		if _, exists := env[ref.Name]; exists {
			return nil, fmt.Errorf("env %s is declared more than once", ref.Name)
		}
		value, ok := resolved[firstNonEmpty(ref.ValueRef, ref.SecretRef)]
		if !ok {
			return nil, fmt.Errorf("env %s missing resolved ref", ref.Name)
		}
		env[ref.Name] = value
	}
	return env, nil
}

func ContainerBuildEnv(workload core.ContainerBuildWorkload, resolved map[string]string) (map[string]string, error) {
	if len(workload.Env) == 0 {
		return nil, nil
	}
	out := make(map[string]string, len(workload.Env))
	for _, ref := range workload.Env {
		if strings.HasPrefix(ref.Name, "WORKFLOW_COMPUTE_BUILD_") {
			return nil, fmt.Errorf("reserved workflow-compute build env %q", ref.Name)
		}
		if _, exists := out[ref.Name]; exists {
			return nil, fmt.Errorf("env %s is declared more than once", ref.Name)
		}
		value, ok := resolved[firstNonEmpty(ref.ValueRef, ref.SecretRef)]
		if !ok {
			return nil, fmt.Errorf("env %s missing resolved ref", ref.Name)
		}
		out[ref.Name] = value
	}
	return out, nil
}

func ResolveContainerBuildPaths(workspace string, workload core.ContainerBuildWorkload) (string, string, error) {
	if strings.TrimSpace(workspace) == "" {
		return "", "", errors.New("workspace is required")
	}
	root := filepath.Clean(workspace)
	contextDir, err := resolveInside(root, workload.ContextDirectory)
	if err != nil {
		return "", "", err
	}
	if err := rejectSymlinkPathComponents(root, contextDir); err != nil {
		return "", "", err
	}
	dockerfile := workload.Dockerfile
	if dockerfile == "" {
		dockerfile = "Dockerfile"
	}
	dockerfilePath, err := resolveInside(contextDir, dockerfile)
	if err != nil {
		return "", "", err
	}
	if err := rejectSymlinkPathComponents(contextDir, dockerfilePath); err != nil {
		return "", "", err
	}
	return contextDir, dockerfile, nil
}

func ValidSHA256Digest(value string) bool {
	const prefix = "sha256:"
	if !strings.HasPrefix(value, prefix) {
		return false
	}
	hexValue := strings.TrimPrefix(value, prefix)
	if len(hexValue) != 64 {
		return false
	}
	for _, r := range hexValue {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			return false
		}
	}
	return true
}

func ParseSandboxedContainerBuildDigestMarker(output []byte) string {
	var digest string
	for _, line := range strings.Split(string(output), "\n") {
		value, ok := strings.CutPrefix(strings.TrimSpace(line), SandboxedContainerBuildDigestMarker)
		if ok {
			if ValidSHA256Digest(value) {
				digest = value
			} else {
				digest = ""
			}
		}
	}
	return digest
}

func CleanContainerPath(value string) string {
	if value == "" || value == "." {
		return "."
	}
	return strings.TrimPrefix(filepath.ToSlash(filepath.Clean(value)), "/")
}

func ReadSandboxedContainerBuildDigest(path string) (string, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return "", err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return "", fmt.Errorf("sandboxed container-build digest path must be regular file")
	}
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	openInfo, err := file.Stat()
	if err != nil {
		return "", err
	}
	if !openInfo.Mode().IsRegular() || !os.SameFile(info, openInfo) {
		return "", fmt.Errorf("sandboxed container-build digest path changed while opening")
	}
	data, err := io.ReadAll(file)
	if err != nil {
		return "", err
	}
	digest := strings.TrimSpace(string(data))
	if !ValidSHA256Digest(digest) {
		return "", fmt.Errorf("invalid sandboxed container-build digest %q", digest)
	}
	return digest, nil
}

func DirectorySize(root string) int64 {
	var total int64
	_ = filepath.WalkDir(root, func(_ string, entry os.DirEntry, err error) error {
		if err != nil || entry.IsDir() {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return nil
		}
		total += info.Size()
		return nil
	})
	return total
}

func commandArtifactBaseDir(workspace, workingDirectory string) (string, error) {
	if err := rejectSymlinkPathComponents(workspace, workspace); err != nil {
		return "", err
	}
	if workingDirectory == "" {
		return workspace, nil
	}
	path, err := resolveInside(workspace, workingDirectory)
	if err != nil {
		return "", err
	}
	if err := rejectSymlinkPathComponents(workspace, path); err != nil {
		return "", err
	}
	return path, nil
}

func hashArtifacts(baseDir string, allowlist []string) (string, error) {
	if baseDir == "" {
		return "", errors.New("workspace is required for artifact allowlist")
	}
	hash := sha256.New()
	paths := slices.Sorted(slices.Values(allowlist))
	for _, allowed := range paths {
		path, err := resolveInside(baseDir, allowed)
		if err != nil {
			return "", err
		}
		if err := rejectSymlinkPathComponents(baseDir, path); err != nil {
			return "", err
		}
		info, err := os.Lstat(path)
		if err != nil {
			return "", fmt.Errorf("stat artifact %s: %w", allowed, err)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return "", fmt.Errorf("artifact %s is a symlink", allowed)
		}
		if info.IsDir() {
			if err := filepath.WalkDir(path, func(child string, entry os.DirEntry, walkErr error) error {
				if walkErr != nil {
					return walkErr
				}
				if entry.IsDir() {
					return nil
				}
				if entry.Type()&os.ModeSymlink != 0 {
					rel, _ := filepath.Rel(baseDir, child)
					return fmt.Errorf("artifact %s is a symlink", filepath.ToSlash(rel))
				}
				return hashFile(hash, baseDir, child)
			}); err != nil {
				return "", err
			}
			continue
		}
		if err := hashFile(hash, baseDir, path); err != nil {
			return "", err
		}
	}
	return "sha256:" + hex.EncodeToString(hash.Sum(nil)), nil
}

func hashFile(hash io.Writer, baseDir, path string) error {
	rel, err := filepath.Rel(baseDir, path)
	if err != nil {
		return err
	}
	pathInfo, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if pathInfo.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("artifact %s is a symlink", filepath.ToSlash(rel))
	}
	if !pathInfo.Mode().IsRegular() {
		return fmt.Errorf("artifact %s is not a regular file", filepath.ToSlash(rel))
	}
	if _, err := fmt.Fprintf(hash, "%s\x00", filepath.ToSlash(rel)); err != nil {
		return err
	}
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	openInfo, err := file.Stat()
	if err != nil {
		return err
	}
	if !os.SameFile(pathInfo, openInfo) {
		return fmt.Errorf("artifact %s changed while opening", filepath.ToSlash(rel))
	}
	if _, err := io.Copy(hash, file); err != nil {
		return err
	}
	_, err = hash.Write([]byte{0})
	return err
}

func resolveInside(baseDir, value string) (string, error) {
	if value == "" {
		return baseDir, nil
	}
	if filepath.IsAbs(value) {
		return "", fmt.Errorf("path %q must be relative", value)
	}
	path := filepath.Clean(filepath.Join(baseDir, value))
	if baseDir == "" {
		return path, nil
	}
	rel, err := filepath.Rel(baseDir, path)
	if err != nil {
		return "", err
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("path %q escapes workspace", value)
	}
	return path, nil
}

func rejectSymlinkPathComponents(root, target string) error {
	root = filepath.Clean(root)
	target = filepath.Clean(target)
	if root == "" || root == "." {
		return nil
	}
	rootInfo, err := os.Lstat(root)
	if err != nil {
		return err
	}
	if rootInfo.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("path %q is a symlink", root)
	}
	if target == root {
		return nil
	}
	rel, err := filepath.Rel(root, target)
	if err != nil {
		return err
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
		return fmt.Errorf("path %q escapes workspace", target)
	}
	current := root
	for _, part := range strings.Split(rel, string(filepath.Separator)) {
		if part == "." || part == "" {
			continue
		}
		current = filepath.Join(current, part)
		info, err := os.Lstat(current)
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("path %q is a symlink", current)
		}
	}
	return nil
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func defaultDuration(value, fallback time.Duration) time.Duration {
	if value > 0 {
		return value
	}
	return fallback
}

func firstTag(tags []string) string {
	if len(tags) == 0 {
		return ""
	}
	return tags[0]
}

func mustJSON(value any) string {
	data, err := json.Marshal(value)
	if err != nil {
		return "null"
	}
	return string(data)
}

func cloneStringMap(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for key, value := range in {
		out[key] = value
	}
	return out
}
