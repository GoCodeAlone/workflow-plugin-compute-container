package internal

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	container "github.com/GoCodeAlone/workflow-plugin-compute-container/container"
	core "github.com/GoCodeAlone/workflow-plugin-compute-core/protocol"
)

func TestManifest(t *testing.T) {
	plugin := NewPlugin()
	manifest := plugin.Manifest()
	if manifest.Name != "workflow-plugin-compute-container" {
		t.Fatalf("name = %q", manifest.Name)
	}
	if manifest.Version != Version {
		t.Fatalf("version = %q, want %q", manifest.Version, Version)
	}
	if manifest.Description == "" {
		t.Fatal("description is required")
	}
}

func TestPluginJSONReferencesRuntimeAdapters(t *testing.T) {
	root := filepath.Clean("..")
	data, err := os.ReadFile(filepath.Join(root, "plugin.json"))
	if err != nil {
		t.Fatal(err)
	}
	var manifest struct {
		RuntimeAdaptersRef       string `json:"runtimeAdaptersRef"`
		ManagedRuntimeBundlesRef string `json:"managedRuntimeBundlesRef"`
		Dependencies             []struct {
			Name       string `json:"name"`
			Constraint string `json:"constraint"`
		} `json:"dependencies"`
	}
	if err := json.Unmarshal(data, &manifest); err != nil {
		t.Fatal(err)
	}
	if manifest.RuntimeAdaptersRef != "runtime-adapters.json" {
		t.Fatalf("runtimeAdaptersRef = %q", manifest.RuntimeAdaptersRef)
	}
	var coreDependencyFound bool
	for _, dependency := range manifest.Dependencies {
		if dependency.Name == "workflow-plugin-compute-core" {
			coreDependencyFound = true
			if dependency.Constraint != ">=0.6.0" {
				t.Fatalf("compute-core dependency constraint = %q", dependency.Constraint)
			}
		}
	}
	if !coreDependencyFound {
		t.Fatal("compute-core dependency not found")
	}
	adapters, err := os.ReadFile(filepath.Join(root, manifest.RuntimeAdaptersRef))
	if err != nil {
		t.Fatal(err)
	}
	var catalog container.RuntimeAdapterCatalogDocument
	if err := json.Unmarshal(adapters, &catalog); err != nil {
		t.Fatal(err)
	}
	if err := catalog.Validate(); err != nil {
		t.Fatalf("runtime adapter catalog invalid: %v", err)
	}
	if len(catalog.Adapters) != 2 {
		t.Fatalf("runtime adapter catalog incomplete: %+v", catalog)
	}
	if len(catalog.RuntimeBackends) != 4 {
		t.Fatalf("runtime backend catalog incomplete: %+v", catalog)
	}
	wantBackends := map[string]core.ContainerRuntimeTool{
		"podman-rootless":                core.ContainerRuntimePodman,
		"docker-desktop":                 core.ContainerRuntimeDocker,
		"nerdctl-containerd":             core.ContainerRuntimeNerdctl,
		"managed-containerd-linux-amd64": core.ContainerRuntimeNerdctl,
	}
	for _, backend := range catalog.RuntimeBackends {
		wantTool, ok := wantBackends[backend.BackendID]
		if !ok {
			t.Fatalf("unexpected runtime backend catalog entry: %+v", backend)
		}
		if !slices.Contains(backend.Tools, wantTool) ||
			!slices.Contains(backend.ExecutorProviders, container.SandboxedCommandProviderName) ||
			!slices.Contains(backend.ExecutorProviders, container.SandboxedContainerBuildProviderName) {
			t.Fatalf("runtime backend catalog missing expected entries: %+v", backend)
		}
		if backend.BackendID == "managed-containerd-linux-amd64" {
			if len(backend.SupportedTargets) != 1 ||
				backend.SupportedTargets[0].OS != "linux" ||
				backend.SupportedTargets[0].Arch != "amd64" {
				t.Fatalf("managed runtime backend target constraints missing: %+v", backend)
			}
		}
		delete(wantBackends, backend.BackendID)
	}
	if len(wantBackends) != 0 {
		t.Fatalf("runtime backend catalog missing entries: %+v", wantBackends)
	}
	if manifest.ManagedRuntimeBundlesRef != "managed-runtime-bundles.json" {
		t.Fatalf("managedRuntimeBundlesRef = %q", manifest.ManagedRuntimeBundlesRef)
	}
	bundlesData, err := os.ReadFile(filepath.Join(root, manifest.ManagedRuntimeBundlesRef))
	if err != nil {
		t.Fatal(err)
	}
	var bundleCatalog container.ManagedRuntimeBundleCatalog
	if err := json.Unmarshal(bundlesData, &bundleCatalog); err != nil {
		t.Fatal(err)
	}
	if _, err := bundleCatalog.Bundle("managed-containerd-linux-amd64", bundleCatalog.GeneratedAt); err != nil {
		t.Fatalf("managed runtime bundle catalog invalid: %v", err)
	}
	if bundleCatalog.ReleaseTag != "v2.3.1" ||
		bundleCatalog.SourceBaseURL != "https://github.com/containerd/nerdctl/releases/download/v2.3.1" {
		t.Fatalf("managed runtime bundle source metadata drifted: %+v", bundleCatalog)
	}
	if len(bundleCatalog.Bundles) != 1 {
		t.Fatalf("managed runtime bundle catalog = %+v", bundleCatalog)
	}
	bundle := bundleCatalog.Bundles[0]
	if bundle.ArtifactName != "nerdctl-full-2.3.1-linux-amd64.tar.gz" ||
		bundle.ArtifactDigest != "sha256:7a0d8efcf55b10b57d831541266adb9c6ec3d55b44ec041c95f6eb994d1faab9" ||
		bundle.ChecksumDigest != "sha256:8a0586ff11d4d5a5d19d59494a10af8c6d41dd95ca72ff347f62d5288bc5131a" ||
		bundle.SignatureDigest != "sha256:f87400e0923e22eab251328bd210bb9e8d3bba2b58dbbb84699622474344d68c" {
		t.Fatalf("managed runtime bundle descriptor is not pinned to the expected upstream asset: %+v", bundle)
	}
	bundlesText := string(bundlesData)
	if strings.Contains(bundlesText, strings.Repeat("1", 32)) ||
		strings.Contains(bundlesText, strings.Repeat("2", 32)) ||
		strings.Contains(bundlesText, strings.Repeat("3", 32)) {
		t.Fatalf("managed runtime bundle catalog contains placeholder digest material")
	}
	for _, adapter := range catalog.Adapters {
		contract := adapter.Contract(core.RuntimeDescriptor{
			Name:                  adapter.AdapterID,
			Version:               "v1.0.0",
			ExecutionSecurityTier: core.ExecutionSandboxedContainer,
			ProofTier:             core.ProofArtifactHash,
			ImageDigest:           "sha256:" + strings.Repeat("a", 64),
			RootFSDigest:          "sha256:" + strings.Repeat("b", 64),
		})
		if err := contract.Validate(); err != nil {
			t.Fatalf("runtime adapter contract for %s invalid: %v", adapter.AdapterID, err)
		}
	}
}

func TestPluginContractsAdvertiseRuntimeBackendReports(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "plugin.contracts.json"))
	if err != nil {
		t.Fatal(err)
	}
	var contracts struct {
		ProtocolTypes []struct {
			Name            string   `json:"name"`
			Wire            string   `json:"wire"`
			GoType          string   `json:"goType"`
			ProtocolVersion string   `json:"protocolVersion"`
			ProducedBy      []string `json:"producedBy"`
		} `json:"protocolTypes"`
	}
	if err := json.Unmarshal(data, &contracts); err != nil {
		t.Fatal(err)
	}
	for _, typ := range contracts.ProtocolTypes {
		if typ.Name == "RuntimeBackendReport" &&
			typ.Wire == "json" &&
			typ.GoType == "github.com/GoCodeAlone/workflow-plugin-compute-core/protocol.RuntimeBackendReport" &&
			typ.ProtocolVersion == core.Version &&
			slices.Contains(typ.ProducedBy, "DockerCompatibleRuntimeProbes") &&
			slices.Contains(typ.ProducedBy, "ManagedContainerdRuntimeProbe") {
			return
		}
	}
	t.Fatalf("RuntimeBackendReport protocol type not advertised: %+v", contracts.ProtocolTypes)
}

func TestPluginContractsAdvertiseManagedRuntimeInstaller(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "plugin.contracts.json"))
	if err != nil {
		t.Fatal(err)
	}
	var contracts struct {
		Contracts []struct {
			Name       string   `json:"name"`
			Wire       string   `json:"wire"`
			GoType     string   `json:"goType"`
			Commands   []string `json:"commands"`
			Produces   []string `json:"produces"`
			Guarantees []string `json:"guarantees"`
		} `json:"contracts"`
	}
	if err := json.Unmarshal(data, &contracts); err != nil {
		t.Fatal(err)
	}
	for _, contract := range contracts.Contracts {
		if contract.Name != "ManagedRuntimeBundleInstaller" {
			continue
		}
		if contract.Wire != "json" ||
			contract.GoType != "github.com/GoCodeAlone/workflow-plugin-compute-container/container.ManagedRuntimeBundleInstaller" ||
			!slices.Contains(contract.Commands, "managed-runtime install") ||
			!slices.Contains(contract.Commands, "managed-runtime doctor") ||
			!slices.Contains(contract.Commands, "managed-runtime uninstall") ||
			!slices.Contains(contract.Commands, "managed-runtime reinstall") ||
			!slices.Contains(contract.Produces, "ManagedRuntimeInstallResult") ||
			!slices.Contains(contract.Produces, "ManagedRuntimeDoctorResult") ||
			!slices.Contains(contract.Produces, "ManagedRuntimeUninstallResult") ||
			!slices.Contains(contract.Produces, "ManagedRuntimeReinstallResult") ||
			!slices.Contains(contract.Guarantees, "scoped-install-root") ||
			!slices.Contains(contract.Guarantees, "pinned-artifact-checksum-signature-digests") {
			t.Fatalf("managed runtime installer contract incomplete: %+v", contract)
		}
		return
	}
	t.Fatalf("ManagedRuntimeBundleInstaller contract not advertised: %+v", contracts.Contracts)
}

func TestManagedRuntimeBundlePackagingScriptMatchesCatalogPins(t *testing.T) {
	script, err := os.ReadFile(filepath.Join("..", "scripts", "package-managed-runtime-bundle.sh"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"release_tag=\"v2.3.1\"",
		"artifact_name=\"nerdctl-full-2.3.1-linux-amd64.tar.gz\"",
		"artifact_digest=\"7a0d8efcf55b10b57d831541266adb9c6ec3d55b44ec041c95f6eb994d1faab9\"",
		"checksum_digest=\"8a0586ff11d4d5a5d19d59494a10af8c6d41dd95ca72ff347f62d5288bc5131a\"",
		"signature_digest=\"f87400e0923e22eab251328bd210bb9e8d3bba2b58dbbb84699622474344d68c\"",
		"grep -F \"${artifact_digest}  ${artifact_name}\"",
	} {
		if !strings.Contains(string(script), want) {
			t.Fatalf("managed runtime packaging script missing %q", want)
		}
	}
}
