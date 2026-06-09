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
		RuntimeAdaptersRef string `json:"runtimeAdaptersRef"`
		Dependencies       []struct {
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
			if dependency.Constraint != ">=0.5.0" {
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
	if len(catalog.RuntimeBackends) != 1 {
		t.Fatalf("runtime backend catalog incomplete: %+v", catalog)
	}
	backend := catalog.RuntimeBackends[0]
	if backend.BackendID != "docker-compatible" ||
		!slices.Contains(backend.Tools, core.ContainerRuntimePodman) ||
		!slices.Contains(backend.Tools, core.ContainerRuntimeDocker) ||
		!slices.Contains(backend.Tools, core.ContainerRuntimeNerdctl) ||
		!slices.Contains(backend.ExecutorProviders, container.SandboxedCommandProviderName) ||
		!slices.Contains(backend.ExecutorProviders, container.SandboxedContainerBuildProviderName) {
		t.Fatalf("runtime backend catalog missing Docker-compatible entries: %+v", backend)
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
			slices.Contains(typ.ProducedBy, "DockerCompatibleRuntimeProbes") {
			return
		}
	}
	t.Fatalf("RuntimeBackendReport protocol type not advertised: %+v", contracts.ProtocolTypes)
}
