// Package internal implements the workflow-plugin-compute-container plugin.
package internal

import (
	sdk "github.com/GoCodeAlone/workflow/plugin/external/sdk"
)

// Version is set at build time via -ldflags
// "-X github.com/GoCodeAlone/workflow-plugin-compute-container/internal.Version=X.Y.Z".
var Version = "0.0.0"

// ComputeContainerPlugin exposes command/container-build runtime adapter metadata.
type ComputeContainerPlugin struct{}

// NewPlugin returns a new plugin instance. main.go calls sdk.Serve(NewPlugin()).
func NewPlugin() sdk.PluginProvider {
	return &ComputeContainerPlugin{}
}

// Manifest returns plugin metadata used by the workflow engine for discovery.
func (p *ComputeContainerPlugin) Manifest() sdk.PluginManifest {
	return sdk.PluginManifest{
		Name:        "workflow-plugin-compute-container",
		Version:     Version,
		Author:      "GoCodeAlone",
		Description: "Public command and container-build runtime adapter plugin for Workflow Compute.",
	}
}
