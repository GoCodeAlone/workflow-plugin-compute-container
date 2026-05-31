package main

import (
	plugin "github.com/GoCodeAlone/workflow-plugin-compute-container/internal"
	sdk "github.com/GoCodeAlone/workflow/plugin/external/sdk"
)

var version = "0.0.0"

func main() {
	plugin.Version = version
	sdk.Serve(plugin.NewPlugin(),
		sdk.WithBuildVersion(sdk.ResolveBuildVersion(plugin.Version)),
	)
}
