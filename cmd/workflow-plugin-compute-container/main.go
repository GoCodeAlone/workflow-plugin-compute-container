package main

import (
	"context"
	"os"

	plugin "github.com/GoCodeAlone/workflow-plugin-compute-container/internal"
	sdk "github.com/GoCodeAlone/workflow/plugin/external/sdk"
)

var version = "0.0.0"

func main() {
	if len(os.Args) > 1 && os.Args[1] == "managed-runtime" {
		os.Exit(plugin.RunManagedRuntimeCLI(context.Background(), os.Args[1:], os.Stdout, os.Stderr))
	}
	plugin.Version = version
	sdk.Serve(plugin.NewPlugin(),
		sdk.WithBuildVersion(sdk.ResolveBuildVersion(plugin.Version)),
	)
}
