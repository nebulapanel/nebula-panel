package buildinfo

// These are set at build time via -ldflags.
// Example:
//   -X github.com/nebula-panel/nebula/apps/api/internal/buildinfo.Version=v1.0.0
//   -X github.com/nebula-panel/nebula/apps/api/internal/buildinfo.GitSHA=abc123
//   -X github.com/nebula-panel/nebula/apps/api/internal/buildinfo.BuildTime=2026-02-12T00:00:00Z
var (
	Version   = "dev"
	GitSHA    = ""
	BuildTime = ""
)

