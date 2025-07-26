package version

import (
	"fmt"
	"runtime"
)

// These variables are set during build time using ldflags
var (
	Version   = "dev"
	CommitSHA = "unknown"
	BuildTime = "unknown"
	GoVersion = runtime.Version()
)

// Info contains version information
type Info struct {
	Version   string `json:"version" yaml:"version"`
	CommitSHA string `json:"commit_sha" yaml:"commit_sha"`
	BuildTime string `json:"build_time" yaml:"build_time"`
	GoVersion string `json:"go_version" yaml:"go_version"`
	OS        string `json:"os" yaml:"os"`
	Arch      string `json:"arch" yaml:"arch"`
}

// GetVersionInfo returns the current version information
func GetVersionInfo() Info {
	return Info{
		Version:   Version,
		CommitSHA: CommitSHA,
		BuildTime: BuildTime,
		GoVersion: GoVersion,
		OS:        runtime.GOOS,
		Arch:      runtime.GOARCH,
	}
}

// String returns a formatted version string
func String() string {
	return fmt.Sprintf("flacon version %s (commit: %s, built: %s)", Version, CommitSHA, BuildTime)
}

// FullString returns detailed version information
func FullString() string {
	info := GetVersionInfo()
	return fmt.Sprintf(`flacon version %s
  Commit SHA: %s
  Build Time: %s
  Go Version: %s
  OS/Arch:    %s/%s`,
		info.Version, info.CommitSHA, info.BuildTime, info.GoVersion, info.OS, info.Arch)
}
