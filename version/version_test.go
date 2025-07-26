package version

import (
	"strings"
	"testing"
)

func TestGetVersionInfo(t *testing.T) {
	info := GetVersionInfo()

	// Check that all fields are populated
	if info.Version == "" {
		t.Error("Version should not be empty")
	}

	if info.CommitSHA == "" {
		t.Error("CommitSHA should not be empty")
	}

	if info.BuildTime == "" {
		t.Error("BuildTime should not be empty")
	}

	if info.GoVersion == "" {
		t.Error("GoVersion should not be empty")
	}

	if info.OS == "" {
		t.Error("OS should not be empty")
	}

	if info.Arch == "" {
		t.Error("Arch should not be empty")
	}
}

func TestString(t *testing.T) {
	versionStr := String()

	// Check that the string contains expected components
	if !strings.Contains(versionStr, "flacon version") {
		t.Error("Version string should contain 'flacon version'")
	}

	if !strings.Contains(versionStr, "commit:") {
		t.Error("Version string should contain commit information")
	}

	if !strings.Contains(versionStr, "built:") {
		t.Error("Version string should contain build time")
	}
}

func TestFullString(t *testing.T) {
	fullStr := FullString()

	// Check that the string contains expected components
	if !strings.Contains(fullStr, "flacon version") {
		t.Error("Full version string should contain 'flacon version'")
	}

	if !strings.Contains(fullStr, "Commit SHA:") {
		t.Error("Full version string should contain commit SHA")
	}

	if !strings.Contains(fullStr, "Build Time:") {
		t.Error("Full version string should contain build time")
	}

	if !strings.Contains(fullStr, "Go Version:") {
		t.Error("Full version string should contain Go version")
	}

	if !strings.Contains(fullStr, "OS/Arch:") {
		t.Error("Full version string should contain OS/Arch information")
	}
}

func TestDefaultValues(t *testing.T) {
	// Test that default values are set correctly
	if Version != "dev" {
		t.Errorf("Expected default Version to be 'dev', got '%s'", Version)
	}

	if CommitSHA != "unknown" {
		t.Errorf("Expected default CommitSHA to be 'unknown', got '%s'", CommitSHA)
	}

	if BuildTime != "unknown" {
		t.Errorf("Expected default BuildTime to be 'unknown', got '%s'", BuildTime)
	}
}
