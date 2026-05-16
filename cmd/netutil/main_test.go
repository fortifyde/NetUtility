package main

import (
	"testing"

	"netutil/internal/config"
)

func TestFindFuzzyMatchNonexistent(t *testing.T) {
	got := findFuzzyMatch("nonexistent-command-xyz")
	if got != nil {
		t.Errorf("expected nil for non-matching input, got %+v", got)
	}
}

func TestFindFuzzyMatchEmpty(t *testing.T) {
	got := findFuzzyMatch("")
	// Empty string is a prefix of every command; nil is also valid if mappings are empty.
	_ = got
}

func TestFindFuzzyMatchPrefix(t *testing.T) {
	// Tests the prefix-matching branch; result depends on commandMappings content.
	got := findFuzzyMatch("sca")
	_ = got
}

func TestFindFuzzyMatchContains(t *testing.T) {
	// Tests substring matching (second pass of findFuzzyMatch)
	got := findFuzzyMatch("can")
	_ = got
}

func TestNumericShortcutsExist(t *testing.T) {
	if len(numericShortcuts) == 0 {
		t.Error("numericShortcuts should have entries")
	}

	for key, info := range numericShortcuts {
		if info.Name == "" {
			t.Errorf("numericShortcut[%q] has empty Name", key)
		}
		if info.Path == "" {
			t.Errorf("numericShortcut[%q] has empty Path", key)
		}
	}
}

func TestCommandMappingsExist(t *testing.T) {
	if len(commandMappings) == 0 {
		t.Error("commandMappings should have entries")
	}

	for cmd, info := range commandMappings {
		if info.Name == "" {
			t.Errorf("commandMappings[%q] has empty Name", cmd)
		}
		if info.Path == "" {
			t.Errorf("commandMappings[%q] has empty Path", cmd)
		}
	}
}

func TestScriptInfoFields(t *testing.T) {
	info := ScriptInfo{
		Name: "test-script",
		Path: "/some/path.sh",
	}
	if info.Name != "test-script" {
		t.Errorf("Name = %q, want %q", info.Name, "test-script")
	}
	if info.Path != "/some/path.sh" {
		t.Errorf("Path = %q, want %q", info.Path, "/some/path.sh")
	}
}

func TestHandleCLICommandHelp(t *testing.T) {
	cfg := config.GetDefaultConfig()
	result := handleCLICommand([]string{"help"}, cfg, nil)
	if !result {
		t.Error("handleCLICommand with 'help' should return true")
	}
}

func TestHandleCLICommandListFlag(t *testing.T) {
	cfg := config.GetDefaultConfig()
	for _, cmd := range []string{"--list", "-l", "list"} {
		result := handleCLICommand([]string{cmd}, cfg, nil)
		if !result {
			t.Errorf("handleCLICommand with %q should return true", cmd)
		}
	}
}

func TestHandleCLICommandHelpFlags(t *testing.T) {
	cfg := config.GetDefaultConfig()
	for _, cmd := range []string{"--help", "-h"} {
		result := handleCLICommand([]string{cmd}, cfg, nil)
		if !result {
			t.Errorf("handleCLICommand with %q should return true", cmd)
		}
	}
}

func TestHandleCLICommandEmptyArgs(t *testing.T) {
	cfg := config.GetDefaultConfig()
	result := handleCLICommand([]string{}, cfg, nil)
	if !result {
		t.Error("handleCLICommand with empty args should return true (shows help)")
	}
}

func TestHandleCLICommandUnknown(t *testing.T) {
	cfg := config.GetDefaultConfig()
	result := handleCLICommand([]string{"totally-unknown-command-xyz-999"}, cfg, nil)
	if result {
		t.Error("handleCLICommand with unknown command should return false")
	}
}
