package metadata

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestNewScriptRegistry(t *testing.T) {
	registry := NewScriptRegistry("/test/path")

	if registry.scriptsDir != "/test/path" {
		t.Errorf("scriptsDir = %s, want /test/path", registry.scriptsDir)
	}
	if registry.Scripts == nil {
		t.Error("Scripts should be initialized")
	}
	if registry.Categories == nil {
		t.Error("Categories should be initialized")
	}
	if registry.Shortcuts == nil {
		t.Error("Shortcuts should be initialized")
	}
}

func TestLoadScriptMetadataValid(t *testing.T) {
	tempDir := t.TempDir()
	metaFile := filepath.Join(tempDir, "test.meta.yaml")

	yamlContent := `script:
  name: Test Script
  description: A test script
  category: discovery
  file: test.sh
  requires_root: true
  estimated_duration: "5m"
  cli_shortcuts:
    - test
    - ts
  keywords:
    - testing
    - example
  output:
    creates_files: true
    file_patterns:
      - "*.txt"
  tags:
    - test
  risk_level: low
  network_access: false
  modifies_system: false
  version: "1.0"
  author: "Test Author"
  last_updated: "2025-01-01"
`

	if err := os.WriteFile(metaFile, []byte(yamlContent), 0644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	registry := NewScriptRegistry(tempDir)
	metadata, err := registry.loadScriptMetadata(metaFile)

	if err != nil {
		t.Fatalf("loadScriptMetadata() error = %v", err)
	}

	if metadata.Script.Name != "Test Script" {
		t.Errorf("Name = %s, want Test Script", metadata.Script.Name)
	}
	if metadata.Script.Category != "discovery" {
		t.Errorf("Category = %s, want discovery", metadata.Script.Category)
	}
	if metadata.Script.File != "test.sh" {
		t.Errorf("File = %s, want test.sh", metadata.Script.File)
	}
	if !metadata.Script.RequiresRoot {
		t.Error("RequiresRoot should be true")
	}
	if len(metadata.Script.CLIShortcuts) != 2 {
		t.Errorf("len(CLIShortcuts) = %d, want 2", len(metadata.Script.CLIShortcuts))
	}
}

func TestLoadScriptMetadataMissingFields(t *testing.T) {
	tests := []struct {
		name        string
		yamlContent string
	}{
		{
			name: "missing name",
			yamlContent: `script:
  description: A test script
  category: discovery
  file: test.sh
`,
		},
		{
			name: "missing file",
			yamlContent: `script:
  name: Test Script
  description: A test script
  category: discovery
`,
		},
		{
			name: "missing category",
			yamlContent: `script:
  name: Test Script
  description: A test script
  file: test.sh
`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tempDir := t.TempDir()
			metaFile := filepath.Join(tempDir, "test.meta.yaml")

			if err := os.WriteFile(metaFile, []byte(tt.yamlContent), 0644); err != nil {
				t.Fatalf("Failed to create test file: %v", err)
			}

			registry := NewScriptRegistry(tempDir)
			_, err := registry.loadScriptMetadata(metaFile)

			if err == nil {
				t.Error("loadScriptMetadata() should return error for missing required fields")
			}
		})
	}
}

func TestLoadScriptMetadataInvalidYAML(t *testing.T) {
	tempDir := t.TempDir()
	metaFile := filepath.Join(tempDir, "test.meta.yaml")

	if err := os.WriteFile(metaFile, []byte("{invalid yaml"), 0644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	registry := NewScriptRegistry(tempDir)
	_, err := registry.loadScriptMetadata(metaFile)

	if err == nil {
		t.Error("loadScriptMetadata() should return error for invalid YAML")
	}
}

func TestAddScript(t *testing.T) {
	registry := NewScriptRegistry("/test")

	metadata := ScriptMetadata{}
	metadata.Script.Name = "Test"
	metadata.Script.Category = "discovery"
	metadata.Script.File = "test.sh"

	registry.addScript(metadata)

	if len(registry.Scripts) != 1 {
		t.Errorf("len(Scripts) = %d, want 1", len(registry.Scripts))
	}
	if registry.Scripts[0].Script.Name != "Test" {
		t.Errorf("Scripts[0].Name = %s, want Test", registry.Scripts[0].Script.Name)
	}
}

func TestBuildIndices(t *testing.T) {
	registry := NewScriptRegistry("/test")

	// Add multiple scripts with shortcuts
	script1 := ScriptMetadata{}
	script1.Script.Name = "Script A"
	script1.Script.Category = "discovery"
	script1.Script.File = "a.sh"
	script1.Script.CLIShortcuts = []string{"sa", "script-a"}

	script2 := ScriptMetadata{}
	script2.Script.Name = "Script B"
	script2.Script.Category = "discovery"
	script2.Script.File = "b.sh"
	script2.Script.CLIShortcuts = []string{"sb"}

	script3 := ScriptMetadata{}
	script3.Script.Name = "Script C"
	script3.Script.Category = "scanning"
	script3.Script.File = "c.sh"
	script3.Script.CLIShortcuts = []string{"sc"}

	registry.Scripts = []ScriptMetadata{script1, script2, script3}
	registry.buildIndices()

	// Test category index
	if len(registry.Categories["discovery"]) != 2 {
		t.Errorf("len(Categories[discovery]) = %d, want 2", len(registry.Categories["discovery"]))
	}
	if len(registry.Categories["scanning"]) != 1 {
		t.Errorf("len(Categories[scanning]) = %d, want 1", len(registry.Categories["scanning"]))
	}

	// Test shortcuts index
	if len(registry.Shortcuts) != 4 {
		t.Errorf("len(Shortcuts) = %d, want 4", len(registry.Shortcuts))
	}
	if script, exists := registry.Shortcuts["sa"]; !exists || script.Script.Name != "Script A" {
		t.Error("Shortcut 'sa' should map to Script A")
	}

	// Test scripts are sorted within categories
	discoveryScripts := registry.Categories["discovery"]
	if discoveryScripts[0].Script.Name != "Script A" {
		t.Errorf("First discovery script should be Script A, got %s", discoveryScripts[0].Script.Name)
	}
}

func TestGetScriptByShortcut(t *testing.T) {
	registry := NewScriptRegistry("/test")

	script := ScriptMetadata{}
	script.Script.Name = "Test Script"
	script.Script.Category = "discovery"
	script.Script.File = "test.sh"
	script.Script.CLIShortcuts = []string{"test", "TS"}

	registry.Scripts = []ScriptMetadata{script}
	registry.buildIndices()

	// Test exact match
	found, exists := registry.GetScriptByShortcut("test")
	if !exists {
		t.Error("GetScriptByShortcut(test) should return existing script")
	}
	if found.Script.Name != "Test Script" {
		t.Errorf("Found script name = %s, want Test Script", found.Script.Name)
	}

	// Test case insensitive
	found, exists = registry.GetScriptByShortcut("TS")
	if !exists {
		t.Error("GetScriptByShortcut should be case insensitive")
	}

	// Test non-existent shortcut
	_, exists = registry.GetScriptByShortcut("nonexistent")
	if exists {
		t.Error("GetScriptByShortcut(nonexistent) should return false")
	}
}

func TestGetScriptsByCategory(t *testing.T) {
	registry := NewScriptRegistry("/test")

	script1 := ScriptMetadata{}
	script1.Script.Name = "Script 1"
	script1.Script.Category = "discovery"
	script1.Script.File = "1.sh"

	script2 := ScriptMetadata{}
	script2.Script.Name = "Script 2"
	script2.Script.Category = "discovery"
	script2.Script.File = "2.sh"

	script3 := ScriptMetadata{}
	script3.Script.Name = "Script 3"
	script3.Script.Category = "scanning"
	script3.Script.File = "3.sh"

	registry.Scripts = []ScriptMetadata{script1, script2, script3}
	registry.buildIndices()

	discoveryScripts := registry.GetScriptsByCategory("discovery")
	if len(discoveryScripts) != 2 {
		t.Errorf("len(discoveryScripts) = %d, want 2", len(discoveryScripts))
	}

	scanningScripts := registry.GetScriptsByCategory("scanning")
	if len(scanningScripts) != 1 {
		t.Errorf("len(scanningScripts) = %d, want 1", len(scanningScripts))
	}

	nonexistent := registry.GetScriptsByCategory("nonexistent")
	if nonexistent != nil {
		t.Error("GetScriptsByCategory(nonexistent) should return nil")
	}
}

func TestGetAllCategories(t *testing.T) {
	registry := NewScriptRegistry("/test")

	// Create scripts in different categories
	categories := []string{"host-config", "utilities", "discovery", "scanning"}
	for _, cat := range categories {
		script := ScriptMetadata{}
		script.Script.Name = "Script"
		script.Script.Category = cat
		script.Script.File = "test.sh"
		registry.Scripts = append(registry.Scripts, script)
	}

	registry.buildIndices()
	allCategories := registry.GetAllCategories()

	// Should return categories in the predefined workflow order
	expectedOrder := []string{"host-config", "discovery", "scanning", "utilities"}
	if len(allCategories) != len(expectedOrder) {
		t.Errorf("len(allCategories) = %d, want %d", len(allCategories), len(expectedOrder))
	}

	for i, expected := range expectedOrder {
		if i >= len(allCategories) || allCategories[i] != expected {
			t.Errorf("Category at index %d = %s, want %s", i, allCategories[i], expected)
		}
	}
	}
func TestGetAllCategoriesWithUnknown(t *testing.T) {
	registry := NewScriptRegistry("/test")

	// Add a category not in the predefined order
	script := ScriptMetadata{}
	script.Script.Name = "Script"
	script.Script.Category = "custom-category"
	script.Script.File = "test.sh"
	registry.Scripts = append(registry.Scripts, script)

	registry.buildIndices()
	allCategories := registry.GetAllCategories()

	// Should include the custom category
	found := false
	for _, cat := range allCategories {
		if cat == "custom-category" {
			found = true
			break
		}
	}

	if !found {
		t.Error("GetAllCategories should include custom categories")
	}
}

func TestSearchScripts(t *testing.T) {
	registry := NewScriptRegistry("/test")

	script1 := ScriptMetadata{}
	script1.Script.Name = "Network Discovery"
	script1.Script.Description = "Discover network devices"
	script1.Script.Category = "discovery"
	script1.Script.File = "1.sh"
	script1.Script.Keywords = []string{"network", "discovery"}
	script1.Script.Tags = []string{"tcp"}

	script2 := ScriptMetadata{}
	script2.Script.Name = "Port Scanner"
	script2.Script.Description = "Scan network ports"
	script2.Script.Category = "scanning"
	script2.Script.File = "2.sh"
	script2.Script.Keywords = []string{"ports", "nmap"}
	script2.Script.Tags = []string{"tcp"}

	script3 := ScriptMetadata{}
	script3.Script.Name = "File Server"
	script3.Script.Description = "Start file server"
	script3.Script.Category = "utilities"
	script3.Script.File = "3.sh"
	script3.Script.Keywords = []string{"http", "server"}

	registry.Scripts = []ScriptMetadata{script1, script2, script3}

	tests := []struct {
		query string
		want  int
	}{
		{"network", 2},     // Matches script1 name and script2 description
		{"discovery", 1},   // Matches script1 name
		{"ports", 1},       // Matches script2 keyword
		{"tcp", 2},         // Matches script1 and script2 tags
		{"server", 1},      // Matches script3 name and keyword
		{"nonexistent", 0}, // No matches
		{"NETWORK", 2},     // Case insensitive
	}

	for _, tt := range tests {
		t.Run(tt.query, func(t *testing.T) {
			results := registry.SearchScripts(tt.query)
			if len(results) != tt.want {
				t.Errorf("SearchScripts(%s) returned %d results, want %d", tt.query, len(results), tt.want)
			}
		})
	}
}

func TestMatchesQuery(t *testing.T) {
	registry := NewScriptRegistry("/test")

	script := ScriptMetadata{}
	script.Script.Name = "Test Script"
	script.Script.Description = "A test description"
	script.Script.Keywords = []string{"keyword1", "keyword2"}
	script.Script.Tags = []string{"tag1"}
	script.Script.CLIShortcuts = []string{"test", "ts"}

	tests := []struct {
		query   string
		matches bool
	}{
		{"test", true},
		{"Test", true},
		{"description", true},
		{"keyword1", true},
		{"tag1", true},
		{"ts", true},
		{"nonexistent", false},
	}

	for _, tt := range tests {
		t.Run(tt.query, func(t *testing.T) {
			matches := registry.matchesQuery(script, strings.ToLower(tt.query))
			if matches != tt.matches {
				t.Errorf("matchesQuery(%s) = %v, want %v", tt.query, matches, tt.matches)
			}
		})
	}
}

func TestFuzzyMatchScript(t *testing.T) {
	registry := NewScriptRegistry("/test")

	script1 := ScriptMetadata{}
	script1.Script.Name = "Network Discovery"
	script1.Script.Category = "discovery"
	script1.Script.File = "netdiscover.sh"
	script1.Script.CLIShortcuts = []string{"netdiscover", "nd"}
	script1.Script.Keywords = []string{"network"}

	script2 := ScriptMetadata{}
	script2.Script.Name = "Port Scanner"
	script2.Script.Category = "scanning"
	script2.Script.File = "portscan.sh"
	script2.Script.CLIShortcuts = []string{"portscan", "ps"}
	script2.Script.Keywords = []string{"scanning"}

	registry.Scripts = []ScriptMetadata{script1, script2}
	registry.buildIndices()

	tests := []struct {
		input     string
		wantFound bool
		wantName  string
	}{
		{"netdiscover", true, "Network Discovery"}, // Exact shortcut match
		{"nd", true, "Network Discovery"},          // Exact shortcut match
		{"net", true, "Network Discovery"},         // Prefix match
		{"discover", true, "Network Discovery"},    // Contains match in shortcut
		{"network", true, "Network Discovery"},     // Keyword match
		{"port", true, "Port Scanner"},             // Prefix match
		{"scanning", true, "Port Scanner"},         // Keyword match
		{"xyz", false, ""},                         // No match
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			script, found := registry.FuzzyMatchScript(tt.input)
			if found != tt.wantFound {
				t.Errorf("FuzzyMatchScript(%s) found = %v, want %v", tt.input, found, tt.wantFound)
			}
			if found && script.Script.Name != tt.wantName {
				t.Errorf("FuzzyMatchScript(%s) returned %s, want %s", tt.input, script.Script.Name, tt.wantName)
			}
		})
	}
}

func TestGetScriptPath(t *testing.T) {
	registry := NewScriptRegistry("/test/scripts")

	script := ScriptMetadata{}
	script.Script.Name = "Test"
	script.Script.Category = "discovery"
	script.Script.File = "test.sh"

	path := registry.GetScriptPath(script)
	expected := filepath.Join("/test/scripts", "discovery", "test.sh")

	if path != expected {
		t.Errorf("GetScriptPath() = %s, want %s", path, expected)
	}
}

func TestValidateScriptFileNotFound(t *testing.T) {
	tempDir := t.TempDir()
	registry := NewScriptRegistry(tempDir)

	// Create metadata for non-existent script
	script := ScriptMetadata{}
	script.Script.Name = "Test"
	script.Script.Category = "discovery"
	script.Script.File = "nonexistent.sh"

	err := registry.ValidateScript(script)
	if err == nil {
		t.Error("ValidateScript() should return error for non-existent script file")
	}
}

func TestValidateScriptFileExists(t *testing.T) {
	tempDir := t.TempDir()
	categoryDir := filepath.Join(tempDir, "discovery")
	if err := os.MkdirAll(categoryDir, 0755); err != nil {
		t.Fatalf("Failed to create category dir: %v", err)
	}

	scriptFile := filepath.Join(categoryDir, "test.sh")
	if err := os.WriteFile(scriptFile, []byte("#!/bin/sh\necho test"), 0755); err != nil {
		t.Fatalf("Failed to create script file: %v", err)
	}

	registry := NewScriptRegistry(tempDir)

	script := ScriptMetadata{}
	script.Script.Name = "Test"
	script.Script.Category = "discovery"
	script.Script.File = "test.sh"

	err := registry.ValidateScript(script)
	if err != nil {
		t.Errorf("ValidateScript() error = %v, want nil", err)
	}
}

func TestParameterStructure(t *testing.T) {
	// Test that Parameter structure can be marshaled/unmarshaled correctly
	param := Parameter{
		Name:        "target",
		Type:        "string",
		Description: "Target IP or CIDR",
		Required:    true,
		Default:     "192.168.1.0/24",
	}
	param.Validation.Pattern = `^\d+\.\d+\.\d+\.\d+`

	data, err := yaml.Marshal(param)
	if err != nil {
		t.Fatalf("Failed to marshal Parameter: %v", err)
	}

	var unmarshaled Parameter
	if err := yaml.Unmarshal(data, &unmarshaled); err != nil {
		t.Fatalf("Failed to unmarshal Parameter: %v", err)
	}

	if unmarshaled.Name != param.Name {
		t.Errorf("Name = %s, want %s", unmarshaled.Name, param.Name)
	}
	if unmarshaled.Required != param.Required {
		t.Errorf("Required = %v, want %v", unmarshaled.Required, param.Required)
	}
}

func TestValidateScript_MissingTool(t *testing.T) {
	dir := t.TempDir()
	scriptFile := filepath.Join(dir, "scan.sh")
	if err := os.WriteFile(scriptFile, []byte("#!/bin/sh\necho test"), 0755); err != nil {
		t.Fatal(err)
	}
	registry := NewScriptRegistry(dir)
	meta := ScriptMetadata{
		Script: ScriptInfo{
			Category: ".",
			File:     "scan.sh",
			Dependencies: Dependencies{
				Tools: []Tool{
					{Name: "definitely-not-a-real-tool-xyz123", CheckCommand: "definitely-not-a-real-tool-xyz123"},
				},
			},
		},
	}
	err := registry.ValidateScript(meta)
	if err == nil {
		t.Error("ValidateScript should return error for missing tool dependency")
	}
	if err != nil && !strings.Contains(err.Error(), "definitely-not-a-real-tool-xyz123") {
		t.Errorf("error should mention the missing tool, got: %v", err)
	}
}

func TestValidateScript_PresentTool(t *testing.T) {
	dir := t.TempDir()
	scriptFile := filepath.Join(dir, "scan.sh")
	if err := os.WriteFile(scriptFile, []byte("#!/bin/sh\necho test"), 0755); err != nil {
		t.Fatal(err)
	}
	registry := NewScriptRegistry(dir)
	meta := ScriptMetadata{
		Script: ScriptInfo{
			Category: ".",
			File:     "scan.sh",
			Dependencies: Dependencies{
				Tools: []Tool{
					{Name: "sh", CheckCommand: "sh"},
				},
			},
		},
	}
	err := registry.ValidateScript(meta)
	if err != nil {
		t.Errorf("ValidateScript should not error for 'sh' tool: %v", err)
	}
}

func TestLoadMetadataIntegration(t *testing.T) {
	tempDir := t.TempDir()

	// Create directory structure
	discoveryDir := filepath.Join(tempDir, "discovery")
	if err := os.MkdirAll(discoveryDir, 0755); err != nil {
		t.Fatalf("Failed to create discovery dir: %v", err)
	}

	// Create metadata file
	metaFile := filepath.Join(discoveryDir, "test.meta.yaml")
	yamlContent := `script:
  name: Test Script
  description: A test script
  category: discovery
  file: test.sh
  requires_root: true
  estimated_duration: "5m"
  cli_shortcuts:
    - test
  keywords:
    - testing
  output:
    creates_files: false
  tags:
    - test
  risk_level: low
  network_access: false
  modifies_system: false
  version: "1.0"
  author: "Test"
  last_updated: "2025-01-01"
`
	if err := os.WriteFile(metaFile, []byte(yamlContent), 0644); err != nil {
		t.Fatalf("Failed to create meta file: %v", err)
	}

	// Load registry
	registry := NewScriptRegistry(tempDir)
	if err := registry.LoadMetadata(); err != nil {
		t.Fatalf("LoadMetadata() error = %v", err)
	}

	// Verify loaded
	if len(registry.Scripts) != 1 {
		t.Errorf("len(Scripts) = %d, want 1", len(registry.Scripts))
	}

	script, exists := registry.GetScriptByShortcut("test")
	if !exists {
		t.Error("Script should be accessible by shortcut")
	}
	if script.Script.Name != "Test Script" {
		t.Errorf("Script name = %s, want Test Script", script.Script.Name)
	}

	categories := registry.GetAllCategories()
	if len(categories) == 0 {
		t.Error("Should have at least one category")
	}
}
