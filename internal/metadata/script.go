package metadata

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// Parameter represents a script parameter definition
type Parameter struct {
	Name        string `yaml:"name"`
	Type        string `yaml:"type"`
	Description string `yaml:"description"`
	Required    bool   `yaml:"required"`
	Default     string `yaml:"default,omitempty"`
	Validation  struct {
		Pattern string `yaml:"pattern,omitempty"`
		Range   struct {
			Min int `yaml:"min,omitempty"`
			Max int `yaml:"max,omitempty"`
		} `yaml:"range,omitempty"`
		Choices []struct {
			Value       string `yaml:"value"`
			Description string `yaml:"description"`
		} `yaml:"choices,omitempty"`
	} `yaml:"validation,omitempty"`
}

// Dependency represents external dependencies
type Dependency struct {
	Tools []struct {
		Name         string `yaml:"name"`
		Package      string `yaml:"package"`
		CheckCommand string `yaml:"check_command"`
	} `yaml:"tools,omitempty"`
	Scripts []string `yaml:"scripts,omitempty"`
}

// Output represents script output information
type Output struct {
	CreatesFiles     bool     `yaml:"creates_files"`
	FilePatterns     []string `yaml:"file_patterns,omitempty"`
	WorkspaceSubdirs []string `yaml:"workspace_subdirs,omitempty"`
}

// Example represents usage examples
type Example struct {
	Description string `yaml:"description"`
	Command     string `yaml:"command"`
}

// ScriptMetadata represents the complete metadata for a script
type ScriptMetadata struct {
	Script struct {
		Name              string      `yaml:"name"`
		Description       string      `yaml:"description"`
		Category          string      `yaml:"category"`
		Subcategory       string      `yaml:"subcategory,omitempty"`
		File              string      `yaml:"file"`
		RequiresRoot      bool        `yaml:"requires_root"`
		EstimatedDuration string      `yaml:"estimated_duration"`
		CLIShortcuts      []string    `yaml:"cli_shortcuts"`
		Keywords          []string    `yaml:"keywords"`
		Parameters        []Parameter `yaml:"parameters,omitempty"`
		Dependencies      Dependency  `yaml:"dependencies,omitempty"`
		Output            Output      `yaml:"output"`
		Tags              []string    `yaml:"tags"`
		RiskLevel         string      `yaml:"risk_level"`
		NetworkAccess     bool        `yaml:"network_access"`
		ModifiesSystem    bool        `yaml:"modifies_system"`
		Examples          []Example   `yaml:"examples,omitempty"`
		Version           string      `yaml:"version"`
		Author            string      `yaml:"author"`
		LastUpdated       string      `yaml:"last_updated"`
	} `yaml:"script"`
}

// ScriptRegistry manages all script metadata
type ScriptRegistry struct {
	Scripts    []ScriptMetadata
	Categories map[string][]ScriptMetadata
	Shortcuts  map[string]ScriptMetadata
	scriptsDir string
}

// NewScriptRegistry creates a new script registry
func NewScriptRegistry(scriptsDir string) *ScriptRegistry {
	return &ScriptRegistry{
		Scripts:    make([]ScriptMetadata, 0),
		Categories: make(map[string][]ScriptMetadata),
		Shortcuts:  make(map[string]ScriptMetadata),
		scriptsDir: scriptsDir,
	}
}

// LoadMetadata loads all script metadata from the scripts directory
func (r *ScriptRegistry) LoadMetadata() error {
	err := filepath.Walk(r.scriptsDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Look for .meta.yaml files
		if strings.HasSuffix(info.Name(), ".meta.yaml") {
			metadata, err := r.loadScriptMetadata(path)
			if err != nil {
				return fmt.Errorf("failed to load metadata from %s: %w", path, err)
			}

			r.addScript(metadata)
		}

		return nil
	})

	if err != nil {
		return fmt.Errorf("failed to walk scripts directory: %w", err)
	}

	r.buildIndices()
	return nil
}

// loadScriptMetadata loads metadata from a single file
func (r *ScriptRegistry) loadScriptMetadata(filepath string) (ScriptMetadata, error) {
	var metadata ScriptMetadata

	data, err := os.ReadFile(filepath)
	if err != nil {
		return metadata, fmt.Errorf("failed to read file: %w", err)
	}

	err = yaml.Unmarshal(data, &metadata)
	if err != nil {
		return metadata, fmt.Errorf("failed to parse YAML: %w", err)
	}

	// Validate required fields
	if metadata.Script.Name == "" || metadata.Script.File == "" || metadata.Script.Category == "" {
		return metadata, fmt.Errorf("missing required fields: name, file, or category")
	}

	return metadata, nil
}

// addScript adds a script to the registry
func (r *ScriptRegistry) addScript(metadata ScriptMetadata) {
	r.Scripts = append(r.Scripts, metadata)
}

// buildIndices builds lookup indices for faster access
func (r *ScriptRegistry) buildIndices() {
	// Clear existing indices
	r.Categories = make(map[string][]ScriptMetadata)
	r.Shortcuts = make(map[string]ScriptMetadata)

	for _, script := range r.Scripts {
		// Build category index
		category := script.Script.Category
		r.Categories[category] = append(r.Categories[category], script)

		// Build shortcuts index
		for _, shortcut := range script.Script.CLIShortcuts {
			r.Shortcuts[strings.ToLower(shortcut)] = script
		}
	}

	// Sort scripts within each category by name
	for category := range r.Categories {
		sort.Slice(r.Categories[category], func(i, j int) bool {
			return r.Categories[category][i].Script.Name < r.Categories[category][j].Script.Name
		})
	}
}

// GetScriptByShortcut returns a script by its CLI shortcut
func (r *ScriptRegistry) GetScriptByShortcut(shortcut string) (ScriptMetadata, bool) {
	script, exists := r.Shortcuts[strings.ToLower(shortcut)]
	return script, exists
}

// GetScriptsByCategory returns all scripts in a category
func (r *ScriptRegistry) GetScriptsByCategory(category string) []ScriptMetadata {
	return r.Categories[category]
}

// GetAllCategories returns all available categories in fixed order
func (r *ScriptRegistry) GetAllCategories() []string {
	// Define the desired category order
	desiredOrder := []string{"system", "network", "vulnerability", "advanced", "config"}

	// Build ordered list of existing categories
	var orderedCategories []string

	// Add categories in desired order if they exist
	for _, category := range desiredOrder {
		if _, exists := r.Categories[category]; exists {
			orderedCategories = append(orderedCategories, category)
		}
	}

	// Add any remaining categories not in the predefined order (for backward compatibility)
	for category := range r.Categories {
		found := false
		for _, ordered := range orderedCategories {
			if category == ordered {
				found = true
				break
			}
		}
		if !found {
			orderedCategories = append(orderedCategories, category)
		}
	}

	return orderedCategories
}

// SearchScripts searches for scripts by keyword
func (r *ScriptRegistry) SearchScripts(query string) []ScriptMetadata {
	query = strings.ToLower(query)
	var results []ScriptMetadata

	for _, script := range r.Scripts {
		// Search in name, description, keywords, and tags
		if r.matchesQuery(script, query) {
			results = append(results, script)
		}
	}

	return results
}

// matchesQuery checks if a script matches the search query
func (r *ScriptRegistry) matchesQuery(script ScriptMetadata, query string) bool {
	// Check name and description
	if strings.Contains(strings.ToLower(script.Script.Name), query) ||
		strings.Contains(strings.ToLower(script.Script.Description), query) {
		return true
	}

	// Check keywords
	for _, keyword := range script.Script.Keywords {
		if strings.Contains(strings.ToLower(keyword), query) {
			return true
		}
	}

	// Check tags
	for _, tag := range script.Script.Tags {
		if strings.Contains(strings.ToLower(tag), query) {
			return true
		}
	}

	// Check CLI shortcuts
	for _, shortcut := range script.Script.CLIShortcuts {
		if strings.Contains(strings.ToLower(shortcut), query) {
			return true
		}
	}

	return false
}

// FuzzyMatchScript finds the best fuzzy match for a command
func (r *ScriptRegistry) FuzzyMatchScript(input string) (ScriptMetadata, bool) {
	input = strings.ToLower(input)

	// First, try exact shortcut match
	if script, exists := r.GetScriptByShortcut(input); exists {
		return script, true
	}

	// Try prefix matches on shortcuts
	for shortcut, script := range r.Shortcuts {
		if strings.HasPrefix(shortcut, input) {
			return script, true
		}
	}

	// Try contains matches on shortcuts
	for shortcut, script := range r.Shortcuts {
		if strings.Contains(shortcut, input) {
			return script, true
		}
	}

	// Try keyword matches
	for _, script := range r.Scripts {
		for _, keyword := range script.Script.Keywords {
			if strings.Contains(strings.ToLower(keyword), input) {
				return script, true
			}
		}
	}

	return ScriptMetadata{}, false
}

// GetScriptPath returns the full path to a script file
func (r *ScriptRegistry) GetScriptPath(script ScriptMetadata) string {
	return filepath.Join(r.scriptsDir, script.Script.Category, script.Script.File)
}

// ValidateScript checks if a script file exists and dependencies are met
func (r *ScriptRegistry) ValidateScript(script ScriptMetadata) error {
	scriptPath := r.GetScriptPath(script)

	// Check if script file exists
	if _, err := os.Stat(scriptPath); os.IsNotExist(err) {
		return fmt.Errorf("script file not found: %s", scriptPath)
	}

	// Check tool dependencies
	for _, tool := range script.Script.Dependencies.Tools {
		if tool.CheckCommand != "" {
			// This would need to be implemented to actually check the command
			// For now, we'll just validate the structure
		}
	}

	return nil
}
