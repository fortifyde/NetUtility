package ui

import (
	"strings"
	"testing"
)

func TestFormatCategoryName(t *testing.T) {
	tui := &TUI{str: stringsEN}
	tests := []struct {
		key  string
		want string
	}{
		{"advanced", "Advanced Tools"},
		{"scanning", "Port Scanning"},
		{"host-config", "Host Configuration"},
		{"utilities", "System Utilities"},
		{"discovery", "Network Discovery"},
		{"unknown-key", "Unknown-key"},
	}
	for _, tt := range tests {
		t.Run(tt.key, func(t *testing.T) {
			if got := tui.formatCategoryName(tt.key); got != tt.want {
				t.Errorf("formatCategoryName(%q) = %q, want %q", tt.key, got, tt.want)
			}
		})
	}
}

func TestMergeInterfaceTasks(t *testing.T) {
	ifaceTask := Task{Name: "Manage Network Interfaces", CanonicalName: "Manage Network Interfaces", Description: "Manage interface states", Script: "/scripts/network_interfaces.sh"}
	vlanTask := Task{Name: "Manage VLAN Interfaces", CanonicalName: "Manage VLAN Interfaces", Description: "Create VLAN subinterfaces", Script: "/scripts/add_vlan.sh"}
	otherTask := Task{Name: "Configure IP Addresses", CanonicalName: "Configure IP Addresses", Description: "Set IPs", Script: "/scripts/configure_ip.sh"}

	input := []Category{
		{
			Name:  "Host Configuration",
			Tasks: []Task{ifaceTask, vlanTask, otherTask},
		},
		{
			Name:  "System Utilities",
			Tasks: []Task{{Name: "Backup", Script: "/scripts/backup.sh"}},
		},
	}

	result := mergeInterfaceTasks(input, stringsEN)

	hostCat := result[0]
	if len(hostCat.Tasks) != 2 {
		t.Fatalf("expected 2 tasks in Host Configuration, got %d", len(hostCat.Tasks))
	}

	composite := hostCat.Tasks[0]
	if composite.Name != "Configure Interfaces" {
		t.Errorf("composite name = %q, want %q", composite.Name, "Configure Interfaces")
	}
	if len(composite.SubTasks) != 2 {
		t.Fatalf("expected 2 sub-tasks, got %d", len(composite.SubTasks))
	}
	if composite.SubTasks[0].Name != "Interface States" {
		t.Errorf("sub-task[0] name = %q, want %q", composite.SubTasks[0].Name, "Interface States")
	}
	if composite.SubTasks[0].Script != ifaceTask.Script {
		t.Errorf("sub-task[0] script = %q, want %q", composite.SubTasks[0].Script, ifaceTask.Script)
	}
	if composite.SubTasks[1].Name != "VLAN Interfaces" {
		t.Errorf("sub-task[1] name = %q, want %q", composite.SubTasks[1].Name, "VLAN Interfaces")
	}
	if composite.SubTasks[1].Script != vlanTask.Script {
		t.Errorf("sub-task[1] script = %q, want %q", composite.SubTasks[1].Script, vlanTask.Script)
	}

	// Other task preserved
	if hostCat.Tasks[1].Name != "Configure IP Addresses" {
		t.Errorf("second task = %q, want %q", hostCat.Tasks[1].Name, "Configure IP Addresses")
	}

	// Other categories untouched
	if len(result[1].Tasks) != 1 {
		t.Errorf("System Utilities task count = %d, want 1", len(result[1].Tasks))
	}
}

func TestMergeInterfaceTasksPartialMatch(t *testing.T) {
	// Only the iface task present, no VLAN task — should be a no-op
	input := []Category{
		{
			Name: "Host Configuration",
			Tasks: []Task{
				{Name: "Manage Network Interfaces", CanonicalName: "Manage Network Interfaces", Script: "/scripts/network_interfaces.sh"},
				{Name: "Configure IP Addresses", CanonicalName: "Configure IP Addresses", Script: "/scripts/configure_ip.sh"},
			},
		},
	}
	result := mergeInterfaceTasks(input, stringsEN)
	if len(result[0].Tasks) != 2 {
		t.Fatalf("expected 2 tasks (no merge), got %d", len(result[0].Tasks))
	}
	if result[0].Tasks[0].Name != "Manage Network Interfaces" {
		t.Errorf("first task = %q, want %q", result[0].Tasks[0].Name, "Manage Network Interfaces")
	}
}

func TestMergeInterfaceTasksNoOp(t *testing.T) {
	// Category without the interface tasks — should pass through unchanged
	input := []Category{
		{
			Name:  "Host Configuration",
			Tasks: []Task{{Name: "Configure IP Addresses", CanonicalName: "Configure IP Addresses", Script: "/scripts/configure_ip.sh"}},
		},
	}
	result := mergeInterfaceTasks(input, stringsEN)
	if len(result[0].Tasks) != 1 || result[0].Tasks[0].Name != "Configure IP Addresses" {
		t.Errorf("no-op merge modified categories unexpectedly: %+v", result[0].Tasks)
	}
}

func TestMergeCaptureAnalysisTasks(t *testing.T) {
	vlanTask := Task{Name: "Extract VLANs", CanonicalName: "Extract VLANs", Description: "Extract VLANs from capture", Script: "/scripts/extract_vlans.sh"}
	macTask := Task{Name: "MAC Address Analysis", CanonicalName: "MAC Address Analysis", Description: "Analyze MAC addresses", Script: "/scripts/mac_analysis.sh"}
	captureTask := Task{Name: "Packet Capture Analysis", CanonicalName: "Packet Capture Analysis", Description: "Analyze pcap files", Script: "/scripts/advanced_packet_analysis.sh"}
	otherTask := Task{Name: "Multi-Phase Discovery", CanonicalName: "Multi-Phase Discovery", Description: "Discover hosts", Script: "/scripts/discovery.sh"}

	input := []Category{
		{
			Name:  "Network Discovery",
			Tasks: []Task{otherTask, vlanTask, macTask, captureTask},
		},
	}

	result := mergeCaptureAnalysisTasks(input, stringsEN)

	cat := result[0]
	if len(cat.Tasks) != 2 {
		t.Fatalf("expected 2 tasks, got %d", len(cat.Tasks))
	}
	if cat.Tasks[0].Name != "Multi-Phase Discovery" {
		t.Errorf("first task = %q, want Multi-Phase Discovery", cat.Tasks[0].Name)
	}
	composite := cat.Tasks[1]
	if composite.Name != "Network Capture Analysis" {
		t.Errorf("composite name = %q, want Network Capture Analysis", composite.Name)
	}
	if len(composite.SubTasks) != 3 {
		t.Fatalf("expected 3 sub-tasks, got %d", len(composite.SubTasks))
	}
	if composite.SubTasks[0].Script != vlanTask.Script {
		t.Errorf("sub-task[0] script = %q, want %q", composite.SubTasks[0].Script, vlanTask.Script)
	}
	if composite.SubTasks[1].Script != macTask.Script {
		t.Errorf("sub-task[1] script = %q, want %q", composite.SubTasks[1].Script, macTask.Script)
	}
	if composite.SubTasks[2].Script != captureTask.Script {
		t.Errorf("sub-task[2] script = %q, want %q", composite.SubTasks[2].Script, captureTask.Script)
	}
}

func TestMergeCaptureAnalysisTasksPartialMatch(t *testing.T) {
	input := []Category{
		{
			Name:  "Network Discovery",
			Tasks: []Task{{Name: "Extract VLANs", CanonicalName: "Extract VLANs"}, {Name: "MAC Address Analysis", CanonicalName: "MAC Address Analysis"}},
		},
	}
	result := mergeCaptureAnalysisTasks(input, stringsEN)
	if len(result[0].Tasks) != 2 {
		t.Fatalf("expected no merge with only 2/3 tasks, got %d tasks", len(result[0].Tasks))
	}
}

func TestSearchAllCategories(t *testing.T) {
	tui := &TUI{str: stringsEN} // nil registry → falls back to hardcoded categories

	// Empty query returns nil
	if got := tui.searchAllCategories(""); got != nil {
		t.Errorf("empty query: expected nil, got %v", got)
	}

	// "scan" matches tasks whose name or description contains "scan" (case-insensitive)
	results := tui.searchAllCategories("scan")
	if len(results) == 0 {
		t.Fatal("expected results for 'scan', got none")
	}
	for _, r := range results {
		combined := strings.ToLower(r.Task.Name + " " + r.Task.Description)
		if !strings.Contains(combined, "scan") {
			t.Errorf("result %q / %q does not match 'scan'", r.Task.Name, r.Task.Description)
		}
	}

	// Case-insensitive: SCAN and scan return same count
	upper := tui.searchAllCategories("SCAN")
	lower := tui.searchAllCategories("scan")
	if len(upper) != len(lower) {
		t.Errorf("case sensitivity mismatch: SCAN=%d scan=%d", len(upper), len(lower))
	}

	// Results span multiple categories when the query is broad enough
	allResults := tui.searchAllCategories("config")
	cats := map[string]bool{}
	for _, r := range allResults {
		cats[r.CategoryName] = true
	}
	if len(cats) < 2 {
		t.Errorf("expected results from at least 2 categories for 'config', got %v", cats)
	}

	// CategoryName is populated on every result
	for _, r := range tui.searchAllCategories("network") {
		if r.CategoryName == "" {
			t.Errorf("result %q has empty CategoryName", r.Task.Name)
		}
	}
}
