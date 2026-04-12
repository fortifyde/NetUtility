package ui

import "testing"

func TestFormatCategoryName(t *testing.T) {
	tui := &TUI{}
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
	ifaceTask := Task{Name: "Manage Network Interfaces", Description: "Manage interface states", Script: "/scripts/network_interfaces.sh"}
	vlanTask  := Task{Name: "Manage VLAN Interfaces", Description: "Create VLAN subinterfaces", Script: "/scripts/add_vlan.sh"}
	otherTask := Task{Name: "Configure IP Addresses", Description: "Set IPs", Script: "/scripts/configure_ip.sh"}

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

	result := mergeInterfaceTasks(input)

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

func TestMergeInterfaceTasksNoOp(t *testing.T) {
	// Category without the interface tasks — should pass through unchanged
	input := []Category{
		{
			Name:  "Host Configuration",
			Tasks: []Task{{Name: "Configure IP Addresses", Script: "/scripts/configure_ip.sh"}},
		},
	}
	result := mergeInterfaceTasks(input)
	if len(result[0].Tasks) != 1 || result[0].Tasks[0].Name != "Configure IP Addresses" {
		t.Errorf("no-op merge modified categories unexpectedly: %+v", result[0].Tasks)
	}
}
