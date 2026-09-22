package ui

import (
	"strings"
	"testing"

	"github.com/rivo/tview"

	"netutil/internal/executor"
)

// renderThroughTextView feeds the formatted string through the same parser the
// screen uses: a TextView with dynamic colors and regions enabled, mirroring
// NewOutputViewer. GetText(true) strips tags via tview's parser, so escaped
// tags round-trip to their literal form while interpreted ones do not.
func renderThroughTextView(t *testing.T, formatted string) string {
	t.Helper()
	view := tview.NewTextView().SetDynamicColors(true).SetRegions(true)
	view.SetText(formatted)
	return view.GetText(true)
}

func TestFormatLinesLockedEscapesBracketTags(t *testing.T) {
	inputs := []string{
		"Scan [OK] done",
		"items [1] [2]",
		"| 1 | 2 | 3 | 4 |",
	}
	lines := make([]executor.OutputLine, len(inputs))
	for i, in := range inputs {
		lines[i] = executor.OutputLine{Content: in, Source: "stdout"}
	}

	formatted := (&OutputViewer{}).formatLinesLocked(lines)
	got := renderThroughTextView(t, formatted)

	// formatLinesLocked newline-terminates every line, including the last.
	want := strings.Join(inputs, "\n") + "\n"
	if got != want {
		t.Errorf("formatted output through TextView = %q, want %q", got, want)
	}

	// A swallowed tag earlier in the buffer must not recolor later lines
	// (tview carries style state across newlines): the pipe-table row after
	// a [OK] line must survive verbatim.
	tableRow := renderThroughTextView(t, formatted)
	if !strings.Contains(tableRow, "| 1 | 2 | 3 | 4 |") {
		t.Errorf("table row corrupted after preceding [OK] line: %q", tableRow)
	}
}

func TestFormatLinesLockedPreservesANSIColors(t *testing.T) {
	lines := []executor.OutputLine{
		{Content: "err \x1b[31mred\x1b[0m tail", Source: "stdout"},
	}

	formatted := (&OutputViewer{}).formatLinesLocked(lines)

	if strings.ContainsRune(formatted, '\x1b') {
		t.Errorf("raw ANSI escape survived formatting: %q", formatted)
	}

	got := renderThroughTextView(t, formatted)
	if !strings.Contains(got, "red") || !strings.Contains(got, "tail") {
		t.Errorf("visible text lost by ANSI translation: %q", got)
	}
}
