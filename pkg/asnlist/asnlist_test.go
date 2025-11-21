package asnlist

import "testing"

// TestParse verifies textual ASN lists are parsed into structured entries.
func TestParse(t *testing.T) {
	text := `# Core providers
AS 123
as456
789
invalid
# Other group
AS321

111`

	got := Parse(text)
	want := []AS{
		{Number: 123, Comment: "Core providers"},
		{Number: 456, Comment: "Core providers"},
		{Number: 789, Comment: "Core providers"},
		{Number: 321, Comment: "Other group"},
		{Number: 111, Comment: ""},
	}

	compareLists(t, got, want)
}

// TestFormat ensures structured lists serialize back to the expected text form.
func TestFormat(t *testing.T) {
	list := []AS{
		{Number: 1, Comment: "Group"},
		{Number: 2, Comment: "Group"},
		{Number: 3, Comment: ""},
		{Number: 4, Comment: "Other"},
	}

	want := "# Group\nAS 1\nAS 2\n\nAS 3\n\n# Other\nAS 4"
	if got := Format(list); got != want {
		t.Fatalf("unexpected text: got %q want %q", got, want)
	}
}

// TestSynthesize confirms duplicates are removed and reported correctly.
func TestSynthesize(t *testing.T) {
	list := []AS{
		{Number: 1, Comment: "first"},
		{Number: 2, Comment: "second"},
		{Number: 1, Comment: "duplicate"},
		{Number: 3, Comment: "third"},
		{Number: 2, Comment: "duplicate"},
	}

	res := Synthesize(list)

	wantNew := []AS{list[0], list[1], list[3]}
	wantRemoved := []AS{list[2], list[4]}

	compareLists(t, res.NewList, wantNew)
	compareLists(t, res.RemovedEntries, wantRemoved)
}

// TestFindContaining checks that entries are located by numeric value.
func TestFindContaining(t *testing.T) {
	list := []AS{{Number: 123}, {Number: 456}}

	if got := FindContaining(list, "AS123"); got != &list[0] {
		t.Fatalf("expected first entry, got %v", got)
	}
	if got := FindContaining(list, "AS 123"); got != &list[0] {
		t.Fatalf("expected first entry, got %v", got)
	}
	if got := FindContaining(list, "123"); got != &list[0] {
		t.Fatalf("expected first entry, got %v", got)
	}
	if got := FindContaining(list, "456"); got != &list[1] {
		t.Fatalf("expected second entry, got %v", got)
	}
	if got := FindContaining(list, "789"); got != nil {
		t.Fatalf("expected nil for missing entry, got %v", got)
	}
	if got := FindContaining(list, "invalid"); got != nil {
		t.Fatalf("expected nil for invalid value, got %v", got)
	}
}

// compareLists asserts two ASN slices are identical for tests.
func compareLists(t *testing.T, got, want []AS) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("unexpected length: got %d want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("entry %d mismatch: got %+v want %+v", i, got[i], want[i])
		}
	}
}
