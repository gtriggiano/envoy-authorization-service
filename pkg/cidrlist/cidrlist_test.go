package cidrlist

import (
	"net/netip"
	"testing"
)

// TestParse validates conversion from text to structured CIDR entries.
func TestParse(t *testing.T) {
	text := `# First comment
79.23.125.0/24
79.23.125.21
not-a-cidr
# Second comment
89.23.125.0/28

59.23.12.0
`

	got := Parse(text)
	want := []CIDR{
		{Value: mustPrefix("79.23.125.0/24"), Comment: "First comment"},
		{Value: mustPrefix("79.23.125.21/32"), Comment: "First comment"},
		{Value: mustPrefix("89.23.125.0/28"), Comment: "Second comment"},
		{Value: mustPrefix("59.23.12.0/32"), Comment: ""},
	}

	if len(got) != len(want) {
		t.Fatalf("unexpected length: got %d want %d", len(got), len(want))
	}
	for i := range want {
		if got[i].Value != want[i].Value || got[i].Comment != want[i].Comment {
			t.Fatalf("entry %d mismatch: got %+v want %+v", i, got[i], want[i])
		}
	}
}

// TestFormat ensures structured CIDRs serialize into the expected text.
func TestFormat(t *testing.T) {
	list := []CIDR{
		{Value: mustPrefix("79.23.125.0/24"), Comment: "Group"},
		{Value: mustPrefix("79.23.125.1/32"), Comment: "Group"},
		{Value: mustPrefix("80.0.0.0/8"), Comment: ""},
		{Value: mustPrefix("90.0.0.0/16"), Comment: "Other"},
	}

	want := "# Group\n79.23.125.0/24\n79.23.125.1/32\n\n80.0.0.0/8\n\n# Other\n90.0.0.0/16"
	if got := Format(list); got != want {
		t.Fatalf("unexpected formatted text:\nGot:\n%q\nWant:\n%q", got, want)
	}
}

// TestSynthesize confirms redundant CIDRs are removed and tracked.
func TestSynthesize(t *testing.T) {
	list := []CIDR{
		{Value: mustPrefix("79.23.125.0/24"), Comment: "block"},
		{Value: mustPrefix("79.23.125.21/32"), Comment: "single"},
		{Value: mustPrefix("10.0.0.0/8"), Comment: "wide"},
		{Value: mustPrefix("10.1.0.0/16"), Comment: "narrow"},
		{Value: mustPrefix("10.1.0.0/16"), Comment: "duplicate"},
	}

	res := Synthesize(list)

	wantNew := []CIDR{list[0], list[2]}
	wantRemoved := []CIDR{list[1], list[3], list[4]}

	compareSlices(t, res.NewList, wantNew)
	compareSlices(t, res.RemovedEntries, wantRemoved)
}

// TestFindContaining checks the helper locates containing CIDRs.
func TestFindContaining(t *testing.T) {
	list := []CIDR{
		{Value: mustPrefix("79.23.125.0/24"), Comment: "first"},
		{Value: mustPrefix("10.0.0.0/8"), Comment: "second"},
	}

	if got, _ := FindContaining(list, "79.23.125.22"); got != &list[0] {
		t.Fatalf("expected first entry for IP, got %v", got)
	}
	if got, _ := FindContaining(list, "10.1.0.0/16"); got != &list[1] {
		t.Fatalf("expected second entry for CIDR, got %v", got)
	}
	if got, found := FindContaining(list, "0.0.0.0"); found || got != nil {
		t.Fatalf("expected nil for non matching IP, got %v", got)
	}
	if got, found := FindContaining(list, "invalid"); found || got != nil {
		t.Fatalf("expected nil for invalid value, got %v", got)
	}
}

func TestParse_EdgeCases(t *testing.T) {
	t.Run("empty string", func(t *testing.T) {
		got := Parse("")
		if len(got) != 0 {
			t.Errorf("expected empty list, got %d entries", len(got))
		}
	})

	t.Run("only comments", func(t *testing.T) {
		got := Parse("# Comment 1\n# Comment 2\n")
		if len(got) != 0 {
			t.Errorf("expected empty list, got %d entries", len(got))
		}
	})

	t.Run("only whitespace", func(t *testing.T) {
		got := Parse("   \n\t\n   ")
		if len(got) != 0 {
			t.Errorf("expected empty list, got %d entries", len(got))
		}
	})

	t.Run("mixed valid and invalid", func(t *testing.T) {
		got := Parse("192.168.1.0/24\ninvalid\n10.0.0.1")
		if len(got) != 2 {
			t.Fatalf("expected 2 entries (skipping invalid), got %d", len(got))
		}
		if got[0].Value.String() != "192.168.1.0/24" {
			t.Errorf("unexpected first entry: %s", got[0].Value)
		}
		if got[1].Value.String() != "10.0.0.1/32" {
			t.Errorf("unexpected second entry: %s", got[1].Value)
		}
	})
}

func TestSynthesize_EdgeCases(t *testing.T) {
	t.Run("empty list", func(t *testing.T) {
		res := Synthesize([]CIDR{})
		if len(res.NewList) != 0 {
			t.Errorf("expected empty NewList, got %d", len(res.NewList))
		}
		if len(res.RemovedEntries) != 0 {
			t.Errorf("expected empty RemovedEntries, got %d", len(res.RemovedEntries))
		}
	})

	t.Run("no overlaps", func(t *testing.T) {
		list := []CIDR{
			{Value: mustPrefix("10.0.0.0/24"), Comment: "a"},
			{Value: mustPrefix("20.0.0.0/24"), Comment: "b"},
		}
		res := Synthesize(list)
		if len(res.NewList) != 2 {
			t.Errorf("expected 2 entries in NewList, got %d", len(res.NewList))
		}
		if len(res.RemovedEntries) != 0 {
			t.Errorf("expected no removed entries, got %d", len(res.RemovedEntries))
		}
	})
}

func TestFormat_EdgeCases(t *testing.T) {
	t.Run("empty list", func(t *testing.T) {
		got := Format([]CIDR{})
		if got != "" {
			t.Errorf("expected empty string, got %q", got)
		}
	})

	t.Run("single entry no comment", func(t *testing.T) {
		list := []CIDR{{Value: mustPrefix("10.0.0.0/8"), Comment: ""}}
		want := "10.0.0.0/8"
		if got := Format(list); got != want {
			t.Errorf("expected %q, got %q", want, got)
		}
	})
}

// compareSlices asserts two CIDR slices are identical for testing.
func compareSlices(t *testing.T, got, want []CIDR) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("unexpected length: got %d want %d", len(got), len(want))
	}
	for i := range want {
		if got[i].Value != want[i].Value || got[i].Comment != want[i].Comment {
			t.Fatalf("entry %d mismatch: got %+v want %+v", i, got[i], want[i])
		}
	}
}

// mustPrefix parses a CIDR and panics on failure to simplify test setup.
func mustPrefix(s string) netip.Prefix {
	p, err := netip.ParsePrefix(s)
	if err != nil {
		panic(err)
	}
	return p.Masked()
}
