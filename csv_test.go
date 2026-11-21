package websec

import (
	"slices"
	"testing"
)

func TestCSVCell(t *testing.T) {
	for _, tc := range []struct{ name, in, want string }{
		// Trigger characters.
		{"equals", "=1+1", "'=1+1"},
		{"plus phone number", "+27821234567", "'+27821234567"},
		{"plus phone number with spaces", "+27 82 555 0101", "'+27 82 555 0101"},
		{"minus", "-5", "'-5"},
		{"at", "@cmd", "'@cmd"},
		{"function", `=HYPERLINK("http://evil.example","x")`, `'=HYPERLINK("http://evil.example","x")`},
		{"at function", "@SUM(A1:A9)", "'@SUM(A1:A9)"},
		// Invisible prefixes are dropped and the quote added, with or without a trigger.
		{"tab", "\t=1", "'=1"},
		{"carriage return", "\r=1", "'=1"},
		{"BOM", "\ufeff=1", "'=1"},
		{"NUL and zero-width space", "\x00\u200b+27", "'+27"},
		{"space", " =1", "'=1"},
		{"tab before plain text", "\tplain", "'plain"},
		{"BOM before plain text", "\ufeffplain", "'plain"},
		{"spaces before plain text", " ABC", "'ABC"},
		// Whitespace-only and invisible-only cells collapse to a lone quote.
		{"lone zero-width space", "\u200b", "'"},
		{"lone BOM", "\ufeff", "'"},
		{"only spaces", "   ", "'"},
		// Untouched.
		{"quotes", `"quotes"`, `"quotes"`},
		{"comma", "a,b", "a,b"},
		{"newline inside", "a\nb", "a\nb"},
		{"CJK", "你好", "你好"},
		{"empty", "", ""},
		{"ordinary", "ordinary", "ordinary"},
		{"multi-byte first rune", "é=1", "é=1"},
		{"trigger not first", "a=1", "a=1"},
		{"trailing space", "plain ", "plain "},
		{"existing quote", "'=1", "'=1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := CSVCell(tc.in); got != tc.want {
				t.Errorf("CSVCell(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestCSVRow(t *testing.T) {
	in := []string{"=1", "ok", " x", ""}
	orig := slices.Clone(in)
	got := CSVRow(in...)
	if want := []string{"'=1", "ok", "'x", ""}; !slices.Equal(got, want) {
		t.Errorf("CSVRow = %q, want %q", got, want)
	}
	if !slices.Equal(in, orig) {
		t.Errorf("CSVRow modified its input: %q", in)
	}
	// The result must not alias the input, even when nothing changes.
	same := []string{"a", "b"}
	out := CSVRow(same...)
	out[0] = "changed"
	if same[0] != "a" {
		t.Error("CSVRow result aliases its input")
	}
	if got := CSVRow("=a", "b"); !slices.Equal(got, []string{"'=a", "b"}) {
		t.Errorf("variadic call: %q", got)
	}
}

func TestCSVRowEmpty(t *testing.T) {
	got := CSVRow()
	if got == nil || len(got) != 0 {
		t.Errorf("CSVRow() = %#v, want empty non-nil", got)
	}
}
