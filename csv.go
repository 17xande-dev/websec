package websec

import (
	"strings"
	"unicode"
)

// CSVCell defuses a spreadsheet formula in a cell about to be written to a
// CSV file that people will open in a spreadsheet.
//
// Excel, Sheets and LibreOffice evaluate a cell that starts with "=", "+", "-"
// or "@", so a value typed into a public form becomes a live formula on
// whoever opens the export. Importers also discard a leading BOM, control
// character, zero-width or other format character, and whitespace before they
// decide whether a cell is a formula, so " =cmd" and a BOM followed by "=cmd" are formulas
// too. CSVCell therefore looks at the first character that remains after those
// are removed.
//
// If anything was removed, or the remaining text starts with one of the four
// trigger characters, the result is "'" followed by the remaining text. The
// invisible prefix is dropped, not preserved. Any other cell is returned
// unchanged.
//
// Use it only for files meant to be read in a spreadsheet. It changes data
// (a negative number "-5" becomes "'-5"), so it is wrong for files another
// program imports.
func CSVCell(s string) string {
	clean := strings.TrimLeftFunc(s, func(r rune) bool {
		return unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || unicode.IsSpace(r)
	})
	if len(clean) != len(s) || (clean != "" && strings.ContainsRune("=+-@", rune(clean[0]))) {
		return "'" + clean
	}
	return s
}

// CSVRow applies [CSVCell] to every cell and returns a new slice; cells is
// never modified, so it is safe to pass a slice that is used afterwards. It
// works as CSVRow(a, b, c) and as CSVRow(record...). With no cells it returns
// an empty, non-nil slice.
func CSVRow(cells ...string) []string {
	out := make([]string, len(cells))
	for i, c := range cells {
		out[i] = CSVCell(c)
	}
	return out
}
