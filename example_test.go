package websec_test

import (
	"encoding/csv"
	"fmt"
	"os"

	"github.com/17xande-dev/websec"
)

func ExampleSafeRedirect() {
	opts := websec.RedirectOptions{
		Prefix:   "/admin/",
		Deny:     []string{"/admin/login"},
		Fallback: "/admin/",
	}
	for _, next := range []string{
		"/admin/users?page=2",    // same-site, under the prefix
		"//evil.example/",        // scheme-relative: another host
		"/admin/\t/evil.example", // the browser strips the tab
		"/admin/../login",        // dot segment leaves the prefix
		"/admin/login",           // denied: would loop back to sign-in
	} {
		fmt.Printf("%q -> %q\n", next, websec.SafeRedirect(next, opts))
	}
	// Output:
	// "/admin/users?page=2" -> "/admin/users?page=2"
	// "//evil.example/" -> "/admin/"
	// "/admin/\t/evil.example" -> "/admin/"
	// "/admin/../login" -> "/admin/"
	// "/admin/login" -> "/admin/"
}

func ExampleCSVCell() {
	for _, s := range []string{"=1+1", " =1+1", "-5", "plain text"} {
		fmt.Printf("%q -> %q\n", s, websec.CSVCell(s))
	}
	// Output:
	// "=1+1" -> "'=1+1"
	// " =1+1" -> "'=1+1"
	// "-5" -> "'-5"
	// "plain text" -> "plain text"
}

func ExampleCSVRow() {
	w := csv.NewWriter(os.Stdout)
	rows := [][]string{
		{"name", "note"},
		{"Ada", "=HYPERLINK(\"http://evil.example\")"},
	}
	for _, r := range rows {
		_ = w.Write(websec.CSVRow(r...))
	}
	w.Flush()
	// Output:
	// name,note
	// Ada,"'=HYPERLINK(""http://evil.example"")"
}
