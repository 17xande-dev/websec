// Package websec holds small, dependency-free web-hardening helpers.
//
// Each helper does one job that is easy to get subtly wrong when written
// inline: validating a post-login redirect target ([SafeRedirect]) and
// defusing spreadsheet formulas in exported cells ([CSVCell], [CSVRow]).
// The documentation of each function explains why its rules exist, because a
// rule whose reason is forgotten is the first one to be "simplified" away.
//
// The package uses only the standard library.
package websec
