# websec

Small, dependency-free web-hardening helpers for Go. The module uses only the
standard library. Each function's documentation explains why its rules exist.

```go
import "github.com/17xande-dev/websec"
```

## SafeRedirect

```go
func SafeRedirect(next string, o RedirectOptions) string

type RedirectOptions struct {
    Prefix   string   // the raw path must begin with this, e.g. "/admin/"
    Deny     []string // decoded-path prefixes that are refused
    Fallback string   // returned verbatim when next is refused
}

const MaxRedirectLen = 2048
```

It returns `next` unchanged when it is a same-site path and `o.Fallback`
otherwise. It never rewrites a value, so there is no "cleaned" form for a second
parser to disagree about.

```go
// After sign-in: send the person back to where they were going.
dest := websec.SafeRedirect(r.FormValue("next"), websec.RedirectOptions{
    Deny:     []string{"/login", "/logout"},
    Fallback: "/",
})
http.Redirect(w, r, dest, http.StatusSeeOther)

// An admin area: only paths under /admin/.
dest = websec.SafeRedirect(next, websec.RedirectOptions{Prefix: "/admin/", Fallback: "/admin/"})
```

### What it refuses, and why

A redirect validator written as a prefix check ("starts with `/`, not `//`")
is wrong because browsers do not parse a URL the way a byte comparison does:

- **TAB, LF and CR are stripped from anywhere in a URL.** `/\t/evil.example`
  becomes `//evil.example`, another host.
- **Leading and trailing C0 controls and spaces are trimmed** from the whole
  URL before parsing, so a trailing space can hide a dot segment:
  `/admin/%2e%2e ` is `/admin/%2e%2e` to a browser and escapes the prefix. A
  value ending in a space is refused (a leading one is impossible, since `next`
  must start with `/`). Other control bytes are never legitimate in a path, so
  any byte below `0x20` or `0x7f` is refused.
- **`\` is read as `/` in the path of an http(s) URL.** `/\evil.example` is
  `//evil.example`. It is refused everywhere in `next`, for simplicity.
- **`%2e` segments are dots.** `/admin/%2e%2e/x` leaves `/admin/`, as does
  `/admin/x/../../evil`. `.`, `..`, `%2e`, `.%2e`, `%2e.` and `%2e%2e` segments
  are refused in any case.
- **`//` means another host** at the start. An empty segment inside a path
  (`/a//b`) is refused too: a canonical path keeps the `Prefix` check
  meaningful, and no legitimate target needs one.

In order, each step refuses to the fallback:

1. empty, or longer than 2048 bytes;
2. not starting with `/`, starting with `//`, ending in a space, or any byte
   below `0x20`, `0x7f` or `\` anywhere;
3. `url.Parse` fails, or finds a scheme, host, user info or opaque part;
4. the decoded path does not start with a single `/`, or has a control byte or
   `\` (this refuses `/%2F/evil`, `/%5cevil`, `/%09/x`, `/%00`);
5. the raw path has an empty segment or a dot segment (a trailing slash is
   fine);
6. `Prefix` is set and the raw path does not begin with it;
7. a `Deny` entry is a prefix of the decoded path.

Query strings, fragments, inner spaces and non-ASCII text are allowed: none of them
can change the host. `/..%2f..%2fetc` is accepted, because to a browser it is a
single ordinary segment.

### Behaviour notes

- `Deny` is a plain string prefix on the **decoded** path, so `/login` also
  refuses `/loginhistory` and `/%6cogin`. Write `/login/` to be narrower.
- `Prefix` is matched against the **raw** path. A prefix that does not start
  with `/` can never match, so it refuses everything: a misconfiguration fails
  closed.
- `Fallback` is returned unvalidated, even if it is itself hostile. Pass a
  constant.
- `next` is never rewritten: an accepted value comes back byte-identical.

## CSVCell and CSVRow

```go
func CSVCell(s string) string
func CSVRow(cells ...string) []string
```

A spreadsheet evaluates a cell that starts with `=`, `+`, `-` or `@`, so text
typed into a public form becomes a live formula for whoever opens the export.
Importers also drop a leading BOM, control character, zero-width or other
format character, and whitespace before deciding, so `" =cmd"` and a BOM
followed by `=cmd` are formulas too. `CSVCell` examines the first character
left after those are removed. If anything was removed, or a trigger character
remains, it returns `'` plus the remaining text; any other cell is returned
as is.

```go
w := csv.NewWriter(out)
w.Write(websec.CSVRow(record...)) // a new slice; record is not modified
```

`CSVRow` applies `CSVCell` to every cell and always returns a new slice
(`CSVRow()` returns an empty, non-nil one).

### Behaviour notes

- The invisible prefix is **dropped**, not kept: `"\tplain"` becomes `'plain`,
  and `"   "` becomes `'`.
- Numbers change too: `-5` becomes `'-5`, and `+27 82 555 0101` becomes
  `'+27 82 555 0101`.
- Use it only for files meant to be opened in a spreadsheet. Do not use it on
  files another program imports, where the apostrophe would corrupt the data.

## Session cookies (`websec/cookie`)

```go
import "github.com/17xande-dev/websec/cookie"
```

Build the policy once at startup with `cookie.New(cookie.Config{Name: "session"})`.
Pass a bare name and a path (`""` means `/`). `New` rejects invalid names and
paths. Use `Set` after sign-in, `Value` to read the credential, and `Clear` at
sign-out.

- Secure cookies at `/` get `__Host-`, which prevents a sibling subdomain
  (including one hosted by a third party) from setting a domain cookie with
  the same name. Secure cookies at a narrower path, such as `/admin`, get
  `__Secure-`: it requires HTTPS but does not prevent another HTTPS subdomain
  from setting a domain cookie. Neither sets `Domain`. `Insecure` is for
  plain-HTTP development only and disables both `Secure` and the prefix.
- Adopting a prefixed name renames a previously bare cookie and signs everyone
  out once. `Value` does not fall back to the old name.
- `HttpOnly` keeps scripts from reading the credential. `SameSite=Lax` keeps it
  off cross-site POSTs without breaking navigation from ordinary links.
  Neither setting varies by route, even for an admin-path cookie.
- Pass the server's absolute session expiry to `Set`. It writes both `Expires`
  and `Max-Age`, rounding down to whole seconds. For directory-backed sign-in
  that should not persist past the browser session, set `BrowserSession` to omit
  both attributes. The server still enforces the session's expiry.

## Changes

- **v0.1.1**: `FuzzSafeRedirect` is now seeded with the browser-semantics rows
  as well as the general table, plus `/admin/x%2fy`, so a mutant that matches
  `Prefix` against the decoded path is caught from the seed corpus. Tests only;
  no behaviour change.
- **v0.1.0**: `SafeRedirect`, `CSVCell` and `CSVRow`.

## Development

```sh
make fmt-check vet test vulncheck
make fuzz   # FuzzSafeRedirect for 60 seconds
```
