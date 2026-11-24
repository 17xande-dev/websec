# websec

Small web-hardening helpers for Go. The root package uses only the standard
library; `csrf` depends on nosurf. Each function's documentation explains why
its rules exist.

```go
import "github.com/17xande-dev/websec"
```

| Package | Purpose |
| --- | --- |
| `websec` | Same-site redirects and spreadsheet-safe CSV cells |
| `websec/csrf` | Request-forgery protection with bounded form parsing |
| `websec/cookie` | Host-only session cookies |
| `websec/session` | Server-side session lifetime and last-seen write policy |
| `websec/session/sessiontest` | Conformance tests for an application's session store |

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

## Request-forgery protection (`websec/csrf`)

```go
import "github.com/17xande-dev/websec/csrf"
```

Build a policy at startup with `csrf.New(csrf.Config{Origin: "https://app.example"})`
and wrap handlers with `p.Handler`. Render `csrf.Token(r)` in the `csrf.FieldName`
hidden field or send it in the `csrf.HeaderName` request header.

Nosurf parses forms to find the token. Without a cap in front, an anonymous
request could make the server read and spool a large body before authentication.
The wrapper applies these rules in order:

1. GET, HEAD, OPTIONS and TRACE are capped at `MaxBody` too (`Limit` is not
   consulted) and refuse a multipart `Content-Type` with 415 before reading
   anything: browsers send no body on these methods, but Go's
   `Request.FormValue` parses and spools a multipart one for any method.
   Non-exempt safe requests still skip the token check and go through nosurf
   so a form page can issue a token.
2. On unsafe methods, resolve the limit (`MaxBody` defaults to 256 KiB, and `Limit`
   can override it). An oversized declared length returns 413 unless the
   upload opts into a custom refusal (see below). Multipart data returns 415
   unless the limit allows it. Otherwise wrap the body in `http.MaxBytesReader`.
3. Exempt requests skip nosurf entirely, so they get no CSRF cookie and their
   handlers receive an unparsed body. Exempt routes must authenticate themselves
   and handle read errors, including `*http.MaxBytesError` on streamed bodies.
4. Parse URL-encoded forms and allowed multipart forms under the cap. Oversized
   reads return 413, other parse failures return 400, and multipart temporary
   files are cleaned up after the request.
5. Nosurf checks the origin and token before running the handler.

The kit's own refusals (413, 415 and 400) log one warning with the status,
method and path (never the query, headers or body) and answer in plain text with
`Cache-Control: no-store`. Set `Config.OnBodyError` to write the response
yourself; the warning is still logged. The hook must not read the body. It is
not called for CSRF failures (`OnFailure`) or the oversized-upload hand-off
(`Oversized`). For example, to show a refusal inside an htmx target:

```go
OnBodyError: func(w http.ResponseWriter, r *http.Request, status int) {
	if r.Header.Get("HX-Request") == "true" {
		w.Header().Set("HX-Retarget", "#form-errors")
		w.Header().Set("HX-Reswap", "innerHTML")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusUnprocessableEntity)
		fmt.Fprint(w, "That request was too large or malformed. Please try again.")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	http.Error(w, http.StatusText(status), status)
},
```

Choose a per-route cap using the mux's actual match (or configure limits on the
already-routed handlers), not a string prefix on the incoming path. Alternate
spellings of a path may not match the same handler. Place any authentication
that must precede upload parsing outside this middleware.

Use the exact lowercase public origin, without a trailing slash. It is always
trusted even when a proxy rewrites `Host`. `TrustedOrigins` adds exact origins
(scheme, host and port); sibling subdomains are not trusted unless listed.
The TLS answer comes from config rather than a forwarded header: a proxy can
terminate TLS, and a client-supplied header must not change the policy.

Cookies are host-only, HttpOnly, Secure by default, and last for the browser
session. They are SameSite=Lax unless `CrossSite` is set for a credentialed
cross-site embed; that option requires Secure. The name is prefixed with `__Host-`
at `/` or `__Secure-` on a narrower path, reducing cookie injection. Plain-HTTP
development explicitly sets `Insecure` and uses the bare name. Adopting the
prefixed name makes forms opened before the change expire once.

Failed CSRF checks log a warning and return a plain-text 403 with
`Cache-Control: no-store`. For `HX-Request: true` the response also sets
`HX-Refresh: true`. Override the response with `OnFailure` if reloading would
discard unsaved typing. The warning is still logged, and `csrf.Reason(r)` is
available inside the override.

Call `p.Renew(w, r)` before writing headers at sign-in, sign-out and when users
change their own password. It replaces the cookie and returns the masked token
for the current response so a pre-sign-in or injected token doesn't survive the
credential change. On exempt or unprotected requests it returns
`csrf.ErrNotProtected` without setting a cookie.

### Custom refusal for oversized uploads

To show a friendly error on an upload route, have `Limit` return a `BodyLimit`
with `Multipart: true` and a `PassOversized` callback. The callback must check
the session and upload permission without reading the body. Set
`Config.Oversized` to a handler that only renders the refusal (for example,
a 422 page with the size limit). `csrf.Oversized(r)` identifies the marked
request and does not attest that its CSRF token was checked.

For a permitted multipart request whose declared size exceeds the cap, the kit
substitutes `http.NoBody` without reading or spooling the upload, closes the
HTTP/1 connection after the response, and lets nosurf check the origin. The
custom handler runs only if the origin check passed and the missing form token
is the only CSRF failure, with no `X-CSRF-Token` header present. It must not
upload anything or change state. Untrusted origins and requests with a CSRF
header are refused. Anonymous or unpermitted callers, exempt routes, and
routes without the opt-in keep the plain 413. A valid `X-CSRF-Token` on an
oversized hand-off is refused with 403 and logged. Streamed uploads that exceed
the cap still get 413 after a bounded read; uploads at or below the cap still
need a valid token.

## Session lifetimes (`websec/session`)

```go
import "github.com/17xande-dev/websec/session"
```

Start with a copy of `session.Default` (two hours idle, twelve hours absolute)
or configure a `session.Lifetime`, and call `Validate` at startup. The
absolute limit is mandatory. Disable the idle limit explicitly with
`IdleOff: true` and `Idle: 0`.

Call `Expired(created, lastSeen, now)` before considering a touch. A session
expires at either enabled deadline, including at the exact instant it is due.
Activity before creation counts as creation. A session created under a clock
that was ahead keeps its absolute limit counted from the stored creation time.
`ExpiresAt` calculates the deadline from the stored timestamps
without reading or adjusting for the current clock. Pass
`AbsoluteExpiry(created)` to the cookie policy for a persistent cookie so
activity cannot extend its lifetime.

With idle expiry enabled, use `NeedsTouch(lastSeen, now)` to avoid writing on
every request, or use `NeedsTouchAfter(lastSeen, now, every)` for a custom,
positive interval. To preserve the throttle under concurrent requests, use
the same current time in the predicate and the update:

```sql
UPDATE ... SET last_seen = :now WHERE token_hash = :h
  AND (last_seen <= :now - <every> OR last_seen > :now)
```

A last-seen time in the future (the clock stepped back) is rewritten to now
at the next request, so it extends a session by at most one request. With
the default `TouchEvery` (one minute), stored activity can lag real activity
by up to a minute, so throttling can make idle expiry arrive up to a minute
early.

## Session store conformance (`websec/session/sessiontest`)

In a `_test.go` file, point the suite at an isolated test database running
your usual session store. For example, if `openTestStore` returns your
test adapter's callbacks:

```go
import (
	"testing"

	"github.com/17xande-dev/websec/session/sessiontest"
)

func TestSessionStore(t *testing.T) {
	s := openTestStore(t)
	sessiontest.Run(t, sessiontest.Harness{
		Lifetime: s.Lifetime,
		NewUser: s.NewUser, Create: s.Create, Lookup: s.Lookup,
		Backdate: s.Backdate, LastSeen: s.LastSeen,
		Sweep: s.Sweep, Count: s.Count, RawRows: s.RawRows,
		Disable: s.Disable, RevokeUser: s.RevokeUser,
		ChangePassword: func(t *testing.T, user, current string) string {
			s.ChangePassword(t, user, current) // this store keeps the current session
			return current
		},
	})
}
```

Use the real sign-in and request-time lookup paths. `Backdate` finds the
row by the token hash and rewrites creation and last-seen times, plus any
derived fields such as stored expiry or directory-check timestamps. For a
SQLite hex-TEXT hash, address the row by the hex digest and write timestamps
in the store's format. For a Postgres BYTEA hash, use the digest bytes and
write `timestamptz` values; SQL `now()` stays unchanged. `RawRows` returns
every stored session column, with text as-is and binary data rendered in hex.
The result must grow when a session is added.

The fixtures require the store's real absolute limit to be at least ten
minutes. If idle expiry is enabled, the idle limit must be at least five
minutes, at least four times the touch interval, and at least five minutes
shorter than the absolute limit. Set `Harness.TouchEvery` to the store's
interval if it is longer than the default minute. With `IdleOff`, leave
`TouchEvery` unset and omit `LastSeen`; the suite reports why it skips idle
and touch.

`ChangePassword` returns the token still valid for the current browser:
the current token, a rotated token, or `""` if all the user's sessions
ended. Only `disable`, `password-change`, and `revoke-user` can be opted
out. Leave the callback nil and give a reason in `NotApplicable`; the
reason is visible in `go test -v`.

## Changes

- **v0.2.0 (unreleased)**: Session cookie helpers, session lifetime policy,
  store conformance tests, and CSRF protection with bounded form parsing and
  opt-in oversized-upload responses, a body cap and multipart refusal on safe
  methods, and an `OnBodyError` hook.
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
