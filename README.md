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
| `websec/session/sessiontest` | Session store conformance tests |
| `websec/webtest` | HTTP integration-test clients, assertions and probes |

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

Query strings, fragments, inner spaces and non-ASCII text are allowed: none
of them can change the host. `/..%2f..%2fetc` is accepted, because to a browser
it is a single ordinary segment.

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

Build the policy once at startup with
`cookie.New(cookie.Config{Name: "session"})`. Pass a bare name and a path
(`""` means `/`). `New` rejects invalid names and paths. Use `Set` after
sign-in, `Value` to read the credential, and `Clear` at sign-out.

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
  and `Max-Age`, rounding down to whole seconds. `Set` measures the remaining
  time with `Config.Now` (default `time.Now`); pass the same clock your session
  store uses. Re-sending the cookie on activity with the same
  `AbsoluteExpiry(created)` keeps its deadline; it never extends the session.
  For directory-backed sign-in that should not persist past the browser session,
  set `BrowserSession` to omit both attributes. The server still enforces the
  session's expiry.

The policy reads `cookie.Config.Now` once at construction; if the application
can swap its clock later (for example, in tests), pass a closure that reads
the current clock on each call:

```go
cfg.Now = func() time.Time {
	return app.now()
}
```

## Request-forgery protection (`websec/csrf`)

```go
import "github.com/17xande-dev/websec/csrf"
```

Build a policy at startup with
`csrf.New(csrf.Config{Origin: "https://app.example"})` and wrap handlers with
`p.Handler`. Render `csrf.Token(r)` in the `csrf.FieldName` hidden field or
send it in the `csrf.HeaderName` request header.

Nosurf parses forms to find the token. Without a cap in front, an anonymous
request could make the server read and spool a large body before authentication.
The wrapper applies these rules in order:

1. GET, HEAD, OPTIONS and TRACE are capped at `MaxBody` too (`Limit` is not
   consulted) and refuse a multipart `Content-Type` with 415 before reading
   anything: browsers send no body on these methods, but Go's
   `Request.FormValue` parses and spools a multipart one for any method.
   Otherwise, a declared length over the cap is not refused: the middleware
   does not read the body, and handler reads are capped at `MaxBody`.
   Non-exempt safe requests still skip the token check and go through nosurf
   so a form page can issue a token.
2. On unsafe methods, resolve the limit (`MaxBody` defaults to 256 KiB, and
   `Limit` can override it) and decide the media type first. Multipart is
   capped by `MultipartMaxBytes` and refused with 415 when that is 0; every
   other body is capped by `MaxBytes` (0 means `MaxBody`, at most 64 MiB).
   An oversized declared length returns 413 unless the upload opts into a
   custom refusal (see below). Otherwise wrap the body in `http.MaxBytesReader`.
3. Exempt requests skip nosurf entirely, so they get no CSRF cookie and their
   handlers receive an unparsed body. Exempt routes must authenticate themselves
   and handle read errors, including `*http.MaxBytesError` on streamed bodies.
4. Parse URL-encoded forms and allowed multipart forms under the cap. Oversized
   reads return 413, other parse failures return 400, and multipart temporary
   files are cleaned up after the request.
5. Nosurf checks the origin and token before running the handler.

The kit's own refusals (413, 415 and 400) log one warning with the status,
method and path (never the query, headers or body; the path is logged as is
unless `LogPath` is set) and answer in plain text with
`Cache-Control: no-store`.
If your paths carry credentials (one-time sign-in or reset links), set
`LogPath` to return a redacted path or the mux pattern. When using
`ServeMux.Handler`, register routes with methods and only log patterns that
include a method followed by a space: a mux-generated redirect can return a
request-derived path instead of a registered pattern. A path can itself
contain a space, so reject path-shaped results too. Use a constant such as
`unmatched` otherwise. With the mux initialized as shown below, for example:

```go
LogPath: func(r *http.Request) string {
	m := mux.Load()
	if m == nil {
		return "unmatched"
	}
	_, pattern := m.Handler(r)
	if method, _, ok := strings.Cut(pattern, " "); ok && method != "" && !strings.Contains(method, "/") {
		return pattern
	}
	return "unmatched"
},
```

A `Logger` whose handler rewrites the top-level `path` attribute also works.

Set `Config.OnBodyError` to write the response
yourself; the warning is still logged. The hook runs after the kit has set
`Cache-Control: no-store` and, for a 413 or 415 on HTTP/1, `Connection: close`
so the server does not need to drain the rest of the body to reuse the
connection. It receives an empty body and no parsed form fields (the query
string stays readable). It is not called for CSRF failures (`OnFailure`), the
oversized-upload hand-off (`Oversized`) or the 500 for a `Limit` bug. Use it to
word the refusal for your users; it cannot accept the request. For example, to
show a refusal inside an htmx target:

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

Inside the hook, `csrf.BodyError(r)` says why: `ErrBodyTooLarge` for every
413, `ErrMultipartRefused` for every 415, and the read or parse error for a
400. A read that ran into a deadline satisfies
`errors.Is(err, os.ErrDeadlineExceeded)`, so a slow upload can get 408:

```go
OnBodyError: func(w http.ResponseWriter, r *http.Request, status int) {
	if errors.Is(csrf.BodyError(r), os.ErrDeadlineExceeded) {
		w.Header().Set("Connection", "close")
		http.Error(w, "The upload took too long. Try again.", http.StatusRequestTimeout)
		return
	}
	http.Error(w, http.StatusText(status), status)
},
```

Branch on the error; do not show or log its text.

The middleware's 413 and 415 refusals also apply to exempt routes. For a
JSON endpoint, check the mux pattern in `OnBodyError` and write a JSON error
instead of the default plain text.

A declared-length 413 or a 415 is sent without reading the body; a streamed
413 can follow a bounded read. On HTTP/1 the connection closes, and a browser
still sending a large upload may show a connection error instead of the
refusal page. If that matters for a refusal before any read, keep a reference
to the original body in middleware outside `p.Handler`. In `OnBodyError`,
drain only a bounded number of bytes under a read deadline before answering,
and only for callers you have already authenticated. Do not drain through
the hook's request body: it is empty.

### Adoption checklist

1. **The origin is required.** `New` fails without `Origin`. Use lowercase
   `https://app.example[:port]` (or `http://` only with `Insecure`): no path,
   query, fragment, userinfo or trailing slash. Leave out the scheme's default
   port and write any other port as browsers do, without leading zeros
   (`https://app.example:443`, `https://app.example:0443` and
   `https://app.example:0` fail startup). Browsers omit default ports and
   normalize leading zeros; the policy also disallows port zero.
   Write internationalized hosts in Punycode, IPv6 literals in canonical
   compressed form, and IPv4 addresses as canonical dotted quads.
   To check a configured value before anything else starts (for example,
   before migrations), call `csrf.ValidateOrigin(value, insecure)`; `New`
   applies exactly the same rules. Every
   `TrustedOrigins` entry has the same format. The origin is always trusted
   even when a proxy rewrites `Host`; sibling subdomains are not trusted unless
   listed; and the TLS answer comes from config, not a forwarded header,
   because a client-supplied header must not change the policy. A value that
   an older hand-written check silently never matched (a trailing slash,
   upper case) now **fails startup**, so validate configuration before
   deploying.

   Nosurf accepts `Sec-Fetch-Site: same-origin` without comparing `Origin`.
   Browsers set that header themselves; page scripts cannot set it, and
   unsafe, non-exempt requests still need a valid token. If your application
   also requires `Origin` to match in this case, keep that additional check
   in front of the middleware.
2. **Duplicates are ignored.** A `TrustedOrigins` entry equal to `Origin` or to
   an earlier entry is accepted and ignored, so a list shared with a CORS
   setup does not fail a start. Malformed entries still fail.
3. **Per-route limits run before routing.** `Limit` runs for unsafe methods;
   `Exempt` runs for requests that reach the exemption check. Either can run
   before `mux.Store`; a nil mux should mean default limits and no exemption.
   Decide with the mux's own match, comparing the **pattern**, never a
   string prefix of `r.URL.Path` (alternate spellings of a path may not reach
   the same handler). Keep a reference to the mux (an
   `atomic.Pointer[http.ServeMux]` when the mux is built after the policy).
   For a path like `/a/./b` that the mux redirects to a matching route,
   `Handler` returns that route's pattern. Its cap applies before the mux
   can send the redirect.

   ```go
   var mux atomic.Pointer[http.ServeMux]

   p, err := csrf.New(csrf.Config{
       Origin: "https://app.example",
       Limit: func(r *http.Request) csrf.BodyLimit {
           m := mux.Load()
           if m == nil {
               return csrf.BodyLimit{}
           }
           if _, pattern := m.Handler(r); pattern == "POST /photos" {
               return csrf.BodyLimit{MultipartMaxBytes: 32 << 20}
           }
           return csrf.BodyLimit{}
       },
       Exempt: func(r *http.Request) bool {
           m := mux.Load()
           if m == nil {
               return false
           }
           _, pattern := m.Handler(r)
           return pattern == "POST /webhook"
       },
   })
   // Check err, then build m and register routes before mux.Store(m).
   // Serve p.Handler(m).
   ```

4. **`Renew` and `Token` work only inside `Handler`.** Outside it (and on
   exempt routes) `Token` returns `""` and `Renew` returns `ErrNotProtected`.
   Check the error. A sign-in test should assert that the CSRF cookie value
   changes.
5. **Build the `*csrf.Protect` before the handlers** and pass it to their
   constructors. If a setter is unavoidable, make route registration fail when
   it was never called: a silent no-op means sign-in never renews the token.
6. **`OnBodyError` is for the kit's own refusals only** (413, 415 and 400); see
   above for what it receives and what the kit has already set.
7. **Caps depend on the media type.** `BodyLimit` has three fields:

   - `MaxBytes` caps every non-multipart body (0 means `Config.MaxBody`;
     more than 64 MiB gets a 500 and an error log, because such a body is
     parsed in memory).
   - `MultipartMaxBytes` allows `multipart/form-data` up to that size; 0
     refuses multipart with 415.
   - `MaxMemory` is the multipart parse memory (0 means
     `min(MultipartMaxBytes, 1 MiB)`; larger values are clamped to
     `MultipartMaxBytes`). Larger file parts spool to disk.

   `MaxBytes` never applies to multipart, and `MultipartMaxBytes` never applies
   to anything else, so a route with a huge upload cap cannot be used to send a
   huge form, JSON or text body. Negative values behave as 0. See the
   `POST /photos` limit in the example above.

Cookies are host-only, HttpOnly, Secure by default, and last for the browser
session. They are SameSite=Lax unless `CrossSite` is set for a credentialed
cross-site embed; that option requires Secure. The name is prefixed with
`__Host-` at `/` or `__Secure-` on a narrower path, reducing cookie injection.
Plain-HTTP development explicitly sets `Insecure` and uses the bare name.
Adopting the prefixed name makes forms opened before the change expire once.

Failed CSRF checks log a warning and return a plain-text 403 with
`Cache-Control: no-store`. For `HX-Request: true` the response also sets
`HX-Refresh: true`. Override the response with `OnFailure` if reloading would
discard unsaved typing. The warning is still logged, and `csrf.Reason(r)` is
available inside the override. Use `errors.Is` to compare it with
`csrf.ErrBadToken`, `csrf.ErrBadOrigin`, `csrf.ErrNoReferer` or
`csrf.ErrBadReferer`.

Call `p.Renew(w, r)` before writing headers at sign-in, sign-out and when users
change their own password. It replaces the cookie and returns the masked token
for the current response so a pre-sign-in or injected token doesn't survive the
credential change. On exempt or unprotected requests it returns
`csrf.ErrNotProtected` without setting a cookie.

### Authenticate before large uploads

The middleware parses an allowed multipart body before anything inside the
mux runs. If an upload route allows large bodies, authenticate the caller
outside `p.Handler` so an anonymous request cannot make it read the upload.
In this example, `lookupSession` checks the session and upload permission
without reading the body and returns the permitted upload cap in bytes.
Pass a mux with `POST /photos` registered.

```go
func protectUploads(mux *http.ServeMux, sessions *cookie.Cookie,
	lookupSession func(*http.Request, string) (capBytes int64, ok bool),
) (http.Handler, error) {
	type uploadCapKey struct{}
	p, err := csrf.New(csrf.Config{
		Origin: "https://app.example",
		Limit: func(r *http.Request) csrf.BodyLimit {
			n, _ := r.Context().Value(uploadCapKey{}).(int64)
			return csrf.BodyLimit{MultipartMaxBytes: n}
		},
	})
	if err != nil {
		return nil, err
	}
	next := p.Handler(mux)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, pattern := mux.Handler(r); pattern == "POST /photos" {
			token, hasCookie := sessions.Value(r)
			var capBytes int64
			var allowed bool
			if hasCookie {
				capBytes, allowed = lookupSession(r, token)
			}
			if !allowed || capBytes <= 0 {
				w.Header().Set("Cache-Control", "no-store")
				if r.ProtoMajor == 1 {
					w.Header().Set("Connection", "close")
				}
				http.Error(w, "Sign in to upload.", http.StatusUnauthorized)
				return
			}
			rc := http.NewResponseController(w)
			now := time.Now()
			if rc.SetReadDeadline(now.Add(30*time.Second)) != nil ||
				rc.SetWriteDeadline(now.Add(35*time.Second)) != nil {
				http.Error(w, "Upload unavailable.", http.StatusServiceUnavailable)
				return
			}
			r = r.WithContext(context.WithValue(r.Context(), uploadCapKey{}, capBytes))
		}
		next.ServeHTTP(w, r)
	}), nil
}
```

### Custom refusal for oversized uploads

To show a friendly error on an upload route, have `Limit` return a `BodyLimit`
with `MultipartMaxBytes` set and a `PassOversized` callback. The callback
must check the session and upload permission without reading the body. Set
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
routes without the opt-in keep the plain 413. A request that sends
`X-CSRF-Token` is refused with 403 even if the token is valid: the friendly
refusal is for browser forms, whose token travels in the discarded body, and
a valid token must never deliver a discarded body to a route. This refusal
after a successful token check is logged. `OnFailure`
is not called for it; a failed origin or token check still goes through
`OnFailure`. Streamed uploads that exceed the cap still get 413 after a
bounded read; uploads at or below the cap still need a valid token.

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

A sweep deletes rows at or past either enabled deadline, counting activity
before creation as creation:

```sql
DELETE FROM sessions
WHERE created_at <= :now - <absolute>
   OR max(created_at, last_seen) <= :now - <idle>
```

Omit the idle term with `IdleOff`; use `GREATEST` instead of `max` in
Postgres. Judge idle expiry with the same clock that wrote `last_seen`:
if Go wrote the timestamp, bind `:now` from that clock rather than using
the database's `now()`.

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
write `timestamptz` values; SQL `now()` stays unchanged. Use the application's
own hash function, or derive it in the test (`sha256.Sum256([]byte(token))`)
if you want the test to pin the stored format. `RawRows` returns every stored
session column, with text as-is and binary data rendered in hex. The result
must grow when a session is added.

If `Lookup` sends the token through your routes as a cookie, set
`CookieTokens: true`: a Cookie header cannot carry the NUL and newline
variants, so the suite sends a truncated and an extended token instead.

The fixtures require the store's real absolute limit to be at least ten
minutes. If idle expiry is enabled, the idle limit must be at least five
minutes, at least four times the touch interval, and at least five minutes
shorter than the absolute limit. Set `Harness.TouchEvery` to the store's
interval if it is longer than the default minute. With `IdleOff`, leave
`TouchEvery` unset and omit `LastSeen`; idle and touch pass without running
and log why (`go test -v` shows the reason).

`ChangePassword` returns the token still valid for the current browser:
the current token, a rotated token, or `""` if all the user's sessions
ended. Only `sessiontest.CaseDisable`, `CasePasswordChange` and
`CaseRevokeUser` can be opted out. Leave the callback nil and give a reason in
`NotApplicable`. Those cases pass without running and log why
(`go test -v` shows the reason); a case your callback skips with `t.Skip`
fails the suite.

```go
NotApplicable: map[sessiontest.Case]string{
	sessiontest.CaseRevokeUser: "accounts are managed by one person",
},
```

Every case has a constant (`CaseFresh`, `CaseAbsolute`, `CaseIdle`, ...) whose
value is the subtest name that `go test` prints.

## webtest

Integration-test helpers: a browser-like client, forms and CSRF tokens, route
sweeps, cookie checks, and body, temporary-file and log probes. Import
`github.com/17xande-dev/websec/webtest` only from `_test.go` files.

```go
c := webtest.New(t, app, "https://app.example") // in-process
// Or use webtest.NewServer(t, srv) for a real connection.
c.Get("/ready").WantStatus(http.StatusNoContent)
```

To sign in once and use the same session in subtests, call `c.With(t)` with
the subtest's `t`:

```go
c.SignIn("/login", url.Values{"password": {pw}})
for _, path := range []string{"/items", "/items/new"} {
	t.Run(path, func(t *testing.T) {
		t.Parallel()
		c.With(t).Get(path).WantStatus(http.StatusOK)
	})
}
```

The returned client and the responses, pages and forms it creates report
assertions to the subtest. Assertion methods on responses, pages and forms
from the original client still report to the original test; fetch them again
through the bound client. Call methods that can fail the test only from the
goroutine running the test they are bound to. Parallel subtests can each use
their own bound client if the shared handler and custom options are safe for
concurrent requests. The cookie jar is shared, not copied: a cookie change in
one subtest is visible to the others.
See the [compiled subtest example](webtest/example_test.go).

The client keeps cookies and sends its `Origin` on unsafe requests by default.
Use `WithOrigin` to override the header without changing the request URL.
As a constructor option it sets the header on every request, including safe
methods; as a request option it sets it only for that request.

Use an `https://` origin in-process and `httptest.NewTLSServer` with `NewServer`
to test production cookie and CSRF settings. The Go jar does not send Secure
cookies to non-loopback HTTP origins; it may still send them to an HTTP
loopback server. The jar does not enforce cookie prefixes, so use `WantCookie`
to check them.

`Cookie(name)` reads the cookies the jar would send to the base URL (path `/`),
so a cookie with `Path=/admin` is invisible to it. `CookieAt(path, name)` asks
the jar for that path instead: `CookieAt("/admin", n)` and `CookieAt("/admin/x", n)`
find an `/admin` cookie, `CookieAt("/", n)` does not, a root cookie is found at
every path, and an empty path means `/`. A path without a leading `/` fails the
test. It mirrors what a browser would send: with the same name stored at several
matching paths it returns the value listed first, the most specific path's, and
a Secure cookie is not returned on an HTTP origin.
See the [compiled example](webtest/example_test.go).

The client neither follows redirects nor parses `Location` automatically.
`Follow` explicitly follows a parseable same-origin 3xx `Location` with a GET;
to check another target, assert on `Location` or use `WantRedirect` instead.
Go's `http.Client` fails on a Location such as `"/\t/evil.example"` before a
test can see it; a browser reads that value as `//evil.example`. In-process
tests see what the handler wrote. Use `Header.Set` or `Header.Add` to write
the canonical `Location` key for the helpers. Over a connection Go's reader
refuses some bytes, and the server turns CR/LF into spaces.

In-process responses do not get automatic `Date` or `Content-Length` headers.
The in-process transport also does not recover handler panics or remove
multipart temp files for the handler.

The client does not send `Sec-Fetch-Site` unless asked: `same-origin` makes
nosurf skip its Origin comparison, which could hide a wrong trusted origin.

```go
res := c.SignIn("/login", url.Values{"email": {"owner@app.example"}, "password": {pw}})
res.WantRedirect(http.StatusSeeOther, "/")
c.Page("/items/new").Form("/items").Set("title", "A").Submit().WantStatus(http.StatusSeeOther)
```

Use `Page.Form("")` if the page has exactly one form. Submit buttons are not
included automatically: use `Set` to add the clicked button's name and value.

Sweep every protected route with its own method. `Run` fails on 2xx, 404, 405
and 5xx whatever `Refused` says, and on fewer protected routes than `Min`.
It returns the number of protected routes swept, not the number of requests.
Routes marked `Public` must give a `Why`; they are logged and skipped.
In a subtest, pass its `t` to `Run`. The `Client` factory returns fresh
anonymous clients, and `Run` binds each one to the supplied `t`.
Each `Cookies` entry is tried separately. `SetCookie` fails if the jar would
not send that cookie to the base URL (for example, a Secure cookie on a
non-loopback HTTP origin), so an unsendable variant cannot pass anonymously.

```go
webtest.Sweep{
	Routes:    webtest.Routes(t, protectedPatterns, map[string]string{"id": "1"}),
	Min:       20,
	Client:    func() *webtest.Client { return webtest.New(t, app, "https://app.example") },
	TokenPage: "/login",
	Refused:   webtest.ByMethod(webtest.RedirectsTo("/login?next="), webtest.Status(http.StatusUnauthorized)),
}.Run(t)
```

See the [compiled sweep and sign-in example](webtest/example_test.go).

`WantCookie` checks the named response cookie against literal attributes as
well as the browser's prefix rules. Write the expected wire name (such as
`"__Host-session"`) and redirect Location by hand. An expectation computed by
the function under test can agree with the same bug.

Use `NewCountingReader(webtest.Filler(n))` to count body reads without
allocating the upload, and `Streamed()` for an unknown length. A zero or
exact read-count assertion belongs in-process: on the wire `N()` counts what
the client pulled from the source, not necessarily what the handler read.
Call the check returned by `NoTempFiles(t)` after the request. It detects
leftovers, not files already removed, and uses `t.Setenv`, so do not use it
with `t.Parallel` or in a parallel ancestor's subtest. A subtest's first
`t.TempDir` call can create a directory under the watched `TMPDIR`, which the
check will report as a leftover.

`Logger` captures Debug and higher slog records as JSON. Wait for any
asynchronous logging before calling `NoSecrets` with the captured text, a
literal marker from the expected log record, and secrets of at least 12 bytes.
It rejects raw and encoded forms anywhere in the captured log. Failed
response assertions can print up to 300 bytes of the response body, so test
output can still contain values rendered by the handler. See the
[upload refusal test](webtest/example_test.go) for a complete example.

Use `Raw` with a test server's TCP address and a verbatim request containing
`Connection: close` to inspect header bytes Go's HTTP reader rejects. It uses
plain TCP, not TLS, and rejects HEAD requests; use `Client.Do` for HEAD.
Reads expect the advertised response framing and have a 30-second connection
deadline. `Raw` cannot undo CR/LF replacement already performed by the server.
Use `HostileRedirects()` as inputs and assert a literal fallback Location.

## Changes

- **v0.5.1**
  - `webtest.NoSecrets` also fails when a secret appears with every byte
    percent-encoded (`%41%42…`, upper or lower-case digits), a form that
    `url.QueryEscape` and `url.PathEscape` do not produce.
  - `(*webtest.Client).CookieAt(path, name)` returns a cookie the jar would
    send to `path`, so a cookie scoped to a sub-path such as `/admin` can be
    read. `Cookie(name)` is unchanged and still reads path `/`.
- **v0.5.0**
  - `webtest` adds integration-test clients, assertions and probes.
  - `(*webtest.Client).With(t)` binds assertions to a subtest while sharing the
    original client's cookies and configuration.
- **v0.4.0**
  - `csrf.ValidateOrigin` and `csrf.New` refuse Unicode hosts and noncanonical
    IPv4 and IPv6 spellings that browsers don't use in `Origin` headers.
    Upgrading: an `Origin` written in one of those spellings (for example
    `https://127.1` or `https://äpp.example`) now fails at startup. Write the
    form a browser sends: dotted-quad IPv4, compressed IPv6, Punycode for
    international names.
  - The `LogPath` example now falls back to a constant for a redirected raw
    path, so a path carrying a secret is never logged.
  - `cookie.Config.Now` is read once at construction; pass a closure when the
    clock is swappable later.
- **v0.3.0**
  - `csrf.ValidateOrigin` checks configuration with the same rules as `New`,
    which now also refuses ports with leading zeros and port zero.
  - `csrf.BodyError` exposes the cause inside `OnBodyError`, including
    `ErrBodyTooLarge` for 413 and `ErrMultipartRefused` for 415.
  - `csrf.Config.LogPath` lets callers log a redacted path or mux pattern.
  - `csrf.ErrBadToken`, `ErrBadOrigin`, `ErrNoReferer` and `ErrBadReferer` let
    callers check `csrf.Reason` without importing nosurf.
  - `cookie.Config.Now` lets `Set` use the session store's clock to measure
    remaining lifetime. `cookie.Config` and `cookie.Cookie` now contain a
    function field, so values of those types can no longer be compared with
    `==` or used as map keys.
  - `sessiontest` reports not-applicable cases as passing without running
    them and logs the reason.
  - `sessiontest.Harness.CookieTokens` substitutes truncated and extended
    tokens for the NUL and trailing-newline variants in the `miss` case.
- **v0.2.0**: Adds session cookie helpers, session lifetime policy, session
  store conformance tests and CSRF protection with bounded form parsing.
  Safe methods have a body cap and refuse multipart; on unsafe methods,
  `BodyLimit` separates `MaxBytes` (at most 64 MiB) from `MultipartMaxBytes`
  (0 refuses multipart). Oversized uploads can opt into a custom refusal,
  but even a valid `X-CSRF-Token` cannot send a discarded body to the route.
  Body refusals can be customized with `OnBodyError`, and
  `Cache-Control: no-store` is set before `OnBodyError` runs. HTTP/1 body
  refusals with 413 or 415, and a 500 due to an invalid `Limit`, set
  `Connection: close`. Origins that spell out the default port are refused;
  duplicate trusted origins are ignored, but malformed entries still fail
  startup. `sessiontest` exports constants for its case names, including
  those that can be listed in `Harness.NotApplicable`.
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

## License

This module is licensed under the [MIT No Attribution license](LICENSE).
