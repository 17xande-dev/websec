// Package cookie builds and clears host-only session cookies with fixed
// security attributes.
package cookie

import (
	"errors"
	"net/http"
	"strings"
	"time"
)

// Config describes a session cookie. HttpOnly keeps the credential out of
// scripts, and SameSite=Lax withholds it on cross-site POSTs.
type Config struct {
	Name           string // bare name, e.g. "session"; the prefix is derived
	Path           string // "" means "/"
	Insecure       bool   // plain-HTTP development only: no Secure attribute or prefix
	BrowserSession bool   // omit Max-Age and Expires

	// Now returns the current time for Set's remaining-lifetime check and
	// Max-Age. nil means time.Now. Set it when the server's session clock is
	// injected, so expiry decisions and the cookie agree.
	Now func() time.Time
}

// Cookie is an immutable session cookie policy created by New.
type Cookie struct {
	name           string
	path           string
	secure         bool
	browserSession bool
	now            func() time.Time
}

// New validates the bare name and path and builds a session cookie policy.
func New(c Config) (*Cookie, error) {
	name := strings.ToLower(c.Name)
	if strings.HasPrefix(name, "__host-") || strings.HasPrefix(name, "__secure-") {
		return nil, errors.New("cookie: name must not include a security prefix")
	}
	if err := (&http.Cookie{Name: c.Name}).Valid(); err != nil {
		return nil, errors.New("cookie: name must be a non-empty RFC 6265 token")
	}
	if c.Path == "" {
		c.Path = "/"
	}
	if c.Path[0] != '/' || len(c.Path) > 1024 {
		return nil, errors.New("cookie: path must start with / and be at most 1024 bytes")
	}
	// Refuse paths net/http would alter rather than silently changing their scope.
	if err := (&http.Cookie{Name: c.Name, Path: c.Path}).Valid(); err != nil || strings.Contains(c.Path, " ") {
		return nil, errors.New("cookie: path must contain only printable ASCII without spaces or semicolons")
	}
	if c.Now == nil {
		c.Now = time.Now
	}
	return &Cookie{
		name:           PrefixedName(c.Name, c.Path, c.Insecure),
		path:           c.Path,
		secure:         !c.Insecure,
		browserSession: c.BrowserSession,
		now:            c.Now,
	}, nil
}

// PrefixedName derives the wire name without validating its inputs. A secure
// root-path cookie gets __Host-; other secure cookies get __Secure-. An empty
// path means /, and insecure cookies keep the bare name.
func PrefixedName(name, path string, insecure bool) string {
	switch {
	case insecure:
		return name
	case path == "" || path == "/":
		return "__Host-" + name
	default:
		return "__Secure-" + name
	}
}

// Name returns the cookie's name on the wire, including any prefix.
func (c *Cookie) Name() string {
	return c.name
}

// Set writes the cookie without extending it past expires. If less than one
// whole second remains, Set clears it. A browser-session cookie ignores expires.
// Set panics if net/http would drop any bytes from value.
func (c *Cookie) Set(w http.ResponseWriter, value string, expires time.Time) {
	wire := c.wireCookie()
	wire.Value = value
	// net/http otherwise logs and strips invalid bytes from an app-minted token.
	if err := wire.Valid(); err != nil {
		panic("cookie: invalid session cookie value")
	}
	if !c.browserSession {
		seconds := expires.Sub(c.now()) / time.Second
		if seconds <= 0 {
			// A MaxAge of zero would omit the attribute, not delete the cookie.
			c.Clear(w)
			return
		}
		wire.Expires = expires.UTC().Truncate(time.Second)
		wire.MaxAge = int(seconds)
	}
	http.SetCookie(w, &wire)
}

// Clear removes the cookie using the same name, path and security attributes.
func (c *Cookie) Clear(w http.ResponseWriter) {
	wire := c.wireCookie()
	wire.MaxAge = -1
	wire.Expires = time.Unix(0, 0).UTC() // Also expire it in clients that ignore Max-Age.
	http.SetCookie(w, &wire)
}

// Value reads only the wire name, without falling back to an old bare name.
func (c *Cookie) Value(r *http.Request) (string, bool) {
	wire, err := r.Cookie(c.name)
	if err != nil {
		return "", false
	}
	return wire.Value, true
}

func (c *Cookie) wireCookie() http.Cookie {
	return http.Cookie{
		Name:     c.name,
		Path:     c.path,
		Secure:   c.secure,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	}
}
