// Package csrf protects browser requests with nosurf and bounds form parsing
// before nosurf looks for a token.
package csrf

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"

	"github.com/17xande-dev/websec/cookie"
	"github.com/justinas/nosurf"
)

const (
	// FieldName is the form field for the masked token.
	FieldName = nosurf.FormFieldName
	// HeaderName is the request header for the masked token.
	HeaderName = nosurf.HeaderName

	defaultMaxBody = 256 << 10
)

// ErrNotProtected is returned when Renew has no active CSRF request.
var ErrNotProtected = errors.New("csrf: request is not protected")

// Config describes the CSRF policy shared by all handlers wrapped by a Protect.
type Config struct {
	// Origin is the public origin, without a trailing slash, and is always
	// trusted. Use the exact scheme://host[:port] sent by browsers.
	Origin         string
	TrustedOrigins []string // extra exact origins for cross-origin requests
	Insecure       bool     // plain-HTTP development only; disables Secure and the prefix
	CrossSite      bool     // SameSite=None for credentialed embeds; requires Secure
	Path           string   // cookie path; "" means "/"
	Name           string   // bare cookie name; "" means "csrf_token"

	Exempt func(*http.Request) bool // exempt requests skip nosurf, not the body limit

	MaxBody int64                         // default cap; 0 means 256 KiB
	Limit   func(*http.Request) BodyLimit // per-request override; nil disallows multipart

	OnFailure http.Handler // replaces the default response, not the warning; Reason is available
	Logger    *slog.Logger // nil means slog.Default()
}

// Protect holds a validated policy. Use New to construct it.
type Protect struct {
	baseCookie http.Cookie
	renew      *nosurf.CSRFHandler
	isAllowed  func(*url.URL) bool
	exempt     func(*http.Request) bool
	maxBody    int64
	limit      func(*http.Request) BodyLimit
	onFailure  http.Handler
	logger     *slog.Logger
}

// New validates the policy and prepares it for use by Handler.
func New(c Config) (*Protect, error) {
	allowed, err := originPolicy(c.Origin, c.TrustedOrigins, c.Insecure)
	if err != nil {
		return nil, err
	}
	if c.CrossSite && c.Insecure {
		return nil, errors.New("csrf: CrossSite requires a secure cookie")
	}
	if c.MaxBody < 0 || c.MaxBody > 64<<20 {
		return nil, errors.New("csrf: MaxBody must be between 0 and 64 MiB")
	}
	if c.MaxBody == 0 {
		c.MaxBody = defaultMaxBody
	}
	if c.Name == "" {
		c.Name = nosurf.CookieName
	}
	if c.Path == "" {
		c.Path = "/"
	}
	// Reuse validation and the wire name (via cookie.PrefixedName) so the
	// session and CSRF cookies agree on their scope rules.
	policy, err := cookie.New(cookie.Config{Name: c.Name, Path: c.Path, Insecure: c.Insecure})
	if err != nil {
		return nil, fmt.Errorf("csrf: %w", err)
	}
	base := http.Cookie{
		Name:     policy.Name(),
		Path:     c.Path,
		HttpOnly: true,
		Secure:   !c.Insecure,
		SameSite: http.SameSiteLaxMode,
	}
	if c.CrossSite {
		base.SameSite = http.SameSiteNoneMode
	}
	renew := nosurf.New(nil)
	renew.SetBaseCookie(base)
	if c.OnFailure == nil {
		c.OnFailure = http.HandlerFunc(defaultFailure)
	}
	if c.Logger == nil {
		c.Logger = slog.Default()
	}
	return &Protect{
		baseCookie: base,
		renew:      renew,
		isAllowed:  allowed,
		exempt:     c.Exempt,
		maxBody:    c.MaxBody,
		limit:      c.Limit,
		onFailure:  c.OnFailure,
		logger:     c.Logger,
	}, nil
}

// Handler wraps next. Several handlers wrapped by the same Protect share a
// cookie and can use tokens issued by one another.
func (p *Protect) Handler(next http.Handler) http.Handler {
	check := nosurf.New(next)
	check.SetBaseCookie(p.baseCookie)
	// The public connection may terminate TLS at a proxy. A request header
	// must not be able to change which scheme nosurf treats as same-origin.
	check.SetIsTLSFunc(func(*http.Request) bool { return p.baseCookie.Secure })
	check.SetIsAllowedOriginFunc(p.isAllowed)
	check.SetFailureHandler(http.HandlerFunc(p.fail))
	return p.limitBody(next, check)
}

// CookieName returns the cookie's name on the wire, including any prefix.
func (p *Protect) CookieName() string {
	return p.baseCookie.Name
}

// Renew replaces the CSRF cookie and returns the new masked token for the
// current response. Call before writing headers, on sign-in, sign-out, or a
// password change. Exempt and unprotected requests return ErrNotProtected.
func (p *Protect) Renew(w http.ResponseWriter, r *http.Request) (string, error) {
	// RegenerateToken assumes the package-global nosurf context already exists.
	if Token(r) == "" {
		return "", ErrNotProtected
	}
	return p.renew.RegenerateToken(w, r), nil
}

// Token returns the masked token for a form or header, or "" outside nosurf.
func Token(r *http.Request) string {
	return nosurf.Token(r)
}

// Reason returns nosurf's failure reason, or nil outside a failed check.
func Reason(r *http.Request) error {
	// In v1.2.0 Reason asserts the context type without checking for absence.
	if Token(r) == "" {
		return nil
	}
	return nosurf.Reason(r)
}

func (p *Protect) fail(w http.ResponseWriter, r *http.Request) {
	reason := Reason(r)
	// A parse error from nosurf can echo the raw Origin header. Only log
	// known constant reasons, not header text controlled by the request.
	switch reason {
	case nosurf.ErrBadOrigin, nosurf.ErrNoReferer, nosurf.ErrBadReferer, nosurf.ErrBadToken:
	default:
		reason = errors.New("malformed origin")
	}
	p.logger.WarnContext(r.Context(), "csrf: request refused",
		"method", r.Method, "path", r.URL.Path, "reason", reason)
	p.onFailure.ServeHTTP(w, r)
}

func defaultFailure(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Header.Get("HX-Request") == "true" {
		w.Header().Set("HX-Refresh", "true")
		http.Error(w, "This form has expired. The page will reload.", http.StatusForbidden)
		return
	}
	http.Error(w, "This form has expired or came from another site. Reload the page and try again.", http.StatusForbidden)
}
