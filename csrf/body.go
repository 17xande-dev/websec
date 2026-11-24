package csrf

import (
	"context"
	"errors"
	"io"
	"mime"
	"net/http"
	"strings"
)

// BodyLimit controls the cap and multipart policy for an unsafe request.
type BodyLimit struct {
	MaxBytes  int64 // 0 means Config.MaxBody
	Multipart bool  // accept multipart/form-data
	MaxMemory int64 // 0 means min(MaxBytes, 1 MiB); file parts may spool above it

	// PassOversized opts a permitted request into the friendly refusal for
	// declared oversized multipart uploads. Check session and upload
	// permission without reading the body. Requires Config.Oversized.
	PassOversized func(*http.Request) bool
}

type oversizedKey struct{}

// Oversized reports whether the body was discarded for an oversized-upload
// refusal. It does not mean the request passed CSRF validation.
func Oversized(r *http.Request) bool {
	return r.Context().Value(oversizedKey{}) == true
}

func (p *Protect) limitBody(next, check http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if safeMethod(r.Method) {
			// Browsers send no body on these methods, but Request.FormValue
			// parses a multipart one for any method and spools its files to
			// disk. Bound it, and refuse the one type that parses.
			if mediaType, _ := requestMediaType(r); mediaType == "multipart/form-data" {
				p.bodyError(w, r, http.StatusUnsupportedMediaType)
				return
			}
			r.Body = http.MaxBytesReader(w, r.Body, p.maxBody)
			if p.isExempt(r) {
				next.ServeHTTP(w, r)
			} else {
				check.ServeHTTP(w, r)
			}
			return
		}

		limit := p.bodyLimit(r)
		if r.ContentLength > limit.MaxBytes {
			if p.oversized != nil && limit.Multipart && limit.PassOversized != nil {
				mediaType, _ := requestMediaType(r)
				if mediaType == "multipart/form-data" && !p.isExempt(r) && limit.PassOversized(r) {
					if r.ProtoMajor == 1 {
						// Don't drain the body to reuse this HTTP/1 connection.
						w.Header().Set("Connection", "close")
					}
					r = r.WithContext(context.WithValue(r.Context(), oversizedKey{}, true))
					// Let nosurf check the origin without seeing any upload data,
					// even if an outer handler populated the parsed form fields.
					r.Body = http.NoBody
					r.Form, r.PostForm, r.MultipartForm = nil, nil, nil
					check.ServeHTTP(w, r)
					return
				}
			}
			p.bodyError(w, r, http.StatusRequestEntityTooLarge)
			return
		}
		mediaType, mediaErr := requestMediaType(r)
		if mediaType == "multipart/form-data" && !limit.Multipart {
			p.bodyError(w, r, http.StatusUnsupportedMediaType)
			return
		}

		r.Body = http.MaxBytesReader(w, r.Body, limit.MaxBytes)
		if p.isExempt(r) {
			next.ServeHTTP(w, r)
			return
		}

		var err error
		switch mediaType {
		case "application/x-www-form-urlencoded":
			if mediaErr != nil {
				err = mediaErr
			} else {
				err = r.ParseForm()
			}
		case "multipart/form-data":
			if mediaErr != nil {
				err = mediaErr
				break
			}
			err = r.ParseMultipartForm(limit.MaxMemory)
			if r.MultipartForm != nil {
				defer r.MultipartForm.RemoveAll()
			}
			if err == nil {
				// The parser stops at the closing boundary. Count any
				// epilogue too, including in a chunked request.
				_, err = io.Copy(io.Discard, r.Body)
			}
		}
		if err != nil {
			status := http.StatusBadRequest
			var tooLarge *http.MaxBytesError
			if errors.As(err, &tooLarge) {
				status = http.StatusRequestEntityTooLarge
			}
			p.bodyError(w, r, status)
			return
		}
		check.ServeHTTP(w, r)
	})
}

func (p *Protect) bodyLimit(r *http.Request) BodyLimit {
	var limit BodyLimit
	if p.limit != nil {
		limit = p.limit(r)
	}
	if limit.MaxBytes <= 0 {
		limit.MaxBytes = p.maxBody
	}
	if limit.MaxMemory <= 0 {
		limit.MaxMemory = min(limit.MaxBytes, 1<<20)
	}
	return limit
}

func (p *Protect) isExempt(r *http.Request) bool {
	return p.exempt != nil && p.exempt(r)
}

func safeMethod(method string) bool {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodTrace:
		return true
	}
	return false
}

func requestMediaType(r *http.Request) (string, error) {
	raw := r.Header.Get("Content-Type")
	mediaType, _, err := mime.ParseMediaType(raw)
	if err != nil {
		// A malformed parameter must not let multipart evade the refusal.
		leading, _, _ := strings.Cut(raw, ";")
		mediaType = strings.ToLower(strings.TrimSpace(leading))
	}
	return mediaType, err
}

// bodyError answers a refusal made by the kit itself before any token check.
// The warning is logged whether or not OnBodyError replaces the response, and
// never includes a request value other than the path (no query, no headers).
func (p *Protect) bodyError(w http.ResponseWriter, r *http.Request, status int) {
	p.logger.WarnContext(r.Context(), "csrf: request body refused",
		"status", status, "method", r.Method, "path", r.URL.Path)
	if p.onBodyErr != nil {
		p.onBodyErr(w, r, status)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	http.Error(w, http.StatusText(status), status)
}
