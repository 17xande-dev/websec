package csrf

import (
	"context"
	"errors"
	"io"
	"mime"
	"net/http"
	"strings"
)

// BodyLimit controls the size caps and multipart policy for an unsafe request.
// The request's media type picks the cap: MaxBytes never applies to multipart,
// and MultipartMaxBytes never applies to anything else. A route with a very
// large upload cap therefore cannot be used to send a very large form, JSON
// or text body.
type BodyLimit struct {
	// MaxBytes caps every non-multipart body. 0 means Config.MaxBody; more
	// than 64 MiB is a programming error (a non-multipart body is parsed in
	// memory) and the request gets 500 without reading anything.
	MaxBytes int64
	// MultipartMaxBytes allows multipart/form-data up to this many bytes. 0
	// refuses multipart with 415. There is no upper bound.
	MultipartMaxBytes int64
	// MaxMemory is the multipart parse memory; file parts may spool to disk
	// above it. 0 means min(MultipartMaxBytes, 1 MiB); a larger value is
	// clamped to MultipartMaxBytes.
	MaxMemory int64

	// PassOversized opts a permitted request into the friendly refusal for
	// multipart uploads whose declared length exceeds MultipartMaxBytes.
	// Check session and upload permission without reading the body. Requires
	// Config.Oversized.
	PassOversized func(*http.Request) bool
}

// maxBodyBound is the largest cap for a body that is parsed in memory.
const maxBodyBound = 64 << 20

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
		if limit.MaxBytes > maxBodyBound {
			p.limitError(w, r)
			return
		}
		// Decide the media type first: every later check uses its cap.
		mediaType, mediaErr := requestMediaType(r)
		capBytes := limit.MaxBytes
		multipart := mediaType == "multipart/form-data"
		if multipart {
			if limit.MultipartMaxBytes <= 0 {
				p.bodyError(w, r, http.StatusUnsupportedMediaType)
				return
			}
			capBytes = limit.MultipartMaxBytes
		}
		if r.ContentLength > capBytes {
			if p.oversized != nil && multipart && limit.PassOversized != nil &&
				!p.isExempt(r) && limit.PassOversized(r) {
				closeConnection(w, r)
				r = r.WithContext(context.WithValue(r.Context(), oversizedKey{}, true))
				// Let nosurf check the origin without seeing any upload data,
				// even if an outer handler populated the parsed form fields.
				r.Body = http.NoBody
				r.Form, r.PostForm, r.MultipartForm = nil, nil, nil
				check.ServeHTTP(w, r)
				return
			}
			p.bodyError(w, r, http.StatusRequestEntityTooLarge)
			return
		}

		r.Body = http.MaxBytesReader(w, r.Body, capBytes)
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
	limit.MultipartMaxBytes = max(limit.MultipartMaxBytes, 0)
	if limit.MaxMemory <= 0 {
		limit.MaxMemory = 1 << 20
	}
	limit.MaxMemory = min(limit.MaxMemory, limit.MultipartMaxBytes)
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
//
// Every 413 and 415 sets Connection: close on HTTP/1 before the hook runs.
//
// The refused body is still attached on the declared-length 413 and the 415
// paths. It is replaced with an empty one first, so a hook that calls
// Request.FormValue or ParseMultipartForm reads and spools nothing.
func (p *Protect) bodyError(w http.ResponseWriter, r *http.Request, status int) {
	r.Body = http.NoBody
	r.Form, r.PostForm, r.MultipartForm = nil, nil, nil
	if status != http.StatusBadRequest {
		closeConnection(w, r)
	}
	p.logger.WarnContext(r.Context(), "csrf: request body refused",
		"status", status, "method", r.Method, "path", r.URL.Path)
	// Set before the hook so a hook that writes a cacheable status is not
	// cached; it may still override the header.
	w.Header().Set("Cache-Control", "no-store")
	if p.onBodyErr != nil {
		p.onBodyErr(w, r, status)
		return
	}
	http.Error(w, http.StatusText(status), status)
}

// limitError answers 500 when a Limit function returns a MaxBytes that no
// non-multipart body may have. It is a bug in the application, not in the
// request, so it is logged as an error and OnBodyError is not consulted.
func (p *Protect) limitError(w http.ResponseWriter, r *http.Request) {
	r.Body = http.NoBody
	r.Form, r.PostForm, r.MultipartForm = nil, nil, nil
	closeConnection(w, r)
	p.logger.ErrorContext(r.Context(), "csrf: Limit returned MaxBytes above 64 MiB", "path", r.URL.Path)
	w.Header().Set("Cache-Control", "no-store")
	http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
}

// closeConnection stops an HTTP/1 server from draining a refused body to
// reuse the connection. HTTP/2 resets the stream instead.
func closeConnection(w http.ResponseWriter, r *http.Request) {
	if r.ProtoMajor == 1 {
		w.Header().Set("Connection", "close")
	}
}
