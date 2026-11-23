package csrf

import (
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
}

func (p *Protect) limitBody(next, check http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if safeMethod(r.Method) {
			if p.isExempt(r) {
				next.ServeHTTP(w, r)
			} else {
				check.ServeHTTP(w, r)
			}
			return
		}

		limit := p.bodyLimit(r)
		if r.ContentLength > limit.MaxBytes {
			bodyError(w, http.StatusRequestEntityTooLarge)
			return
		}
		mediaType, mediaErr := requestMediaType(r)
		if mediaType == "multipart/form-data" && !limit.Multipart {
			bodyError(w, http.StatusUnsupportedMediaType)
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
			bodyError(w, status)
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

func bodyError(w http.ResponseWriter, status int) {
	http.Error(w, http.StatusText(status), status)
}
