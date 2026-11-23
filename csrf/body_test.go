package csrf_test

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/17xande-dev/websec/csrf"
)

const urlencoded = "application/x-www-form-urlencoded"

type countedBody struct {
	io.ReadCloser
	n     int64
	calls int
}

func (b *countedBody) Read(p []byte) (int, error) {
	b.calls++
	n, err := b.ReadCloser.Read(p)
	b.n += int64(n)
	return n, err
}

// A wrapper that hides strings.Reader's length sends a chunked request.
type streamed struct{ io.Reader }

type repeatedByte byte

func (b repeatedByte) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = byte(b)
	}
	return len(p), nil
}

type bodyObservation struct {
	read int64
	next bool
}

func observeBody(next func(http.ResponseWriter, *http.Request), p *csrf.Protect, observations chan<- bodyObservation) http.Handler {
	protected := p.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Test-Next", "true")
		next(w, r)
	}))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := &countedBody{ReadCloser: r.Body}
		r.Body = body
		protected.ServeHTTP(w, r)
		observations <- bodyObservation{body.n, w.Header().Get("X-Test-Next") == "true"}
	})
}

func TestBodyCap(t *testing.T) {
	const capBytes = 256 << 10
	tmp := t.TempDir()
	t.Setenv("TMPDIR", tmp)
	p := mustNew(t, csrf.Config{
		Origin: ownOrigin,
		Limit: func(r *http.Request) csrf.BodyLimit {
			if r.URL.Path == "/larger" {
				return csrf.BodyLimit{MaxBytes: capBytes + 1}
			}
			if r.URL.Path == "/large-form" {
				return csrf.BodyLimit{MaxBytes: 64 << 20}
			}
			return csrf.BodyLimit{}
		},
	})
	observations := make(chan bodyObservation, 1)
	s, client := server(t, observeBody(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			fmt.Fprint(w, csrf.Token(r))
			return
		}
		if r.PostForm.Get("field") == "" && r.Method == http.MethodPost {
			t.Error("next did not receive PostForm")
		}
		w.WriteHeader(http.StatusNoContent)
	}, p, observations))
	token, _ := formToken(t, s, client, "/")
	<-observations
	validPrefix := url.Values{csrf.FieldName: {token}}.Encode() + "&field="
	atPlusOne := validPrefix + strings.Repeat("x", capBytes+1-len(validPrefix))
	const multipartType = "multipart/form-data; boundary=test-boundary"
	const head = "--test-boundary\r\nContent-Disposition: form-data; name=\"file\"; filename=\"body.txt\"\r\n\r\n"
	const tail = "\r\n--test-boundary--\r\n"
	var largeAnonymous io.Reader = io.MultiReader(strings.NewReader(head),
		io.LimitReader(repeatedByte('x'), (64<<20)-int64(len(head)+len(tail))), strings.NewReader(tail))

	for _, tc := range []struct {
		name, method, path, mediaType string
		body                          io.Reader
		length, maxRead               int64
		status                        int
		anonymous                     bool
	}{
		{"declared URL-encoded cap plus one", "POST", "/", urlencoded, strings.NewReader(atPlusOne), 0, 0, 413, false},
		{"chunked 8 MiB URL-encoded valid token", "POST", "/", urlencoded,
			streamed{io.MultiReader(strings.NewReader(validPrefix), io.LimitReader(repeatedByte('x'), (8<<20)-int64(len(validPrefix))))},
			0, capBytes + 64<<10, 413, false},
		{"anonymous 64 MiB multipart", "POST", "/large-form", multipartType, largeAnonymous, 64 << 20, 0, 415, true},
		{"mixed case multipart type", "POST", "/", "Multipart/Form-Data; boundary=test-boundary", strings.NewReader(head + tail), 0, 0, 415, true},
		{"malformed multipart type", "POST", "/", "multipart/form-data;;", strings.NewReader(head + tail), 0, 0, 415, true},
		{"PUT over cap", "PUT", "/", urlencoded, strings.NewReader(atPlusOne), 0, 0, 413, false},
		{"PATCH over cap", "PATCH", "/", urlencoded, strings.NewReader(atPlusOne), 0, 0, 413, false},
		{"DELETE over cap", "DELETE", "/", urlencoded, strings.NewReader(atPlusOne), 0, 0, 413, false},
		{"extension method over cap", "UPDATE", "/", urlencoded, strings.NewReader(atPlusOne), 0, 0, 413, false},
		{"valid URL-encoded form", "POST", "/", urlencoded, strings.NewReader(validPrefix + "text"), 0, capBytes, 204, false},
		{"URL-encoded override", "POST", "/larger", urlencoded, strings.NewReader(atPlusOne), 0, capBytes + 1, 204, false},
		{"URL-encoded near override", "POST", "/larger/", urlencoded, strings.NewReader(atPlusOne), 0, 0, 413, false},
		{"malformed URL-encoded form", "POST", "/", urlencoded, strings.NewReader(validPrefix + "%zz"), 0, capBytes, 400, false},
		{"size check precedes multipart refusal", "POST", "/", multipartType, strings.NewReader(atPlusOne), 0, 0, 413, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := request(t, tc.method, s.URL+tc.path, tc.body)
			if tc.length != 0 {
				req.ContentLength = tc.length
			}
			req.Header.Set("Content-Type", tc.mediaType)
			req.Header.Set("Origin", ownOrigin)
			doer := client
			if tc.anonymous {
				doer = s.Client()
			}
			resp, _ := send(t, doer, req)
			obs := <-observations
			if resp.StatusCode != tc.status || obs.next != (tc.status == 204) || obs.read > tc.maxRead || len(resp.Header.Values("Set-Cookie")) != 0 {
				t.Errorf("status=%d, next=%t, bytes read=%d, Set-Cookie=%d; want status=%d, at most %d read and no cookie",
					resp.StatusCode, obs.next, obs.read, len(resp.Header.Values("Set-Cookie")), tc.status, tc.maxRead)
			}
			if tc.status == 204 && obs.read == 0 {
				t.Error("body was not parsed")
			}
			assertTempEntries(t, tmp, false)
		})
	}
}

func TestSafeMethods(t *testing.T) {
	p := mustNew(t, csrf.Config{
		Origin: ownOrigin, MaxBody: 1,
		Limit: func(*http.Request) csrf.BodyLimit {
			t.Error("Limit called on safe method")
			return csrf.BodyLimit{}
		},
	})
	s, _ := server(t, p.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if csrf.Token(r) == "" || r.PostForm != nil || r.MultipartForm != nil {
			t.Error("safe request was not passed unchanged to nosurf")
		}
		w.WriteHeader(http.StatusNoContent)
	})))
	for _, method := range []string{http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodTrace} {
		t.Run(method, func(t *testing.T) {
			req := request(t, method, s.URL, strings.NewReader("body beyond cap"))
			req.Header.Set("Content-Type", "multipart/form-data;;")
			resp, _ := send(t, s.Client(), req)
			if resp.StatusCode != 204 || len(resp.Cookies()) != 1 {
				t.Errorf("status=%d, cookies=%d; want 204 and one cookie", resp.StatusCode, len(resp.Cookies()))
			}
		})
	}
}

func TestExempt(t *testing.T) {
	const raw = "field=raw+text"
	const capBytes = int64(len(raw))
	p := mustNew(t, csrf.Config{
		Origin: ownOrigin, MaxBody: capBytes,
		Exempt: func(r *http.Request) bool { return r.URL.Path == "/notify" || r.URL.Path == "/authorize" },
	})
	observations := make(chan bodyObservation, 1)
	s, _ := server(t, observeBody(func(w http.ResponseWriter, r *http.Request) {
		if r.PostForm != nil || r.MultipartForm != nil || csrf.Token(r) != "" || csrf.Reason(r) != nil {
			t.Error("exempt handler received a parsed body or nosurf context")
		}
		body, err := io.ReadAll(r.Body)
		var tooLarge *http.MaxBytesError
		switch {
		case errors.As(err, &tooLarge):
			w.WriteHeader(http.StatusRequestEntityTooLarge)
		case err != nil || string(body) != raw && r.Method == http.MethodPost:
			t.Errorf("exempt handler did not receive the raw body: %q, %v", body, err)
			w.WriteHeader(http.StatusBadRequest)
		default:
			w.WriteHeader(http.StatusNoContent)
		}
	}, p, observations))
	for _, tc := range []struct {
		name, method, path string
		body               io.Reader
		status             int
		next, cookie       bool
		read               int64
	}{
		{"webhook-style raw form", "POST", "/notify", strings.NewReader(raw), 204, true, false, capBytes},
		{"webhook-style declared oversized", "POST", "/notify", strings.NewReader(raw + "x"), 413, false, false, 0},
		{"webhook-style streamed oversized", "POST", "/notify", streamed{strings.NewReader(raw + "x")}, 413, true, false, capBytes + 1},
		{"authorization-style safe method", "GET", "/authorize", nil, 204, true, false, 0},
		{"trailing slash is not exempt", "POST", "/notify/", strings.NewReader(raw), 403, false, true, capBytes},
		{"different case is not exempt", "POST", "/Notify", strings.NewReader(raw), 403, false, true, capBytes},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := request(t, tc.method, s.URL+tc.path, tc.body)
			req.Header.Set("Content-Type", urlencoded)
			req.Header.Set("Origin", ownOrigin)
			resp, _ := send(t, s.Client(), req)
			obs := <-observations
			if resp.StatusCode != tc.status || obs.next != tc.next || obs.read != tc.read || (len(resp.Cookies()) != 0) != tc.cookie {
				t.Errorf("status=%d, next=%t, bytes=%d, cookies=%d; want status=%d, next=%t, bytes=%d, cookie=%t",
					resp.StatusCode, obs.next, obs.read, len(resp.Cookies()), tc.status, tc.next, tc.read, tc.cookie)
			}
		})
	}
}

func TestMultipartCap(t *testing.T) {
	const capBytes = 2 << 20
	tmp := t.TempDir()
	t.Setenv("TMPDIR", tmp)
	p := mustNew(t, csrf.Config{
		Origin: ownOrigin,
		Limit: func(r *http.Request) csrf.BodyLimit {
			limit := csrf.BodyLimit{MaxBytes: capBytes, Multipart: true}
			if r.URL.Path == "/in-memory" {
				limit.MaxMemory = capBytes
			}
			return limit
		},
	})
	observations := make(chan bodyObservation, 1)
	s, client := server(t, observeBody(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			fmt.Fprint(w, csrf.Token(r))
			return
		}
		if r.MultipartForm == nil || len(r.MultipartForm.File["file"]) != 1 || r.PostForm.Get(csrf.FieldName) == "" {
			t.Error("next did not receive parsed multipart form")
		}
		assertTempEntries(t, tmp, r.URL.Path != "/in-memory")
		w.WriteHeader(http.StatusNoContent)
	}, p, observations))
	token, _ := formToken(t, s, client, "/")
	<-observations
	for _, tc := range []struct {
		name, path                   string
		size                         int
		chunked, epilogue, malformed bool
		status                       int
		maxRead                      int64
	}{
		{"upload at exact limit", "/upload", capBytes, false, false, false, 204, capBytes},
		{"declared upload one MiB over", "/upload", capBytes + 1<<20, false, false, false, 413, 0},
		{"streamed upload one MiB over", "/upload", capBytes + 1<<20, true, false, false, 413, capBytes + 1},
		{"streamed multipart epilogue over cap", "/upload", capBytes, true, true, false, 413, capBytes + 1},
		{"upload stays in memory", "/in-memory", capBytes, false, false, false, 204, capBytes},
		{"malformed multipart body", "/upload", capBytes, false, false, true, 400, capBytes},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body, mediaType := multipartBody(t, token, tc.size)
			if tc.epilogue {
				body = append(body, []byte(strings.Repeat("x", 1<<20))...)
			}
			if tc.malformed {
				body = body[:len(body)-1024]
			}
			var reader io.Reader = bytes.NewReader(body)
			if tc.chunked {
				reader = streamed{reader}
			}
			req := request(t, http.MethodPost, s.URL+tc.path, reader)
			req.Header.Set("Content-Type", mediaType)
			req.Header.Set("Origin", ownOrigin)
			resp, _ := send(t, client, req)
			obs := <-observations
			if resp.StatusCode != tc.status || obs.next != (tc.status == 204) || obs.read > tc.maxRead || len(resp.Cookies()) != 0 {
				t.Errorf("status=%d, next=%t, bytes=%d, cookies=%d; want status=%d, at most %d read and no cookie",
					resp.StatusCode, obs.next, obs.read, len(resp.Cookies()), tc.status, tc.maxRead)
			}
			assertTempEntries(t, tmp, false)
		})
	}
}

func multipartBody(t *testing.T, token string, size int) ([]byte, string) {
	t.Helper()
	var buf bytes.Buffer
	form := multipart.NewWriter(&buf)
	if err := form.WriteField(csrf.FieldName, token); err != nil {
		t.Fatal(err)
	}
	file, err := form.CreateFormFile("file", "upload.txt")
	if err != nil {
		t.Fatal(err)
	}
	// Write the closing boundary separately to determine its exact size.
	var end bytes.Buffer
	closing := multipart.NewWriter(&end)
	if err := closing.SetBoundary(form.Boundary()); err != nil {
		t.Fatal(err)
	}
	if err := closing.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := io.CopyN(file, repeatedByte('x'), int64(size-buf.Len()-end.Len())); err != nil {
		t.Fatal(err)
	}
	if err := form.Close(); err != nil {
		t.Fatal(err)
	}
	if buf.Len() != size {
		t.Fatalf("multipart fixture has %d bytes, want %d", buf.Len(), size)
	}
	return buf.Bytes(), form.FormDataContentType()
}

func assertTempEntries(t *testing.T, dir string, wantEntries bool) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil || (len(entries) != 0) != wantEntries {
		t.Errorf("multipart temp entries=%d, err=%v, want any=%t", len(entries), err, wantEntries)
	}
}
