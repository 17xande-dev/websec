package csrf_test

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime/multipart"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/17xande-dev/websec/csrf"
)

const urlencoded = "application/x-www-form-urlencoded"

type bodyRefusal struct {
	status int
	cause  error
}

func observeBodyRefusal(refusals chan<- bodyRefusal) func(http.ResponseWriter, *http.Request, int) {
	return func(w http.ResponseWriter, r *http.Request, status int) {
		refusals <- bodyRefusal{status: status, cause: csrf.BodyError(r)}
		w.WriteHeader(status)
	}
}

func TestBodyErrorCause(t *testing.T) {
	const multipartType = "multipart/form-data; boundary=test-boundary"
	const part = "--test-boundary\r\nContent-Disposition: form-data; name=\"field\"\r\n\r\n"
	for _, tc := range []struct {
		name, method, mediaType string
		body                    io.Reader
		multipartCap            int64
		status                  int
		wantCause               error
		wantMaxBytes            bool
	}{
		{"declared oversize", "POST", urlencoded, strings.NewReader("field=" + strings.Repeat("x", 64)),
			0, 413, csrf.ErrBodyTooLarge, false},
		{"chunked URL-encoded oversize", "POST", urlencoded, streamed{strings.NewReader("field=" + strings.Repeat("x", 64))},
			0, 413, csrf.ErrBodyTooLarge, true},
		{"chunked multipart oversize", "POST", multipartType,
			streamed{strings.NewReader(part + strings.Repeat("x", 128) + "\r\n--test-boundary--\r\n")},
			128, 413, csrf.ErrBodyTooLarge, true},
		{"unsafe multipart refused", "POST", multipartType, strings.NewReader("--test-boundary--\r\n"),
			0, 415, csrf.ErrMultipartRefused, false},
		{"safe multipart refused", "GET", multipartType, strings.NewReader("--test-boundary--\r\n"),
			128, 415, csrf.ErrMultipartRefused, false},
		{"malformed media parameter", "POST", urlencoded + "; charset", strings.NewReader("field=x"),
			0, 400, nil, false},
		{"truncated multipart", "POST", multipartType, strings.NewReader(part + "x\r\n--wrong-boundary--\r\n"),
			128, 400, nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			refusals := make(chan bodyRefusal, 1)
			p := mustNew(t, csrf.Config{
				Origin: ownOrigin, MaxBody: 32, OnBodyError: observeBodyRefusal(refusals),
				Limit: func(*http.Request) csrf.BodyLimit {
					return csrf.BodyLimit{MultipartMaxBytes: tc.multipartCap}
				},
			})
			s, client := server(t, p.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				t.Error("refused request reached the wrapped handler")
				w.WriteHeader(http.StatusNoContent)
			})))
			req := request(t, tc.method, s.URL, tc.body)
			req.Header.Set("Content-Type", tc.mediaType)
			req.Header.Set("Origin", ownOrigin)
			if resp, _ := send(t, client, req); resp.StatusCode != tc.status {
				t.Errorf("response status = %d, want %d", resp.StatusCode, tc.status)
			}
			select {
			case got := <-refusals:
				if got.status != tc.status || got.cause == nil {
					t.Errorf("hook got status %d, cause %v; want status %d and non-nil cause", got.status, got.cause, tc.status)
				}
				for _, sentinel := range []error{csrf.ErrBodyTooLarge, csrf.ErrMultipartRefused} {
					if errors.Is(got.cause, sentinel) != (tc.wantCause == sentinel) {
						t.Errorf("cause %v does not match expected classification %v", got.cause, tc.wantCause)
					}
				}
				var maxBytes *http.MaxBytesError
				if errors.As(got.cause, &maxBytes) != tc.wantMaxBytes {
					t.Errorf("cause = %v, want *http.MaxBytesError in chain: %t", got.cause, tc.wantMaxBytes)
				}
			default:
				t.Error("OnBodyError did not run")
			}
		})
	}
}

func TestBodyErrorTimeout(t *testing.T) {
	for _, tc := range []struct{ name, mediaType, prefix string }{
		{"URL-encoded", urlencoded, "field=x"},
		{"multipart", "multipart/form-data; boundary=test-boundary",
			"--test-boundary\r\nContent-Disposition: form-data; name=\"field\"\r\n\r\nx"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			refusals := make(chan bodyRefusal, 1)
			p := mustNew(t, csrf.Config{
				Origin: ownOrigin, OnBodyError: observeBodyRefusal(refusals),
				Limit: func(*http.Request) csrf.BodyLimit {
					return csrf.BodyLimit{MultipartMaxBytes: 128 << 10}
				},
			})
			protected := p.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				t.Error("incomplete request reached the wrapped handler")
				w.WriteHeader(http.StatusNoContent)
			}))
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if err := http.NewResponseController(w).SetReadDeadline(time.Now().Add(200 * time.Millisecond)); err != nil {
					t.Errorf("set read deadline: %v", err)
					w.WriteHeader(http.StatusInternalServerError)
					return
				}
				protected.ServeHTTP(w, r)
			}))
			defer s.Close()
			conn, err := net.DialTimeout("tcp", s.Listener.Addr().String(), 5*time.Second)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
				t.Fatal(err)
			}
			// Keep the connection open after a partial write so the server
			// must hit its read deadline rather than see EOF.
			if _, err := fmt.Fprintf(conn, "POST / HTTP/1.1\r\nHost: app.example\r\nContent-Type: %s\r\n"+
				"Content-Length: 100000\r\nConnection: close\r\n\r\n%s", tc.mediaType, tc.prefix); err != nil {
				t.Fatal(err)
			}
			resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusBadRequest {
				t.Errorf("response status = %d, want 400", resp.StatusCode)
			}
			select {
			case got := <-refusals:
				if got.status != http.StatusBadRequest || !errors.Is(got.cause, os.ErrDeadlineExceeded) {
					t.Errorf("hook got status %d, cause %v; want 400 and a deadline error", got.status, got.cause)
				}
			default:
				t.Error("OnBodyError did not run")
			}
		})
	}
}

func TestBodyErrorOutsideHook(t *testing.T) {
	refusals := make(chan bodyRefusal, 1)
	check := func(status int) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if err := csrf.BodyError(r); err != nil {
				t.Errorf("handler writing status %d got BodyError = %v, want nil", status, err)
			}
			w.WriteHeader(status)
		}
	}
	p := mustNew(t, csrf.Config{
		Origin: ownOrigin, OnFailure: check(http.StatusForbidden), Oversized: check(http.StatusUnprocessableEntity),
		OnBodyError: observeBodyRefusal(refusals),
		Limit: func(*http.Request) csrf.BodyLimit {
			return csrf.BodyLimit{MultipartMaxBytes: 1, PassOversized: func(*http.Request) bool { return true }}
		},
	})
	s, client := server(t, p.Handler(check(http.StatusNoContent)))

	// A malformed form sets a cause without closing the HTTP/1.1 connection
	// as a 413 or 415 would. The next request must not inherit that cause.
	req := request(t, http.MethodPost, s.URL, strings.NewReader("field=%zz"))
	req.Header.Set("Content-Type", urlencoded)
	req.Header.Set("Origin", ownOrigin)
	if resp, _ := send(t, client, req); resp.StatusCode != http.StatusBadRequest || resp.Proto != "HTTP/1.1" || resp.Close {
		t.Fatalf("refusal = %d %s, close=%t; want 400 on a persistent HTTP/1.1 connection", resp.StatusCode, resp.Proto, resp.Close)
	}
	select {
	case got := <-refusals:
		if got.status != http.StatusBadRequest || got.cause == nil {
			t.Fatalf("hook got status %d, cause %v; want 400 and a non-nil cause", got.status, got.cause)
		}
	default:
		t.Fatal("OnBodyError did not run")
	}

	for _, tc := range []struct {
		name, method string
		body         io.Reader
		want         int
	}{
		{"wrapped handler", "GET", nil, 204},
		{"OnFailure", "POST", nil, 403},
		{"Oversized", "POST", strings.NewReader("--test-boundary--\r\n"), 422},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := request(t, tc.method, s.URL, tc.body)
			var reused bool
			if tc.want == http.StatusNoContent {
				req = req.WithContext(httptrace.WithClientTrace(req.Context(), &httptrace.ClientTrace{
					GotConn: func(info httptrace.GotConnInfo) { reused = info.Reused },
				}))
			}
			req.Header.Set("Origin", ownOrigin)
			if tc.body != nil {
				req.Header.Set("Content-Type", "multipart/form-data; boundary=test-boundary")
			}
			if resp, _ := send(t, client, req); resp.StatusCode != tc.want {
				t.Errorf("status = %d, want %d", resp.StatusCode, tc.want)
			}
			if tc.want == http.StatusNoContent && !reused {
				t.Error("wrapped handler did not reuse the refused request's connection")
			}
		})
	}
}

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
		{"duplicate boundary multipart type", "POST", "/", "multipart/form-data;boundary=x;boundary=y", strings.NewReader(head + tail), 0, 0, 415, true},
		{"duplicate boundary mixed case type", "POST", "/", "Multipart/Form-Data;boundary=x;boundary=y", strings.NewReader(head + tail), 0, 0, 415, true},
		{"duplicate boundary type with padding", "POST", "/", "multipart/form-data ;boundary=x;boundary=y", strings.NewReader(head + tail), 0, 0, 415, true},
		{"PUT over cap", "PUT", "/", urlencoded, strings.NewReader(atPlusOne), 0, 0, 413, false},
		{"PATCH over cap", "PATCH", "/", urlencoded, strings.NewReader(atPlusOne), 0, 0, 413, false},
		{"DELETE over cap", "DELETE", "/", urlencoded, strings.NewReader(atPlusOne), 0, 0, 413, false},
		{"extension method over cap", "UPDATE", "/", urlencoded, strings.NewReader(atPlusOne), 0, 0, 413, false},
		{"valid URL-encoded form", "POST", "/", urlencoded, strings.NewReader(validPrefix + "text"), 0, capBytes, 204, false},
		{"URL-encoded override", "POST", "/larger", urlencoded, strings.NewReader(atPlusOne), 0, capBytes + 1, 204, false},
		{"URL-encoded near override", "POST", "/larger/", urlencoded, strings.NewReader(atPlusOne), 0, 0, 413, false},
		{"malformed URL-encoded form", "POST", "/", urlencoded, strings.NewReader(validPrefix + "%zz"), 0, capBytes, 400, false},
		{"multipart refusal precedes the size check", "POST", "/", multipartType, strings.NewReader(atPlusOne), 0, 0, 415, true},
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
			t.Error("safe request reached the handler without a token or with a parsed body")
		}
		w.WriteHeader(http.StatusNoContent)
	})))
	for _, method := range []string{http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodTrace} {
		t.Run(method, func(t *testing.T) {
			req := request(t, method, s.URL, strings.NewReader("body beyond cap"))
			req.Header.Set("Content-Type", "text/plain")
			resp, _ := send(t, s.Client(), req)
			if resp.StatusCode != 204 || len(resp.Cookies()) != 1 {
				t.Errorf("status=%d, cookies=%d; want 204 and one cookie", resp.StatusCode, len(resp.Cookies()))
			}
		})
	}
}

func TestSafeMethodBody(t *testing.T) {
	const capBytes = 256 << 10
	tmp := t.TempDir()
	t.Setenv("TMPDIR", tmp)
	p := mustNew(t, csrf.Config{
		Origin: ownOrigin,
		Exempt: func(r *http.Request) bool { return r.URL.Path == "/notify" },
	})
	observations := make(chan bodyObservation, 1)
	s, _ := server(t, observeBody(func(w http.ResponseWriter, r *http.Request) {
		// A handler that reads form values, as a login page reading a
		// redirect target would, parses any multipart body.
		_ = r.FormValue("q")
		if r.URL.Path == "/drain" || r.URL.Path == "/notify" {
			if _, err := io.Copy(io.Discard, r.Body); err != nil {
				var tooLarge *http.MaxBytesError
				if errors.As(err, &tooLarge) {
					w.WriteHeader(http.StatusRequestEntityTooLarge)
					return
				}
			}
		}
		w.WriteHeader(http.StatusNoContent)
	}, p, observations))
	const multipartType = "multipart/form-data; boundary=test-boundary"
	const head = "--test-boundary\r\nContent-Disposition: form-data; name=\"file\"; filename=\"body.txt\"\r\n\r\n"
	const tail = "\r\n--test-boundary--\r\n"
	large := func() io.Reader {
		return io.MultiReader(strings.NewReader(head),
			io.LimitReader(repeatedByte('x'), (64<<20)-int64(len(head)+len(tail))), strings.NewReader(tail))
	}
	for _, tc := range []struct {
		name, method, path, mediaType string
		body                          func() io.Reader
		length, maxRead               int64
		status                        int
		next                          bool
	}{
		{"GET with 64 MiB multipart", "GET", "/search", multipartType, large, 64 << 20, 0, 415, false},
		{"HEAD with multipart", "HEAD", "/search", multipartType, large, 0, 0, 415, false},
		{"OPTIONS with multipart", "OPTIONS", "/search", multipartType, large, 0, 0, 415, false},
		{"TRACE with multipart", "TRACE", "/search", multipartType, large, 0, 0, 415, false},
		{"GET with malformed multipart type", "GET", "/search", "multipart/form-data;boundary=x;boundary=y", large, 0, 0, 415, false},
		{"exempt GET with multipart", "GET", "/notify", multipartType, large, 0, 0, 415, false},
		{"GET with streamed oversized body", "GET", "/drain", "text/plain",
			func() io.Reader { return streamed{io.LimitReader(repeatedByte('x'), 8<<20)} }, 0, capBytes + 1, 413, true},
		{"exempt GET with streamed oversized body", "GET", "/notify", "text/plain",
			func() io.Reader { return streamed{io.LimitReader(repeatedByte('x'), 8<<20)} }, 0, capBytes + 1, 413, true},
		{"GET with a small body", "GET", "/drain", "text/plain",
			func() io.Reader { return strings.NewReader("small") }, 0, 5, 204, true},
		{"GET without a body", "GET", "/search", "", func() io.Reader { return nil }, 0, 0, 204, true},
		{"exempt GET without a body", "GET", "/notify", "", func() io.Reader { return nil }, 0, 0, 204, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := request(t, tc.method, s.URL+tc.path+"?q=a", tc.body())
			if tc.length != 0 {
				req.ContentLength = tc.length
			}
			if tc.mediaType != "" {
				req.Header.Set("Content-Type", tc.mediaType)
			}
			resp, _ := send(t, s.Client(), req)
			obs := <-observations
			if resp.StatusCode != tc.status || obs.next != tc.next || obs.read > tc.maxRead {
				t.Errorf("status=%d, next=%t, bytes read=%d; want status=%d, next=%t, at most %d read",
					resp.StatusCode, obs.next, obs.read, tc.status, tc.next, tc.maxRead)
			}
			assertTempEntries(t, tmp, false)
		})
	}
}

func TestBodyError(t *testing.T) {
	const capBytes = 1 << 10
	const multipartType = "multipart/form-data; boundary=test-boundary"
	const secret = "private-value"
	type refusal struct {
		name, method, path, mediaType string
		body                          io.Reader
		status                        int
	}
	cases := func() []refusal {
		return []refusal{
			{"declared oversized", "POST", "/form", urlencoded, strings.NewReader(strings.Repeat("x", capBytes+1)), 413},
			{"streamed oversized", "POST", "/form", urlencoded, streamed{strings.NewReader("a=" + strings.Repeat("x", capBytes+1))}, 413},
			{"multipart not allowed", "POST", "/form", multipartType, strings.NewReader("--test-boundary--\r\n"), 415},
			{"safe method multipart", "GET", "/form", multipartType, strings.NewReader("--test-boundary--\r\n"), 415},
			{"malformed form", "POST", "/form", urlencoded, strings.NewReader("a=%zz"), 400},
		}
	}
	do := func(t *testing.T, s *httptest.Server, tc refusal) (*http.Response, string) {
		req := request(t, tc.method, s.URL+tc.path+"?q="+secret, tc.body)
		req.Header.Set("Content-Type", tc.mediaType)
		req.Header.Set("Origin", ownOrigin)
		req.Header.Set("X-Private", secret)
		req.Header.Set("HX-Request", "true")
		return send(t, s.Client(), req)
	}
	assertOneWarning := func(t *testing.T, logs *logBuffer, tc refusal) {
		t.Helper()
		raw := strings.TrimSpace(logs.String())
		var record map[string]any
		if strings.Contains(raw, "\n") || json.Unmarshal([]byte(raw), &record) != nil ||
			record["level"] != "WARN" || record["msg"] != "csrf: request body refused" ||
			record["status"] != float64(tc.status) || record["method"] != tc.method || record["path"] != tc.path {
			t.Errorf("want one warning with status, method and path; got %q", raw)
		}
		if strings.Contains(raw, secret) || strings.Contains(raw, "test-boundary") {
			t.Errorf("warning disclosed a request value: %q", raw)
		}
	}
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) })

	t.Run("default response", func(t *testing.T) {
		for _, tc := range cases() {
			t.Run(tc.name, func(t *testing.T) {
				var logs logBuffer
				s, _ := server(t, mustNew(t, csrf.Config{Origin: ownOrigin, MaxBody: capBytes,
					Logger: slog.New(slog.NewJSONHandler(&logs, nil))}).Handler(next))
				resp, body := do(t, s, tc)
				if resp.StatusCode != tc.status || body != http.StatusText(tc.status)+"\n" ||
					resp.Header.Get("Cache-Control") != "no-store" || resp.Header.Get("HX-Refresh") != "" ||
					resp.Header.Get("Content-Type") != "text/plain; charset=utf-8" {
					t.Errorf("response = %d %q, Cache-Control=%q", resp.StatusCode, body, resp.Header.Get("Cache-Control"))
				}
				assertOneWarning(t, &logs, tc)
			})
		}
	})

	t.Run("hook", func(t *testing.T) {
		for _, tc := range cases() {
			t.Run(tc.name, func(t *testing.T) {
				var logs logBuffer
				calls := make(chan int, 2)
				s, _ := server(t, mustNew(t, csrf.Config{Origin: ownOrigin, MaxBody: capBytes,
					Logger: slog.New(slog.NewJSONHandler(&logs, nil)),
					OnBodyError: func(w http.ResponseWriter, r *http.Request, status int) {
						calls <- status
						if r.Header.Get("HX-Request") == "true" {
							w.Header().Set("HX-Retarget", "#errors")
							w.Header().Set("HX-Reswap", "innerHTML")
						}
						w.WriteHeader(http.StatusUnprocessableEntity)
						fmt.Fprintf(w, "refused: %d", status)
					}}).Handler(next))
				resp, body := do(t, s, tc)
				if len(calls) != 1 || <-calls != tc.status {
					t.Fatalf("hook was not called exactly once with status %d", tc.status)
				}
				if resp.StatusCode != 422 || body != fmt.Sprintf("refused: %d", tc.status) || resp.Header.Get("HX-Retarget") != "#errors" ||
					resp.Header.Get("Cache-Control") != "no-store" {
					t.Errorf("hook response = %d %q, Cache-Control=%q", resp.StatusCode, body, resp.Header.Get("Cache-Control"))
				}
				assertOneWarning(t, &logs, tc)
			})
		}
	})

	t.Run("not called for token failures or the oversized hand-off", func(t *testing.T) {
		var calls, failures int
		s, _ := server(t, mustNew(t, csrf.Config{
			Origin: ownOrigin, MaxBody: capBytes,
			Limit: func(*http.Request) csrf.BodyLimit {
				return csrf.BodyLimit{MultipartMaxBytes: capBytes,
					PassOversized: func(*http.Request) bool { return true }}
			},
			Oversized: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				http.Error(w, "choose a smaller file", http.StatusUnprocessableEntity)
			}),
			OnFailure: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				failures++
				w.WriteHeader(http.StatusForbidden)
			}),
			OnBodyError: func(w http.ResponseWriter, r *http.Request, status int) { calls++ },
			Logger:      slog.New(slog.NewJSONHandler(io.Discard, nil)),
		}).Handler(next))
		for _, tc := range []struct {
			name, mediaType string
			body            string
			status          int
		}{
			{"missing token", urlencoded, "a=b", 403},
			{"oversized hand-off", multipartType, strings.Repeat("x", capBytes+1), 422},
		} {
			req := request(t, "POST", s.URL+"/form", strings.NewReader(tc.body))
			req.Header.Set("Content-Type", tc.mediaType)
			req.Header.Set("Origin", ownOrigin)
			if resp, _ := send(t, s.Client(), req); resp.StatusCode != tc.status {
				t.Errorf("%s: status = %d, want %d", tc.name, resp.StatusCode, tc.status)
			}
		}
		if calls != 0 || failures != 1 {
			t.Errorf("OnBodyError calls = %d, OnFailure calls = %d; want 0 and 1", calls, failures)
		}
	})
}

// A refused request still carries its original body when the hook runs. A hook
// that parses it (FormValue spools multipart files to disk) or reads it must
// get an empty body, on both protocol versions.
func TestBodyErrorHookGetsEmptyBody(t *testing.T) {
	const multipartType = "multipart/form-data; boundary=test-boundary"
	const head = "--test-boundary\r\nContent-Disposition: form-data; name=\"file\"; filename=\"body.txt\"\r\n\r\n"
	const tail = "\r\n--test-boundary--\r\n"
	large := func() io.Reader {
		return io.MultiReader(strings.NewReader(head),
			io.LimitReader(repeatedByte('x'), (64<<20)-int64(len(head)+len(tail))), strings.NewReader(tail))
	}
	type hook struct {
		name string
		fn   func(w http.ResponseWriter, r *http.Request, status int) // nil means the default response
	}
	hooks := []hook{
		{"default response", nil},
		{"hook calls FormValue", func(w http.ResponseWriter, r *http.Request, status int) {
			fmt.Fprintf(w, "q=%s file=%t", r.FormValue("q"), r.MultipartForm != nil && len(r.MultipartForm.File) != 0)
		}},
		{"hook reads the body", func(w http.ResponseWriter, r *http.Request, status int) {
			body, err := io.ReadAll(r.Body)
			fmt.Fprintf(w, "body=%d err=%v", len(body), err)
		}},
	}
	for _, proto := range []int{1, 2} {
		for _, tc := range []struct {
			name, method, mediaType string
			status                  int
		}{
			{"POST with declared 64 MiB multipart", "POST", multipartType, 413},
			{"GET with declared 64 MiB multipart", "GET", multipartType, 415},
		} {
			for _, h := range hooks {
				t.Run(fmt.Sprintf("HTTP/%d %s %s", proto, tc.name, h.name), func(t *testing.T) {
					tmp := t.TempDir()
					t.Setenv("TMPDIR", tmp)
					// The POST row needs a route that allows multipart, so
					// the refusal under test is the declared-length 413.
					p := mustNew(t, csrf.Config{Origin: ownOrigin, OnBodyError: h.fn,
						Limit:  func(*http.Request) csrf.BodyLimit { return csrf.BodyLimit{MultipartMaxBytes: 1 << 20} },
						Logger: slog.New(slog.NewJSONHandler(io.Discard, nil))})
					observations := make(chan bodyObservation, 1)
					s := httptest.NewUnstartedServer(observeBody(func(w http.ResponseWriter, r *http.Request) {
						t.Error("next called for a refused request")
					}, p, observations))
					s.EnableHTTP2 = proto == 2
					s.StartTLS()
					t.Cleanup(s.Close)

					req := request(t, tc.method, s.URL+"/form?q=a", large())
					req.ContentLength = 64 << 20
					req.Header.Set("Content-Type", tc.mediaType)
					req.Header.Set("Origin", ownOrigin)
					resp, body := send(t, s.Client(), req)
					obs := <-observations
					if resp.ProtoMajor != proto {
						t.Fatalf("response protocol = HTTP/%d, want HTTP/%d", resp.ProtoMajor, proto)
					}
					wantStatus := http.StatusOK // the hooks above write no status
					if h.fn == nil {
						wantStatus = tc.status
					}
					if resp.StatusCode != wantStatus || obs.read != 0 {
						t.Errorf("status=%d, bytes read=%d; want status %d and none read", resp.StatusCode, obs.read, wantStatus)
					}
					switch h.name {
					case "hook calls FormValue":
						if body != "q=a file=false" {
							t.Errorf("hook saw %q", body)
						}
					case "hook reads the body":
						if body != "body=0 err=<nil>" {
							t.Errorf("hook saw %q", body)
						}
					}
					assertTempEntries(t, tmp, false)
				})
			}
		}
	}
}

// An outer layer may already have parsed the form (a method override, say).
// A refusal must not hand those fields to the hook either.
func TestBodyErrorHookGetsNoParsedFields(t *testing.T) {
	const multipartType = "multipart/form-data; boundary=test-boundary"
	for _, tc := range []struct {
		name, method, mediaType string
		body                    string
		status                  int
	}{
		{"declared oversized", "POST", urlencoded, strings.Repeat("x", 1<<10+1), 413},
		{"multipart not allowed", "POST", multipartType, "--test-boundary--\r\n", 415},
		{"safe method multipart", "GET", multipartType, "--test-boundary--\r\n", 415},
	} {
		t.Run(tc.name, func(t *testing.T) {
			seen := make(chan string, 1)
			p := mustNew(t, csrf.Config{Origin: ownOrigin, MaxBody: 1 << 10,
				Logger: slog.New(slog.NewJSONHandler(io.Discard, nil)),
				OnBodyError: func(w http.ResponseWriter, r *http.Request, status int) {
					body, _ := io.ReadAll(r.Body)
					seen <- fmt.Sprintf("status=%d form=%d postform=%d multipart=%t value=%q body=%d",
						status, len(r.Form), len(r.PostForm), r.MultipartForm != nil, r.FormValue("planted"), len(body))
				}})
			outer := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				r.Form = url.Values{"planted": {"secret"}}
				r.PostForm = url.Values{"planted": {"secret"}}
				r.MultipartForm = &multipart.Form{Value: map[string][]string{"planted": {"secret"}}}
				p.Handler(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
					t.Error("next called for a refused request")
				})).ServeHTTP(w, r)
			})
			s, _ := server(t, outer)
			req := request(t, tc.method, s.URL+"/form", strings.NewReader(tc.body))
			req.Header.Set("Content-Type", tc.mediaType)
			req.Header.Set("Origin", ownOrigin)
			send(t, s.Client(), req)
			want := fmt.Sprintf("status=%d form=0 postform=0 multipart=false value=\"\" body=0", tc.status)
			if got := <-seen; got != want {
				t.Errorf("hook saw %s; want %s", got, want)
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
			limit := csrf.BodyLimit{MultipartMaxBytes: capBytes}
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

// The media type decides the cap: a route with a large multipart cap must not
// accept a large body of any other type, and the reverse.
func TestBodyLimitByMediaType(t *testing.T) {
	const defaultCap = 256 << 10
	tmp := t.TempDir()
	t.Setenv("TMPDIR", tmp)
	var logs logBuffer
	p := mustNew(t, csrf.Config{
		Origin: ownOrigin,
		Logger: slog.New(slog.NewJSONHandler(&logs, nil)),
		Limit: func(r *http.Request) csrf.BodyLimit {
			switch r.URL.Path {
			case "/no-multipart":
				return csrf.BodyLimit{}
			case "/medium":
				return csrf.BodyLimit{MaxBytes: 512 << 10}
			case "/too-large":
				return csrf.BodyLimit{MaxBytes: 64<<20 + 1, MultipartMaxBytes: 4 << 20}
			case "/max-64":
				return csrf.BodyLimit{MaxBytes: 64 << 20}
			case "/negative":
				return csrf.BodyLimit{MaxBytes: -1, MultipartMaxBytes: -1, MaxMemory: -1}
			case "/small-multipart":
				return csrf.BodyLimit{MaxBytes: 512 << 10, MultipartMaxBytes: 64 << 10}
			case "/clamped":
				return csrf.BodyLimit{MultipartMaxBytes: 1 << 20, MaxMemory: 8 << 20}
			}
			return csrf.BodyLimit{MultipartMaxBytes: 4 << 20}
		},
	})
	observations := make(chan bodyObservation, 1)
	s, client := server(t, observeBody(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			fmt.Fprint(w, csrf.Token(r))
			return
		}
		// A 1 MiB upload must stay in memory when MaxMemory is clamped to it.
		if r.URL.Path == "/clamped" {
			assertTempEntries(t, tmp, false)
		}
		w.WriteHeader(http.StatusNoContent)
	}, p, observations))
	token, _ := formToken(t, s, client, "/")
	<-observations
	prefix := url.Values{csrf.FieldName: {token}}.Encode() + "&field="
	for _, tc := range []struct {
		name, path, mediaType string
		size                  int // body bytes; multipart when mediaType is empty
		maxRead               int64
		status                int
		streamed              bool
		header                bool // token in a header, so the body type does not matter
	}{
		{"declared URL-encoded cap plus one", "/upload", urlencoded, defaultCap + 1, 0, 413, false, false},
		{"streamed 8 MiB URL-encoded", "/upload", urlencoded, 8 << 20, defaultCap + 64<<10, 413, true, false},
		{"declared 1 MiB JSON", "/upload", "application/json", 1 << 20, 0, 413, false, true},
		{"declared 1 MiB text", "/upload", "text/plain", 1 << 20, 0, 413, false, true},
		{"multipart at exactly the cap", "/upload", "", 4 << 20, 4 << 20, 204, false, false},
		{"multipart 5 MiB declared", "/upload", "", 5 << 20, 0, 413, false, false},
		{"multipart refused when the cap is 0", "/no-multipart", "", 1 << 10, 0, 415, false, false},
		{"multipart refused when the cap is negative", "/negative", "", 1 << 10, 0, 415, false, false},
		{"malformed multipart type refused when the cap is 0", "/no-multipart", "multipart/form-data;;", 1 << 10, 0, 415, false, false},
		{"URL-encoded within a larger MaxBytes", "/medium", urlencoded, 300 << 10, 300 << 10, 204, false, false},
		{"URL-encoded over a larger MaxBytes", "/medium", urlencoded, 512<<10 + 1, 0, 413, false, false},
		{"multipart ignores MaxBytes", "/medium", "", 1 << 10, 0, 415, false, false},
		{"multipart capped at its own smaller value", "/small-multipart", "", 100 << 10, 0, 413, false, false},
		{"multipart within its own smaller value", "/small-multipart", "", 32 << 10, 32 << 10, 204, false, false},
		{"MaxBytes of exactly 64 MiB", "/max-64", urlencoded, 1 << 10, 1 << 10, 204, false, false},
		{"MaxBytes above 64 MiB", "/too-large", urlencoded, 1 << 10, 0, 500, false, false},
		{"MaxBytes above 64 MiB for multipart", "/too-large", "", 1 << 10, 0, 500, false, false},
		{"negative values act as 0", "/negative", urlencoded, defaultCap + 1, 0, 413, false, false},
		{"MaxMemory above the multipart cap", "/clamped", "", 1 << 20, 1 << 20, 204, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			logs.mu.Lock()
			logs.buf.Reset()
			logs.mu.Unlock()
			mediaType := tc.mediaType
			var reader io.Reader
			switch {
			case mediaType == "":
				var body []byte
				body, mediaType = multipartBody(t, token, tc.size)
				reader = bytes.NewReader(body)
			case tc.header:
				reader = strings.NewReader(strings.Repeat("x", tc.size))
			case tc.streamed:
				reader = streamed{io.MultiReader(strings.NewReader(prefix), io.LimitReader(repeatedByte('x'), int64(tc.size-len(prefix))))}
			default:
				reader = strings.NewReader(prefix + strings.Repeat("x", max(tc.size-len(prefix), 0)))
			}
			req := request(t, "POST", s.URL+tc.path, reader)
			req.Header.Set("Content-Type", mediaType)
			req.Header.Set("Origin", ownOrigin)
			if tc.header {
				req.Header.Set(csrf.HeaderName, token)
			}
			resp, _ := send(t, client, req)
			obs := <-observations
			if resp.StatusCode != tc.status || obs.next != (tc.status == 204) || obs.read > tc.maxRead {
				t.Errorf("status=%d, next=%t, bytes read=%d; want status=%d and at most %d read",
					resp.StatusCode, obs.next, obs.read, tc.status, tc.maxRead)
			}
			if tc.status == 500 {
				var record map[string]any
				raw := strings.TrimSpace(logs.String())
				if json.Unmarshal([]byte(raw), &record) != nil || record["level"] != "ERROR" ||
					record["msg"] != "csrf: Limit returned MaxBytes above 64 MiB" || record["path"] != tc.path {
					t.Errorf("want one error log with the path; got %q", raw)
				}
				if !resp.Close || resp.Header.Get("Cache-Control") != "no-store" {
					t.Errorf("500 must close the connection and not be cacheable")
				}
			}
			assertTempEntries(t, tmp, false)
		})
	}
}

// The 64 MiB bound is a bug in the application, so the error hook (meant for
// request refusals) is not consulted.
func TestBodyLimitAboveBoundSkipsHook(t *testing.T) {
	called := false
	p := mustNew(t, csrf.Config{
		Origin:      ownOrigin,
		Logger:      slog.New(slog.NewJSONHandler(io.Discard, nil)),
		Limit:       func(*http.Request) csrf.BodyLimit { return csrf.BodyLimit{MaxBytes: 64<<20 + 1} },
		OnBodyError: func(http.ResponseWriter, *http.Request, int) { called = true },
	})
	s, _ := server(t, p.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("next called")
	})))
	req := request(t, "POST", s.URL, strings.NewReader("a=b"))
	req.Header.Set("Content-Type", urlencoded)
	if resp, _ := send(t, s.Client(), req); resp.StatusCode != 500 || called {
		t.Errorf("status=%d, hook called=%t; want 500 and no hook", resp.StatusCode, called)
	}
}

// The connection is closed after every 413, 415 and 500 on which the body was
// not read, so the server does not drain it to reuse the connection.
func TestBodyErrorClosesConnection(t *testing.T) {
	const multipartType = "multipart/form-data; boundary=test-boundary"
	limit := func(r *http.Request) csrf.BodyLimit {
		switch r.URL.Path {
		case "/upload":
			return csrf.BodyLimit{MultipartMaxBytes: 1 << 10}
		case "/broken":
			return csrf.BodyLimit{MaxBytes: 64<<20 + 1}
		}
		return csrf.BodyLimit{}
	}
	// Small enough for net/http to drain and reuse the connection on its own.
	big := strings.Repeat("x", 2<<10)
	for _, hook := range []bool{false, true} {
		conf := csrf.Config{Origin: ownOrigin, MaxBody: 1 << 10, Limit: limit, Logger: slog.New(slog.NewJSONHandler(io.Discard, nil))}
		if hook {
			conf.OnBodyError = func(w http.ResponseWriter, r *http.Request, status int) { w.WriteHeader(status) }
		}
		s, _ := server(t, mustNew(t, conf).Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		})))
		for _, tc := range []struct {
			name, method, path, mediaType, body string
			status                              int
		}{
			{"declared 413", "POST", "/form", urlencoded, big, 413},
			{"declared multipart 413", "POST", "/upload", multipartType, big, 413},
			{"multipart 415", "POST", "/form", multipartType, "x", 415},
			{"safe method multipart 415", "GET", "/form", multipartType, "x", 415},
			{"Limit bound 500", "POST", "/broken", urlencoded, "a=b", 500},
		} {
			t.Run(fmt.Sprintf("hook=%t/%s", hook, tc.name), func(t *testing.T) {
				req := request(t, tc.method, s.URL+tc.path, strings.NewReader(tc.body))
				req.Header.Set("Content-Type", tc.mediaType)
				req.Header.Set("Origin", ownOrigin)
				resp, _ := send(t, s.Client(), req)
				// net/http hides the Connection header from the client; Close is
				// the visible effect.
				if resp.StatusCode != tc.status || resp.ProtoMajor != 1 || !resp.Close {
					t.Errorf("status=%d, HTTP/%d, close=%t; want %d, HTTP/1 and a closed connection",
						resp.StatusCode, resp.ProtoMajor, resp.Close, tc.status)
				}
			})
		}
	}
}
