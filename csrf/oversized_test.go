package csrf_test

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"testing"

	"github.com/17xande-dev/websec/csrf"
	"github.com/justinas/nosurf"
)

func TestOversizedUpload(t *testing.T) {
	const capBytes = 512 << 10
	const friendly = "Choose a smaller file.\n"
	const refused = "Request Entity Too Large\n"
	tmp := t.TempDir()
	t.Setenv("TMPDIR", tmp)

	mux := http.NewServeMux()
	conf := csrf.Config{
		Origin: ownOrigin,
		Limit: func(r *http.Request) csrf.BodyLimit {
			limit := csrf.BodyLimit{MaxBytes: capBytes, Multipart: true, MaxMemory: 1024}
			switch r.Pattern {
			case "POST /upload", "POST /exempt", "POST /no-renderer":
				limit.PassOversized = func(r *http.Request) bool {
					if r.ContentLength <= capBytes {
						t.Error("PassOversized called without a declared oversized body")
					}
					c, err := r.Cookie("session")
					return err == nil && c.Value == "uploader"
				}
			}
			return limit
		},
		Exempt: func(r *http.Request) bool { return r.Pattern == "POST /exempt" },
		Oversized: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !csrf.Oversized(r) || r.Body != http.NoBody || r.MultipartForm != nil {
				t.Error("refusal handler did not receive the oversized marker and an empty body")
			}
			assertTempEntries(t, tmp, false)
			http.Error(w, "Choose a smaller file.", http.StatusUnprocessableEntity)
		}),
		OnFailure: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assertTempEntries(t, tmp, !csrf.Oversized(r))
			http.Error(w, csrf.Reason(r).Error(), http.StatusForbidden)
		}),
	}
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if csrf.Oversized(r) {
			t.Error("normal handler saw an oversized request")
		}
		if r.Method == http.MethodGet {
			fmt.Fprint(w, csrf.Token(r))
			return
		}
		if r.MultipartForm == nil || len(r.MultipartForm.File["file"]) != 1 {
			t.Error("at-limit upload was not parsed")
		}
		w.WriteHeader(http.StatusNoContent)
	})
	// Record reads at the middleware boundary, separately from transport
	// buffering, and inspect the temp directory before and after the refusal.
	type observation struct {
		read  int64
		calls int
		close bool
	}
	observations := make(chan observation, 1)
	observe := func(h http.Handler) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			body := &countedBody{ReadCloser: r.Body}
			r.Body = body
			h.ServeHTTP(w, r)
			observations <- observation{body.n, body.calls, w.Header().Get("Connection") == "close"}
		}
	}
	protected := observe(mustNew(t, conf).Handler(next))
	mux.Handle("GET /upload", protected)
	mux.Handle("POST /upload", protected)
	mux.Handle("POST /ordinary", protected)
	mux.Handle("POST /exempt", protected)
	conf.Oversized = nil
	mux.Handle("POST /no-renderer", observe(mustNew(t, conf).Handler(next)))
	s, client := server(t, mux)
	token, _ := formToken(t, s, client, "/upload")
	<-observations

	for _, tc := range []struct {
		name, path, session                       string
		origin, headerToken                       string
		wantText                                  string
		status                                    int
		wantRead                                  int64
		atLimit, streamed                         bool
		noToken, emptyHeader, nonMultipart, close bool
	}{
		{name: "permitted", session: "uploader", status: 422, wantText: friendly, close: true},
		{name: "untrusted origin", session: "uploader", origin: "https://other.example", status: 403, wantText: nosurf.ErrBadOrigin.Error() + "\n", close: true},
		{name: "anonymous", status: 413, wantText: refused},
		{name: "session without upload permission", session: "viewer", status: 413, wantText: refused},
		{name: "invalid header token", session: "uploader", headerToken: "invalid", status: 403, wantText: nosurf.ErrBadToken.Error() + "\n", close: true},
		{name: "empty header token", session: "uploader", emptyHeader: true, status: 403, wantText: nosurf.ErrBadToken.Error() + "\n", close: true},
		{name: "valid header token", session: "uploader", headerToken: token, status: 403, wantText: "Forbidden\n", close: true},
		{name: "ordinary route", path: "/ordinary", session: "uploader", status: 413, wantText: refused},
		{name: "exempt route", path: "/exempt", session: "uploader", status: 413, wantText: refused},
		{name: "missing renderer", path: "/no-renderer", session: "uploader", status: 413, wantText: refused},
		{name: "not multipart", session: "uploader", nonMultipart: true, status: 413, wantText: refused},
		{name: "streamed oversized", session: "uploader", streamed: true, status: 413, wantText: refused, wantRead: capBytes + 1},
		{name: "anonymous streamed oversized", streamed: true, status: 413, wantText: refused, wantRead: capBytes + 1},
		{name: "at limit with valid token", session: "uploader", atLimit: true, status: 204, wantRead: capBytes},
		{name: "at limit without token", session: "uploader", atLimit: true, noToken: true, status: 403, wantRead: capBytes, wantText: nosurf.ErrBadToken.Error() + "\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			size := capBytes + 1
			if tc.atLimit {
				size = capBytes
			} else if tc.streamed {
				size = capBytes + 1<<20
			}
			formToken := token
			if tc.noToken {
				formToken = ""
			}
			body, mediaType := multipartBody(t, formToken, size)
			if tc.nonMultipart {
				mediaType = urlencoded
			}
			var reader io.Reader = bytes.NewReader(body)
			if tc.streamed {
				reader = streamed{reader}
			}
			path := tc.path
			if path == "" {
				path = "/upload"
			}
			// No header or query parameter can create the internal marker.
			req := request(t, http.MethodPost, s.URL+path+"?oversized=true&"+url.QueryEscape(csrf.FieldName)+"="+url.QueryEscape(token), reader)
			req.Header.Set("X-Oversized", "true")
			req.Header.Set("Content-Type", mediaType)
			req.Header.Set("Origin", ownOrigin)
			if tc.origin != "" {
				req.Header.Set("Origin", tc.origin)
			}
			if tc.headerToken != "" || tc.emptyHeader {
				req.Header.Set(csrf.HeaderName, tc.headerToken)
			}
			doer := client
			if tc.session == "" {
				doer = s.Client()
			} else {
				req.AddCookie(&http.Cookie{Name: "session", Value: tc.session})
			}
			resp, text := send(t, doer, req)
			obs := <-observations
			if resp.StatusCode != tc.status || text != tc.wantText {
				t.Errorf("response = %d %q; want %d %q", resp.StatusCode, text, tc.status, tc.wantText)
			}
			if obs.read != tc.wantRead || (tc.wantRead == 0 && obs.calls != 0) {
				t.Errorf("body read %d bytes in %d calls; want %d bytes", obs.read, obs.calls, tc.wantRead)
			}
			if tc.close && (resp.ProtoMajor != 1 || !resp.Close || !obs.close) {
				t.Error("oversized hand-off did not close the HTTP/1 connection")
			}
			if len(resp.Cookies()) != 0 {
				t.Error("upload response unexpectedly set a cookie")
			}
			assertTempEntries(t, tmp, false)
		})
	}
}
