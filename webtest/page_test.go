package webtest

import (
	"io"
	"net/http"
	"net/url"
	"os"
	"reflect"
	"strings"
	"testing"
)

func fixtureHTML(t testing.TB, name string) string {
	t.Helper()
	body, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

func pageClient(t testing.TB, status int, body string) *Client {
	t.Helper()
	return New(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(status)
		io.WriteString(w, body)
	}), testOrigin)
}

func TestPageToken(t *testing.T) {
	for _, tt := range []struct {
		name, body, want, wantMsg string
	}{
		{name: "missing", body: `<form></form>`, wantMsg: `no "csrf_token" input on page (1 forms found)`},
		{name: "wrong field", body: `<form><input name=token value=abc></form>`, wantMsg: `no "csrf_token" input on page (1 forms found)`},
		{name: "comment", body: `<!-- <input name="csrf_token" value="comment"> -->`, wantMsg: `no "csrf_token" input on page (0 forms found)`},
		{name: "script", body: `<SCRIPT>const example = '<input name="csrf_token" value="script">';</SCRIPT>`, wantMsg: `no "csrf_token" input on page (0 forms found)`},
		{name: "style", body: `<style>p::before { content: '<input name="csrf_token" value="style">'; }</style>`, wantMsg: `no "csrf_token" input on page (0 forms found)`},
		{name: "template", body: `<template><form><input name=csrf_token value=inert></form></template>`, wantMsg: `no "csrf_token" input on page (0 forms found)`},
		{name: "attribute order and double quotes", body: `<form><input value="a&#43;b&#61;" name="csrf_token"></form>`, want: "a+b="},
		{name: "uppercase and single quotes", body: `<FORM><INPUT NAME='csrf_token' VALUE='a&#43;b&#61;'></FORM>`, want: "a+b="},
		{name: "unquoted outside any form", body: `<input name=csrf_token value=a&#43;b&#61;>`, want: "a+b="},
		{
			name: "two forms with equal decoded values",
			body: `<form><input name=csrf_token value="same&#43;"></form><form><input name=csrf_token value="same+"></form>`, want: "same+",
		},
		{
			name:    "two forms with different values",
			body:    `<form><input name=csrf_token value=first></form><form><input name=csrf_token value=second></form>`,
			wantMsg: `conflicting "csrf_token" inputs on page (2 forms found)`,
		},
		{
			name:    "out of form token disagrees",
			body:    `<input name=csrf_token value=outside><form><input name=csrf_token value=inside></form>`,
			wantMsg: `conflicting "csrf_token" inputs on page (1 forms found)`,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			const path = "/items/edit?mode=full"
			msg := tt.wantMsg
			if msg != "" {
				msg = "GET " + path + `: status 200, body "`
			}
			rec := recordFailure(t, func(t testing.TB) {
				if got := pageClient(t, http.StatusOK, tt.body).Page(path).Token(); tt.wantMsg == "" && got != tt.want {
					t.Errorf("Token() = %q; want %q", got, tt.want)
				}
			})
			got := strings.Join(rec.messages, "\n")
			if rec.Failed() != (tt.wantMsg != "") || !strings.Contains(got, msg) || !strings.Contains(got, tt.wantMsg) {
				t.Errorf("failed = %v, messages = %q; want failure containing %q and %q", rec.Failed(), got, msg, tt.wantMsg)
			}
		})
	}
}

func TestPageStatus(t *testing.T) {
	const body = `<input name=csrf_token value=token>`
	checkFailure(t, func(t testing.TB) {
		pageClient(t, http.StatusSeeOther, body).Page("/items")
	}, true, "GET /items: status 303")
	// Response.Page deliberately allows inspecting an error response's HTML.
	if got := pageClient(t, http.StatusBadRequest, body).Get("/items").Page().Token(); got != "token" {
		t.Errorf("Token() = %q; want token", got)
	}
}

func TestFormValues(t *testing.T) {
	p := pageClient(t, http.StatusOK, fixtureHTML(t, "forms.html")).Page("/items/edit")
	if got := p.Token(); got != "a+b=" {
		t.Errorf("Token() = %q; want a+b=", got)
	}
	for _, tt := range []struct {
		action string
		want   url.Values
	}{
		{
			action: "save?from=edit&view=full",
			want: url.Values{
				"csrf_token": {"a+b="}, "version": {"v&1"}, "title": {"A & B"}, "date": {"2026-10-02"},
				"empty": {""}, "check": {"on", ""}, "radio": {"yes"}, "defaultRadio": {"on"},
				"note": {"first <input> +\nsecond"}, "emptyNote": {""}, "one": {"x+y"},
				"defaultSelect": {"First & second"}, "several": {"one", ""},
			},
		},
		{action: "find", want: url.Values{"csrf_token": {"a+b="}, "q": {"some words"}}},
	} {
		t.Run(tt.action, func(t *testing.T) {
			if got := p.Form(tt.action).Values(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Values() = %#v; want %#v", got, tt.want)
			}
		})
	}
}

func TestFormSubmit(t *testing.T) {
	for _, tt := range []struct {
		name, page, action, method, target, body string
	}{
		{"relative POST", "/items/edit?mode=full", "../save?x=1", "POST", "/save?x=1", "csrf_token=a%2Bb%3D&title=two+words&title=next"},
		{"absolute POST", "/items/edit", testOrigin + "/save", "post", "/save", "csrf_token=a%2Bb%3D&title=two+words&title=next"},
		{"default action and method", "/items/edit?mode=full", "", "", "/items/edit?csrf_token=a%2Bb%3D&title=two+words&title=next", ""},
		{"GET replaces action query", "/items/edit", "search?x=1#result", "get", "/items/search?csrf_token=a%2Bb%3D&title=two+words&title=next", ""},
	} {
		t.Run(tt.name, func(t *testing.T) {
			h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("X-Step") == "load" {
					io.WriteString(w, `<form action="`+tt.action+`" method="`+tt.method+`">
						<input name=csrf_token value="a&#43;b&#61;">
						<input name=title value=old><input name=drop value=old></form>`)
					return
				}
				method := http.MethodGet
				var mediaType string
				if tt.body != "" {
					method, mediaType = http.MethodPost, "application/x-www-form-urlencoded"
				}
				body, err := io.ReadAll(r.Body)
				if r.Method != method || r.RequestURI != tt.target || string(body) != tt.body || err != nil ||
					r.Header.Get("Content-Type") != mediaType || r.Header.Get("X-Step") != "submit" {
					t.Errorf("submission: %s %s, headers %v, body %q, read error %v; want %s %s, body %q",
						r.Method, r.RequestURI, r.Header, body, err, method, tt.target, tt.body)
				}
				w.WriteHeader(http.StatusNoContent)
			})
			mode := "server"
			if strings.HasPrefix(tt.action, testOrigin) {
				mode = "in-process"
			}
			c := testClient(t, h, mode)
			p := c.Page(tt.page, Header("X-Step", "load"))
			f := p.Form("").Set("title", "two words", "next").Delete("drop")
			v := f.Values()
			v["csrf_token"][0] = "not the token"
			delete(v, "title")
			f.Submit(Header("X-Step", "submit")).WantStatus(http.StatusNoContent)
			if got := p.Form("").Values().Get("title"); got != "old" {
				t.Errorf("original default = %q; want old", got)
			}
		})
	}
}

func TestFormFailures(t *testing.T) {
	for _, tt := range []struct {
		name, body, action, wantMsg string
		submit                      bool
	}{
		{"zero forms", "<p>Empty</p>", "", `form action "" matched 0 forms (0 forms found)`, false},
		{"no match", `<form action="/save"></form>`, "/other", `form action "/other" matched 0 forms (1 forms found)`, false},
		{"two forms", `<form action="/one"></form><form action="/two"></form>`, "", `form action "" matched 2 forms (2 forms found)`, false},
		{"same action", `<form action="/save"></form><form action="/save"></form>`, "/save", `form action "/save" matched 2 forms (2 forms found)`, false},
		{"multipart", `<form method=post enctype="multipart/form-data"></form>`, "", `multipart/form-data"; build the body and use Do`, true},
		{"invalid action", `<form action="/%"></form>`, "", `invalid form action "/%"`, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			checkFailure(t, func(t testing.TB) {
				f := pageClient(t, http.StatusOK, tt.body).Page("/items").Form(tt.action)
				if tt.submit {
					f.Submit()
				}
			}, true, tt.wantMsg)
		})
	}
}
