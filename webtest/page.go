package webtest

import (
	"net/http"
	"net/url"
	"strings"

	"golang.org/x/net/html"
)

// Page holds the forms and CSRF token inputs parsed from a response.
type Page struct {
	response *Response
	forms    []*Form
	tokens   []string
}

// Page gets path, requires status 200, and parses the response as HTML.
func (c *Client) Page(path string, opts ...Option) *Page {
	c.t.Helper()
	r := c.Get(path, opts...)
	r.WantStatus(http.StatusOK)
	return r.Page()
}

// Page parses the response body as HTML without checking the status.
func (r *Response) Page() *Page {
	r.t.Helper()
	p := &Page{response: r}
	p.scan()
	return p
}

// Token returns the decoded value of the page's TokenField inputs. It fails
// if there are no such inputs or their values differ.
func (p *Page) Token() string {
	r := p.response
	r.t.Helper()
	if len(p.tokens) == 0 {
		r.t.Fatalf("%s: no %q input on page (%d forms found)", r.summary(), TokenField, len(p.forms))
	}
	for _, token := range p.tokens[1:] {
		if token != p.tokens[0] {
			r.t.Fatalf("%s: conflicting %q inputs on page (%d forms found)", r.summary(), TokenField, len(p.forms))
		}
	}
	return p.tokens[0]
}

// Form returns a fresh copy of the one form with the decoded action attribute
// action. An empty action selects the page's only form, regardless of its action.
func (p *Page) Form(action string) *Form {
	r := p.response
	r.t.Helper()
	var found *Form
	var matches int
	for _, f := range p.forms {
		if action == "" || f.action == action {
			found = f
			matches++
		}
	}
	if matches != 1 {
		r.t.Fatalf("%s: form action %q matched %d forms (%d forms found); want one", r.summary(), action, matches, len(p.forms))
	}
	return found.copy()
}

func (p *Page) scan() {
	z := html.NewTokenizer(strings.NewReader(p.response.Body))
	var f *Form
	var selectInput *selectControl
	var templateDepth int
	for {
		switch z.Next() {
		case html.ErrorToken:
			selectInput.finish(f)
			// A strings.Reader and an unlimited tokenizer can stop only at EOF.
			return
		case html.TextToken:
			if templateDepth == 0 && selectInput != nil && selectInput.option != nil {
				selectInput.text.Write(z.Text())
			}
		case html.EndTagToken:
			tag, _ := z.TagName()
			if string(tag) == "template" && templateDepth > 0 {
				templateDepth--
				continue
			}
			if templateDepth > 0 {
				continue
			}
			switch string(tag) {
			case "option":
				if selectInput != nil {
					selectInput.finishOption()
				}
			case "optgroup":
				if selectInput != nil {
					selectInput.finishOption()
					selectInput.groupDisabled = false
				}
			case "select", "form":
				selectInput.finish(f)
				selectInput = nil
				if string(tag) == "form" {
					f = nil
				}
			}
		case html.StartTagToken, html.SelfClosingTagToken:
			tok := z.Token()
			if tok.Data == "template" {
				templateDepth++
			}
			if templateDepth > 0 {
				continue
			}
			a := attributes(tok)
			name := a["name"]
			if tok.Data == "input" && name == TokenField {
				p.tokens = append(p.tokens, a["value"])
			}
			if tok.Data == "form" && f == nil {
				f = &Form{response: p.response, action: a["action"], method: a["method"],
					enctype: a["enctype"], values: make(url.Values)}
				p.forms = append(p.forms, f)
			}
			if f == nil {
				continue
			}
			if selectInput != nil {
				selectInput.startOption(tok.Data, a)
				continue
			}
			_, disabled := a["disabled"]
			switch tok.Data {
			case "input":
				kind := strings.ToLower(a["type"])
				f.password = f.password || kind == "password"
				if name != "" && !disabled {
					addInput(f.values, name, kind, a)
				}
			case "textarea":
				if name != "" && !disabled {
					// The tokenizer treats textarea content as RCDATA.
					value := ""
					if z.Next() == html.TextToken {
						value = strings.TrimPrefix(string(z.Text()), "\n")
					}
					f.values.Add(name, value)
				}
			case "select":
				_, multiple := a["multiple"]
				selectInput = &selectControl{name: name, disabled: disabled, multiple: multiple}
			}
		}
	}
}

func attributes(tok html.Token) map[string]string {
	a := make(map[string]string, len(tok.Attr))
	for _, attr := range tok.Attr {
		// HTML keeps the first occurrence of a duplicate attribute.
		if _, exists := a[attr.Key]; !exists {
			a[attr.Key] = attr.Val
		}
	}
	return a
}

func addInput(values url.Values, name, kind string, a map[string]string) {
	value, hasValue := a["value"]
	switch kind {
	case "button", "reset", "submit", "image", "file":
		return
	case "checkbox", "radio":
		if _, checked := a["checked"]; !checked {
			return
		}
		if !hasValue {
			value = "on"
		}
	}
	values.Add(name, value)
}

type selectControl struct {
	name                              string
	disabled, multiple, groupDisabled bool
	first                             string
	hasFirst                          bool
	selected                          []string
	option                            map[string]string
	text                              strings.Builder
}

func (s *selectControl) startOption(tag string, a map[string]string) {
	switch tag {
	case "option":
		s.finishOption()
		s.option = a
	case "optgroup":
		s.finishOption()
		_, s.groupDisabled = a["disabled"]
	}
}

func (s *selectControl) finishOption() {
	if s.option == nil {
		return
	}
	value, ok := s.option["value"]
	if !ok {
		value = strings.Join(strings.FieldsFunc(s.text.String(), func(r rune) bool {
			return strings.ContainsRune(" \t\n\f\r", r)
		}), " ")
	}
	_, disabled := s.option["disabled"]
	if !disabled && !s.groupDisabled {
		if !s.hasFirst {
			s.first, s.hasFirst = value, true
		}
		if _, selected := s.option["selected"]; selected {
			s.selected = append(s.selected, value)
		}
	}
	s.option = nil
	s.text.Reset()
}

func (s *selectControl) finish(f *Form) {
	if s == nil || s.name == "" || s.disabled {
		return
	}
	s.finishOption()
	switch {
	case s.multiple:
		for _, v := range s.selected {
			f.values.Add(s.name, v)
		}
	case len(s.selected) > 0:
		f.values.Add(s.name, s.selected[len(s.selected)-1])
	case s.hasFirst:
		f.values.Add(s.name, s.first)
	}
}
