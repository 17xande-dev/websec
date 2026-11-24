package webtest_test

import (
	"testing"

	"github.com/17xande-dev/websec/csrf"
	"github.com/17xande-dev/websec/webtest"
)

func TestTokenFieldMatchesCSRF(t *testing.T) {
	if got, want := webtest.TokenField, csrf.FieldName; got != want {
		t.Errorf("webtest.TokenField = %q; csrf.FieldName = %q", got, want)
	}
}
