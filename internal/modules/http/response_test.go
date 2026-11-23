package http

import (
	"net/http"
	"net/url"
	"reflect"
	"testing"
)

func TestRedirectChainOnlyEmitsScopedOrigins(t *testing.T) {
	firstURL, _ := url.Parse("https://example.com/start?token=secret")
	lastURL, _ := url.Parse("https://example.com/final?session=secret")
	firstRequest := &http.Request{URL: firstURL}
	firstResponse := &http.Response{Request: firstRequest}
	lastRequest := &http.Request{URL: lastURL, Response: firstResponse}
	result := redirectChain(&http.Response{Request: lastRequest})
	want := []string{"https://example.com", "https://example.com"}
	if !reflect.DeepEqual(result, want) {
		t.Fatalf("redirect chain = %#v, want %#v", result, want)
	}
}
