package http

import (
	"context"
	"errors"
	"github.com/caseypc/wasp/internal/network"
	"net/http"
	"net/url"
	"time"
)

type Probe struct {
	Client *network.Client
}
type Result struct {
	StatusCode  int                 `json:"status_code"`
	Status      string              `json:"status"`
	HTTPVersion string              `json:"http_version"`
	DurationMS  int64               `json:"duration_ms"`
	Headers     map[string][]string `json:"headers"`
	Redirects   []string            `json:"redirects"`
	FinalURL    string              `json:"final_url"`
	BodyBytes   int                 `json:"body_bytes"`
	HSTS        string              `json:"hsts,omitempty"`
}

func (p Probe) Collect(ctx context.Context, target *url.URL) (Result, error) {
	if p.Client == nil {
		return Result{}, errors.New("HTTP probe requires the scoped network client")
	}
	start := time.Now()
	resp, body, err := p.Client.Do(ctx, http.MethodGet, target)
	if err != nil {
		return Result{}, err
	}
	headers := make(map[string][]string)
	for _, key := range []string{
		"Strict-Transport-Security", "X-Content-Type-Options",
		"Referrer-Policy", "X-Frame-Options", "Permissions-Policy",
	} {
		values := resp.Header.Values(key)
		if len(values) > 0 {
			headers[http.CanonicalHeaderKey(key)] = append([]string(nil), values...)
		}
	}
	if len(resp.Header.Values("Content-Security-Policy")) > 0 {
		headers[http.CanonicalHeaderKey("Content-Security-Policy")] = []string{"<present; value omitted>"}
	}
	redirects := redirectChain(resp)
	finalURL := target.String()
	if resp.Request != nil && resp.Request.URL != nil {
		finalURL = safeOrigin(resp.Request.URL)
	}
	result := Result{
		StatusCode: resp.StatusCode, Status: resp.Status, HTTPVersion: resp.Proto,
		DurationMS: time.Since(start).Milliseconds(), Headers: headers,
		Redirects: redirects, FinalURL: finalURL, BodyBytes: len(body),
	}
	result.HSTS = resp.Header.Get("Strict-Transport-Security")
	return result, nil
}
func redirectChain(resp *http.Response) []string {
	var reverse []string
	for r := resp; r != nil; r = responseBefore(r) {
		if r.Request != nil && r.Request.URL != nil {
			reverse = append(reverse, safeOrigin(r.Request.URL))
		}
	}
	for i, j := 0, len(reverse)-1; i < j; i, j = i+1, j-1 {
		reverse[i], reverse[j] = reverse[j], reverse[i]
	}
	if len(reverse) > 1 {
		return reverse
	}
	return []string{}
}
func safeOrigin(u *url.URL) string {
	if u == nil {
		return ""
	}
	copy := *u
	copy.User = nil
	copy.Path = ""
	copy.RawPath = ""
	copy.RawQuery = ""
	copy.Fragment = ""
	return copy.String()
}
func responseBefore(resp *http.Response) *http.Response {
	if resp.Request == nil {
		return nil
	}
	return resp.Request.Response
}
