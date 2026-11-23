package network

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/caseypc/wasp/internal/config"
)

type Client struct {
	http        *http.Client
	scope       config.Scope
	resolver    Resolver
	requests    atomic.Int64
	maxRequests int64
	maxBytes    int64
}

func NewClient(scope config.Scope, resolver Resolver, timeout time.Duration, maxRedirects int, maxRequests int, maxBytes int64) *Client {
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	if timeout <= 0 {
		timeout = config.DefaultTimeout
	}
	if maxRedirects < 0 {
		maxRedirects = 0
	}
	if maxRequests <= 0 {
		maxRequests = config.DefaultMaxRequests
	}
	if maxBytes <= 0 {
		maxBytes = config.DefaultMaxResponseBytes
	}
	c := &Client{
		scope: scope, resolver: resolver, maxRequests: int64(maxRequests), maxBytes: maxBytes,
	}
	transport := &http.Transport{
		Proxy:                 nil,
		ForceAttemptHTTP2:     true,
		TLSHandshakeTimeout:   timeout,
		ResponseHeaderTimeout: timeout,
		IdleConnTimeout:       5 * time.Second,
		MaxConnsPerHost:       4,
		MaxIdleConnsPerHost:   2,
		DialContext:           c.dialContext,
	}
	transport.MaxIdleConns = 8
	c.http = &http.Client{
		Transport: transport,
		Timeout:   timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) > maxRedirects {
				return errors.New("redirect limit exceeded")
			}
			if !scopeAllowsRedirect(scope, req.URL) {
				return errors.New("redirect is outside configured scope")
			}
			return nil
		},
	}
	return c
}
func (c *Client) Do(ctx context.Context, method string, target *url.URL) (*http.Response, []byte, error) {
	if !InScope(target, c.scope) {
		return nil, nil, errors.New("request target is outside configured scope")
	}
	req, err := http.NewRequestWithContext(ctx, method, target.String(), nil)
	if err != nil {
		return nil, nil, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("User-Agent", config.UserAgent())
	resp, err := c.http.Do(req)
	if err != nil {
		if strings.Contains(err.Error(), "outside configured scope") || strings.Contains(err.Error(), "not public-routable") {
			return nil, nil, fmt.Errorf("%w: %v", ErrScopeDenied, err)
		}
		return nil, nil, err
	}
	body, readErr := io.ReadAll(io.LimitReader(resp.Body, c.maxBytes+1))
	closeErr := resp.Body.Close()
	if int64(len(body)) > c.maxBytes {
		return resp, nil, ErrResponseTooLarge
	}
	if readErr != nil {
		return resp, nil, fmt.Errorf("read bounded response: %w", readErr)
	}
	if closeErr != nil {
		return resp, nil, fmt.Errorf("close response: %w", closeErr)
	}
	return resp, body, nil
}
func (c *Client) Resolve(ctx context.Context, host string) ([]netip.Addr, error) {
	if ip, err := netip.ParseAddr(host); err == nil {
		if !IsPublicAddress(ip) {
			return nil, fmt.Errorf("%w: resolved address is not public-routable", ErrScopeDenied)
		}
		return []netip.Addr{ip}, nil
	}
	results, err := c.resolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}
	if len(results) == 0 {
		return nil, errors.New("hostname resolved to no addresses")
	}
	addresses := make([]netip.Addr, 0, len(results))
	for _, result := range results {
		addr, ok := netip.AddrFromSlice(result.IP)
		if !ok {
			return nil, errors.New("resolver returned an invalid address")
		}
		addr = addr.Unmap()
		if !IsPublicAddress(addr) {
			return nil, fmt.Errorf("%w: hostname resolved to a non-public address", ErrScopeDenied)
		}
		addresses = append(addresses, addr)
	}
	return addresses, nil
}
func (c *Client) Dial(ctx context.Context, host, port string) (net.Conn, netip.Addr, error) {
	u := &url.URL{Scheme: "https", Host: net.JoinHostPort(host, port)}
	if !InScope(u, c.scope) {
		return nil, netip.Addr{}, fmt.Errorf("%w: connection endpoint is outside configured scope", ErrScopeDenied)
	}
	addresses, err := c.Resolve(ctx, host)
	if err != nil {
		return nil, netip.Addr{}, err
	}
	dialer := net.Dialer{Timeout: config.DefaultTimeout, KeepAlive: 15 * time.Second}
	var lastErr error
	for _, addr := range addresses {
		conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(addr.String(), port))
		if err == nil {
			return conn, addr, nil
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = errors.New("no usable resolved address")
	}
	return nil, netip.Addr{}, lastErr
}
func (c *Client) dialContext(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, errors.New("invalid connection address")
	}
	if !hostPortAllowed(host, port, c.scope) {
		return nil, fmt.Errorf("%w: connection endpoint is outside configured scope", ErrScopeDenied)
	}
	current := c.requests.Add(1)
	if current > c.maxRequests {
		return nil, ErrRequestLimit
	}
	addresses, err := c.Resolve(ctx, host)
	if err != nil {
		return nil, err
	}
	dialer := net.Dialer{Timeout: config.DefaultTimeout, KeepAlive: 15 * time.Second}
	var lastErr error
	for _, addr := range addresses {
		conn, err := dialer.DialContext(ctx, network, net.JoinHostPort(addr.String(), port))
		if err == nil {
			return conn, nil
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = errors.New("no usable resolved address")
	}
	return nil, lastErr
}
func scopeAllowsRedirect(scope config.Scope, target *url.URL) bool {
	if !scope.FollowInScopeRedirects {
		return false
	}
	return InScope(target, scope)
}
func hostPortAllowed(host, port string, scope config.Scope) bool {
	scheme := "https"
	if port == "80" {
		scheme = "http"
	}
	u := &url.URL{Scheme: scheme, Host: net.JoinHostPort(host, port)}
	return InScope(u, scope)
}

var (
	ErrScopeDenied      = errors.New("scope denied")
	ErrRequestLimit     = errors.New("request limit exceeded")
	ErrResponseTooLarge = errors.New("response exceeded configured byte limit")
)

func ParsePort(port string) (int, error) {
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return 0, errors.New("invalid TCP port")
	}
	return n, nil
}
