package network

import (
	"context"
	"errors"
	"fmt"
	"github.com/caseypc/wasp/internal/config"
	"golang.org/x/net/idna"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
)

type Target struct {
	Input string
	URL   *url.URL
	Host  string
	Port  string
}

func ParseTarget(input string) (Target, error) {
	raw := strings.TrimSpace(input)
	if raw == "" {
		return Target{}, errors.New("target is empty")
	}
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return Target{}, errors.New("target must be a hostname or http(s) URL")
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return Target{}, errors.New("target scheme must be http or https")
	}
	if u.User != nil {
		return Target{}, errors.New("credential-bearing target URLs are not allowed")
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return Target{}, errors.New("target query strings and fragments are not allowed")
	}
	if u.Path != "" && u.Path != "/" {
		return Target{}, errors.New("target URL must identify an origin, not a path")
	}
	host := strings.TrimSuffix(u.Hostname(), ".")
	if host == "" {
		return Target{}, errors.New("target hostname is empty")
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		host = ip.String()
		if !IsPublicAddress(ip) {
			return Target{}, fmt.Errorf("%w: target address is not public-routable", ErrScopeDenied)
		}
	} else {
		ascii, err := idna.Lookup.ToASCII(host)
		if err != nil {
			return Target{}, errors.New("target hostname is invalid")
		}
		host = strings.ToLower(ascii)
		if strings.Contains(host, "%") || len(host) > 253 {
			return Target{}, errors.New("target hostname is invalid")
		}
		for _, label := range strings.Split(host, ".") {
			if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
				return Target{}, errors.New("target hostname is invalid")
			}
		}
	}
	port := u.Port()
	if port == "" {
		if u.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return Target{}, errors.New("target port is invalid")
	}
	u.Host = net.JoinHostPort(host, port)
	u.Path = ""
	return Target{Input: input, URL: u, Host: host, Port: port}, nil
}
func InScope(u *url.URL, scope config.Scope) bool {
	if u == nil || (u.Scheme != "https" && u.Scheme != "http") || u.User != nil {
		return false
	}
	host := strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
	if ip, err := netip.ParseAddr(host); err == nil {
		host = ip.String()
	} else if ascii, err := idna.Lookup.ToASCII(host); err == nil {
		host = strings.ToLower(ascii)
	} else {
		return false
	}
	hostAllowed := false
	for _, entry := range scope.IncludeHosts {
		entry = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(entry)), ".")
		ascii, err := idna.Lookup.ToASCII(entry)
		if err != nil {
			continue
		}
		entry = strings.ToLower(ascii)
		if host == entry || (scope.IncludeSubdomains && strings.HasSuffix(host, "."+entry)) {
			hostAllowed = true
			break
		}
	}
	if !hostAllowed {
		return false
	}
	schemeAllowed := len(scope.AllowedSchemes) == 0
	for _, scheme := range scope.AllowedSchemes {
		if scheme == u.Scheme {
			schemeAllowed = true
		}
	}
	if !schemeAllowed {
		return false
	}
	port := u.Port()
	if port == "" {
		if u.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	if len(scope.AllowedPorts) > 0 {
		portAllowed := false
		for _, allowed := range scope.AllowedPorts {
			if port == strconv.Itoa(allowed) {
				portAllowed = true
				break
			}
		}
		if !portAllowed {
			return false
		}
	}
	return true
}
func IsPublicAddress(addr netip.Addr) bool {
	if addr.Is4In6() {
		addr = addr.Unmap()
	}
	if !addr.IsValid() || !addr.IsGlobalUnicast() || addr.IsPrivate() || addr.IsLoopback() || addr.IsLinkLocalUnicast() || addr.IsMulticast() || addr.IsUnspecified() {
		return false
	}
	if addr.Is4() {
		blocked := []netip.Prefix{
			netip.MustParsePrefix("0.0.0.0/8"), netip.MustParsePrefix("100.64.0.0/10"),
			netip.MustParsePrefix("192.0.0.0/24"), netip.MustParsePrefix("192.0.2.0/24"),
			netip.MustParsePrefix("198.18.0.0/15"), netip.MustParsePrefix("198.51.100.0/24"),
			netip.MustParsePrefix("203.0.113.0/24"), netip.MustParsePrefix("240.0.0.0/4"),
		}
		for _, prefix := range blocked {
			if prefix.Contains(addr) {
				return false
			}
		}
		return true
	}
	global := netip.MustParsePrefix("2000::/3")
	blocked := []netip.Prefix{
		netip.MustParsePrefix("2001::/23"), netip.MustParsePrefix("2001:db8::/32"),
		netip.MustParsePrefix("2002::/16"), netip.MustParsePrefix("3fff::/20"),
	}
	if !global.Contains(addr) {
		return false
	}
	for _, prefix := range blocked {
		if prefix.Contains(addr) {
			return false
		}
	}
	return true
}

type Resolver interface {
	LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error)
}
