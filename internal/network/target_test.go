package network

import (
	"github.com/caseypc/wasp/internal/config"
	"net/netip"
	"net/url"
	"testing"
)

func TestParseTargetNormalizesAndRejectsCredentialURLs(t *testing.T) {
	tests := []struct {
		input, host, port string
		wantErr           bool
	}{
		{"Example.COM", "example.com", "443", false},
		{"https://bücher.example", "xn--bcher-kva.example", "443", false},
		{"https://user:secret@example.com", "", "", true},
		{"file:///etc/passwd", "", "", true},
		{"https://example.com/a", "", "", true},
		{"https://example.com:99999", "", "", true},
		{"https://[::1]", "", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got, err := ParseTarget(tt.input)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ParseTarget() error = %v, wantErr %v", err, tt.wantErr)
			}
			if err == nil && (got.Host != tt.host || got.Port != tt.port) {
				t.Fatalf("ParseTarget() = %s:%s, want %s:%s", got.Host, got.Port, tt.host, tt.port)
			}
		})
	}
}
func TestInScopeUsesHostLabelsAndExplicitPorts(t *testing.T) {
	scope := config.Scope{
		IncludeHosts:   []string{"example.com"},
		AllowedSchemes: []string{"https"},
		AllowedPorts:   []int{443},
	}
	for _, tc := range []struct {
		value string
		want  bool
	}{
		{"https://example.com", true},
		{"https://evil-example.com", false},
		{"https://example.com.evil.test", false},
		{"http://example.com", false},
		{"https://example.com:8443", false},
	} {
		u, err := url.Parse(tc.value)
		if err != nil {
			t.Fatal(err)
		}
		if got := InScope(u, scope); got != tc.want {
			t.Errorf("InScope(%q) = %t, want %t", tc.value, got, tc.want)
		}
	}
	scope.IncludeSubdomains = true
	u, _ := url.Parse("https://a.example.com")
	if !InScope(u, scope) {
		t.Fatal("configured subdomain was rejected")
	}
}
func TestIsPublicAddressBlocksSpecialAndMappedRanges(t *testing.T) {
	for _, value := range []string{
		"127.0.0.1", "10.1.2.3", "169.254.169.254", "192.0.2.1",
		"100.64.0.1", "::1", "fc00::1", "fe80::1", "::ffff:127.0.0.1",
		"2001:db8::1", "2002::1",
	} {
		addr := netip.MustParseAddr(value)
		if IsPublicAddress(addr) {
			t.Errorf("IsPublicAddress(%s) = true, want false", addr)
		}
	}
	for _, value := range []string{"8.8.8.8", "2606:4700:4700::1111"} {
		addr := netip.MustParseAddr(value)
		if !IsPublicAddress(addr) {
			t.Errorf("IsPublicAddress(%s) = false, want true", addr)
		}
	}
}
