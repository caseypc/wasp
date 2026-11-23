package network

import (
	"context"
	"errors"
	"github.com/caseypc/wasp/internal/config"
	"net"
	"testing"
)

type fixedResolver struct {
	values []net.IPAddr
}

func (r fixedResolver) LookupIPAddr(context.Context, string) ([]net.IPAddr, error) {
	return r.values, nil
}
func TestResolveRejectsAnyPrivateAnswerToPreventRebinding(t *testing.T) {
	client := NewClient(config.Scope{IncludeHosts: []string{"example.com"}, AllowedSchemes: []string{"https"}, AllowedPorts: []int{443}},
		fixedResolver{values: []net.IPAddr{{IP: net.ParseIP("8.8.8.8")}, {IP: net.ParseIP("127.0.0.1")}}}, 0, 0, 10, 1024)
	_, err := client.Resolve(context.Background(), "example.com")
	if !errors.Is(err, ErrScopeDenied) {
		t.Fatalf("Resolve() error = %v, want scope denial", err)
	}
}
