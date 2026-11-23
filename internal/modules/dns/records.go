package dns

import (
	"context"
	"errors"
	"github.com/caseypc/wasp/internal/network"
	"net/netip"
)

type Probe struct {
	Client *network.Client
}
type Result struct {
	Addresses []netip.Addr `json:"addresses"`
}

func (p Probe) Collect(ctx context.Context, hostname string) (Result, error) {
	if p.Client == nil {
		return Result{}, errors.New("DNS probe requires the scoped network client")
	}
	addresses, err := p.Client.Resolve(ctx, hostname)
	if err != nil {
		return Result{}, err
	}
	return Result{Addresses: addresses}, nil
}
