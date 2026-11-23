package tls

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/caseypc/wasp/internal/network"
	"time"
)

type Probe struct {
	Client *network.Client
	Now    func() time.Time
}
type Result struct {
	Subject            string
	Issuer             string
	SANs               []string
	SerialNumber       string
	SHA256Fingerprint  string
	NotBefore          time.Time
	NotAfter           time.Time
	SignatureAlgorithm string
	PublicKeyAlgorithm string
	PublicKeyBits      int
	TLSVersion         string
	CipherSuite        string
	ChainLength        int
	ChainVerified      bool
	VerificationError  string
	Expired            bool
}

func (p Probe) Collect(ctx context.Context, host, port string) (Result, error) {
	if p.Client == nil {
		return Result{}, errors.New("TLS probe requires the scoped network client")
	}
	now := time.Now
	if p.Now != nil {
		now = p.Now
	}
	raw, _, err := p.Client.Dial(ctx, host, port)
	if err != nil {
		return Result{}, err
	}
	defer raw.Close()
	var peer *x509.Certificate
	var verificationError string
	var verified bool
	cfg := &tls.Config{
		ServerName: host,
		// This probe reads certificate evidence only; it performs explicit X.509
		// verification below and never sends application data on this connection.
		InsecureSkipVerify: true,
		VerifyConnection: func(state tls.ConnectionState) error {
			if len(state.PeerCertificates) == 0 {
				return errors.New("server sent no certificate")
			}
			peer = state.PeerCertificates[0]
			roots, rootErr := x509.SystemCertPool()
			if rootErr != nil || roots == nil {
				verificationError = "system trust roots unavailable"
				return nil
			}
			intermediates := x509.NewCertPool()
			for _, cert := range state.PeerCertificates[1:] {
				intermediates.AddCert(cert)
			}
			_, verifyErr := peer.Verify(x509.VerifyOptions{
				DNSName: host, Roots: roots, Intermediates: intermediates, CurrentTime: now(),
			})
			if verifyErr != nil {
				verificationError = verifyErr.Error()
				return nil
			}
			verified = true
			return nil
		},
	}
	conn := tls.Client(raw, cfg)
	if err := conn.HandshakeContext(ctx); err != nil {
		return Result{}, fmt.Errorf("TLS handshake failed: %w", err)
	}
	defer conn.Close()
	state := conn.ConnectionState()
	if peer == nil && len(state.PeerCertificates) > 0 {
		peer = state.PeerCertificates[0]
	}
	if peer == nil {
		return Result{}, errors.New("server sent no certificate")
	}
	fingerprint := sha256.Sum256(peer.Raw)
	bits := publicKeyBits(peer)
	return Result{
		Subject: peer.Subject.String(), Issuer: peer.Issuer.String(),
		SANs: append([]string(nil), peer.DNSNames...), SerialNumber: peer.SerialNumber.Text(16),
		SHA256Fingerprint: hex.EncodeToString(fingerprint[:]),
		NotBefore:         peer.NotBefore.UTC(), NotAfter: peer.NotAfter.UTC(),
		SignatureAlgorithm: peer.SignatureAlgorithm.String(),
		PublicKeyAlgorithm: peer.PublicKeyAlgorithm.String(), PublicKeyBits: bits,
		TLSVersion: tlsVersion(state.Version), CipherSuite: tls.CipherSuiteName(state.CipherSuite),
		ChainLength: len(state.PeerCertificates), ChainVerified: verified,
		VerificationError: verificationError, Expired: now().After(peer.NotAfter),
	}, nil
}
func publicKeyBits(cert *x509.Certificate) int {
	switch key := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		return key.N.BitLen()
	case *ecdsa.PublicKey:
		return key.Params().BitSize
	case ed25519.PublicKey:
		return len(key) * 8
	default:
		return 0
	}
}
func tlsVersion(version uint16) string {
	switch version {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return "unknown"
	}
}
