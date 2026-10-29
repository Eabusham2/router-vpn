// Package controllertransport authenticates the native Windows loopback
// connection before any private request crosses it. Its public leaf pin is
// transferred over the separately verified launcher/controller pipe. No CA,
// certificate, private key, or access secret is installed or persisted.
package controllertransport

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"errors"
	"math/big"
	"net"
	"time"
)

const Address = "127.0.0.1:8788"
const BaseURL = "https://" + Address

type Identity struct {
	certificate tls.Certificate
	pin         string
}

// NewIdentity creates a certificate/key pair owned by this controller process.
// Authentication uses the exact captured leaf, not a public trust chain or a
// mutable machine-wide certificate callback. The key is never serialized.
func NewIdentity() (*Identity, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}
	if serial.Sign() == 0 {
		serial.SetInt64(1)
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "Router VPN local controller"},
		NotBefore:    now.Add(-time.Minute), NotAfter: now.AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:           []net.IP{net.IPv4(127, 0, 0, 1)},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(der)
	return &Identity{certificate: tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, pin: hex.EncodeToString(digest[:])}, nil
}

func (identity *Identity) Pin() string {
	if identity == nil {
		return ""
	}
	return identity.pin
}

func (identity *Identity) Config() (*tls.Config, error) {
	if identity == nil || !validSecret(identity.pin) || len(identity.certificate.Certificate) != 1 || identity.certificate.PrivateKey == nil {
		return nil, errors.New("the native controller has no captured TLS identity")
	}
	return &tls.Config{
		MinVersion:             tls.VersionTLS12,
		Certificates:           []tls.Certificate{identity.certificate},
		NextProtos:             []string{"http/1.1"},
		SessionTicketsDisabled: true,
	}, nil
}

// Process is the already-retained native kernel process, not a PID supplied by
// an HTTP response. Windows' launcher owns its original process handle.
type Process interface {
	PID() uint32
	Alive() error
}

func pinnedTLS(pin string, owner Process) (*tls.Config, error) {
	if !validSecret(pin) || owner == nil || owner.PID() == 0 {
		return nil, errors.New("the native controller requires its captured process and immutable TLS pin")
	}
	expected, _ := hex.DecodeString(pin)
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		ServerName: "127.0.0.1",
		NextProtos: []string{"http/1.1"},
		// A self-signed session certificate is authenticated only by the exact
		// independently captured leaf below. There is no permissive callback or
		// fallback to accepting an arbitrary locally trusted certificate.
		InsecureSkipVerify: true,
		VerifyConnection: func(state tls.ConnectionState) error {
			if err := owner.Alive(); err != nil {
				return err
			}
			if len(state.PeerCertificates) != 1 || state.DidResume || state.NegotiatedProtocol != "" && state.NegotiatedProtocol != "http/1.1" {
				return errors.New("the native controller TLS peer is not its captured leaf")
			}
			leaf := state.PeerCertificates[0]
			digest := sha256.Sum256(leaf.Raw)
			if subtle.ConstantTimeCompare(digest[:], expected) != 1 || leaf.IsCA || leaf.VerifyHostname("127.0.0.1") != nil {
				return errors.New("the native controller TLS certificate does not match the captured session")
			}
			return owner.Alive()
		},
	}, nil
}

func validSecret(value string) bool {
	return validHex(value, 64)
}

func validOwner(value string) bool {
	return validHex(value, 32)
}

func validHex(value string, length int) bool {
	if len(value) != length {
		return false
	}
	for _, char := range value {
		if char < '0' || char > '9' && char < 'a' || char > 'f' {
			return false
		}
	}
	return true
}

// Retired is distinct from a network error. A closed owner cannot be revived by
// a successful retry, a fresh local listener, or a delayed HTTP completion.
var ErrRetired = errors.New("the captured native controller transport is retired")

func ownedContext(parent, lifetime context.Context) (context.Context, func()) {
	ctx, cancel := context.WithCancel(parent)
	joined := make(chan struct{})
	stop := context.AfterFunc(lifetime, func() {
		defer close(joined)
		cancel()
	})
	return ctx, func() {
		if !stop() {
			<-joined
		}
		cancel()
	}
}
