package snowflake_client

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"os"
	"sync/atomic"
	"testing"
	"time"
)

var (
	fixtureCA     *x509.Certificate
	fixtureCAKey  *ecdsa.PrivateKey
	fixtureSerial atomic.Int64
)

// Only this test binary trusts this generated local CA. Production transports
// retain their normal certificate verification; there is no insecure option
// or test certificate path in the shipping adapter.
func TestMain(m *testing.M) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "RouterVPN local transport fixture CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, ca, ca, &key.PublicKey, key)
	if err != nil {
		panic(err)
	}
	fixtureCA, err = x509.ParseCertificate(der)
	if err != nil {
		panic(err)
	}
	fixtureCAKey = key
	pool := x509.NewCertPool()
	pool.AddCert(fixtureCA)
	os.Setenv("GODEBUG", os.Getenv("GODEBUG")+",x509usefallbackroots=1")
	x509.SetFallbackRoots(pool)
	os.Exit(m.Run())
}

func fixtureCertificate(t *testing.T, names ...string) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(fixtureSerial.Add(1) + 10), DNSNames: names,
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, leaf, fixtureCA, &key.PublicKey, fixtureCAKey)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}
