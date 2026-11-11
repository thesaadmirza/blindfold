package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"net"
	"testing"
	"time"
)

func verify(a *authority, der []byte, host string) error {
	roots := x509.NewCertPool()
	roots.AddCert(a.cert)
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return err
	}
	_, err = cert.Verify(x509.VerifyOptions{DNSName: host, Roots: roots})
	return err
}

func TestLeafForAPolicyHostVerifies(t *testing.T) {
	a, err := newAuthority([]string{"gitlab.com"})
	if err != nil {
		t.Fatal(err)
	}

	c, err := a.leaf("gitlab.com")
	if err != nil {
		t.Fatal(err)
	}

	if err := verify(a, c.Certificate[0], "gitlab.com"); err != nil {
		t.Fatal(err)
	}
	if again, _ := a.leaf("gitlab.com"); again != c {
		t.Fatal("leaf was not cached")
	}
}

func TestNoLeafForOtherHosts(t *testing.T) {
	a, _ := newAuthority([]string{"gitlab.com"})

	for _, host := range []string{"evil.example", "sub.gitlab.com", "127.0.0.1"} {
		if _, err := a.leaf(host); err == nil {
			t.Errorf("issued a certificate for %s", host)
		}
	}
}

// Even with the CA key in hand, a certificate for another site must not
// verify, because the CA itself is limited to the policy hosts.
func TestNameConstraintsHoldWithTheKey(t *testing.T) {
	a, _ := newAuthority([]string{"gitlab.com"})
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	forge := func(tmpl *x509.Certificate) []byte {
		tmpl.SerialNumber = serial()
		tmpl.NotBefore = time.Now().Add(-time.Hour)
		tmpl.NotAfter = time.Now().Add(time.Hour)
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, a.cert, &key.PublicKey, a.key)
		if err != nil {
			t.Fatal(err)
		}
		return der
	}

	if err := verify(a, forge(&x509.Certificate{DNSNames: []string{"evil.example"}}), "evil.example"); err == nil {
		t.Error("forged certificate for evil.example verified")
	}
	if err := verify(a, forge(&x509.Certificate{IPAddresses: []net.IP{net.ParseIP("1.2.3.4")}}), "1.2.3.4"); err == nil {
		t.Error("forged certificate for an IP verified")
	}
}

func TestCARefusesNoHosts(t *testing.T) {
	if _, err := newAuthority(nil); err == nil {
		t.Fatal("made an unconstrained CA")
	}
}
