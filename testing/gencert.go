// Generate a self-signed P-256 certificate covering localhost / 127.0.0.1 plus
// the ECH inner/outer test names. Usage: gencert <cert.pem> <key.pem> <serial> <cn>
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"strconv"
	"time"
)

func main() {
	certPath, keyPath := os.Args[1], os.Args[2]
	serial, _ := strconv.Atoi(os.Args[3])
	cn := os.Args[4]
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := x509.Certificate{
		SerialNumber:          big.NewInt(int64(serial)),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * 365 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:              []string{"localhost", "public.example.com", "secret.internal"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, _ := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	cf, _ := os.Create(certPath)
	pem.Encode(cf, &pem.Block{Type: "CERTIFICATE", Bytes: der})
	cf.Close()
	kb, _ := x509.MarshalPKCS8PrivateKey(priv)
	kf, _ := os.Create(keyPath)
	pem.Encode(kf, &pem.Block{Type: "PRIVATE KEY", Bytes: kb})
	kf.Close()
}
