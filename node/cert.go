package node

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/wyx2685/v2node/common/file"
)

func (c *Controller) renewCertTask(_ context.Context) error {
	// Run the actual (potentially multi-minute, for ACME DNS-01 propagation)
	// renewal detached from this task's execution-timeout. The generic Task
	// wrapper (common/task) treats an Execute that runs past min(5*Interval,
	// 5min)=5min as "the task hung -> reload the whole node", which is wrong
	// for cert renewal, where a multi-minute runtime is normal, not a hang:
	// a slow-but-healthy renewal used to spuriously reload the entire node
	// while the real lego HTTP call kept running orphaned in the background.
	// This task fires at most once per 24h, so a detached goroutine can't
	// overlap with itself.
	//
	// Errors now log at Error level (was Info, effectively invisible at
	// production log levels) so a persistently-failing renewal is actually
	// noticeable before the cert expires.
	go func() {
		l, err := NewLego(c.info.Common.CertInfo)
		if err != nil {
			log.WithField("tag", c.tag).Error("renew cert: new lego error: ", err)
			return
		}
		if err := l.RenewCert(); err != nil {
			log.WithField("tag", c.tag).Error("renew cert failed: ", err)
		}
	}()
	return nil
}

func (c *Controller) requestCert() error {
	cert := c.info.Common.CertInfo
	switch cert.CertMode {
	case "none", "":
	case "file":
		if cert.CertFile == "" || cert.KeyFile == "" {
			return fmt.Errorf("cert file path or key file path not exist")
		}
	case "dns", "http":
		if cert.CertFile == "" || cert.KeyFile == "" {
			return fmt.Errorf("cert file path or key file path not exist")
		}
		if file.IsExist(cert.CertFile) && file.IsExist(cert.KeyFile) {
			return nil
		}
		l, err := NewLego(cert)
		if err != nil {
			return fmt.Errorf("create lego object error: %s", err)
		}
		err = l.CreateCert()
		if err != nil {
			return fmt.Errorf("create lego cert error: %s", err)
		}
	case "self":
		if cert.CertFile == "" || cert.KeyFile == "" {
			return fmt.Errorf("cert file path or key file path not exist")
		}
		if file.IsExist(cert.CertFile) && file.IsExist(cert.KeyFile) {
			return nil
		}
		err := generateSelfSslCertificate(
			cert.CertDomain,
			cert.CertFile,
			cert.KeyFile)
		if err != nil {
			return fmt.Errorf("generate self cert error: %s", err)
		}
	default:
		return fmt.Errorf("unsupported certmode: %s", cert.CertMode)
	}
	return nil
}

func generateSelfSslCertificate(domain, certPath, keyPath string) error {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("generate rsa key error: %s", err)
	}
	tmpl := &x509.Certificate{
		Version:      3,
		SerialNumber: big.NewInt(time.Now().Unix()),
		Subject: pkix.Name{
			CommonName: domain,
		},
		DNSNames:              []string{domain},
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(30, 0, 0),
	}
	cert, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(certPath, os.O_CREATE|os.O_RDWR, 0644)
	if err != nil {
		return err
	}
	err = pem.Encode(f, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert,
	})
	if err != nil {
		return err
	}
	f, err = os.OpenFile(keyPath, os.O_CREATE|os.O_RDWR, 0644)
	if err != nil {
		return err
	}
	err = pem.Encode(f, &pem.Block{
		// key is an RSA key encoded via MarshalPKCS1PrivateKey - the PEM
		// block type must say so. Go's own tls.X509KeyPair loader ignores
		// this field so xray-core's cert loading path never actually broke,
		// but any tool that trusts the label (openssl, other clients) would
		// have parsed this as garbage.
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})
	if err != nil {
		return err
	}
	return nil
}
