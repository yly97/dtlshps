package util

import (
	"crypto/tls"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
)

// LoadCertificates 从文件中加载证书
func LoadCertificates(path string) (*tls.Certificate, error) {
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return nil, err
	}

	var certificate tls.Certificate
	for {
		block, rest := pem.Decode(data)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			return nil, errors.New("file is not a certificate")
		}
		certificate.Certificate = append(certificate.Certificate, block.Bytes)
		data = rest
	}

	if len(certificate.Certificate) == 0 {
		return nil, errors.New("no certificate found")
	}

	return &certificate, nil
}

// TODO
// LoadPreShareKeys 从json文件中加载PSK
func LoadPreShareKeys(path string) map[string][]byte {
	return nil
}
