// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package aqua

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"math/big"
	"time"

	"github.com/pion/dtls/v2/pkg/crypto/hash"
)

type ecdsaSignature struct {
	R, S *big.Int
}

func verifyCertificateVerify(plainText []byte, hashAlgorithm hash.Algorithm, signature []byte, rawCertificates [][]byte) error {
	if len(rawCertificates) == 0 {
		return errNoCertificate
	}

	cert, err := x509.ParseCertificate(rawCertificates[0])
	if err != nil {
		return err
	}

	switch p := cert.PublicKey.(type) {
	case ed25519.PublicKey:
		if ok := ed25519.Verify(p, plainText, signature); !ok {
			return errSignatureMismatch
		}
		return nil
	case *ecdsa.PublicKey:
		ecdsaSig := &ecdsaSignature{}
		if _, err := asn1.Unmarshal(signature, ecdsaSig); err != nil {
			return err
		}
		if ecdsaSig.R.Sign() <= 0 || ecdsaSig.S.Sign() <= 0 {
			return errSignatureMismatch
		}
		hash := hashAlgorithm.Digest(plainText)
		if !ecdsa.Verify(p, hash, ecdsaSig.R, ecdsaSig.S) {
			return errSignatureMismatch
		}
		return nil
	case *rsa.PublicKey:
		switch cert.SignatureAlgorithm {
		case x509.SHA1WithRSA, x509.SHA256WithRSA, x509.SHA384WithRSA, x509.SHA512WithRSA:
			hash := hashAlgorithm.Digest(plainText)
			return rsa.VerifyPKCS1v15(p, hashAlgorithm.CryptoHash(), hash, signature)
		default:
			return errUnsupportSignAlgorithm
		}
	}

	return errUnsupportSignAlgorithm
}

// loadCertificates 将byte切片表示的certificates转换为x509.Certificate对象切片
func loadCertificates(rawCertificates [][]byte) ([]*x509.Certificate, error) {
	if len(rawCertificates) == 0 {
		return nil, errNoCertificate
	}

	certs := make([]*x509.Certificate, 0, len(rawCertificates))
	for _, rawCert := range rawCertificates {
		cert, err := x509.ParseCertificate(rawCert)
		if err != nil {
			return nil, err
		}
		certs = append(certs, cert)
	}
	return certs, nil
}

func verifyClientCert(certs []*x509.Certificate, roots *x509.CertPool) (chains [][]*x509.Certificate, err error) {
	intermediateCAPool := x509.NewCertPool()
	for _, cert := range certs[1:] {
		intermediateCAPool.AddCert(cert)
	}
	opts := x509.VerifyOptions{
		Roots:         roots,
		CurrentTime:   time.Now(),
		Intermediates: intermediateCAPool,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	return certs[0].Verify(opts)
}

// verifyServerCert 传入服务端证书链以及根证书，验证服务端证书并返回完整的证书链
func verifyServerCert(certs []*x509.Certificate, roots *x509.CertPool) (chains [][]*x509.Certificate, err error) {
	intermediateCAPool := x509.NewCertPool()
	for _, cert := range certs[1:] {
		intermediateCAPool.AddCert(cert)
	}
	opts := x509.VerifyOptions{
		Roots:         roots,
		CurrentTime:   time.Now(),
		Intermediates: intermediateCAPool,
	}
	return certs[0].Verify(opts)
}
