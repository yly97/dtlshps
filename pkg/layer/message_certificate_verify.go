package layer

import (
	"encoding/binary"

	"github.com/pion/dtls/v2/pkg/crypto/hash"
	"github.com/pion/dtls/v2/pkg/crypto/signature"
)

type MessageCertificateVerify struct {
	HashAlgorithm      hash.Algorithm
	SignatureAlgorithm signature.Algorithm
	Signature          []byte
}

func (m *MessageCertificateVerify) Marshal() ([]byte, error) {
	out := make([]byte, 4+len(m.Signature))
	out[0] = byte(m.HashAlgorithm)
	out[1] = byte(m.SignatureAlgorithm)
	binary.BigEndian.PutUint16(out[2:], uint16(len(m.Signature)))
	copy(out[4:], m.Signature)

	return out, nil
}

func (m *MessageCertificateVerify) Unmarshal(data []byte) error {
	if len(data) < 4 {
		return errBufferTooSmall
	}

	m.HashAlgorithm = hash.Algorithm(data[0])
	if _, ok := hash.Algorithms()[m.HashAlgorithm]; !ok {
		return errInvalidHashAlgorithm
	}

	m.SignatureAlgorithm = signature.Algorithm(data[1])
	if _, ok := signature.Algorithms()[m.SignatureAlgorithm]; !ok {
		return errInvalidSignatureAlgorithm
	}

	signatureLen := int(binary.BigEndian.Uint16(data[2:]))
	if len(data) < signatureLen+4 {
		return errBufferTooSmall
	}
	m.Signature = append([]byte{}, data[4:]...)

	return nil
}

func (m *MessageCertificateVerify) MessageType() MessageType {
	return TypeCertificateVerify
}
