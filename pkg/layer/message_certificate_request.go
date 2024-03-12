package layer

import (
	"encoding/binary"

	"github.com/pion/dtls/v2/pkg/crypto/clientcertificate"
	"github.com/pion/dtls/v2/pkg/crypto/hash"
	"github.com/pion/dtls/v2/pkg/crypto/signature"
	"github.com/pion/dtls/v2/pkg/crypto/signaturehash"
)

type MessageCertificateRequest struct {
	CertificateTypes            []clientcertificate.Type
	SignatureHashAlgorithms     []signaturehash.Algorithm
	CertificateAuthoritiesNames [][]byte
}

func (m *MessageCertificateRequest) Marshal() ([]byte, error) {
	out := []byte{byte(len(m.CertificateTypes))}
	for _, v := range m.CertificateTypes {
		out = append(out, byte(v))
	}

	out = binary.BigEndian.AppendUint16(out, uint16(len(m.SignatureHashAlgorithms)<<1))
	for _, v := range m.SignatureHashAlgorithms {
		out = append(out, byte(v.Hash), byte(v.Signature))
	}

	casLength := 0
	for _, ca := range m.CertificateAuthoritiesNames {
		casLength += len(ca) + 2
	}
	out = binary.BigEndian.AppendUint16(out, uint16(casLength))
	for _, ca := range m.CertificateAuthoritiesNames {
		out = binary.BigEndian.AppendUint16(out, uint16(len(ca)))
		out = append(out, ca...)
	}

	return out, nil
}

func (m *MessageCertificateRequest) Unmarshal(data []byte) error {
	if len(data) < 5 {
		return errBufferTooSmall
	}

	// CertificateTypes
	offset := 0
	n := int(data[0])
	offset++
	if len(data) < offset+n+2 {
		return errBufferTooSmall
	}
	for i := 0; i < n; i++ {
		certType := clientcertificate.Type(data[offset+i])
		if _, ok := clientcertificate.Types()[certType]; ok {
			m.CertificateTypes = append(m.CertificateTypes, certType)
		}
	}
	offset += n

	// SignatureHashAlgorithms
	n = int(binary.BigEndian.Uint16(data[offset:]))
	offset += 2
	if len(data) < offset+n+2 {
		return errBufferTooSmall
	}
	for i := offset; i < offset+n; i += 2 {
		h := hash.Algorithm(data[i]) // 怎么是uint16？
		s := signature.Algorithm(data[i+1])
		if _, ok := hash.Algorithms()[h]; !ok {
			continue
		} else if _, ok := signature.Algorithms()[s]; !ok {
			continue
		}
		m.SignatureHashAlgorithms = append(m.SignatureHashAlgorithms, signaturehash.Algorithm{Signature: s, Hash: h})
	}

	// CA Names
	offset += n
	n = int(binary.BigEndian.Uint16(data[offset:]))
	offset += 2
	if len(data) < offset+n {
		return errBufferTooSmall
	}
	cas := make([]byte, n)
	copy(cas, data[offset:offset+n])
	m.CertificateAuthoritiesNames = nil
	for len(cas) > 0 {
		if len(cas) < 2 {
			return errBufferTooSmall
		}
		caLen := binary.BigEndian.Uint16(cas)
		cas = cas[2:]
		if len(cas) < int(caLen) {
			return errBufferTooSmall
		}
		m.CertificateAuthoritiesNames = append(m.CertificateAuthoritiesNames, cas[:caLen])
		cas = cas[caLen:]
	}

	return nil
}

func (m *MessageCertificateRequest) MessageType() MessageType {
	return TypeCertificateRequest
}
