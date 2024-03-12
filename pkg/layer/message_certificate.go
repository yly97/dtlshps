package layer

import (
	"github.com/yly97/dtlshps/pkg/util"
)

type MessageCertificate struct {
	Certificate [][]byte
}

const certificateLengthFieldSize = 3

func (m *MessageCertificate) Marshal() ([]byte, error) {
	out := make([]byte, certificateLengthFieldSize)

	for _, r := range m.Certificate {
		// Certificate Length
		out = util.BigEndian.AppendUint24(out, uint32(len(r)))

		// Certificate body
		out = append(out, r...)
	}

	// Total Payload Size
	util.BigEndian.PutUint24(out[0:3], uint32(len(out)-certificateLengthFieldSize))
	return out, nil
}

func (m *MessageCertificate) Unmarshal(data []byte) error {
	if len(data) < certificateLengthFieldSize {
		return errBufferTooSmall
	}
	if certificateBodyLen := int(util.BigEndian.Uint24(data)); certificateBodyLen+certificateLengthFieldSize != len(data) {
		return errLengthMismatch
	}

	offset := certificateLengthFieldSize
	for offset < len(data) {
		certificateLen := int(util.BigEndian.Uint24(data[offset:]))
		offset += certificateLengthFieldSize

		if offset+certificateLen > len(data) {
			return errLengthMismatch
		}

		m.Certificate = append(m.Certificate, append([]byte{}, data[offset:offset+certificateLen]...))
		offset += certificateLen
	}

	return nil
}

func (m *MessageCertificate) MessageType() MessageType {
	return TypeCertificate
}
