package layer

import (
	"encoding/binary"

	"github.com/pion/dtls/v2/pkg/protocol"
)

const serverHelloFixedSize = 34

type MessageServerHello struct {
	Version           DTLSVersion
	Random            [32]byte
	SessionID         []byte
	CipherSuite       uint16
	CompressionMethod protocol.CompressionMethod
	Extensions        []byte
}

func (m *MessageServerHello) Marshal() ([]byte, error) {
	out := make([]byte, serverHelloFixedSize)
	binary.BigEndian.PutUint16(out, uint16(m.Version))
	copy(out[2:], m.Random[:])
	out = append(out, byte(len(m.SessionID)))
	out = append(out, m.SessionID...)
	out = binary.BigEndian.AppendUint16(out, m.CipherSuite)
	out = append(out, byte(m.CompressionMethod.ID))
	out = binary.BigEndian.AppendUint16(out, uint16(len(m.Extensions))) // 暂不解码扩展
	out = append(out, m.Extensions...)

	return out, nil
}

// TODO 保证data正确才能调用
func (m *MessageServerHello) Unmarshal(data []byte) error {
	m.Version = DTLSVersion(binary.BigEndian.Uint16(data))
	copy(m.Random[:], data[2:])

	offset := serverHelloFixedSize
	n := int(data[offset])
	offset++
	m.SessionID = append([]byte{}, data[offset:offset+n]...)
	offset += n

	m.CipherSuite = binary.BigEndian.Uint16(data[offset:])
	offset += 2

	if compressionMethod, ok := protocol.CompressionMethods()[protocol.CompressionMethodID(data[offset])]; ok {
		m.CompressionMethod = *compressionMethod
		offset++
	} else {
		return errInvalidCompressionMethod
	}

	n = int(binary.BigEndian.Uint16(data[offset:]))
	offset += 2
	m.Extensions = append([]byte{}, data[offset:offset+n]...)

	return nil
}

func (m *MessageServerHello) MessageType() MessageType {
	return TypeServerHello
}
