package layer

import (
	"encoding/binary"

	"github.com/pion/dtls/v2/pkg/protocol"
)

const (
	clientHelloFixedSize = 34
	RandomLength         = 32
)

type MessageClientHello struct {
	Version            DTLSVersion
	Random             [32]byte
	Cookie             []byte
	SessionID          []byte
	CipherSuites       []uint16
	CompressionMethods []*protocol.CompressionMethod
	Extensions         []byte
}

func (m *MessageClientHello) Marshal() ([]byte, error) {
	out := make([]byte, clientHelloFixedSize)
	binary.BigEndian.PutUint16(out, uint16(m.Version))

	copy(out[2:], m.Random[:])
	out = append(out, byte(len(m.SessionID)))
	out = append(out, m.SessionID...)
	out = append(out, byte(len(m.Cookie)))
	out = append(out, m.Cookie...)
	out = append(out, encodeCipherSuiteIDs(m.CipherSuites)...)
	out = append(out, protocol.EncodeCompressionMethods(m.CompressionMethods)...)
	out = binary.BigEndian.AppendUint16(out, uint16(len(m.Extensions))) // 暂不解码扩展
	out = append(out, m.Extensions...)

	return out, nil
}

func (m *MessageClientHello) Unmarshal(data []byte) error {
	m.Version = DTLSVersion(binary.BigEndian.Uint16(data))
	copy(m.Random[:], data[2:])

	offset := clientHelloFixedSize

	// SessionID
	if len(data) < offset+1 {
		return errBufferTooSmall
	}
	n := int(data[offset])
	offset++
	if len(data) < offset+n {
		return errBufferTooSmall
	}
	m.SessionID = append([]byte{}, data[offset:offset+n]...) // 往nil切片append长度为0的切片还是nil
	offset += n

	// Cookie
	if len(data) < offset+1 {
		return errBufferTooSmall
	}
	n = int(data[offset])
	offset++
	if len(data) < offset+n {
		return errBufferTooSmall
	}
	m.Cookie = append([]byte{}, data[offset:offset+n]...)
	offset += n

	// CipherSuites
	cipherSuites, err := decodeCipherSuiteIDs(data[offset:])
	if err != nil {
		return err
	}
	m.CipherSuites = cipherSuites
	offset += int(binary.BigEndian.Uint16(data[offset:])) + 2

	// CompressionMethods
	compressionMethods, err := protocol.DecodeCompressionMethods(data[offset:])
	if err != nil {
		return err
	}
	m.CompressionMethods = compressionMethods
	offset += int(data[offset]) + 1

	// Extensions
	n = int(binary.BigEndian.Uint16(data[offset:]))
	offset += 2
	m.Extensions = append([]byte{}, data[offset:offset+n]...)

	return nil
}

func (m *MessageClientHello) MessageType() MessageType {
	return TypeClientHello
}
