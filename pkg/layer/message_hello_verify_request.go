package layer

import "encoding/binary"

type MessageHelloVerifyRequest struct {
	Version DTLSVersion
	Cookie  []byte
}

func (m *MessageHelloVerifyRequest) Marshal() ([]byte, error) {
	if len(m.Cookie) > 255 {
		return nil, errCookieTooLong
	}

	out := make([]byte, 3+len(m.Cookie))
	binary.BigEndian.PutUint16(out, uint16(m.Version))
	out[2] = byte(len(m.Cookie))
	copy(out[3:], m.Cookie)

	return out, nil
}

func (m *MessageHelloVerifyRequest) Unmarshal(data []byte) error {
	if len(data) < 3 {
		return errBufferTooSmall
	}

	cookieLength := int(data[2])
	if len(data) < 3+cookieLength {
		return errBufferTooSmall
	}
	m.Version = DTLSVersion(binary.BigEndian.Uint16(data))
	m.Cookie = append([]byte{}, data[3:]...)

	return nil
}

func (m *MessageHelloVerifyRequest) MessageType() MessageType {
	return TypeHelloVerifyRequest
}
