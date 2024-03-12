package layer

import (
	"encoding/binary"

	"github.com/yly97/dtlshps/pkg/util"
)

const HandshakeHeaderSize = 12

// HandshakeHeader
type HandshakeHeader struct {
	MessageType     MessageType
	MessageLength   uint32 // uint24
	MessageSequence uint16
	FragmentOffset  uint32 // uint24
	FragmentLength  uint32 // uint24
}

func (h *HandshakeHeader) Marshal() ([]byte, error) {
	out := make([]byte, HandshakeHeaderSize)
	out[0] = byte(h.MessageType)
	util.BigEndian.PutUint24(out[1:], h.MessageLength)
	binary.BigEndian.PutUint16(out[4:], h.MessageSequence)
	util.BigEndian.PutUint24(out[6:], h.FragmentOffset)
	util.BigEndian.PutUint24(out[9:], h.FragmentLength)

	return out, nil
}

func (h *HandshakeHeader) Unmarshal(data []byte) error {
	if len(data) < HandshakeHeaderSize {
		return errBufferTooSmall
	}

	h.MessageType = MessageType(data[0])
	h.MessageLength = util.BigEndian.Uint24(data[1:])
	h.MessageSequence = binary.BigEndian.Uint16(data[4:])
	h.FragmentOffset = util.BigEndian.Uint24(data[6:])
	h.FragmentLength = util.BigEndian.Uint24(data[9:])

	return nil
}

// Handshake
type Handshake struct {
	Header  HandshakeHeader
	Message Message
}

func (h *Handshake) Marshal() ([]byte, error) {
	if h.Message == nil {
		return nil, errHandshakeMessageUnset
	} else if h.Header.FragmentOffset != 0 {
		return nil, errUnableToMarshalFragmented
	}

	message, err := h.Message.Marshal()
	if err != nil {
		return nil, err
	}

	// messageSequeuce在状态机的send中设置
	h.Header.MessageType = h.Message.MessageType()
	h.Header.MessageLength = uint32(len(message))
	h.Header.FragmentLength = h.Header.MessageLength
	header, err := h.Header.Marshal()
	if err != nil {
		return nil, err
	}
	return append(header, message...), nil
}

func (h *Handshake) Unmarshal(data []byte) error {
	if err := h.Header.Unmarshal(data); err != nil {
		return err
	}

	reportedLen := util.BigEndian.Uint24(data[1:])
	if uint32(len(data)-HandshakeHeaderSize) != reportedLen {
		return errLengthMismatch
	} else if reportedLen != h.Header.FragmentLength {
		return errLengthMismatch
	}

	switch h.Header.MessageType {
	case TypeClientHello:
		h.Message = &MessageClientHello{}
	case TypeServerHello:
		h.Message = &MessageServerHello{}
	case TypeHelloVerifyRequest:
		h.Message = &MessageHelloVerifyRequest{}
	case TypeCertificate:
		h.Message = &MessageCertificate{}
	case TypeCertificateRequest:
		h.Message = &MessageCertificateRequest{}
	case TypeServerHelloDone:
		h.Message = &MessageServerHelloDone{}
	case TypeCertificateVerify:
		h.Message = &MessageCertificateVerify{}
	case TypeFinished:
		h.Message = &MessageFinished{}
	case TypeKeyExchange:
		h.Message = &MessageKeyExchange{}
	case TypeIdentity:
		h.Message = &MessageIdentity{}
	default:
		return errInvalidHandshakeType
	}

	return h.Message.Unmarshal(data[HandshakeHeaderSize:])
}

func (h *Handshake) DTLSType() DTLSType {
	return DTLSTypeHandshake
}
