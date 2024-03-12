package layer

type MessageType uint8

const (
	TypeClientHello        MessageType = 1
	TypeServerHello        MessageType = 2
	TypeHelloVerifyRequest MessageType = 3
	TypeCertificate        MessageType = 11
	TypeCertificateRequest MessageType = 13
	TypeServerHelloDone    MessageType = 14
	TypeCertificateVerify  MessageType = 15
	TypeFinished           MessageType = 20
	TypeKeyExchange        MessageType = 31
	TypeIdentity           MessageType = 32
)

func (t MessageType) String() string {
	switch t {
	case TypeClientHello:
		return "ClientHello"
	case TypeServerHello:
		return "ServerHello"
	case TypeHelloVerifyRequest:
		return "HelloVerifyRequest"
	case TypeCertificate:
		return "TypeCertificate"
	case TypeCertificateRequest:
		return "CertificateRequest"
	case TypeServerHelloDone:
		return "ServerHelloDone"
	case TypeCertificateVerify:
		return "CertificateVerify"
	case TypeFinished:
		return "Finished"
	case TypeKeyExchange:
		return "KeyExchange"
	case TypeIdentity:
		return "Identity"
	default:
		return "Uknown"
	}
}

type Message interface {
	Marshal() ([]byte, error)
	Unmarshal([]byte) error
	MessageType() MessageType
}
