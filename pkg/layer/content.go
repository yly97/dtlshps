package layer

type DTLSType uint8

const (
	DTLSTypeChangeCipherSpec DTLSType = 20
	DTLSTypeAlert            DTLSType = 21
	DTLSTypeHandshake        DTLSType = 22
)

func (d DTLSType) String() string {
	switch d {
	case DTLSTypeChangeCipherSpec:
		return "ChangeCipherSpec"
	case DTLSTypeAlert:
		return "Alert"
	case DTLSTypeHandshake:
		return "Handshake"
	default:
		return "Uknown"
	}
}

type Content interface {
	DTLSType() DTLSType
	Marshal() ([]byte, error)
	Unmarshal([]byte) error
}
