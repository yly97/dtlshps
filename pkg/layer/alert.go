package layer

type Level byte

const (
	Warning Level = 1
	Fatal   Level = 2
)

func (l Level) String() string {
	switch l {
	case Warning:
		return "Warning"
	case Fatal:
		return "Fatal"
	default:
		return "Invalid Alert Level"
	}
}

type Description byte

const (
	CloseNotify            Description = 0
	UnexpectedMessage      Description = 10
	BadRecordMac           Description = 20
	DecryptionFailed       Description = 21
	RecordOverflow         Description = 22
	DecompressionFailure   Description = 30
	HandshakeFailure       Description = 40
	NoCertificate          Description = 41
	BadCertificate         Description = 42
	UnsupportedCertificate Description = 43
	CertificateRevoked     Description = 44
	CertificateExpired     Description = 45
	CertificateUnknown     Description = 46
	IllegalParameter       Description = 47
	UnknownCA              Description = 48
	AccessDenied           Description = 49
	DecodeError            Description = 50
	DecryptError           Description = 51
	ExportRestriction      Description = 60
	ProtocolVersion        Description = 70
	InsufficientSecurity   Description = 71
	InternalError          Description = 80
	UserCanceled           Description = 90
	NoRenegotiation        Description = 100
	UnsupportedExtension   Description = 110
	NoApplicationProtocol  Description = 120
	AuthenticationFailure  Description = 121
)

func (d Description) String() string {
	switch d {
	case CloseNotify:
		return "CloseNotify"
	case UnexpectedMessage:
		return "UnexpectedMessage"
	case BadRecordMac:
		return "BadRecordMac"
	case DecryptionFailed:
		return "DecryptionFailed"
	case RecordOverflow:
		return "RecordOverflow"
	case DecompressionFailure:
		return "DecompressionFailure"
	case HandshakeFailure:
		return "HandshakeFailure"
	case NoCertificate:
		return "NoCertificate"
	case BadCertificate:
		return "BadCertificate"
	case UnsupportedCertificate:
		return "UnsupportedCertificate"
	case CertificateRevoked:
		return "CertificateRevoked"
	case CertificateExpired:
		return "CertificateExpired"
	case CertificateUnknown:
		return "CertificateUnknown"
	case IllegalParameter:
		return "IllegalParameter"
	case UnknownCA:
		return "UnknownCA"
	case AccessDenied:
		return "AccessDenied"
	case DecodeError:
		return "DecodeError"
	case DecryptError:
		return "DecryptError"
	case ExportRestriction:
		return "ExportRestriction"
	case ProtocolVersion:
		return "ProtocolVersion"
	case InsufficientSecurity:
		return "InsufficientSecurity"
	case InternalError:
		return "InternalError"
	case UserCanceled:
		return "UserCanceled"
	case NoRenegotiation:
		return "NoRenegotiation"
	case UnsupportedExtension:
		return "UnsupportedExtension"
	case NoApplicationProtocol:
		return "NoApplicationProtocol"
	default:
		return "Invalid alert description"
	}
}

type Alert struct {
	Level       Level
	Description Description
}

func (a *Alert) Marshal() ([]byte, error) {
	return []byte{byte(a.Level), byte(a.Description)}, nil
}

func (a *Alert) Unmarshal(data []byte) error {
	if len(data) < 2 {
		return errBufferTooSmall
	}

	a.Level = Level(data[0])
	a.Description = Description(data[1])

	return nil
}

func (a *Alert) DTLSType() DTLSType {
	return DTLSTypeAlert
}
