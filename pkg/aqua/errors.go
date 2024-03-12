package aqua

import (
	"errors"
	"fmt"

	"github.com/yly97/dtlshps/pkg/layer"
)

var (
	errInvalidPacket          = errors.New("invalid packet")
	errFragmentLengthMismatch = errors.New("fragment length not match")
	errUnexpectedType         = errors.New("unexpected type")
	errSequenceNumberOverflow = errors.New("sequence number overflow")
	errInvalidHandshakeState  = errors.New("Invalid handshake state")
	errBufferOverflow         = errors.New("packet buffer overflow")
	errNoCertificate          = errors.New("no certificate found")
	errUnsupportSignAlgorithm = errors.New("unsupport signature algorithm")
	errSignatureMismatch      = errors.New("signature mis match")
	errCookieMismatch         = errors.New("ClientHello cookie does not match")
)

type AlertError struct {
	msg string
	err error
}

func wrapAlertError(alert *layer.Alert, err error) *AlertError {
	return &AlertError{
		msg: fmt.Sprintf("Alert %s %s", alert.Level, alert.Description),
		err: err,
	}
}

func (e *AlertError) Error() string {
	return e.msg
}

func (e *AlertError) Unwrap() error {
	return e.err
}
