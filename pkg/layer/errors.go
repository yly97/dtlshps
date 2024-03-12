package layer

import "errors"

var (
	errSequenceNumberOverflow    = errors.New("sequence number overflow")
	errBufferTooSmall            = errors.New("buffer too small")
	errUnsupportedVersion        = errors.New("unsuported protocol version")
	errInvalidDTLSType           = errors.New("invalid DTLS type")
	errInvalidHandshakeType      = errors.New("invalid handshake type")
	errCookieTooLong             = errors.New("cookie too long")
	errLengthMismatch            = errors.New("length mismatch")
	errInvalidHashAlgorithm      = errors.New("invalid hash algorithm")
	errInvalidSignatureAlgorithm = errors.New("invalid signature algorithm")
	errInvalidCompressionMethod  = errors.New("invalid compression method")
	errHandshakeMessageUnset     = errors.New("handshake message unset")
	errUnableToMarshalFragmented = errors.New("unable to marshal fragmented")
)
