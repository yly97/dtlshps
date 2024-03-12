package layer

import (
	"encoding/binary"

	"github.com/yly97/dtlshps/pkg/util"
)

const (
	RecordHeaderSize  = 13
	MaxSequenceNumber = 0x0000FFFFFFFFFFFF
)

// RecordHeader
type RecordHeader struct {
	ContentType    DTLSType    // uint8
	Version        DTLSVersion // uint16
	Epoch          uint16
	SequenceNumber uint64 // uint48
	ContentLength  uint16
}

func (r *RecordHeader) Marshal() ([]byte, error) {
	if r.SequenceNumber > MaxSequenceNumber {
		return nil, errSequenceNumberOverflow
	}

	out := make([]byte, RecordHeaderSize)
	out[0] = byte(r.ContentType)
	binary.BigEndian.PutUint16(out[1:], uint16(r.Version))
	binary.BigEndian.PutUint16(out[3:], r.Epoch)
	util.BigEndian.PutUint48(out[5:], r.SequenceNumber)
	binary.BigEndian.PutUint16(out[11:], r.ContentLength)

	return out, nil
}

func (r *RecordHeader) Unmarshal(data []byte) error {
	if len(data) < RecordHeaderSize {
		return errBufferTooSmall
	}

	r.ContentType = DTLSType(data[0])
	r.Version = DTLSVersion(binary.BigEndian.Uint16(data[1:]))
	if r.Version != Version1_0 && r.Version != Version1_2 {
		return errUnsupportedVersion
	}

	r.Epoch = binary.BigEndian.Uint16(data[3:])
	r.SequenceNumber = util.BigEndian.Uint48(data[5:])
	r.ContentLength = binary.BigEndian.Uint16(data[11:])

	return nil
}

// Record
type Record struct {
	Header  RecordHeader
	Content Content
}

func (r *Record) Marshal() ([]byte, error) {
	content, err := r.Content.Marshal()
	if err != nil {
		return nil, err
	}

	// header中的sequenceNumber在发送时设置
	r.Header.ContentType = r.Content.DTLSType()
	r.Header.ContentLength = uint16(len(content))

	header, err := r.Header.Marshal()
	if err != nil {
		return nil, err
	}

	return append(header, content...), nil
}

func (r *Record) Unmarshal(data []byte) error {
	if err := r.Header.Unmarshal(data); err != nil {
		return errBufferTooSmall
	}

	switch r.Header.ContentType {
	case DTLSTypeHandshake:
		r.Content = &Handshake{}
	case DTLSTypeChangeCipherSpec:
		r.Content = &ChangeCipherSpec{}
	case DTLSTypeAlert:
		r.Content = &Alert{}
	default:
		return errInvalidDTLSType
	}

	return r.Content.Unmarshal(data[RecordHeaderSize:])
}
