package util

var BigEndian bigEndian

type bigEndian struct{}

func (bigEndian) Uint24(b []byte) uint32 {
	_ = b[2]
	return uint32(b[2]) | uint32(b[1])<<8 | uint32(b[0])<<16
}

func (bigEndian) PutUint24(b []byte, v uint32) {
	_ = b[2]
	b[0] = byte(v >> 16)
	b[1] = byte(v >> 8)
	b[2] = byte(v)
}

func (bigEndian) AppendUint24(b []byte, v uint32) []byte {
	return append(b,
		byte(v>>16),
		byte(v>>8),
		byte(v),
	)
}

func (bigEndian) Uint48(b []byte) uint64 {
	_ = b[5]
	return uint64(b[5]) | uint64(b[4])<<8 | uint64(b[3])<<16 | uint64(b[2])<<24 | uint64(b[1])<<32 | uint64(b[0])<<40
}

func (bigEndian) PutUint48(b []byte, v uint64) {
	_ = b[5]
	b[0] = byte(v >> 40)
	b[1] = byte(v >> 32)
	b[2] = byte(v >> 24)
	b[3] = byte(v >> 16)
	b[4] = byte(v >> 8)
	b[5] = byte(v)
}
