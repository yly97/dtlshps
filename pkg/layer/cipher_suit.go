package layer

import "encoding/binary"

func decodeCipherSuiteIDs(buf []byte) ([]uint16, error) {
	if len(buf) < 2 {
		return nil, errBufferTooSmall
	}
	cipherSuitesLength := int(binary.BigEndian.Uint16(buf[0:]))
	if len(buf) < cipherSuitesLength+2 {
		return nil, errBufferTooSmall
	}

	cipherSuitesCount := cipherSuitesLength >> 1
	cipherSuites := make([]uint16, cipherSuitesCount)
	for i := 0; i < cipherSuitesCount; i++ {
		cipherSuites[i] = binary.BigEndian.Uint16(buf[(i<<1)+2:])
	}
	return cipherSuites, nil
}

func encodeCipherSuiteIDs(cipherSuites []uint16) []byte {
	out := make([]byte, 2)
	binary.BigEndian.PutUint16(out, uint16(len(cipherSuites)<<1))
	for _, id := range cipherSuites {
		out = binary.BigEndian.AppendUint16(out, id)
	}
	return out
}
