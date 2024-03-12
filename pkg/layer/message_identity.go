package layer

const identityFixedLength uint8 = 3

type MessageIdentity struct {
	Info []byte
}

func (m *MessageIdentity) Marshal() ([]byte, error) {
	return append([]byte{}, m.Info...), nil
}

func (m *MessageIdentity) Unmarshal(data []byte) error {
	m.Info = append(m.Info, data...)
	return nil
}

func (m *MessageIdentity) MessageType() MessageType {
	return TypeIdentity
}
