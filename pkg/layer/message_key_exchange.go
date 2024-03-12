package layer

const keyExchangeFixedLength uint8 = 3

type MessageKeyExchange struct {
	PreMasterSecret []byte
}

func (m *MessageKeyExchange) Marshal() ([]byte, error) {
	return append([]byte{}, m.PreMasterSecret...), nil
}

func (m *MessageKeyExchange) Unmarshal(data []byte) error {
	m.PreMasterSecret = append(m.PreMasterSecret, data...)
	return nil
}

func (m *MessageKeyExchange) MessageType() MessageType {
	return TypeKeyExchange
}
