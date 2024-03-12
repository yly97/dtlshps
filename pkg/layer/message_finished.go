package layer

type MessageFinished struct {
	VerifyData []byte
}

func (m *MessageFinished) Marshal() ([]byte, error) {
	return append([]byte{}, m.VerifyData...), nil
}

func (m *MessageFinished) Unmarshal(data []byte) error {
	m.VerifyData = append(m.VerifyData, data...)
	return nil
}

func (m *MessageFinished) MessageType() MessageType {
	return TypeFinished
}
