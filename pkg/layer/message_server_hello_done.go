package layer

type MessageServerHelloDone struct{}

func (s *MessageServerHelloDone) Marshal() ([]byte, error) {
	return []byte{}, nil
}

func (s *MessageServerHelloDone) Unmarshal(data []byte) error {
	return nil
}

func (s *MessageServerHelloDone) MessageType() MessageType {
	return TypeServerHelloDone
}
