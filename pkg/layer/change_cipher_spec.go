package layer

import "errors"

type ChangeCipherSpec struct{}

func (c *ChangeCipherSpec) Marshal() ([]byte, error) {
	return []byte{0x01}, nil
}

func (c *ChangeCipherSpec) Unmarshal(data []byte) error {
	if len(data) == 1 && data[0] == 0x01 {
		return nil
	}

	return errors.New("invalid change cipher spec")
}

func (c *ChangeCipherSpec) DTLSType() DTLSType {
	return DTLSTypeChangeCipherSpec
}
