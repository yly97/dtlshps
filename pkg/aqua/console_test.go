package aqua

import (
	"testing"
)

func TestGetConn(t *testing.T) {
	cfg := &Config{}
	console := NewConsole(cfg)
	id1 := &ConnID{
		SrcIP:   []byte("abcd"),
		SrcPort: 4444,
		DstIP:   []byte("efgh"),
		DstPort: 12345,
	}

	id2 := &ConnID{
		SrcIP:   []byte("efgh"),
		SrcPort: 12345,
		DstIP:   []byte("abcd"),
		DstPort: 4444,
	}

	console.getConn(id1)
	if _, ok := console.getConn(id2); !ok {
		t.Error("reverse addr not exists!")
	}
}
