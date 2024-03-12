package main

import (
	"bytes"
	"crypto/rand"
	"reflect"
	"testing"

	"github.com/pion/dtls/v2/pkg/crypto/prf"
	"github.com/pion/dtls/v2/pkg/protocol"
	"github.com/pion/dtls/v2/pkg/protocol/handshake"
	"github.com/pion/dtls/v2/pkg/protocol/recordlayer"
	log "github.com/sirupsen/logrus"
	"github.com/yly97/dtlshps/pkg/ciphersuite"
)

func TestCipherSuite(t *testing.T) {
	cCipherSuite := &ciphersuite.TLSEcdheEcdsaWithAes128GcmSha256{}
	preMasterSecret := []byte("1234567890qwertyuiopasdfghjklzxc")
	clientRandom := make([]byte, 32)
	rand.Read(clientRandom)
	serverRandom := make([]byte, 32)
	rand.Read(serverRandom)
	masterSecret, err := prf.MasterSecret(preMasterSecret, clientRandom, serverRandom, cCipherSuite.HashFunc())
	if err != nil {
		log.Fatal(err)
	}
	_ = cCipherSuite.Init(masterSecret, clientRandom, serverRandom, true)

	sCipherSuite := &ciphersuite.TLSEcdheEcdsaWithAes128GcmSha256{}
	_ = sCipherSuite.Init(masterSecret, clientRandom, serverRandom, false)

	c1CipherSuite := &ciphersuite.TLSEcdheEcdsaWithAes128GcmSha256{}
	_ = c1CipherSuite.Init(masterSecret, clientRandom, serverRandom, true)

	s1CipherSuite := &ciphersuite.TLSEcdheEcdsaWithAes128GcmSha256{}
	_ = s1CipherSuite.Init(masterSecret, clientRandom, serverRandom, false)

	rawClientHello := []byte{
		0xfe, 0xfd, 0xb6, 0x2f, 0xce, 0x5c, 0x42, 0x54, 0xff, 0x86, 0xe1, 0x24, 0x41, 0x91, 0x42,
		0x62, 0x15, 0xad, 0x16, 0xc9, 0x15, 0x8d, 0x95, 0x71, 0x8a, 0xbb, 0x22, 0xd7, 0x47, 0xec,
		0xd8, 0x3d, 0xdc, 0x4b, 0x20, 0xe0, 0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7, 0xe8, 0xe9,
		0xea, 0xeb, 0xec, 0xed, 0xee, 0xef, 0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8,
		0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff, 0x14, 0xe6, 0x14, 0x3a, 0x1b, 0x04, 0xea, 0x9e,
		0x7a, 0x14, 0xd6, 0x6c, 0x57, 0xd0, 0x0e, 0x32, 0x85, 0x76, 0x18, 0xde, 0xd8, 0x00, 0x04,
		0xc0, 0x2b, 0xc0, 0x0a, 0x01, 0x00, 0x00, 0x08, 0x00, 0x0a, 0x00, 0x04, 0x00, 0x02, 0x00,
		0x1d,
	}

	ch := &handshake.MessageClientHello{}
	ch.Unmarshal(rawClientHello)
	record := &recordlayer.RecordLayer{
		Header: recordlayer.Header{
			Version:     protocol.Version1_2,
			Epoch:       1,
			ContentType: protocol.ContentTypeHandshake,
		},
		Content: &handshake.Handshake{
			Message: ch,
		},
	}

	data, err := record.Marshal()
	if err != nil {
		log.Fatal(err)
	}

	encryptData, err := cCipherSuite.Encrypt(record, data)
	if err != nil {
		log.Fatal(err)
	}

	decryptData1, err := s1CipherSuite.Decrypt(encryptData)
	if err != nil {
		log.Fatal(err)
	}

	record.Header.SequenceNumber = 0
	encryptData1, err := c1CipherSuite.Encrypt(record, decryptData1)
	if err != nil {
		log.Fatal(err)
	}

	decryptData, err := sCipherSuite.Decrypt(encryptData1)
	if err != nil {
		log.Fatal(err)
	}

	if !bytes.Equal(rawClientHello, decryptData[25:]) {
		t.Errorf("decrypt: got %#v, want %#v", rawClientHello, decryptData[25:])
	}

	if !reflect.DeepEqual(rawClientHello, decryptData[25:]) {
		t.Errorf("decrypt: got %#v, want %#v", rawClientHello, decryptData[25:])
	}
}
