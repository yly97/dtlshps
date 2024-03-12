package aqua

import (
	"bytes"
	"crypto/rand"

	"github.com/pion/dtls/v2"
	"github.com/pion/dtls/v2/pkg/crypto/prf"
	log "github.com/sirupsen/logrus"
	"github.com/yly97/dtlshps/pkg/ciphersuite"
	"github.com/yly97/dtlshps/pkg/layer"
)

// TODO 把Parse和Generate从Handle从分离出来，关键是解决消息的缓存问题
type flightGenerate func(*Conn, *handshakeConfig) ([]*layer.Record, error)

// 传入参数应该细分一下
type flightHandle func(*Conn, *handshakeConfig) (flightVal, []*layer.Record, error)

// flight0
func flight0Generate(c *Conn, cfg *handshakeConfig) ([]*layer.Record, error) {
	return nil, nil
}

func flight0Handle(c *Conn, cfg *handshakeConfig) (flightVal, []*layer.Record, error) {
	seq, msgs, ok := c.clientCache.fullPullMap(0,
		handshakeCachePullRule{layer.TypeClientHello, true, false},
	)
	if !ok {
		return 0, nil, nil
	}
	c.state.clientRecvMessageSequence = seq

	var records []*layer.Record

	// ClientHello
	var clientHello *layer.MessageClientHello
	if clientHello, ok = msgs[layer.TypeClientHello].(*layer.MessageClientHello); !ok {
		return 0, nil, errUnexpectedType
	}
	c.state.clientRandom = clientHello.Random[:] // client端随机数

	// 生成 HelloVerifyRequest消息
	c.state.cookie = make([]byte, cookieLength)
	if _, err := rand.Read(c.state.cookie); err != nil {
		return 0, nil, err
	}
	helloVerify := &layer.MessageHelloVerifyRequest{
		Version: layer.Version1_2,
		Cookie:  c.state.cookie,
	}
	records = append(records, newHandshakeRecord(helloVerify, layer.Version1_2, 0))

	return flight2, records, nil // 跳转到flight2
}

// flight1
func flight1Generate(c *Conn, cfg *handshakeConfig) ([]*layer.Record, error) {
	return nil, nil
}

func flight1Handle(c *Conn, cfg *handshakeConfig) (flightVal, []*layer.Record, error) {
	seq, msgs, ok := c.serverCache.fullPullMap(0,
		handshakeCachePullRule{layer.TypeHelloVerifyRequest, false, false})
	if !ok {
		return 0, nil, nil
	}
	c.state.serverRecvMessageSequence = seq

	var records []*layer.Record

	// HelloVerifyRequest
	var helloVerify *layer.MessageHelloVerifyRequest
	if helloVerify, ok = msgs[layer.TypeHelloVerifyRequest].(*layer.MessageHelloVerifyRequest); !ok {
		return 0, nil, errUnexpectedType
	}

	records = append(records, newHandshakeRecord(helloVerify, layer.Version1_2, 0))

	return flight2, records, nil
}

// flight2
func flight2Generate(c *Conn, cfg *handshakeConfig) ([]*layer.Record, error) {
	var records []*layer.Record
	helloVerify := &layer.MessageHelloVerifyRequest{
		Version: layer.Version1_2,
		Cookie:  c.state.cookie,
	}
	records = append(records, newHandshakeRecord(helloVerify, layer.Version1_2, 0))
	return nil, nil
}

func flight2Handle(c *Conn, cfg *handshakeConfig) (flightVal, []*layer.Record, error) {
	seq, msgs, ok := c.clientCache.fullPullMap(c.state.clientRecvMessageSequence,
		handshakeCachePullRule{layer.TypeClientHello, true, false},
	)
	if !ok {
		return 0, nil, nil
	}
	c.state.clientRecvMessageSequence = seq

	var records []*layer.Record

	// ClientHello 需要验证cookie
	var clientHello *layer.MessageClientHello
	if clientHello, ok = msgs[layer.TypeClientHello].(*layer.MessageClientHello); !ok {
		return 0, nil, errUnexpectedType
	}
	records = append(records, newHandshakeRecord(clientHello, layer.Version1_2, 0))
	if !bytes.Equal(c.state.cookie, clientHello.Cookie) {
		alert := &layer.Alert{Level: layer.Fatal, Description: layer.AccessDenied}
		return 0, []*layer.Record{newAlertRecord(alert, layer.Version1_2, 0)}, wrapAlertError(alert, errCookieMismatch)
	}

	// KeyExchange 生成32位的随机数作为客户端服务端的preMasterSecret
	c.state.preMasterSecret = make([]byte, 32)
	rand.Read(c.state.preMasterSecret)
	keyExchange := &layer.MessageKeyExchange{
		PreMasterSecret: c.state.preMasterSecret,
	}
	log.Tracef("generate preMasterSecret: %#v", c.state.preMasterSecret)
	records = append(records, newHandshakeRecord(keyExchange, layer.Version1_2, 0))

	return flight3, records, nil
}

// flight3
func flight3Generate(c *Conn, cfg *handshakeConfig) ([]*layer.Record, error) {
	return nil, nil
}

func flight3Handle(c *Conn, cfg *handshakeConfig) (flightVal, []*layer.Record, error) {
	seq, msgs, ok := c.serverCache.fullPullMap(c.state.serverRecvMessageSequence,
		handshakeCachePullRule{layer.TypeServerHello, false, false},
		handshakeCachePullRule{layer.TypeCertificate, false, true},
		handshakeCachePullRule{layer.TypeCertificateRequest, false, true},
		handshakeCachePullRule{layer.TypeServerHelloDone, false, false},
	)
	if !ok {
		return 0, nil, nil
	}
	c.state.serverRecvMessageSequence = seq

	var records []*layer.Record

	// ServerHello
	var serverHello *layer.MessageServerHello
	if serverHello, ok = msgs[layer.TypeServerHello].(*layer.MessageServerHello); !ok {
		return 0, nil, errUnexpectedType
	}
	records = append(records, newHandshakeRecord(serverHello, layer.Version1_2, 0))
	c.state.serverRandom = serverHello.Random[:] // server端随机数

	// TODO 根据client和server端的随机数以及控制器生成的preMasterSecret生成主密钥，
	// 因为加密解密对应的读写偏移量不同（目前对密码学相关的东西还不是很了解），所以client端和server端要分别生成，一个用来解密client加密的finished消息，
	// 另一个用来加密finished消息后发送向server端，这样做是因为finished消息的MessageSequence发生了变化
	c.state.clientCipherSuite = &ciphersuite.TLSEcdheEcdsaWithAes128GcmSha256{}
	c.state.serverCipherSuite = &ciphersuite.TLSEcdheEcdsaWithAes128GcmSha256{}
	if !c.state.serverCipherSuite.IsInitialized() {
		clientRandom := c.state.clientRandom
		serverRandom := c.state.serverRandom

		var err error
		c.state.masterSecret, err = prf.MasterSecret(c.state.preMasterSecret, clientRandom[:], serverRandom[:], c.state.serverCipherSuite.HashFunc())
		if err != nil {
			return 0, nil, err
		}

		if err := c.state.serverCipherSuite.Init(c.state.masterSecret, clientRandom[:], serverRandom[:], false); err != nil {
			return 0, nil, err
		}
		if err := c.state.clientCipherSuite.Init(c.state.masterSecret, clientRandom[:], serverRandom[:], true); err != nil {
			return 0, nil, err
		}
	}

	// TODO CertificateRequest消息中的signature和hash算法可以由控制器设置
	// CertificateRequest(optional) 收到这个消息说明server端要求验证client端的证书和verify消息
	var certReq *layer.MessageCertificateRequest
	if certReq, ok = msgs[layer.TypeCertificateRequest].(*layer.MessageCertificateRequest); ok {
		c.state.serverRequestedCertificate = true
		records = append(records, newHandshakeRecord(certReq, layer.Version1_2, 0))
	}

	// Certificate(optional) 根据选择的密码套件类型判断是否需要证书，验证通过后发送Identity消息，
	// 如果不需要验证证书则发送空的identity消息
	identity := &layer.MessageIdentity{}
	if cert, ok := msgs[layer.TypeCertificate].(*layer.MessageCertificate); ok {
		c.state.serverCertificates = cert.Certificate

		certs, err := loadCertificates(cert.Certificate)
		if err != nil {
			alert := &layer.Alert{Level: layer.Fatal, Description: layer.BadCertificate}
			return 0, []*layer.Record{newAlertRecord(alert, layer.Version1_2, 0)}, wrapAlertError(alert, err)
		}
		if _, err := verifyServerCert(certs, cfg.rootCAs); err != nil {
			// 验证未通过返回Alert消息以及Alert错误
			alert := &layer.Alert{Level: layer.Fatal, Description: layer.BadCertificate}
			return 0, []*layer.Record{newAlertRecord(alert, layer.Version1_2, 0)}, wrapAlertError(alert, err)
		}

		log.Trace("server certificate is valid")
		identity.Info = append([]byte{}, certs[0].RawSubject...)
	} else if c.state.clientCipherSuite.AuthenticationType() == dtls.CipherSuiteAuthenticationTypeCertificate {
		alert := &layer.Alert{Level: layer.Fatal, Description: layer.NoCertificate}
		return 0, []*layer.Record{newAlertRecord(alert, layer.Version1_2, 0)}, wrapAlertError(alert, errNoCertificate)
	}
	records = append(records, newHandshakeRecord(identity, layer.Version1_2, 0))

	// KeyExchange
	keyExchange := &layer.MessageKeyExchange{
		PreMasterSecret: c.state.preMasterSecret,
	}
	records = append(records, newHandshakeRecord(keyExchange, layer.Version1_2, 0))

	// ServerHelloDone
	var serverHelloDone *layer.MessageServerHelloDone
	if serverHelloDone, ok = msgs[layer.TypeServerHelloDone].(*layer.MessageServerHelloDone); !ok {
		return 0, nil, errUnexpectedType
	}
	records = append(records, newHandshakeRecord(serverHelloDone, layer.Version1_2, 0))

	return flight4, records, nil
}

// flight4
func flight4Generate(c *Conn, cfg *handshakeConfig) ([]*layer.Record, error) {
	return nil, nil
}

func flight4Handle(c *Conn, cfg *handshakeConfig) (flightVal, []*layer.Record, error) {
	seq, msgs, ok := c.clientCache.fullPullMap(c.state.clientRecvMessageSequence,
		handshakeCachePullRule{layer.TypeCertificate, true, true},
		handshakeCachePullRule{layer.TypeCertificateVerify, true, true},
		handshakeCachePullRule{layer.TypeFinished, true, false},
	)
	if !ok {
		return 0, nil, nil
	}
	c.state.clientRecvMessageSequence = seq

	var records []*layer.Record

	// Certificate
	if cert, ok := msgs[layer.TypeCertificate].(*layer.MessageCertificate); ok {
		c.state.clientCertificates = cert.Certificate
	} else if c.state.serverRequestedCertificate {
		alert := &layer.Alert{Level: layer.Fatal, Description: layer.NoCertificate}
		return 0, []*layer.Record{newAlertRecord(alert, layer.Version1_2, 0)}, wrapAlertError(alert, errNoCertificate)
	}

	// CertificateVerify 如果要求验证证书，且证书和Verify消息都验证通过，则将证书中的Subject作为Identity消息发送给server，
	// 如果不需要验证证书则发送空的Identity消息，否则向双方发送Alert消息
	identity := &layer.MessageIdentity{}
	if certVeify, ok := msgs[layer.TypeCertificateVerify].(*layer.MessageCertificateVerify); ok {
		if c.state.clientCertificates == nil {
			alert := &layer.Alert{Level: layer.Fatal, Description: layer.NoCertificate}
			return 0, []*layer.Record{newAlertRecord(alert, layer.Version1_2, 0)}, wrapAlertError(alert, errNoCertificate)
		}

		// 验证client证书
		certs, err := loadCertificates(c.state.clientCertificates)
		if err != nil {
			alert := &layer.Alert{Level: layer.Fatal, Description: layer.BadCertificate}
			return 0, []*layer.Record{newAlertRecord(alert, layer.Version1_2, 0)}, wrapAlertError(alert, err)
		}
		if _, err := verifyClientCert(certs, cfg.rootCAs); err != nil {
			alert := &layer.Alert{Level: layer.Fatal, Description: layer.BadCertificate}
			return 0, []*layer.Record{newAlertRecord(alert, layer.Version1_2, 0)}, wrapAlertError(alert, err)
		}

		// 验证CertificateVerify消息
		plainText := c.clientCache.pullAndMerge(
			handshakeCachePullRule{layer.TypeClientHello, true, false},
			handshakeCachePullRule{layer.TypeServerHello, false, false},
			handshakeCachePullRule{layer.TypeCertificateRequest, false, false},
			handshakeCachePullRule{layer.TypeIdentity, false, false},
			handshakeCachePullRule{layer.TypeKeyExchange, false, false},
			handshakeCachePullRule{layer.TypeServerHelloDone, false, false},
			handshakeCachePullRule{layer.TypeCertificate, true, false},
		)
		if err := verifyCertificateVerify(plainText, certVeify.HashAlgorithm, certVeify.Signature, c.state.clientCertificates); err != nil {
			alert := &layer.Alert{Level: layer.Fatal, Description: layer.BadCertificate}
			return 0, []*layer.Record{newAlertRecord(alert, layer.Version1_2, 0)}, wrapAlertError(alert, err)
		}
		log.Trace("client certificate and verify message is valid")
		identity.Info = append([]byte{}, certs[0].RawSubject...)
	} else if c.state.clientCertificates != nil {
		return 0, nil, nil
	}
	records = append(records, newHandshakeRecord(identity, layer.Version1_2, 0))

	// ChangeCipherSpec
	records = append(records, newChangeCipherSpecRecord(layer.Version1_2))

	// 生成发送给server端的Finished消息
	plainText := c.serverCache.pullAndMerge(
		handshakeCachePullRule{layer.TypeClientHello, true, false},
		handshakeCachePullRule{layer.TypeKeyExchange, true, false},
		handshakeCachePullRule{layer.TypeServerHello, false, false},
		handshakeCachePullRule{layer.TypeCertificate, false, false},
		handshakeCachePullRule{layer.TypeCertificateRequest, false, false},
		handshakeCachePullRule{layer.TypeServerHelloDone, false, false},
		// handshakeCachePullRule{air.TypeIdentity, true, false},
	)
	verifyData, err := prf.VerifyDataClient(c.state.masterSecret, plainText, c.state.clientCipherSuite.HashFunc())
	if err != nil {
		return 0, nil, err
	}
	finished := &layer.MessageFinished{
		VerifyData: verifyData,
	}
	records = append(records, newHandshakeRecord(finished, layer.Version1_2, 1))

	return flight5, records, nil
}

// flight5
func flight5Generate(c *Conn, cfg *handshakeConfig) ([]*layer.Record, error) {
	return nil, nil
}

func flight5Handle(c *Conn, cfg *handshakeConfig) (flightVal, []*layer.Record, error) {
	seq, _, ok := c.serverCache.fullPullMap(c.state.serverRecvMessageSequence,
		handshakeCachePullRule{layer.TypeFinished, false, false},
	)
	if !ok {
		return 0, nil, nil
	}
	c.state.serverRecvMessageSequence = seq

	var records []*layer.Record

	records = append(records, newChangeCipherSpecRecord(layer.Version1_2))

	// 生成发送个client端的Finished消息
	plainText := c.clientCache.pullAndMerge(
		handshakeCachePullRule{layer.TypeClientHello, true, false},
		handshakeCachePullRule{layer.TypeServerHello, false, false},
		handshakeCachePullRule{layer.TypeCertificateRequest, false, false},
		handshakeCachePullRule{layer.TypeIdentity, false, false},
		handshakeCachePullRule{layer.TypeKeyExchange, false, false},
		handshakeCachePullRule{layer.TypeServerHelloDone, false, false},
		handshakeCachePullRule{layer.TypeCertificate, true, false},
		handshakeCachePullRule{layer.TypeCertificateVerify, true, false},
		handshakeCachePullRule{layer.TypeFinished, true, false},
	)
	verifyData, err := prf.VerifyDataServer(c.state.masterSecret, plainText, c.state.serverCipherSuite.HashFunc())
	if err != nil {
		return 0, nil, err
	}
	finished := &layer.MessageFinished{
		VerifyData: verifyData,
	}
	records = append(records, newHandshakeRecord(finished, layer.Version1_2, 1))

	return flight6, records, nil
}

// flight6
func flight6Generate(c *Conn, cfg *handshakeConfig) ([]*layer.Record, error) {
	return nil, nil
}

func flight6Handle(c *Conn, cfg *handshakeConfig) (flightVal, []*layer.Record, error) {
	return flight6, nil, nil
}

func newHandshakeRecord(msg layer.Message, version layer.DTLSVersion, epoch uint16) *layer.Record {
	return &layer.Record{
		Header: layer.RecordHeader{
			Version: version,
			Epoch:   epoch,
		},
		Content: &layer.Handshake{
			Message: msg,
		},
	}
}

func newChangeCipherSpecRecord(version layer.DTLSVersion) *layer.Record {
	return &layer.Record{
		Header: layer.RecordHeader{
			Version: version,
		},
		Content: &layer.ChangeCipherSpec{},
	}
}

func newAlertRecord(alert *layer.Alert, version layer.DTLSVersion, epoch uint16) *layer.Record {
	return &layer.Record{
		Header: layer.RecordHeader{
			Version: version,
			Epoch:   epoch,
		},
		Content: alert,
	}
}

func dispalyRecords(records []*layer.Record) {
	for _, r := range records {
		data, err := r.Marshal()
		if err != nil {
			log.Fatal(err)
		}
		log.Infof("%#v", data)
	}
}
