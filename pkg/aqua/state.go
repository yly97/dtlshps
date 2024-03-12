package aqua

import (
	"github.com/pion/dtls/v2"
	"github.com/pion/dtls/v2/pkg/crypto/elliptic"
)

// TODO 连接过程中通信双方的状态信息
type State struct {
	clientRandom, serverRandom []byte
	serverCipherSuite          dtls.CipherSuite // server端选择的密码套件，忽略密钥交换的部分
	clientCipherSuite          dtls.CipherSuite
	CipherSuiteID              dtls.CipherSuiteID

	preMasterSecret []byte
	masterSecret    []byte
	// extendedMasterSecret bool

	namedCurve   elliptic.Curve
	localKeypair *elliptic.Keypair
	cookie       []byte

	clientSendMessageSequence int // uint16
	clientRecvMessageSequence int
	serverSendMessageSequence int
	serverRecvMessageSequence int
	clientSequenceNumber      []uint64 // uint48 每一个epoch对应的序列号都从0开始单调递增
	serverSequenceNumber      []uint64
	clientCertificates        [][]byte
	serverCertificates        [][]byte

	serverRequestedCertificate bool   // 是否收到CertificateRequest
	localCertificatesVerify    []byte // cache CertificateVerify
	localVerifyData            []byte // cached VerifyData
	localKeySignature          []byte // cached keySignature
}
