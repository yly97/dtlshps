package aqua

import (
	"context"
	"crypto/x509"
	"errors"
	"sync/atomic"
	"time"

	"github.com/pion/dtls/v2/pkg/protocol/recordlayer"
	log "github.com/sirupsen/logrus"
	"github.com/yly97/dtlshps/pkg/layer"
)

type handshakeState uint8

const (
	handshakeErrored handshakeState = iota
	handshakePreparing
	handshakeSending
	handshakeWaiting
	handshakeFinished
)

func (s handshakeState) String() string {
	switch s {
	case handshakeErrored:
		return "Errored"
	case handshakePreparing:
		return "Preparing"
	case handshakeSending:
		return "Sending"
	case handshakeWaiting:
		return "Waiting"
	case handshakeFinished:
		return "Finished"
	default:
		return "Unknown"
	}
}

type handshakeConfig struct {
	// serverName              string
	// insecureSkipVerify      bool
	// clientCAs               *x509.CertPool
	// ellipticCurves          []elliptic.Curve
	rootCAs                 *x509.CertPool // CA证书以及所有主机对应的PSK应该存放在一个公共的只在控制器启动时加载的结构体中
	insecureSkipHelloVerify bool
	retransmitInterval      time.Duration
	timewaitInterval        time.Duration // 握手结束后的等待时间
}

type handshakeFSM struct {
	currentFlight flightVal
	completed     atomic.Bool
	flight        *Packet // 缓存上一个传送的packet，重传时用到
	config        *handshakeConfig
}

// TODO currentFlight可配置
func newHandshakeFSM(config *handshakeConfig) *handshakeFSM {
	log.Debug("hanshakeFSM starts to work...")
	return &handshakeFSM{
		currentFlight: flight0,
		config:        config,
	}
}

func (m *handshakeFSM) run(ctx context.Context, conn *Conn) error {
	// 解析握手消息
	state := handshakeWaiting
	for {
		if m.completed.Load() == true {
			log.Debug("time wait exhausted, handshake FSM exit")
			return nil
		}
		log.Debugf("[handshake] %s: %s", m.currentFlight.String(), state.String())
		var err error
		switch state {
		case handshakePreparing:
			state, err = m.prepare(ctx, conn)
		case handshakeSending:
			state, err = m.send(ctx, conn)
		case handshakeWaiting:
			state, err = m.wait(ctx, conn)
		case handshakeFinished:
			state, err = m.finish(ctx, conn)
		default:
			return errInvalidHandshakeState
		}
		if err != nil {
			return err
		}
	}
}

func (s *handshakeFSM) prepare(ctx context.Context, c *Conn) (handshakeState, error) {
	// TODO 消息生成还是应该在这里完成
	// 填充握手消息序列号
	if s.currentFlight == flight2 {
		swapAddress(s.flight)
	}
	if s.flight.Dest == ToServer {
		// client -> server
		s.flight.populateMessageSequence(&c.state.clientSendMessageSequence)
	} else {
		s.flight.populateMessageSequence(&c.state.serverSendMessageSequence)
	}

	return handshakeSending, nil
}

func (s *handshakeFSM) send(ctx context.Context, c *Conn) (handshakeState, error) {
	if s.flight == nil {
		// flight1消息（在flight0Handle中处理）不够且超过重传时间后会重发上一个消息，此时s.flight是nil，直接跳转到waiting状态继续读
		return handshakeWaiting, nil
	}
	if err := c.sendPackets(ctx, s.flight); err != nil {
		return handshakeErrored, err
	}
	if s.currentFlight == flight6 {
		return handshakeFinished, nil
	}
	return handshakeWaiting, nil
}

func (s *handshakeFSM) wait(ctx context.Context, c *Conn) (handshakeState, error) {
	handle, err := s.currentFlight.getFlightHandler()
	if err != nil {
		return handshakeErrored, err
	}

	retransmitTimer := time.NewTimer(s.config.retransmitInterval)
	for {
		select {
		case packet := <-c.packetChannel():
			rawRecords, err := recordlayer.UnpackDatagram(packet.Payload)
			if err != nil {
				return handshakeErrored, err
			}
			if err = handleHandshakeMessages(rawRecords, c, packet.Dest); err != nil {
				return handshakeErrored, err
			}
			nextFlight, records, err := handle(c, s.config)
			var alertErr *AlertError
			if errors.As(err, &alertErr) {
				// Alert消息，发送后直接进入handshakeFinish状态
				log.Tracef("[handshake] %v", alertErr)
				s.flight = moveWithRecords(packet, records)
				s.currentFlight = unknown
				if err = c.notify(ctx, s.flight); err == nil {
					return handshakeFinished, nil
				}
			}
			if err != nil {
				return handshakeErrored, err
			}
			if nextFlight == 0 {
				// keep read
				break
			}
			log.Debugf("[handshake] %s -> %s", s.currentFlight.String(), nextFlight.String())
			s.flight = moveWithRecords(packet, records)
			s.currentFlight = nextFlight
			return handshakePreparing, nil

		case <-retransmitTimer.C:
			return handshakeSending, nil

		case <-ctx.Done():
			return handshakeErrored, ctx.Err()
		}
	}
}

func (s *handshakeFSM) finish(ctx context.Context, c *Conn) (handshakeState, error) {
	timewaitInterval := time.NewTimer(s.config.timewaitInterval)
	select {
	case <-c.packetChannel():
		// 单纯重传，不处理数据包了
		if s.flight.DTLSType == layer.DTLSTypeAlert {
			c.notify(ctx, s.flight)
			return handshakeFinished, nil
		} else {
			return handshakeSending, nil
		}

	case <-timewaitInterval.C:
		s.completed.Store(true)
		return handshakeFinished, nil

	case <-ctx.Done():
		return handshakeErrored, ctx.Err()
	}
}

// TODO 握手消息fragment的合并, 以及修改下处理发送方向的逻辑
// handleHandshakeMessages 解析并存入handshakeCache
func handleHandshakeMessages(rawRecords [][]byte, c *Conn, dest Destination) error {
	for _, data := range rawRecords {
		h := &layer.RecordHeader{}
		if err := h.Unmarshal(data); err != nil {
			log.Debugf("discarded broken packet: %v", err)
			return err
		}

		// 解密，只有Finished消息需要解密
		if h.Epoch != 0 {
			var err error
			if dest == ToServer {
				// client -> server
				data, err = c.state.serverCipherSuite.Decrypt(data)
				if err != nil {
					log.Debugf("decrypt failed: %s", err)
					return err
				}
			} else {
				// server -> client
				data, err = c.state.clientCipherSuite.Decrypt(data)
				if err != nil {
					log.Debugf("decrypt failed: %s", err)
					return err
				}
			}
			// log.Tracef("decrypted finished message: %#v", data)
		}

		record := &layer.Record{}
		if err := record.Unmarshal(data); err != nil {
			return err
		}

		if h.ContentType == layer.DTLSTypeHandshake {
			switch dest {
			case ToServer:
				isComplete, err := mergeAndCache(data[layer.RecordHeaderSize:], c.clientFragments, c.clientCache, true)
				if err != nil {
					return err
				}
				if !isComplete {
					continue
				}
			case ToClient:
				isComplete, err := mergeAndCache(data[layer.RecordHeaderSize:], c.serverFragments, c.serverCache, false)
				if err != nil {
					return err
				}
				if !isComplete {
					continue
				}
			}
		}
	}

	return nil
}

// mergeAndCache 处理分片并缓存消息，data不包括RecordLayer的首部
func mergeAndCache(data []byte, buffer *fragmentBuffer, cache *handshakeCache, isClient bool) (bool, error) {
	out, err := buffer.merge(data)
	if err != nil {
		return false, err
	}
	if out == nil {
		// 消息是分片且未收到所有分片
		return false, nil
	}

	hand := &layer.Handshake{}
	if err = hand.Unmarshal(out); err != nil {
		return false, err
	}
	cache.push(out, hand.Header.MessageSequence, hand.Header.MessageType, isClient)
	return true, nil
}

func swapAddress(p *Packet) {
	p.Dest = 1 - p.Dest
	p.IPv4.SrcIP, p.IPv4.DstIP = p.IPv4.DstIP, p.IPv4.SrcIP
	p.UDP.SrcPort, p.UDP.DstPort = p.UDP.DstPort, p.UDP.SrcPort
}
