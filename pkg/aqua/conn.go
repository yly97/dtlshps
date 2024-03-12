package aqua

import (
	"bytes"
	"context"
	"encoding/binary"
	"net"
	"strconv"
	"sync/atomic"

	v1 "github.com/p4lang/p4runtime/go/p4/v1"
	"github.com/pion/dtls/v2/pkg/protocol"
	"github.com/pion/dtls/v2/pkg/protocol/recordlayer"
	log "github.com/sirupsen/logrus"
	"github.com/yly97/dtlshps/pkg/layer"
)

const (
	cookieLength      = 20
	inboundBufferSize = 8192
	mtu               = 1200
)

// ConnID
type ConnID struct {
	SrcIP   net.IP
	SrcPort uint16
	DstIP   net.IP
	DstPort uint16
}

func GetIdFromPacket(packet *Packet) *ConnID {
	return &ConnID{
		SrcIP:   packet.IPv4.SrcIP,
		SrcPort: uint16(packet.UDP.SrcPort),
		DstIP:   packet.IPv4.DstIP,
		DstPort: uint16(packet.UDP.DstPort),
	}
}

// Bytes 返回[SrcIP,SrcPort,DstIP,DstPort]的字节切片
func (c *ConnID) Bytes() []byte {
	b := make([]byte, 12)
	copy(b, c.SrcIP)
	binary.BigEndian.PutUint16(b[4:], c.SrcPort)
	copy(b[6:], c.DstIP)
	binary.BigEndian.PutUint16(b[10:], c.DstPort)
	return b
}

// ReverseBytes 返回[DstIP,DstPort,SrcIP,SrcPort]的字节切片
func (c *ConnID) ReverseBytes() []byte {
	b := make([]byte, 12)
	copy(b, c.DstIP)
	binary.BigEndian.PutUint16(b[4:], c.DstPort)
	copy(b[6:], c.SrcIP)
	binary.BigEndian.PutUint16(b[10:], c.SrcPort)
	return b
}

// String 返回字符串标识的ConnID（[srcIP:srcPort -> dstIP:dstPort]）
func (c *ConnID) String() string {
	ids := "[" + c.SrcIP.String() + ":" + strconv.Itoa(int(c.SrcPort))
	ids += " -> "
	ids += c.DstIP.String() + ":" + strconv.Itoa(int(c.DstPort)) + "]"
	return ids
}

// getIdPair
func (c *ConnID) getIdPair() (string, string) {
	return string(c.Bytes()), string(c.ReverseBytes())
}

var defaultBufferSize = 1024

// Conn
type Conn struct {
	cid             *ConnID
	clientIP        net.IP // 只存client的IP地址，只在构造时设置
	state           *State
	buffer          chan *Packet
	clientFragments *fragmentBuffer // 握手消息分片处理
	serverFragments *fragmentBuffer
	clientCache     *handshakeCache // 缓存通信双方握手消息，用于验证CertificateVerify消息以及生成Finished消息
	serverCache     *handshakeCache
	fsm             *handshakeFSM
}

// TODO FSM的初始化
func newConn(cid *ConnID, clientIP net.IP) *Conn {
	state := &State{}
	return &Conn{
		cid:             cid,
		clientIP:        clientIP,
		state:           state,
		buffer:          make(chan *Packet, defaultBufferSize), // 可配置
		clientFragments: newFragmentBuffer(),
		serverFragments: newFragmentBuffer(),
		clientCache:     newHandshakeCache(),
		serverCache:     newHandshakeCache(),
	}
}

// WriteTo 非阻塞向Conn的Buffer中写入一个packet，会返回buffer溢出错误
func (c *Conn) WriteTo(data *Packet) error {
	select {
	case c.buffer <- data:
		return nil
	default:
		return errBufferOverflow
	}
}

// ConnID
func (c *Conn) ConnID() *ConnID {
	return c.cid
}

// Dest 传入数据包的源地址，用来判断数据包的接收方
func (c *Conn) Dest(srcIP net.IP) Destination {
	if srcIP.Equal(c.clientIP) {
		return ToServer
	} else {
		return ToClient
	}
}

// packetChannel
func (c *Conn) packetChannel() <-chan *Packet {
	return c.buffer
}

// hanshake 握手完成后停留一段时间后退出，时间长短可配置
func (c *Conn) handshake(ctx context.Context, config *handshakeConfig) error {
	c.fsm = newHandshakeFSM(config)
	if err := c.fsm.run(ctx, c); err != nil {
		return err
	}
	return nil
}

// TODO handshake fragment超过MTU的分片、Record未超过MTU时合并以及超过MTU时的分包，
// 重新发送包时，Record的序列号需要递增还是维持不变？如果不变的化processPackets不该在sendPackets中调用
func (c *Conn) sendPackets(ctx context.Context, packet *Packet) error {
	data, err := c.processPackets(packet.Records, packet.Dest)
	if err != nil {
		return err
	}
	packet.Payload = data
	out, err := packet.Serialize()
	if err != nil {
		return err
	}

	packetOut := &v1.PacketOut{
		Payload: out,
	}
	if err := packet.Sender.SendPacketOut(ctx, packetOut); err != nil {
		log.Infof("Client %d failed to send PacketOut: %v", packet.Sender.DeviceId(), err)
	}

	return nil
}

func (c *Conn) processPackets(records []*layer.Record, dest Destination) ([]byte, error) {
	var out bytes.Buffer

	// 应该有更好的处理方式
	if dest == ToServer {
		// client -> server
		for _, r := range records {
			epoch := r.Header.Epoch
			for len(c.state.clientSequenceNumber) <= int(epoch) {
				c.state.clientSequenceNumber = append(c.state.clientSequenceNumber, uint64(0))
			}
			seq := atomic.AddUint64(&c.state.clientSequenceNumber[epoch], 1) - 1
			if seq > layer.MaxSequenceNumber {
				return nil, errSequenceNumberOverflow
			}

			r.Header.SequenceNumber = seq
			data, err := r.Marshal()
			if err != nil {
				return nil, err
			}
			if hand, ok := r.Content.(*layer.Handshake); ok {
				c.serverCache.push(data[layer.RecordHeaderSize:], hand.Header.MessageSequence, hand.Header.MessageType, true)
			}
			if r.Header.Epoch != 0 {
				data, err = c.state.clientCipherSuite.Encrypt(newPionRecord(r), data) // TODO
				if err != nil {
					return nil, err
				}
				// log.Tracef("encrypted finished message: %#v", data)
			}
			out.Write(data)
		}
	} else {
		// server -> client
		for _, r := range records {
			epoch := r.Header.Epoch
			for len(c.state.serverSequenceNumber) <= int(epoch) {
				c.state.serverSequenceNumber = append(c.state.serverSequenceNumber, uint64(0))
			}
			seq := atomic.AddUint64(&c.state.serverSequenceNumber[epoch], 1) - 1
			if seq > layer.MaxSequenceNumber {
				return nil, errSequenceNumberOverflow
			}

			r.Header.SequenceNumber = seq
			data, err := r.Marshal()
			if err != nil {
				return nil, err
			}
			if hand, ok := r.Content.(*layer.Handshake); ok {
				c.clientCache.push(data[layer.RecordHeaderSize:], hand.Header.MessageSequence, hand.Header.MessageType, false)
			}
			if r.Header.Epoch != 0 {
				data, err = c.state.serverCipherSuite.Encrypt(newPionRecord(r), data) // TODO
				if err != nil {
					return nil, err
				}
				// log.Tracef("encrypted finished message: %#v", data)
			}
			out.Write(data)
		}
	}
	return out.Bytes(), nil
}

// notify 向client端和server端都发送一个Alert消息
func (c *Conn) notify(ctx context.Context, p *Packet) error {
	if err := c.sendPackets(ctx, p); err != nil {
		return err
	}

	// TODO 这里发的两个消息都会通过同一个client发送，或许应该更好的封装一下通信双方的信息
	p.IPv4.SrcIP, p.IPv4.DstIP = p.IPv4.DstIP, p.IPv4.SrcIP
	p.Dest = 1 - p.Dest
	p.UDP.SrcPort, p.UDP.DstPort = p.UDP.DstPort, p.UDP.SrcPort

	return c.sendPackets(ctx, p)
}

func newPionRecord(record *layer.Record) *recordlayer.RecordLayer {
	return &recordlayer.RecordLayer{
		Header: recordlayer.Header{
			ContentType:    protocol.ContentType(record.Header.ContentType),
			Version:        protocol.Version1_2,
			Epoch:          record.Header.Epoch,
			SequenceNumber: record.Header.SequenceNumber,
			ContentLen:     record.Header.ContentLength,
		},
	}
}
