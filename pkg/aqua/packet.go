package aqua

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/yly97/dtlshps/pkg/client"
	"github.com/yly97/dtlshps/pkg/layer"
)

// Destination 数据包目的地，其实用bool类型就够了，一个Conn的传输方向就只有两个
type Destination uint8

const (
	ToClient Destination = 0
	ToServer Destination = 1
)

// Packet 在收到PacketIn时会将数据包封装成该结构体，处理完后发送PacketOut时也用该结构体，
// 数据包处理的整个流程中结构体的转变是：v1.PacketIn -> Pakcet -> v1.PakcetOut，
// PacketIn和PacketOut是P4runtime使用Protocol定义的消息结构体
type Packet struct {
	layer.DTLSType // 在发送时区分packet类型

	Ethernet *layers.Ethernet
	IPv4     *layers.IPv4
	UDP      *layers.UDP
	Payload  []byte

	Sender  *client.Client  // 发送packet的client
	Dest    Destination     // packet接收方
	Records []*layer.Record // depressed
}

// NewPacket 只创建底层协议栈为ethernet、ipv4、udp协议的报文，用Google的gopacket库解码
func NewPacket(data []byte, options gopacket.DecodeOptions) (*Packet, error) {
	packet := gopacket.NewPacket(data, layers.LayerTypeEthernet, options)
	ethernetLayer := packet.Layer(layers.LayerTypeEthernet)
	if ethernetLayer == nil {
		return nil, errInvalidPacket
	}
	ethernet, _ := ethernetLayer.(*layers.Ethernet)
	ipv4Layer := packet.Layer(layers.LayerTypeIPv4)
	if ipv4Layer == nil {
		return nil, errInvalidPacket
	}
	ipv4, _ := ipv4Layer.(*layers.IPv4)
	udpLayer := packet.Layer(layers.LayerTypeUDP)
	if udpLayer == nil {
		return nil, errInvalidPacket
	}
	udp, _ := udpLayer.(*layers.UDP)

	return &Packet{
		Ethernet: ethernet,
		IPv4:     ipv4,
		UDP:      udp,
		Payload:  udp.Payload,
	}, nil
}

// moveWithRecords 设置Packet的records字段，再根据records[0]来设置DTLSType字段
func moveWithRecords(p *Packet, records []*layer.Record) *Packet {
	if len(records) > 0 {
		p.Records = records
		p.DTLSType = records[0].Header.ContentType
	}

	return p
}

// Serialize 编码应用层数据，重新计算UDP首部、IPv4首部的长度和校验和字段
func (p *Packet) Serialize() ([]byte, error) {
	buf := gopacket.NewSerializeBufferExpectedSize(p.headerLength(), len(p.Payload))
	bytes, err := buf.AppendBytes(len(p.Payload))
	if err != nil {
		return nil, err
	}
	copy(bytes, p.Payload)
	p.UDP.SetNetworkLayerForChecksum(p.IPv4) // udp校验和计算需要计算伪头部，要用到IP首部的srcIP和dstIP
	// SerializeLayers 会清除buf中的数据，Payload的类型没找到，暂时没法用
	// gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, p.ethernet, p.ipv4, p.udp)
	options := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	p.UDP.SerializeTo(buf, options)
	p.IPv4.SerializeTo(buf, options)
	p.Ethernet.SerializeTo(buf, options)
	return buf.Bytes(), nil
}

func (p *Packet) SerializeHeader() []byte {
	out := make([]byte, 0, p.headerLength())
	out = append(out, p.Ethernet.Contents...)
	out = append(out, p.IPv4.Contents...)
	out = append(out, p.UDP.Contents...)
	return out
}

func (p *Packet) headerLength() int {
	_ = p.Ethernet.Contents
	_ = p.IPv4.Contents
	_ = p.UDP.Contents
	return len(p.Ethernet.Contents) + len(p.IPv4.Contents) + len(p.UDP.Contents)
}

func (p *Packet) populateMessageSequence(seq *int) {
	for _, r := range p.Records {
		// 这里不能用RecordHeader的ContentType来判断，生成数据时未填类型字段
		if handshake, ok := r.Content.(*layer.Handshake); ok {
			handshake.Header.MessageSequence = uint16(*seq)
			(*seq)++
		}
	}
}
