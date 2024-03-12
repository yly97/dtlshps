package aqua

import (
	"context"
	"fmt"
	"io"
	"os"
	"sync"
	"sync/atomic"

	"github.com/google/gopacket"
	v1 "github.com/p4lang/p4runtime/go/p4/v1"
	log "github.com/sirupsen/logrus"
	"github.com/yly97/dtlshps/pkg/client"
)

const (
	defaultReceiveChannelSize = 1024
)

var (
	Default = RuntimeOptions{}
	Install = RuntimeOptions{SetFwdPipeConfig: true}
)

type RuntimeOptions struct {
	// 决定是否安装P4 source到交换机，可以考虑改成为每个交换机独立设置
	SetFwdPipeConfig bool
}

type InitialEntriesFunc func(context.Context, *client.Client)

type Console struct {
	idClientMap         map[uint64]*client.Client     // 通过deviceId找到client
	addrClientMap       map[string]*client.Client     // 通过目的IP找到client
	initialEntriesFnMap map[uint64]InitialEntriesFunc // 交换机初始化表项函数
	num                 atomic.Int32                  // client数量
	config              *Config                       // 非线程安全，不能在Console执行Run之后改动

	p4InfoBytes []byte
	binBytes    []byte

	stop <-chan struct{} // 控制台的关闭信号，触发后会通知所有子协程退出
	wg   sync.WaitGroup  // 等待子协程的退出

	connMutex sync.Mutex       // 保证conns的互斥访问
	conns     map[string]*Conn // string为通信双方地址的四元组[dstIP:dstPort, srcIP:srcPort]
}

func NewConsole(config *Config) *Console {
	// 需要检查config
	return &Console{
		idClientMap:         make(map[uint64]*client.Client),
		addrClientMap:       make(map[string]*client.Client),
		initialEntriesFnMap: make(map[uint64]InitialEntriesFunc),
		conns:               make(map[string]*Conn),
		config:              config,
		stop:                config.StopCh,
	}
}

// AddClient 添加一个client
func (c *Console) AddClient(cli *client.Client) {
	c.idClientMap[cli.DeviceId()] = cli
	c.num.Add(1)
}

// Run 使所有添加到控制器的client开始运行
func (c *Console) Run(options RuntimeOptions) {
	ctx := context.Background() // TODO empty context
	clientErr := make(chan error)
	for _, cli := range c.idClientMap {
		c.wg.Add(1)
		// 每个client都开启一个goroutine，client会接收各自对应的交换机发送的消息
		go func(cli *client.Client) {
			defer c.wg.Done()
			log.Infof("Client %d starts to work", cli.DeviceId())

			cli.RegisterPacketInHandler(c.packetInHandler)
			if err := cli.Run(); err != nil {
				clientErr <- err
			}
		}(cli)

		done := cli.Watch()
		<-done
	}

	// 初始化
	c.initialize(ctx, options)
	log.Info("Do Ctrl-C to quit")

	for {
		// 阻塞，直到子协程出错或者收到关闭信号
		select {
		case err := <-clientErr:
			// TODO 错误处理
			if err != io.EOF {
				log.Fatal(err)
			}
		case <-c.stop:
			// 关闭所有client，并等待它们退出
			c.closeAll()
			c.wg.Wait()
			return
		}
	}
}

// LoadFwdPipeConfig 加载P4Runtime配置文件，用来设置转发流水线，包括一个json文件和p4info.txt文件
func (c *Console) LoadFwdPipeConfig(binPath, p4InfoPath string) error {
	var err error
	if c.binBytes, err = os.ReadFile(binPath); err != nil {
		return err
	}
	if c.p4InfoBytes, err = os.ReadFile(p4InfoPath); err != nil {
		return err
	}
	return nil
}

// SetInitializationEntries 设置deviceId对应的交换机的初始化表项，覆盖设置
func (c *Console) SetInitializationEntries(deviceId uint64, fn InitialEntriesFunc) error {
	if _, ok := c.idClientMap[deviceId]; !ok {
		return fmt.Errorf("device %d not exists", deviceId)
	}
	c.initialEntriesFnMap[deviceId] = fn
	return nil
}

func (c *Console) closeAll() {
	log.Debug("Console is closing...")
	for _, cli := range c.idClientMap {
		cli.Close()
	}
}

func (c *Console) initialize(ctx context.Context, opt RuntimeOptions) {
	for _, cli := range c.idClientMap {
		if opt.SetFwdPipeConfig {
			if _, err := cli.SetFwdPipeFromBytes(ctx, c.binBytes, c.p4InfoBytes, 0); err != nil {
				log.Fatalf("Failed to set forwarding pipeline config: %v", err)
			}
			log.Infof("Successful installed forwarding pipeline config to device %d!", cli.DeviceId())
		}

		resp, err := cli.Capabilities(ctx, &v1.CapabilitiesRequest{})
		if err != nil {
			log.Fatalf("Error in Capabilities RPC: %v", err)
		}
		log.Infof("P4Runtime server version is %s", resp.P4RuntimeApiVersion)

		// 下发初始化流表项
		if fn, ok := c.initialEntriesFnMap[cli.DeviceId()]; ok {
			fn(ctx, cli)
		}
	}
}

// getConn 返回已存在的Conn或是新创建的Conn，如果Conn已经bool返回true，如果是新建的Conn，还要确定client端的IP地址
func (c *Console) getConn(cid *ConnID) (*Conn, bool) {
	id1, id2 := cid.getIdPair() // 对应同一个Conn

	c.connMutex.Lock()
	conn, ok := c.conns[id1]
	if ok {
		c.connMutex.Unlock()
		return conn, true
	}
	conn = newConn(cid, cid.SrcIP)
	c.conns[id1] = conn
	c.conns[id2] = conn
	c.connMutex.Unlock()
	return conn, false
}

func (c *Console) delConn(cid *ConnID) {
	id1, id2 := cid.getIdPair()

	c.connMutex.Lock()
	delete(c.conns, id1)
	delete(c.conns, id2)
	c.connMutex.Unlock()
}

// packetInHandler
func (c *Console) packetInHandler(ctx context.Context, receiver *client.Client, rawPacket *v1.PacketIn) error {
	packet, err := NewPacket(rawPacket.Payload, gopacket.Default)
	if err != nil {
		return err
	}

	// packet id(pid): 由[srcIP,srcPort,dstIP,dstPort] 12字节组成，能根据pid获取这个packet的接收方和发送方的IP地址和端口号，
	// 同时也能根据pid获取对应的Conn，pid为[a,b,c,d]和[c,d,a,b]的Packet获取的Conn是同一个
	pid := GetIdFromPacket(packet)
	conn, ok := c.getConn(pid)
	if !ok {
		// 新创建的Conn，开启一个处理握手过程的协程，生命周期由接收到PacketIn的client所在的协程管理，
		// 如果不关心握手是否安全退出，Add和Done可以不必要调用
		receiver.Add(1) // 好像没啥用。。。
		go func() {
			defer func() {
				c.delConn(conn.ConnID())
				log.Debugf("delete connection: %s", conn.ConnID().String())
				receiver.Done()
			}()
			log.Debugf("get a new connection: %s", conn.ConnID().String())
			cfg := &handshakeConfig{
				rootCAs:                 c.config.RootCAs,
				retransmitInterval:      c.config.RetransmitInterval,
				timewaitInterval:        c.config.TimewaitInterval,
				insecureSkipHelloVerify: c.config.InsecureSkipHelloVerify,
			}

			// 目前来看由client传入packetInHandler的context好像没什么作用，连接的超时时限应该是在Console中设置
			handshakeCtx, _ := c.config.ConnectionContext()
			if err := conn.handshake(handshakeCtx, cfg); err != nil {
				log.Errorf("connection: %s exit: %v", conn.ConnID().String(), err)
				return
			}
		}()
	}

	// 记录该IP地址的主机是归属于哪个client管理的
	c.addrClientMap[string(pid.SrcIP)] = receiver
	// 确定发送PacketOut的client，默认就是接收PacketIn的client
	sender := receiver
	if cli, ok := c.addrClientMap[string(pid.DstIP)]; ok {
		sender = cli
	}
	packet.Sender = sender
	packet.Dest = conn.Dest(pid.SrcIP) // 一条连接就两个方向，根据packet的srcIP确定发送方向

	if err := conn.WriteTo(packet); err != nil {
		return err
	}

	return nil
}
