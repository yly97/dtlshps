package client

import (
	"context"
	"fmt"
	"io"
	"sync"
	"sync/atomic"

	log "github.com/sirupsen/logrus"
	code "google.golang.org/genproto/googleapis/rpc/code"
	"google.golang.org/grpc"

	p4_config_v1 "github.com/p4lang/p4runtime/go/p4/config/v1"
	p4_v1 "github.com/p4lang/p4runtime/go/p4/v1"
)

const (
	P4RuntimePort = 9559
)

type ClientOptions struct {
	CanonicalBytestrings bool
}

var defaultClientOptions = ClientOptions{
	CanonicalBytestrings: true,
}

func DisableCanonicalBytestrings(options *ClientOptions) {
	options.CanonicalBytestrings = false
}

type Client struct {
	ClientOptions
	p4_v1.P4RuntimeClient

	deviceID   uint64
	electionID *p4_v1.Uint128
	p4Info     *p4_config_v1.P4Info
	role       *p4_v1.Role

	primary       atomic.Bool
	arbitrationCh chan bool

	stream       p4_v1.P4Runtime_StreamChannelClient
	streamSendCh chan *p4_v1.StreamMessageRequest

	readWG  sync.WaitGroup // 等待readLoop退出
	connErr chan error     // readLoop中返回的error
	stopCh  chan struct{}  // 通知关闭的channel
	running atomic.Bool

	handleWG        sync.WaitGroup                                        // 等待用户传入的回调函数中创建的协程退出
	packetInHandler func(context.Context, *Client, *p4_v1.PacketIn) error // 处理PacketIn的回调函数
}

// NewClient 创建一个P4RuntimeClient
func NewClient(
	clientConn grpc.ClientConnInterface,
	deviceID uint64,
	electionID *p4_v1.Uint128,
	sendChSize uint32,
	optionsModifierFns ...func(*ClientOptions),
) *Client {
	return NewClientForRole(clientConn, deviceID, electionID, nil, sendChSize, optionsModifierFns...)
}

func NewClientForRole(
	clientConn grpc.ClientConnInterface,
	deviceID uint64,
	electionID *p4_v1.Uint128,
	role *p4_v1.Role,
	sendChSize uint32,
	optionsModifierFns ...func(*ClientOptions),
) *Client {
	options := defaultClientOptions
	for _, fn := range optionsModifierFns {
		fn(&options)
	}

	p4RtClient := p4_v1.NewP4RuntimeClient(clientConn)

	return &Client{
		ClientOptions:   options,
		P4RuntimeClient: p4RtClient,
		deviceID:        deviceID,
		electionID:      electionID,
		role:            role,
		streamSendCh:    make(chan *p4_v1.StreamMessageRequest, sendChSize),
		connErr:         make(chan error, 1),
		stopCh:          make(chan struct{}),
		arbitrationCh:   make(chan bool),
	}
}

// Run
func (c *Client) Run() error {
	c.running.Store(true)

	var err error
	// 这里传入一个empty context，stream的关闭通过调用CloseSend，这样关闭的弊端是：
	// 如果defer调用CloseSend，在defer函数调用期间收到readLoop的错误无法返回。
	// 解决办法：手动CloseSend，或者用WithContext返回的关闭函数
	c.stream, err = c.StreamChannel(context.Background())
	if err != nil {
		return err
	}
	handleCtx, cancel := context.WithCancel(context.Background())
	defer func() {
		c.stream.CloseSend() // readLoop阻塞于Recv操作，CloseSend一定能保证它退出
		cancel()
		c.readWG.Wait()
		c.handleWG.Wait()
		// TODO 可能存在readLoop中error未处理的情况
		// 1. CloseSend会导致readLoop收到io.EOF（正常退出，不处理）
		// 2. Send操作导致的error返回和readLoop中Recv操作的error处理处理可能同时发生（第一个会返回，剩下的清理掉）
		// 3. 进入defer函数在CloseSend调用前收到的子协程错误（没想好怎么做）
		// 非阻塞清空error
		select {
		case err := <-c.connErr:
			log.Debugf("Client %d closed: %v", c.deviceID, err)
		default:
			log.Debugf("Client %d closed success!", c.deviceID)
		}
		c.running.Store(false)
	}()

	// 启动readLoop
	c.readWG.Add(1)
	go c.readLoop(handleCtx)

	if err := c.sendArbitration(); err != nil {
		log.Errorf("Client %d failed to send arbitration: %v", c.deviceID, err)
		return err
	}

	for {
		select {
		case out := <-c.streamSendCh:
			if err := c.stream.Send(out); err != nil {
				log.Errorf("Client %d failed to send a stream message : %v", c.deviceID, err)
				return err
			}
		case err := <-c.connErr:
			return err
		case <-c.stopCh:
			return nil
		}
	}
}

// Watch 必须要调用，开启一个协程读取arbitration消息的仲裁结果
func (c *Client) Watch() <-chan struct{} {
	done, sent := make(chan struct{}), false
	go func() {
		for {
			select {
			case isPrimary := <-c.arbitrationCh:
				if !sent {
					done <- struct{}{}
					sent = true
				}
				if isPrimary {
					log.Infof("Client %d is primary client!", c.deviceID)
				} else {
					log.Infof("Client %d is not primary client!", c.deviceID)
				}
			case <-c.stopCh:
				return
			}
		}
	}()

	return done
}

func (c *Client) RegisterPacketInHandler(fn func(context.Context, *Client, *p4_v1.PacketIn) error) {
	c.packetInHandler = fn
}

// Add handleWaitGroup计数器加1，回调函数中开协程时使用
func (c *Client) Add(delta int) {
	c.handleWG.Add(delta)
}

// Done handleWaitGroup计数器减1
func (c *Client) Done() {
	c.handleWG.Done()
}

// notifyErr 非阻塞向connErr中写入一个错误，connErr缓冲大小为1，防止多个协程写错误时出现阻塞
func (c *Client) notifyErr(err error) {
	select {
	case c.connErr <- err:
	default:
	}
}

// Close 通知client关闭。
func (c *Client) Close() {
	close(c.stopCh)
}

func (c *Client) WriteUpdate(ctx context.Context, update *p4_v1.Update) error {
	req := &p4_v1.WriteRequest{
		DeviceId:   c.deviceID,
		ElectionId: c.electionID,
		Updates:    []*p4_v1.Update{update},
	}
	if c.role != nil {
		req.Role = c.role.Name
	}
	_, err := c.Write(ctx, req)
	return err
}

func (c *Client) ReadEntitySingle(ctx context.Context, entity *p4_v1.Entity) (*p4_v1.Entity, error) {
	req := &p4_v1.ReadRequest{
		DeviceId: c.deviceID,
		Entities: []*p4_v1.Entity{entity},
	}
	if c.role != nil {
		req.Role = c.role.Name
	}
	stream, err := c.Read(ctx, req)
	if err != nil {
		return nil, err
	}
	var readEntity *p4_v1.Entity
	count := 0
	for {
		rep, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		for _, e := range rep.Entities {
			count++
			readEntity = e
		}
	}
	if count == 0 {
		return nil, fmt.Errorf("expected a single entity but got none")
	}
	if count > 1 {
		return nil, fmt.Errorf("expected a single entity but got several")
	}
	return readEntity, nil
}

// ReadEntityWildcard will block and send all read entities on readEntityCh. It will close the
// channel when the RPC completes and return any error that may have occurred.
func (c *Client) ReadEntityWildcard(ctx context.Context, entity *p4_v1.Entity, readEntityCh chan<- *p4_v1.Entity) error {
	defer close(readEntityCh)

	req := &p4_v1.ReadRequest{
		DeviceId: c.deviceID,
		Entities: []*p4_v1.Entity{entity},
	}
	if c.role != nil {
		req.Role = c.role.Name
	}
	stream, err := c.Read(ctx, req)
	if err != nil {
		return err
	}
	for {
		rep, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		for _, e := range rep.Entities {
			readEntityCh <- e
		}
	}
	return nil
}

func (c *Client) SendMessage(ctx context.Context, msg *p4_v1.StreamMessageRequest) error {
	select {
	case c.streamSendCh <- msg:
		break
	case <-ctx.Done():
		return ctx.Err()
	}
	return nil
}

func (c *Client) SendPacketOut(ctx context.Context, pkt *p4_v1.PacketOut) error {
	msg := &p4_v1.StreamMessageRequest{Update: &p4_v1.StreamMessageRequest_Packet{Packet: pkt}}
	return c.SendMessage(ctx, msg)
}

func (c *Client) DeviceId() uint64 {
	return c.deviceID
}

func (c *Client) sendArbitration() error {
	arbitrationMsg := &p4_v1.StreamMessageRequest{
		Update: &p4_v1.StreamMessageRequest_Arbitration{
			Arbitration: &p4_v1.MasterArbitrationUpdate{
				DeviceId:   c.deviceID,
				ElectionId: c.electionID,
				Role:       c.role,
			},
		},
	}
	return c.stream.Send(arbitrationMsg)
}

// readLoop 接收并处理StreamMessageResponse，只会阻塞在stream的Recv方法，
// 只会在Recv返回error退出，其中包括父协程调用CloseSend后收到的的io.EOF
func (c *Client) readLoop(ctx context.Context) {
	defer c.readWG.Done()

	for {
		in, err := c.stream.Recv()
		if err != nil {
			// 所有error由父协程处理，包括主动调用CloseSend关闭连接时收到的io.EOF
			c.notifyErr(err)
			return
		}

		switch msg := in.Update.(type) {
		case *p4_v1.StreamMessageResponse_Arbitration:
			if msg.Arbitration.Status.Code != int32(code.Code_OK) {
				c.arbitrationCh <- false
				c.primary.Store(false)
			} else {
				c.arbitrationCh <- true
				c.primary.Store(true)
			}
		default:
			if err := c.handleMessage(ctx, in); err != nil {
				c.notifyErr(err)
				return
			}
		}
	}
}

// TODO
func (c *Client) handleMessage(ctx context.Context, msg *p4_v1.StreamMessageResponse) error {
	switch m := msg.Update.(type) {
	case *p4_v1.StreamMessageResponse_Packet:
		log.Debugf("Received PacketIn")

		if c.packetInHandler != nil {
			if err := c.packetInHandler(ctx, c, m.Packet); err != nil {
				return err
			}
		}
	case *p4_v1.StreamMessageResponse_Digest:
		log.Debugf("Received DigestList")
	case *p4_v1.StreamMessageResponse_IdleTimeoutNotification:
		log.Debugf("Received IdleTimeoutNotification")
	case *p4_v1.StreamMessageResponse_Error:
		log.Errorf("Received StreamError")
	default:
		log.Errorf("Received unknown stream message")
	}
	return nil
}
