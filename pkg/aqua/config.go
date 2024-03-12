package aqua

import (
	"context"
	"crypto/x509"
	"time"
)

type Config struct {
	RetransmitInterval      time.Duration
	TimewaitInterval        time.Duration                                // 握手结束后的等待时间
	ConnectionContext       func() (context.Context, context.CancelFunc) // 设置Connection的握手时限
	RootCAs                 *x509.CertPool
	InsecureSkipHelloVerify bool
	StopCh                  <-chan struct{} // TODO 通过其他方式设置
}

func (c *Config) connectionContext() (context.Context, context.CancelFunc) {
	if c.ConnectionContext == nil {
		return defaultConnectionContext()
	}
	return c.connectionContext()
}

func defaultConnectionContext() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), time.Second*30)
}
