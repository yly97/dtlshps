package main

import (
	"context"
	"crypto/x509"
	"flag"
	"time"

	v1 "github.com/p4lang/p4runtime/go/p4/v1"
	log "github.com/sirupsen/logrus"
	"github.com/yly97/dtlshps/cmd/entry"
	"github.com/yly97/dtlshps/pkg/aqua"
	"github.com/yly97/dtlshps/pkg/client"
	"github.com/yly97/dtlshps/pkg/signals"
	"github.com/yly97/dtlshps/pkg/util"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

const (
	defaultBinPath      = "/home/p4/go_work/dtlshps/p4src/build/gate.json"
	defaultP4InfoPath   = "/home/p4/go_work/dtlshps/p4src/build/gate.p4.p4info.txt"
	defaultRootCertPath = "certificates/server.pub.pem"
)

var (
	verbose      int
	binPath      string
	p4InfoPath   string
	rootCertPath string
)

func main() {
	flag.IntVar(&verbose, "verbose", 2, "Set log level(0:trace, 1:debug, 2:info)")
	flag.StringVar(&binPath, "bin", defaultBinPath, "Path to p4 runtime json file")
	flag.StringVar(&p4InfoPath, "p4info", defaultP4InfoPath, "Path to p4info txt file")
	flag.StringVar(&rootCertPath, "ca", defaultRootCertPath, "Path to root certificate")
	flag.Parse()

	switch verbose {
	case 0:
		log.SetLevel(log.TraceLevel)
	case 1:
		log.SetLevel(log.DebugLevel)
	}

	stopCh := signals.RegisterSignalHandlers()

	// 加载证书
	rootCert, err := util.LoadCertificates(rootCertPath)
	if err != nil {
		log.Fatalf("load root certificate error: %v", err)
	}
	cert, err := x509.ParseCertificate(rootCert.Certificate[0])
	if err != nil {
		log.Fatalf("parse root certificate error: %v", err)
	}
	certPool := x509.NewCertPool()
	certPool.AddCert(cert)

	// 设置
	ctx := context.Background()
	cfg := &aqua.Config{
		RetransmitInterval: time.Second,
		TimewaitInterval:   time.Second * 5,
		ConnectionContext: func() (context.Context, context.CancelFunc) {
			return context.WithTimeout(ctx, time.Second*30)
		},
		RootCAs: certPool,
		StopCh:  stopCh,
	}

	// 创建Console
	console := aqua.NewConsole(cfg)

	if err := console.LoadFwdPipeConfig(binPath, p4InfoPath); err != nil {
		log.Fatal(err)
	}

	// ----------------------添加switch1------------------------
	conn1, err := grpc.Dial("0.0.0.0:9559", grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Fatalf("Failed to dial: %v", err)
	}
	client1 := client.NewClient(conn1, 1, &v1.Uint128{High: 0, Low: 1}, 1024)
	console.AddClient(client1)
	console.SetInitializationEntries(client1.DeviceId(), entry.TableEntriesToSw1)

	// ----------------------添加switch2------------------------
	conn2, err := grpc.Dial("0.0.0.0:9560", grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Fatalf("Failed to dial: %v", err)
	}
	client2 := client.NewClient(conn2, 2, &v1.Uint128{High: 0, Low: 1}, 1024)
	console.AddClient(client2)
	console.SetInitializationEntries(client2.DeviceId(), entry.TableEntriesToSw2)

	// Console Run
	console.Run(aqua.Install)
	log.Info("All client stopped!")
}
