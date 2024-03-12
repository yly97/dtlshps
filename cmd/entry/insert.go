package entry

import (
	"context"

	log "github.com/sirupsen/logrus"
	"github.com/yly97/dtlshps/pkg/client"
	"github.com/yly97/dtlshps/pkg/util"
)

// 下发到switch1的流表项
func TableEntriesToSw1(ctx context.Context, cli *client.Client) {
	InsertIPv4Entry(ctx, cli, "10.0.1.1", "08:00:00:00:01:11", 1)
	InsertIPv4Entry(ctx, cli, "10.0.2.2", "08:00:00:00:02:22", 2)
	InsertIPv4Entry(ctx, cli, "10.0.3.3", "08:00:00:00:02:00", 3)
	InsertIPv4Entry(ctx, cli, "10.0.4.4", "08:00:00:00:02:00", 3)

	InsertRecordEntry(ctx, cli, 1, 20)
	// InsertRecordEntry(ctx, cli, 1, 21)
	InsertRecordEntry(ctx, cli, 1, 22)
	InsertRecordEntry(ctx, cli, 2, 20)
	// InsertRecordEntry(ctx, cli, 2, 21)
	InsertRecordEntry(ctx, cli, 2, 22)
	log.Infof("Successful initializea table entries of switch %d", cli.DeviceId())
}

// 下发到switch2的流表项
func TableEntriesToSw2(ctx context.Context, cli *client.Client) {
	InsertIPv4Entry(ctx, cli, "10.0.1.1", "08:00:00:00:01:00", 1)
	InsertIPv4Entry(ctx, cli, "10.0.2.2", "08:00:00:00:01:00", 1)
	InsertIPv4Entry(ctx, cli, "10.0.3.3", "08:00:00:00:03:33", 2)
	InsertIPv4Entry(ctx, cli, "10.0.4.4", "08:00:00:00:04:44", 3)

	InsertRecordEntry(ctx, cli, 2, 20)
	// InsertRecordEntry(ctx, cli, 2, 21)
	InsertRecordEntry(ctx, cli, 2, 22)
	InsertRecordEntry(ctx, cli, 3, 20)
	// InsertRecordEntry(ctx, cli, 3, 21)
	InsertRecordEntry(ctx, cli, 3, 22)
	log.Infof("Successful initializea table entries of switch %d", cli.DeviceId())
}

func InsertIPv4Entry(ctx context.Context, cli *client.Client, dstIp, dstMac string, egressPort uint32) {
	egressPortBytes, _ := util.UInt32ToBinaryCompressed(egressPort)
	dstIpBytes, _ := util.IpToBinary(dstIp)
	dstMacBytes, _ := util.MacToBinary(dstMac)
	ipv4Entry := cli.NewTableEntry(
		"MyIngress.ipv4_tbl",
		map[string]client.MatchInterface{
			"hdr.ipv4.dstAddr": &client.LpmMatch{
				Value: dstIpBytes,
				PLen:  32,
			},
		},
		cli.NewTableActionDirect("MyIngress.ipv4_forward", [][]byte{dstMacBytes, egressPortBytes}),
		nil,
	)
	if err := cli.InsertTableEntry(ctx, ipv4Entry); err != nil {
		log.Errorf("failed to insert entry:%v", err)
	}
}

func InsertRecordEntry(ctx context.Context, cli *client.Client, ingressPort, contentType uint32) {
	ingressPortBytes, _ := util.UInt32ToBinaryCompressed(ingressPort)
	contentTypeBytes, _ := util.UInt32ToBinaryCompressed(contentType)
	recordEntry := cli.NewTableEntry(
		"MyIngress.record_tbl",
		map[string]client.MatchInterface{
			"standard_metadata.ingress_port": &client.ExactMatch{
				Value: ingressPortBytes,
			},
			"hdr.record.contentType": &client.ExactMatch{
				Value: contentTypeBytes,
			},
		},
		cli.NewTableActionDirect("MyIngress.send_to_cpu", [][]byte{}),
		nil,
	)
	if err := cli.InsertTableEntry(ctx, recordEntry); err != nil {
		log.Errorf("failed to insert entry:%v", err)
	}
}
