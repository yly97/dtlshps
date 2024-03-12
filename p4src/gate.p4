// 工作在三层以上，二层的协议不处理
// TODO 考虑加个简单的Maclearning模块
// apply模块中一个表不能多次调用apply，即使是在不同的条件分支中，有点无语。。

#include <core.p4>
#include <v1model.p4>

#define CPU_PORT 14

const bit<16> TYPE_IPV4 = 0x0800;
// const bit<16> TYPE_ARP  = 0x0806;

const bit<8>  TYPE_TCP  = 6;
const bit<8>  TYPE_UDP  = 17;

// const bit<16> DTLS_VERSION1_0 = 0xfeff;
const bit<16> DTLS_VERSION1_2 = 0xfefd;

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

header udp_t {
    bit<16> dstPort;
    bit<16> srcPort;
    bit<16> totalLen;
    bit<16> checksum;
}

header record_t {
    bit<8> contentType;
    bit<16> version;
    bit<16> epoch;
    bit<48> sequenceNumber;
    bit<16> contentLen;
}

struct metadata {
}

@controller_header("packet_in")
header packet_in_t {
    bit<16> ingress_port;
}

@controller_header("packet_out")
header packet_out_t {
    bit<16> egress_spec;
}

struct headers {
    packet_in_t  packetIn;
    packet_out_t packetOut;
    ethernet_t   ethernet;
    ipv4_t       ipv4;
    udp_t        udp;
    record_t     record;
}


/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
	    transition select (standard_metadata.ingress_port){
            CPU_PORT: parse_packet_out;	
	        default: parse_ethernet;
        }
    }
    state parse_packet_out {
        packet.extract(hdr.packetOut);
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select (hdr.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
	    transition select (hdr.ipv4.protocol) {
            TYPE_UDP: parse_udp;
            default: accept;
        }
    }

    state parse_udp {
        packet.extract(hdr.udp);
        
        // 这里直接转移到record报头的解析状态，
        // Ingress中会根据version字段判断是否是DTLS消息
        transition parse_record;
    }

    state parse_record {
        packet.extract(hdr.record);
        transition accept;
    }
}

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {   
    apply {
        verify_checksum(
            hdr.ipv4.isValid(),
            { hdr.ipv4.version,
              hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
    }
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

    action drop() {
        mark_to_drop(standard_metadata);
    }
    
    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        standard_metadata.egress_spec = port;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }
    
    // Ipv4转发表
    table ipv4_tbl {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            ipv4_forward;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = drop();
    }
    
    action send_to_cpu() {
        standard_metadata.egress_spec = CPU_PORT;
    }

    // 识别gate入口端口以及handshake消息表
    table record_tbl {
        key = {
            standard_metadata.ingress_port: exact;
            hdr.record.contentType: exact;
        }
        actions = {
            send_to_cpu;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = drop();
    }

    apply {
        if (hdr.record.isValid() && hdr.record.version == DTLS_VERSION1_2 && record_tbl.apply().hit) {
            // PacketIn 说明是从gate入口进入且是握手消息
            hdr.packetIn.setValid();
            hdr.packetIn.ingress_port = (bit<16>)standard_metadata.ingress_port;
        } else {
            // 不是DTLS握手消息或者不是从gate入口进入的包（包括从控制器传来的DTLS握手消息）
            // 按ipv4规则转发
            if (hdr.ipv4.isValid()) {
                ipv4_tbl.apply();
            }

            if (standard_metadata.ingress_port == CPU_PORT) {
                // TODO 可能要处理PacketOut中的信息
                hdr.packetOut.setInvalid();
            }
        }

    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {  }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers  hdr, inout metadata meta) {
     apply {
        update_checksum(
            hdr.ipv4.isValid(),
            { hdr.ipv4.version,
              hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
    }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.packetIn); // 只能说这里忘了emit，控制器收到的PacketIn就会少几个字节
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.udp);
        packet.emit(hdr.record);
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
