/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

typedef bit<9>  port_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;
typedef bit<16> mcastGrp_t;

const port_t CPU_PORT           = 0x1;

const bit<16> ARP_OP_REQ        = 0x0001;
const bit<16> ARP_OP_REPLY      = 0x0002;
const macAddr_t ARP_REQ_ADDR      = 0xFFFFFFFFFFFF;

const bit<16> TYPE_ARP          = 0x0806;
const bit<16> TYPE_CPU_METADATA = 0x080a;
const bit<16> TYPE_IPV4         = 0x0800;


header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header cpu_metadata_t {
    bit<8> fromCpu;
    bit<16> origEtherType;
    bit<16> srcPort;
    bit<16> dstPort;
}

header arp_t {
    bit<16> hwType;
    bit<16> protoType;
    bit<8> hwAddrLen;
    bit<8> protoAddrLen;
    bit<16> opcode;
    // assumes hardware type is ethernet and protocol is IP
    macAddr_t srcEth;
    ip4Addr_t srcIP;
    macAddr_t dstEth;
    ip4Addr_t dstIP;
}

header ipv4_t { // stolen from cache.p4
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

struct headers {
    ethernet_t        ethernet;
    cpu_metadata_t    cpu_metadata;
    arp_t             arp;
    ipv4_t            ipv4;
}

struct metadata { }

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {
    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_ARP: parse_arp;
            TYPE_CPU_METADATA: parse_cpu_metadata;
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_cpu_metadata {
        packet.extract(hdr.cpu_metadata);
        transition select(hdr.cpu_metadata.origEtherType) {
            TYPE_ARP: parse_arp;
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_arp {
        packet.extract(hdr.arp);
        transition accept;
    }

    state parse_ipv4 { // filling IP headers properly
        packet.extract(hdr.ipv4);
        transition accept;
    }
}

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    // actually verify checksum ?
    apply {
        // verify_checksum(
	    // hdr.ipv4.isValid(),
        // hdr.ipv4.hdrChecksum,
        //     { hdr.ipv4.version,
	    //       hdr.ipv4.ihl,
        //       hdr.ipv4.diffserv,
        //       hdr.ipv4.totalLen,
        //       hdr.ipv4.identification,
        //       hdr.ipv4.flags,
        //       hdr.ipv4.fragOffset,
        //       hdr.ipv4.ttl,
        //       hdr.ipv4.protocol,
        //       hdr.ipv4.srcAddr,
        //       hdr.ipv4.dstAddr },
        //     HashAlgorithm.csum16);
    }
}

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

    counter(1, CounterType.packets) ip_count;
    counter(1, CounterType.packets) arp_count;
    counter(1, CounterType.packets) cpu_count;

    // state variable so we can properly track the next hop IP and use it to find next hop MAC
    ip4Addr_t ip_next_hop;

    action drop() {
        mark_to_drop(standard_metadata);
    }

    action set_egr(port_t port) {
        standard_metadata.egress_spec = port;
    }

    action set_mgid(mcastGrp_t mgid) {
        standard_metadata.mcast_grp = mgid;
    }

    action cpu_meta_encap() {
        hdr.cpu_metadata.setValid();
        hdr.cpu_metadata.origEtherType = hdr.ethernet.etherType;
        hdr.cpu_metadata.srcPort = (bit<16>)standard_metadata.ingress_port;
        hdr.ethernet.etherType = TYPE_CPU_METADATA;
    }

    action cpu_meta_decap() {
        hdr.ethernet.etherType = hdr.cpu_metadata.origEtherType;
        hdr.cpu_metadata.setInvalid();
    }

    action send_to_cpu() {
        cpu_meta_encap();
        standard_metadata.egress_spec = CPU_PORT;
    }

    action update_IPegress(port_t egr_port, ip4Addr_t next_hop) {
        // sets the local exit port & next hop IP addr so we can match on the arp table
        standard_metadata.egress_port = egr_port;
        ip_next_hop = next_hop;
    }

    action update_mac(macAddr_t mac_next_hop) {
        // swaps mac addresses in the ethernet header and puts the next-hop mac addr in dst
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = mac_next_hop;
    }

    table fwd_l2 {
        key = {
            hdr.ethernet.dstAddr: exact;
        }
        actions = {
            set_egr;
            set_mgid;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = drop();
    }
    
    // IP Routing table- key: addr/prefix pairs, value/action: egress port & next-hop IP addr
    // ternary table & definitely a match table
    table ipv4_table {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            update_IPegress;
            send_to_cpu;
            drop;
        }
        size = 1024;
        default_action = send_to_cpu();
    }

    // ARP table- takes IP addr and returns MAC addr for next hop, modified by control plane
    table arp_table {
        key = {
            ip_next_hop: exact;
        }
        actions = {
            update_mac;
            NoAction;
        }
        size = 64;
        default_action = NoAction;
    }

    // CPU IP table- needs know what IPs go internal to the CPU and to PWOSPF
    // software adds IPs to recognize
    table cpu_fwd {
        key = {
            hdr.ipv4.dstAddr: exact;
        }
        actions = {
            update_IPegress;
            send_to_cpu;
            NoAction;
        }
        size = 1024;
        default_action = NoAction;
    }

    apply {
        if (standard_metadata.ingress_port == CPU_PORT)
            cpu_meta_decap();
        
        if (hdr.arp.isValid()) {
            arp_count.count((bit<32>) 1);
        }

        if (hdr.arp.isValid() && standard_metadata.ingress_port != CPU_PORT) {
            send_to_cpu();
        }
        else if (hdr.cpu_metadata.dstPort != 0 && standard_metadata.ingress_port == CPU_PORT) {
            // if a packet coming from the CPU, we need to move the port from
            // CPU metadata to standard metadata
            standard_metadata.egress_spec = (bit<9>) hdr.cpu_metadata.dstPort;
        }
        else if (hdr.ipv4.isValid()) {
            ip_count.count((bit<32>) 1);

            hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
            if (hdr.ipv4.ttl <= 0) {
                drop();
            }

            if(!cpu_fwd.apply().hit) {
                // if it doesn't go to the CPU, do normal IP lookup & routing
                ipv4_table.apply();
                arp_table.apply();
            }
        }
        else if (hdr.ethernet.isValid()) {
            fwd_l2.apply();
        }
        else {
            send_to_cpu();
        }

        if(standard_metadata.egress_spec == CPU_PORT) {
            cpu_count.count((bit<32>) 1);
        }
    }
}

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply { }
}

control MyComputeChecksum(inout headers  hdr, inout metadata meta) {
     apply { // stolen from cache.p4
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

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.cpu_metadata);
        packet.emit(hdr.arp);
        packet.emit(hdr.ipv4);
    }
}

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
