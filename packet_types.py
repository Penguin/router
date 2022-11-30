from scapy.fields import BitField, ByteField, ShortField, IPField, ByteEnumField, XShortField, LEShortField, LELongField, FieldLenField, PacketListField
from scapy.packet import Packet, bind_layers
from scapy.layers.inet import IP
from scapy.layers.l2 import Ether, ARP
from scapy.all import *

TYPE_CPU_METADATA = 0x080a
PWOSPF_PROTO = 89

PWOSPF_HELLO_TYPE = 1
PWOSPF_LSU_TYPE = 4

PWOSPF_TYPES = {
    PWOSPF_HELLO_TYPE: 'HELLO',
    PWOSPF_LSU_TYPE: 'LSU'
}

class CPUMetadata(Packet):
    name = "CPUMetadata"
    fields_desc = [ ByteField("fromCpu", 0),
                    ShortField("origEtherType", None),
                    ShortField("srcPort", None),
                    ShortField("dstPort", None)]

class PWOSPF(Packet):
    name = 'PWOSPF'
    fields_desc = [
        ByteField('version', 2),
        ByteEnumField('type', 1, PWOSPF_TYPES),
        ShortField('len', None),
        IPField('routerid', '0.0.0.0'),
        IPField('areaid', '224.0.0.5'), # arbitrary value
        XShortField('chksum', None),
        LEShortField('authtype', 0),
        LELongField('auth1', 0),
        LELongField('auth2', 0)
    ]

class HELLO(Packet):
    name = "HELLO"
    fields_desc = [ IPField("mask", None),
                    ShortField("helloint", None),
                    ShortField("padding", 0)]

class AD(Packet):
    name = 'AD'
    fields_desc = [ IPField('subnet', None),
                    IPField('mask', None),
                    IPField('routerid', None)
    ]

class LSU(Packet):
    name = 'LSU'
    fields_desc = [ LEShortField('sequence', 0),
                    LEShortField('ttl', 64),
                    FieldLenField('adcount', None, count_of='ads'),
                    PacketListField('ads', [], AD, 
                        count_from=lambda pkt: pkt.adcount,
                        length_from=lambda pkt: pkt.adcount * 12)
    ]

bind_layers(Ether, CPUMetadata, type=TYPE_CPU_METADATA)
bind_layers(CPUMetadata, IP, origEtherType=0x0800)
bind_layers(CPUMetadata, ARP, origEtherType=0x0806)

bind_layers(IP, PWOSPF, proto=PWOSPF_PROTO)
bind_layers(PWOSPF, HELLO, type=PWOSPF_HELLO_TYPE)
bind_layers(PWOSPF, LSU, type=PWOSPF_LSU_TYPE)