from threading import Thread, Event
from scapy.all import sendp
from scapy.all import Packet, Ether, ARP, ICMP
from scapy.layers.inet import IP
from async_sniff import sniff
from packet_types import CPUMetadata, PWOSPF, HELLO, AD, LSU
import collections
import time

ARP_OP_REQ   = 0x0001
ARP_OP_REPLY = 0x0002
DEF_MASK     = 3
DEF_HELLOINT = 3
SUBNET       = 0xffffff00 # 255.255.255.0 (arbitrary)
DEF_LSUINT   = 30
HELLO_TYPE   = 0x01
LSU_TYPE     = 0x04


ALLSPFRouters = '224.0.0.5'

OSPF_PROT_NUM = 89

class PWOSPFThread(Thread):
    def __init__(self, controller, lsuint):
        super(PWOSPFThread, self).__init__()
        self.controller = controller
        self.lsuint = lsuint

    def run(self):
        if len(self.controller.topology[self.controller.routerID]) < 1:
            for i in range(2, 5):
                if i != 4:
                    port = i
                
                    # building & sending packet
                    pkt = Ether()/CPUMetadata()/IP()/PWOSPF()/HELLO()
                    pkt[Ether].src = self.controller.MAC
                    pkt[Ether].dst = "ff:ff:ff:ff:ff:ff"
                    pkt[CPUMetadata].fromCpu = 1
                    pkt[CPUMetadata].origEtherType = 0x0800
                    pkt[CPUMetadata].srcPort = 1
                    pkt[CPUMetadata].dstPort = port
                    pkt[IP].src = self.controller.routerID
                    pkt[IP].dst = "224.0.0.5"
                    pkt[IP].proto = OSPF_PROT_NUM
                    pkt[PWOSPF].version = 2
                    pkt[PWOSPF].type = HELLO_TYPE
                    pkt[PWOSPF].length = 0
                    pkt[PWOSPF].routerID = self.controller.routerID
                    # print("PKT RID: " + pkt[PWOSPF].routerID)
                    pkt[PWOSPF].areaID = self.controller.areaID
                    pkt[PWOSPF].checksum = 0
                    pkt[HELLO].netmask = DEF_MASK
                    pkt[HELLO].helloint = DEF_HELLOINT

                    # print("sending HELLO from " + self.controller.routerID + " port: " + str(port))
                    self.controller.send(pkt)
        time.sleep(10)

        for i in self.controller.topology[self.controller.routerID]:
                # resolving ports
                port = 2 # hopefully we change this with a value from the table
                nexthop_rid = i[0]
                if nexthop_rid in self.controller.mac_for_ip.keys():
                    MAC = self.controller.mac_for_ip[nexthop_rid]
                    port = self.controller.port_for_mac[MAC]
                
                # building & sending packet
                pkt = Ether()/CPUMetadata()/IP()/PWOSPF()/HELLO()
                pkt[Ether].src = self.controller.MAC
                pkt[Ether].dst = "ff:ff:ff:ff:ff:ff"
                pkt[CPUMetadata].fromCpu = 1
                pkt[CPUMetadata].origEtherType = 0x0800
                pkt[CPUMetadata].srcPort = 1
                pkt[CPUMetadata].dstPort = port
                pkt[IP].src = self.controller.routerID
                pkt[IP].dst = "224.0.0.5"
                pkt[IP].proto = OSPF_PROT_NUM
                pkt[PWOSPF].version = 2
                pkt[PWOSPF].type = HELLO_TYPE
                pkt[PWOSPF].length = 0
                pkt[PWOSPF].routerID = self.controller.routerID
                pkt[PWOSPF].areaID = self.controller.areaID
                pkt[PWOSPF].checksum = 0
                pkt[HELLO].netmask = DEF_MASK
                pkt[HELLO].helloint = DEF_HELLOINT

                # print("sending HELLO from " + self.controller.routerID)
                self.controller.send(pkt)

        for dest in self.controller.topology[self.controller.routerID]:
            # LSU AD packets to be sent
            ads = []
            for i in self.controller.topology[self.controller.routerID]:
                pkt = AD()
                pkt[AD].subnet = self.controller.routerID
                pkt[AD].mask = DEF_MASK
                pkt[AD].routerID = i[0]
                ads.append(pkt)

            # Send LSU packet
            pkt = Ether()/CPUMetadata()/IP()/PWOSPF()/LSU()
            pkt[Ether].src = self.controller.MAC
            pkt[Ether].dst = "ff:ff:ff:ff:ff:ff"
            pkt[CPUMetadata].fromCpu = 1
            pkt[CPUMetadata].origEtherType = 0x0800
            pkt[CPUMetadata].srcPort = 1
            # pkt[CPUMetadata].dstPort gets set by floodLSUPkt()
            pkt[IP].src = self.controller.routerID
            # pkt[IP].dst gets set by floodLSUPkt()
            pkt[IP].proto = OSPF_PROT_NUM
            pkt[PWOSPF].version = 2
            pkt[PWOSPF].type = LSU
            pkt[PWOSPF].length = 0
            pkt[PWOSPF].routerID = self.controller.routerID
            pkt[PWOSPF].areaID = self.controller.areaID
            pkt[PWOSPF].checksum = 0
            pkt[LSU].sequence = self.controller.lsu_seq
            pkt[LSU].ttl = 64
            pkt[LSU].numAds = len(ads)
            pkt[LSU].adList = ads

            self.controller.lsu_seq = self.controller.lsu_seq + 1
            self.controller.floodLSU(pkt)

        now = time.time()
        self.controller.neighborUptime[self.controller.routerID] = now
        for r in self.controller.neighborUptime.keys():
            if ( (now - self.controller.neighborUptime[r]) > ( 3 *self.lsuint)):
                del self.controller.topology[r]

        
        time.sleep(5)

        

class MacLearningController(Thread):
    def __init__(self, sw, MAC, routerID, areaID, start_wait=0.3):
        super(MacLearningController, self).__init__()
        self.sw = sw
        self.start_wait = start_wait # time to wait for the controller to be listenning
        self.iface = sw.intfs[1].name
        self.port_for_mac = {}
        self.mac_for_ip = {}
        self.stop_event = Event()
        self.MAC = MAC
        self.routerID = routerID
        self.areaID = areaID
        # self.interfaces = []
        # self.interface_ips = set()
        self.last_LSU = {} # dict where the key == routerID and value == most recent LSU pkt recieved
        self.topology = {} # this router's picture of the network- each key is a router ID, and the value is a list of adjacent router IDs
        self.neighborUptime = {} # dict where key == adjacent router ID and value = last time we recieved an update from that router
        self.lsu_seq = 0
        self.in_table = [] # list of IPs we have in our routing table

        self.topology[self.routerID] = []

        self.pwospfThread = PWOSPFThread(controller = self, lsuint=DEF_LSUINT)

    def addMacAddr(self, mac, port):
        # Don't re-add the mac-port mapping if we already have it:
        if mac in self.port_for_mac: return

        self.sw.insertTableEntry(table_name='MyIngress.fwd_l2',
                match_fields={'hdr.ethernet.dstAddr': [mac]},
                action_name='MyIngress.set_egr',
                action_params={'port': port})
        self.port_for_mac[mac] = port

    def addIPAddr(self, ip, mac):
        # Don't re-add the ip-mac mapping if we already have it:
        if ip in self.mac_for_ip: return

        self.sw.insertTableEntry(table_name='MyIngress.arp_table',
                match_fields={'ip_next_hop': [ip]},
                action_name='MyIngress.update_mac',
                action_params={'mac_next_hop': mac})
        self.mac_for_ip[ip] = mac

    def handleArpReply(self, pkt):
        self.addMacAddr(pkt[ARP].hwsrc, pkt[CPUMetadata].srcPort)
        self.addIPAddr(pkt[ARP].psrc, pkt[ARP].hwsrc)
        self.send(pkt)

    def handleArpRequest(self, pkt):
        self.addMacAddr(pkt[ARP].hwsrc, pkt[CPUMetadata].srcPort)
        self.addIPAddr(pkt[ARP].psrc, pkt[ARP].hwsrc) # need to add IP addr to ip/mac table too
        # if the packet is going to connected host, create and send a reply
        # if (pkt[ARP].pdst == '100.0.3.10'):
        #     print(self.routerID + '0')
        if pkt[ARP].pdst == self.routerID + '0' or pkt[ARP].pdst == self.routerID:
            # print(pkt[ARP].pdst)
            destination = pkt[ARP].pdst
            pkt[Ether].dst = pkt[Ether].src
            pkt[Ether].src = self.MAC
            pkt[ARP].op = ARP_OP_REPLY
            pkt[ARP].hwdst = pkt[ARP].hwsrc
            pkt[ARP].pdst = pkt[ARP].psrc
            pkt[ARP].psrc = destination
            pkt[ARP].hwsrc = self.MAC
        
        self.send(pkt)

    def findNextHops(self):
        # run djikstra's algorithm to find out the shortest path to any router from self.routerID
        # once we know the path, create a dict where key == destination and value == next hop router ID
        # print("in nexthops, mac for IP: ")
        # print(self.mac_for_ip.keys())
        # print(self.routerID)
        # print(self.topology[self.routerID])
        
        nextHops = {}
        start_queue = []
        visited = set()
        visited.add(self.routerID)
        for r in self.topology[self.routerID]: # iterate through router thruples (r_id, subnet, mask)
            nextHops[r[0]] = r[0] # the router ID is at index 0 of the thruple
            visited.add(r[0])
            # print("R0: " + r[0])
            start_queue.append(r[0])

        queue = collections.deque(start_queue)
        while(queue):
            curr_r_id = queue.popleft()
            for adj_router in self.topology[curr_r_id]:
                adj_routerID = adj_router[0]
                if(adj_routerID not in visited):
                    visited.add(adj_routerID)
                    nextHops[adj_routerID] = nextHops[curr_r_id] # set the optimal egress point for the new node as one for the previous node in the path to self.routerID
                    queue.append(adj_routerID)

        return nextHops

    def updateRouting(self, nextHops):
        # takes dict of next hop router IDs and updates the ipv4 forwarding table in the 
        # data plane

        for destination in nextHops.keys():
            nexthop_rid = nextHops[destination]
            # print("NEXTHOP")
            # print(nexthop_rid)
            # print("curr ID")
            # print(self.routerID)
            # print("MAC FOR IP KEYS")
            # print(self.mac_for_ip.keys())
            checker_rid = nexthop_rid + '0'
            if checker_rid in self.mac_for_ip: # we can only update the table if we know the egress port
                MAC = self.mac_for_ip[checker_rid]
                port = self.port_for_mac[MAC]
                
                if nexthop_rid not in self.in_table:
                    self.sw.insertTableEntry(table_name='MyIngress.ipv4_table',
                        match_fields={'hdr.ipv4.dstAddr': [destination, 32]},
                        action_name='MyIngress.update_IPegress',
                        action_params={'egr_port': port, 'next_hop': nexthop_rid})
                    self.in_table.append(nexthop_rid)

    def floodLSU(self, pkt): # send LSUs to all neighboring routers
        ttl = pkt[LSU].ttl - 1
        if ttl > 0:
            for i in self.topology[self.routerID]:
                    nexthop_rid = i[0]
                    if nexthop_rid in self.mac_for_ip.keys():
                        MAC = self.mac_for_ip[nexthop_rid]
                        port = self.port_for_mac[MAC]
                        
                        floodPkt = pkt
                        floodPkt[CPUMetadata].dstPort = port
                        floodPkt[IP].dst = nexthop_rid
                        floodPkt[LSU].ttl = ttl
                        if floodPkt[IP].dst != floodPkt[IP].src:
                            self.send(floodPkt)
    
    def handlePkt(self, pkt):
        #pkt.show2()
        assert CPUMetadata in pkt, "Should only receive packets from switch with special header"

        # Ignore packets that the CPU sends:
        if pkt[CPUMetadata].fromCpu == 1: return

        if ARP in pkt:
            if pkt[ARP].op == ARP_OP_REQ:
                self.handleArpRequest(pkt)
            elif pkt[ARP].op == ARP_OP_REPLY:
                self.handleArpReply(pkt)

            # print("MAC FOR IP KEYS")
            # print(self.mac_for_ip.keys())
            nextHops = self.findNextHops() # runs BFS and gets a dict of next hops for shortest path
            self.updateRouting(nextHops)   # updates routing table with next hops
            # self.floodLSU(pkt) 

        if IP in pkt:
            # if we get pkt not destined for this switch, there's a problem
            if(pkt[IP].dst != 0 and pkt[IP].dst != ALLSPFRouters): # TODO: make a list of IPs to check against here
                print("cpu recieved IP pkt") # ICMP unreachable?

        if PWOSPF in pkt:
            if pkt[PWOSPF].version != 2:
                return

            if HELLO in pkt:
                # print("recieved HELLO on " + self.routerID + " from " + pkt[IP].src)
                r_id = pkt[IP].src
                
                if r_id in self.neighborUptime:
                    # if we already know we're neighbors, update their uptime so they dont get timed out
                    self.neighborUptime[r_id] = time.time()
                else:
                    # if we don't know this neighbor, add it to the DB, rebuild DB, and send LSU
                    # to other router's neighbors so they know
                    self.neighborUptime[r_id] = time.time()
                    self.topology[self.routerID].append((r_id, SUBNET, pkt[HELLO].mask))
                    self.topology[r_id] = []
                    self.topology[r_id].append((self.routerID, SUBNET, DEF_MASK))
                    
                    # print(self.topology[self.routerID])
                    nextHops = self.findNextHops()
                    self.updateRouting(nextHops)
                

            if LSU in pkt:
                r_id = pkt[IP].src

                if r_id == self.routerID:
                    return # don't care about our own updates

                # check against sequence num
                if r_id in self.last_LSU:
                    prev_pkt = self.last_LSU[r_id]
                    if pkt[LSU].sequence == prev_pkt.sequence: # no new data so return
                        return
                    if pkt[LSU].ads == prev_pkt.ads:
                        self.last_LSU[r_id] = pkt
                        self.floodLSU(pkt)
                        return

                self.last_LSU[r_id] = pkt # if we got here, pkt has usable data

                # need to update topology
                if r_id not in self.topology:
                    self.topology[r_id] = []

                self.neighborUptime[r_id] = time.time() # make sure it doesn't get timed out

                for AD in pkt[LSU].ads:
                    # need to process ads
                    AD_ID = AD.routerid # getting advertisement router ID
                    if AD_ID not in self.topology:
                        self.topology[AD_ID] = []
                    
                    linked_fwd = False
                    linked_bwd = False

                    for i in self.topology[r_id]: # if pkt router ID is linked to AD ID in our view
                        if i[0] == AD_ID:
                            linked_fwd = True
                            break
                    
                    for i in self.topology[AD_ID]: # if they're linked the other way in our view
                        if i[0] == r_id:
                            linked_bwd = True
                            break

                    if not linked_fwd:
                        self.topology[r_id].append((AD_ID, AD.subnet, AD.mask)) # adding the link to our view of the network

                    if not linked_bwd:
                        subnet = None
                        mask = None
                        for i in self.topology[self.routerID]: # finding the subnet and mask of the router that sent this LSU
                            if i[0] == r_id:
                                subnet = i[1]
                                mask = i[2]

                        self.topology[AD_ID].append((r_id, subnet, mask)) # adding that to our view of the network

                nextHops = self.findNextHops() # runs BFS and gets a dict of next hops for shortest path
                self.updateRouting(nextHops)   # updates routing table with next hops
                self.floodLSU(pkt)      


    def send(self, *args, **override_kwargs):
        pkt = args[0]
        assert CPUMetadata in pkt, "Controller must send packets with special header"
        pkt[CPUMetadata].fromCpu = 1
        kwargs = dict(iface=self.iface, verbose=False)
        kwargs.update(override_kwargs)
        sendp(*args, **kwargs)

    def run(self):
        sniff(iface=self.iface, prn=self.handlePkt, stop_event=self.stop_event)

    def start(self, *args, **kwargs):
        super(MacLearningController, self).start(*args, **kwargs)
        self.pwospfThread.start()
        time.sleep(self.start_wait)

    def join(self, *args, **kwargs):
        self.stop_event.set()
        super(MacLearningController, self).join(*args, **kwargs)

