from p4app import P4Mininet
from my_topo import SingleSwitchTopo, HatTopo
from controller import MacLearningController
import time

# Add three hosts. Port 1 (h1) is reserved for the CPU.
N = 3

topo = HatTopo() # SingleSwitchTopo(N)
net = P4Mininet(program='l2switch.p4', topo=topo, auto_arp=False)
net.start()

sw1, r1, h1 = net.get('s1'), net.get('cpu1'), net.get('h1')
sw2, r2, h2 = net.get('s2'), net.get('cpu2'), net.get('h2')
sw3, r3, h3 = net.get('s3'), net.get('cpu3'), net.get('h3')

# Add a mcast group for all ports (except for the CPU port)
bcast_mgid = 1
sw1.addMulticastGroup(mgid=bcast_mgid, ports=range(2, N+1))
sw2.addMulticastGroup(mgid=bcast_mgid, ports=range(2, N+1))
sw3.addMulticastGroup(mgid=bcast_mgid, ports=range(2, N+1))

# Send MAC bcast packets to the bcast multicast group
sw1.insertTableEntry(table_name='MyIngress.fwd_l2',
        match_fields={'hdr.ethernet.dstAddr': ["ff:ff:ff:ff:ff:ff"]},
        action_name='MyIngress.set_mgid',
        action_params={'mgid': bcast_mgid})
sw2.insertTableEntry(table_name='MyIngress.fwd_l2',
        match_fields={'hdr.ethernet.dstAddr': ["ff:ff:ff:ff:ff:ff"]},
        action_name='MyIngress.set_mgid',
        action_params={'mgid': bcast_mgid})
sw3.insertTableEntry(table_name='MyIngress.fwd_l2',
        match_fields={'hdr.ethernet.dstAddr': ["ff:ff:ff:ff:ff:ff"]},
        action_name='MyIngress.set_mgid',
        action_params={'mgid': bcast_mgid})

# Set attached host IPs in local IP tables
sw1.insertTableEntry(table_name='MyIngress.cpu_fwd',
        match_fields={'hdr.ipv4.dstAddr': '100.0.1.10'},
        action_name='MyIngress.update_IPegress',
        action_params={'egr_port': 4, 'next_hop': '100.0.1.10'})
sw2.insertTableEntry(table_name='MyIngress.cpu_fwd',
        match_fields={'hdr.ipv4.dstAddr': '100.0.2.10'},
        action_name='MyIngress.update_IPegress',
        action_params={'egr_port': 4, 'next_hop': '100.0.2.10'})
sw3.insertTableEntry(table_name='MyIngress.cpu_fwd',
        match_fields={'hdr.ipv4.dstAddr': '100.0.3.10'},
        action_name='MyIngress.update_IPegress',
        action_params={'egr_port': 4, 'next_hop': '100.0.3.10'})

print('Booting routers...\n')

# Start the controllers
cpu1 = MacLearningController(sw1, r1.MAC(), r1.IP(), 1)
cpu2 = MacLearningController(sw2, r2.MAC(), r2.IP(), 1)
cpu3 = MacLearningController(sw3, r3.MAC(), r3.IP(), 1)
cpu1.start()
cpu2.start()
cpu3.start()

print('Pinging host 100.0.3.10 from host 100.0.1.10:\n')
print(h1.cmd('arping -c1 100.0.3.10'))

print('Pinging h1 from h2\n')
print(h2.cmd('arping -c1 100.0.1.10'))

print("Pinging h2 from h3\n")
print(h3.cmd('arping -c1 100.0.2.10'))

print('Waiting for PWOSPF setup...\n')

time.sleep(10) # allow time for PWOSPF to settle

# print('Reading counters from switch 1:\n')
# print('IP packets: ' + str(sw1.readCounter('ip_count', 1)[0]))
# print('ARP packets: ' + str(sw1.readCounter('arp_count', 1)[0]))
# print('CPU packets: ' + str(sw1.readCounter('cpu_count', 1)[0]))
# print('')

# # Add a mcast group for all ports (except for the CPU port)
# bcast_mgid = 1
# sw = net.get('s1')
# sw.addMulticastGroup(mgid=bcast_mgid, ports=range(2, N+1))

# # Send MAC bcast packets to the bcast multicast group
# sw.insertTableEntry(table_name='MyIngress.fwd_l2',
#         match_fields={'hdr.ethernet.dstAddr': ["ff:ff:ff:ff:ff:ff"]},
#         action_name='MyIngress.set_mgid',
#         action_params={'mgid': bcast_mgid})

# # Start the MAC learning controller
# cpu = MacLearningController(sw, sw.MAC(), sw.IP(), 1) # (self, sw, MAC, routerID, areaID, start_wait=0.3)
# cpu.start()

# h2, h3 = net.get('h2'), net.get('h3')

# print(h2.cmd('arping -c1 10.0.0.3'))

# print(h3.cmd('ping -c1 10.0.0.2'))

# These table entries were added by the CPU:
sw1.printTableEntries()
sw2.printTableEntries()
sw3.printTableEntries()
