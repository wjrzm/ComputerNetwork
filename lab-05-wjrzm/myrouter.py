#!/usr/bin/env python3

'''
Basic IPv4 router (static routing) in Python.
'''
import time
import switchyard
from switchyard.lib.userlib import *
import ipaddress

class Info():
    def __init__(self,prefix,mask,nexthop,name):
        self.prefix = prefix
        self.mask = mask
        self.nexthop = nexthop
        self.name = name

class Node():
    def __init__(self,packet,info = None,icmp_info = None):
        self.packet = packet
        self.info = info
        self.cnt = 0
        self.time = 0
        self.icmp_info = icmp_info

class Router(object):
    def __init__(self, net: switchyard.llnetbase.LLNetBase):
        self.net = net
        # other initialization stuff here
        self.ipList = [intf.ipaddr for intf in net.interfaces()]
        self.macList = [intf.ethaddr for intf in net.interfaces()]
        self.arpTable = {}
        self.forwardTable = []
        self.interfaces = net.interfaces()

        for intf in net.interfaces():
            prefix = IPv4Network(str(intf.ipaddr) + "/" + str(intf.netmask),strict=False)
            node_info = Info(prefix.network_address,intf.netmask,None,intf.name)
            self.forwardTable.append(node_info)

        file = open("forwarding_table.txt")
        while 1:
            line = file.readline()
            if not line:
                break
            else:
                line = line.strip('\n').split(" ")
                node_info = Info(IPv4Address(line[0]),IPv4Address(line[1]),IPv4Address(line[2]),line[3])
                self.forwardTable.append(node_info)

        for i in self.forwardTable:
            print(i.prefix," ",i.mask," ",i.nexthop," ",i.name)

    def handle_packet(self, recv: switchyard.llnetbase.ReceivedPacket,queue):
        timestamp, ifaceName, packet = recv
        # TODO: your logic here

        log_info("Got a packet: {}".format(str(packet)))

        if packet.has_header(IPv4):
            head = (packet[IPv4])
            if head.dst in self.ipList:
                log_info("IP has matched!")
                if packet.has_header(ICMP):
                    if packet[ICMP].icmptype == ICMPType.EchoRequest:
                        log_info("Received an ICMP request!")
                        
                        icmp = ICMP()
                        icmp.icmptype = ICMPType.EchoReply
                        icmp.icmpcode = ICMPCodeEchoReply.EchoReply
                        icmp.icmpdata.sequence = packet[ICMP].icmpdata.sequence
                        icmp.icmpdata.data = packet[ICMP].icmpdata.data

                        ip = IPv4()
                        ip.src = head.dst
                        ip.dst = head.src
                        ip.protocol = IPProtocol.ICMP
                        ip.ttl = 64
                        ip.ipid = 0

                        ether = Ethernet()
                        ether.ethertype = EtherType.IP

                        packet = ether + ip + icmp
                        head = (packet[IPv4])
                    
                else:
                    log_info("Not an ICMP packets!")
                    
                    ether = Ethernet()
                    ether.src = packet[Ethernet].dst
                    ether.dst = packet[Ethernet].src
                    ether.ethertype = EtherType.IP

                    i = packet.get_header_index(Ethernet)
                    del packet[i]

                    icmp = ICMP()
                    icmp.icmptype = ICMPType.DestinationUnreachable
                    icmp.icmpcode = ICMPCodeDestinationUnreachable.PortUnreachable
                    icmp.icmpdata.data = packet.to_bytes()[:28]

                    ip = IPv4()
                    for i in self.interfaces:
                        if i.name == ifaceName:
                            ip.src = i.ipaddr
                            break
                    
                    ip.dst = head.src
                    ip.protocol = IPProtocol.ICMP
                    ip.ttl = 64
                    ip.ipid = 0



                    packet = ether + ip + icmp
                    head = packet[IPv4]
                        
            head.ttl -= 1
            print(head.ttl)

            if head.ttl <= 0:
                log_info("TTL decreased to zero!")

                ether = Ethernet()
                ether.src = packet[Ethernet].dst
                ether.dst = packet[Ethernet].src
                ether.ethertype = EtherType.IP

                i = packet.get_header_index(Ethernet)
                del packet[i]

                icmp = ICMP()
                icmp.icmptype = ICMPType.TimeExceeded
                icmp.icmpcode = ICMPCodeTimeExceeded.TTLExpired
                icmp.icmpdata.data = packet.to_bytes()[:28]

                ip = IPv4()
                for i in self.interfaces:
                    if i.name == ifaceName:
                        ip.src = i.ipaddr
                        break
                
                ip.dst = head.src
                ip.protocol = IPProtocol.ICMP
                ip.ttl = 64
                ip.ipid = 0

                packet = ether + ip + icmp
                head = packet[IPv4]
                print("TimeExceed",packet)

            print("ipv4",head)
            prefixlen = 0
            index = 0
            best = -1
            for i in self.forwardTable:
                if (int(head.dst) & int(i.mask)) == int(i.prefix):
                    netprefix = IPv4Network(str(i.prefix)+"/"+str(i.mask))
                    if netprefix.prefixlen > prefixlen:
                        prefixlen = netprefix.prefixlen
                        best = index
                index += 1
            if best == -1:
                log_info("There is no match!")

                ether = Ethernet()
                ether.src = packet[Ethernet].dst
                ether.dst = packet[Ethernet].src
                ether.ethertype = EtherType.IP

                i = packet.get_header_index(Ethernet)
                del packet[i]

                icmp = ICMP()
                icmp.icmptype = ICMPType.DestinationUnreachable
                icmp.icmpcode = ICMPCodeDestinationUnreachable.NetworkUnreachable

                icmp.icmpdata.data = packet.to_bytes()[:28]

                ip = IPv4()
                for i in self.interfaces:
                    if i.name == ifaceName:
                        ip.src = i.ipaddr
                        break
                
                ip.dst = head.src
                ip.protocol = IPProtocol.ICMP
                ip.ttl = 64
                ip.ipid = 0

                packet = ether + ip + icmp
                head = packet[IPv4]

                prefixlen = 0
                index = 0
                best = -1
                for i in self.forwardTable:
                    if (int(head.dst) & int(i.mask)) == int(i.prefix):
                        netprefix = IPv4Network(str(i.prefix)+"/"+str(i.mask))
                        if netprefix.prefixlen > prefixlen:
                            prefixlen = netprefix.prefixlen
                            best = index
                    index += 1
                print("Best",best)
                queue.append(Node(packet,self.forwardTable[best],icmp_info=ifaceName))

            else:
                queue.append(Node(packet,self.forwardTable[best],icmp_info=ifaceName))
        

        arp = packet.get_header(Arp)
        if arp is None:
            log_info("It's not an arp packet!")
        else:
            log_info("Received an arp packet!")
            self.arpTable[arp.senderprotoaddr] = arp.senderhwaddr
            if arp.operation == 1:
                log_info("Received a request!")
                for i in range(len(self.ipList)):
                    if self.ipList[i] == arp.targetprotoaddr:
                        log_info("I got it!")
                        answer = create_ip_arp_reply(self.macList[i],arp.senderhwaddr,self.ipList[i],arp.senderprotoaddr)
                        self.net.send_packet(ifaceName,answer)
                        log_info("Sent an answer: {}".format(str(answer)))
                        break
            else:
                if arp.operation == 2:
                    log_info("Received a reply!")
                    self.arpTable[arp.targetprotoaddr] = arp.targethwaddr
                else:
                    log_info("Received an arp which is not a request or a reply!")
        
        print("Print ARP table:")
        for (k,v) in self.arpTable.items():
            print("%s \t" % k,v)

    def handle_queue(self,queue):
        if len(queue) != 0:
            for intf in self.interfaces:
                if intf.name == queue[0].info.name:
                    port = intf
            if queue[0].info.nexthop is None:
                targetIp = queue[0].packet[IPv4].dst
            else:
                targetIp = queue[0].info.nexthop

            flag = 0

            for (k,v) in self.arpTable.items():
                if k == targetIp:
                    print("common",targetIp)
                    queue[0].packet[Ethernet].dst = v
                    queue[0].packet[Ethernet].src = port.ethaddr
                    print("send pac (find) ",queue[0].packet," through ",port)   
                    self.net.send_packet(port,queue[0].packet)
                    del(queue[0])
                    flag = 1
                    break
            
            if flag == 0:
                if queue[0].cnt >= 5:
                    log_info("Count number bigger than five!")

                    ether = Ethernet()
                    ether.src = queue[0].packet[Ethernet].dst
                    ether.dst = queue[0].packet[Ethernet].src
                    ether.ethertype = EtherType.IP

                    i = queue[0].packet.get_header_index(Ethernet)
                    del queue[0].packet[i]

                    icmp = ICMP()
                    icmp.icmptype = ICMPType.DestinationUnreachable
                    icmp.icmpcode = ICMPCodeDestinationUnreachable.HostUnreachable
                    icmp.icmpdata.data = queue[0].packet.to_bytes()[:28]

                    ip = IPv4()
                    for i in self.interfaces:
                        if i.name == queue[0].icmp_info:
                            ip.src = i.ipaddr
                            break
                    
                    ip.dst = queue[0].packet[IPv4].src
                    ip.protocol = IPProtocol.ICMP
                    ip.ttl = 64
                    ip.ipid = 0

                    packet = ether + ip + icmp
                    head = packet[IPv4]

                    prefixlen = 0
                    index = 0
                    best = -1
                    for i in self.forwardTable:
                        if (int(head.dst) & int(i.mask)) == int(i.prefix):
                            netprefix = IPv4Network(str(i.prefix)+"/"+str(i.mask))
                            if netprefix.prefixlen > prefixlen:
                                prefixlen = netprefix.prefixlen
                                best = index
                        index += 1
                    
                    immediate = Node(packet,self.forwardTable[best],queue[0].icmp_info)
                    del(queue[0])

                    for intf in self.interfaces:
                        if intf.name == immediate.info.name:
                            port = intf
                    
                    if immediate.info.nexthop is None:
                        targetIp = immediate.packet[IPv4].dst
                    else:
                        targetIp = immediate.info.nexthop

                    tempFlag = 0

                    for (k,v) in self.arpTable.items():
                        if k == targetIp:
                            immediate.packet[Ethernet].dst = v
                            immediate.packet[Ethernet].src = port.ethaddr
                            self.net.send_packet(port,immediate.packet)
                            tempFlag = 1
                            break
                    
                    if tempFlag == 0:
                        ether = Ethernet()
                        ether.src = port.ethaddr
                        ether.dst = 'ff:ff:ff:ff:ff:ff'
                        ether.ethertype = EtherType.ARP
                        arp = Arp(operation=ArpOperation.Request,
                                senderhwaddr=port.ethaddr,
                                senderprotoaddr=port.ipaddr,
                                targethwaddr='ff:ff:ff:ff:ff:ff',
                                targetprotoaddr=targetIp)
                        arppacket = ether + arp

                        self.net.send_packet(port,arppacket)
                        immediate.cnt += 1
                        immediate.time = time.time()
                        queue.append(immediate)

                else:
                    if (queue[0].cnt == 0) or (time.time() - queue[0].time) > 1:
                        ether = Ethernet()
                        ether.src = port.ethaddr
                        ether.dst = 'ff:ff:ff:ff:ff:ff'
                        ether.ethertype = EtherType.ARP
                        arp = Arp(operation=ArpOperation.Request,
                                senderhwaddr=port.ethaddr,
                                senderprotoaddr=port.ipaddr,
                                targethwaddr='ff:ff:ff:ff:ff:ff',
                                targetprotoaddr=targetIp)
                        arppacket = ether + arp     
                        self.net.send_packet(port,arppacket)
                        queue[0].cnt += 1
                        queue[0].time = time.time()







    def start(self):
        '''A running daemon of the router.
        Receive packets until the end of time.
        '''

        queue = []
        
        while True:

            self.handle_queue(queue)

            try:
                recv = self.net.recv_packet(timeout=1.0)
            except NoPackets:
                continue
            except Shutdown:
                break

            self.handle_packet(recv,queue)

        self.stop()

    def stop(self):
        self.net.shutdown()


def main(net):
    '''
    Main entry point for router.  Just create Router
    object and get it going.
    '''
    router = Router(net)
    router.start()
