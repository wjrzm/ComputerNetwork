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
    def __init__(self,packet,info):
        self.packet = packet
        self.info = info
        self.cnt = 0
        self.time = 0

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
            head = packet[IPv4]

            head.ttl -= 1
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
                print("There is no match!")
            else:
                queue.append(Node(packet,self.forwardTable[best]))


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
        
        log_info("Print ARP table:")
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
                    queue[0].packet[Ethernet].dst = v
                    queue[0].packet[Ethernet].src = port.ethaddr
                    self.net.send_packet(port,queue[0].packet)
                    del(queue[0])
                    flag = 1
                    break
            
            if flag == 0:
                if queue[0].cnt >= 5:
                    del(queue[0])
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
