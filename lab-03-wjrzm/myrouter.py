#!/usr/bin/env python3

'''
Basic IPv4 router (static routing) in Python.
'''
import time
import switchyard
from switchyard.lib.userlib import *


class Router(object):
    def __init__(self, net: switchyard.llnetbase.LLNetBase):
        self.net = net
        # other initialization stuff here
        self.ipList = [intf.ipaddr for intf in net.interfaces()]
        self.macList = [intf.ethaddr for intf in net.interfaces()]
        self.arpTable = {}


    def handle_packet(self, recv: switchyard.llnetbase.ReceivedPacket):
        timestamp, ifaceName, packet = recv
        # TODO: your logic here
        log_info("Got a packet: {}".format(str(packet)))
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





    def start(self):
        '''A running daemon of the router.
        Receive packets until the end of time.
        '''
        while True:
            try:
                recv = self.net.recv_packet(timeout=1.0)
            except NoPackets:
                continue
            except Shutdown:
                break

            self.handle_packet(recv)

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
