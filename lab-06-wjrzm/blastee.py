#!/usr/bin/env python3

import time
import threading
from struct import pack
import switchyard
from switchyard.lib.address import *
from switchyard.lib.packet import *
from switchyard.lib.userlib import *


class Blastee:
    def __init__(
            self,
            net: switchyard.llnetbase.LLNetBase,
            blasterIp,
            num
    ):
        self.net = net
        # TODO: store the parameters
        self.blasterIp = IPv4Address(blasterIp)
        self.num = int(num)

    def handle_packet(self, recv: switchyard.llnetbase.ReceivedPacket):
        _, fromIface, packet = recv
        log_info(f"I got a packet from {fromIface}")
        # log_info(f"Pkt: {packet}")
        packetACK = Ethernet() + IPv4(protocol=IPProtocol.UDP) + UDP()
        seq = packet[3].to_bytes()[0:4]
        payload = packet[3].to_bytes()[6:14]
        seqnum=int.from_bytes(seq, byteorder='big', signed=False)
        print(seqnum)
        
        packetACK += seq
        packetACK += payload
        packetACK[Ethernet].src=EthAddr('20:00:00:00:00:01')
        packetACK[IPv4].src=IPv4Address('192.168.200.1')
        packetACK[Ethernet].dst=EthAddr('10:00:00:00:00:01')
        packetACK[IPv4].dst=self.blasterIp
        
        self.net.send_packet(self.net.interfaces()[0],packetACK)

    def start(self):
        '''A running daemon of the blastee.
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

        self.shutdown()

    def shutdown(self):
        self.net.shutdown()


def main(net, **kwargs):
    blastee = Blastee(net, **kwargs)
    blastee.start()
