#!/usr/bin/env python3

import time
import threading
import random
from random import randint

import switchyard
from switchyard.lib.address import *
from switchyard.lib.packet import *
from switchyard.lib.userlib import *


class Middlebox:
    def __init__(
            self,
            net: switchyard.llnetbase.LLNetBase,
            dropRate="0.19"
    ):
        self.net = net
        self.dropRate = float(dropRate)
        print(self.dropRate)

    def handle_packet(self, recv: switchyard.llnetbase.ReceivedPacket):
        _, fromIface, packet = recv
        if fromIface == "middlebox-eth0":
            log_debug("Received from blaster")
            '''
            Received data packet
            Should I drop it?
            If not, modify headers & send to blastee
            '''
            if random.random() < self.dropRate:
                log_info("Packet dropped!")
            else:
                packet[Ethernet].dst = EthAddr('20:00:00:00:00:01')
                self.net.send_packet("middlebox-eth1", packet)
                seq2=packet[3].to_bytes()[0:4]
                seq3=int.from_bytes(seq2, byteorder='big', signed=False)
                print("send pac"," ",seq3)
        elif fromIface == "middlebox-eth1":
            log_info("Received from blastee")
            '''
            Received ACK
            Modify headers & send to blaster. Not dropping ACK packets!
            net.send_packet("middlebox-eth0", pkt)
            '''
            packet[Ethernet].dst = EthAddr('10:00:00:00:00:01')
            self.net.send_packet("middlebox-eth0",packet)
        else:
            log_debug("Oops :))")

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

        self.shutdown()

    def shutdown(self):
        self.net.shutdown()


def main(net, **kwargs):
    middlebox = Middlebox(net, **kwargs)
    middlebox.start()
