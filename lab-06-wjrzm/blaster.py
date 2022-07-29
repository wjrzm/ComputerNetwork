#!/usr/bin/env python3

import time
from random import randint
import switchyard
from switchyard.lib.address import *
from switchyard.lib.packet import *
from switchyard.lib.userlib import *

class Node():
    def __init__(self, packet, sequence):
        self.packet = packet
        self.sequence = sequence
        self.ackflag = 0

class Blaster:
    def __init__(
            self,
            net: switchyard.llnetbase.LLNetBase,
            blasteeIp,
            num,
            length="100",
            senderWindow="5",
            timeout="300",
            recvTimeout="100"
    ):
        self.net = net
        # TODO: store the parameters
        self.blasteeIp = IPv4Address(blasteeIp)
        self.num = int(num)
        self.length = int(length)
        self.senderWindow = int(senderWindow)
        self.timeout = int(timeout) / 1000
        self.recvTimeout = int(recvTimeout) / 1000
        self.seq = 1
        self.LHS = 1
        self.RHS = 1
        self.reTX = 0
        self.TOs = 0


    def handle_packet(self, recv: switchyard.llnetbase.ReceivedPacket, queue, tempTime):
        _, fromIface, packet = recv
        log_info("I got a packet")
        seq = packet[3].to_bytes()[0:4]
        seqnum = int.from_bytes(seq, byteorder='big', signed=False)
        for node in queue:
            if node.sequence == seqnum:
                node.ackflag = 1
        while len(queue) > 0:
            if queue[0].ackflag == 1 :
                del(queue[0])
                if self.LHS < self.RHS:
                    self.LHS = self.LHS + 1
                tempTime = time.time()
            else:
                break

        

    def handle_no_packet(self, queue, startTime, tempTime):
        log_info("Didn't receive anything")
        now = time.time()
        if now - tempTime > self.timeout:
            for node in queue:
                if node.ackflag == 0:
                    self.net.send_packet(self.net.interfaces()[0],node.packet)
                    self.reTX += 1
                    self.TOs += 1
                
        # Do other things here and send packet
        if self.RHS < self.num:
            if self.RHS - self.LHS + 1 < self.senderWindow:
                # Creating the headers for the packet
                pkt = Ethernet() + IPv4() + UDP()
                pkt[1].protocol = IPProtocol.UDP
                pkt += self.seq.to_bytes(4,byteorder='big', signed=False)
                pkt += self.length.to_bytes(2,byteorder='big', signed=False)
                pkt += b'Test'
                pkt[Ethernet].dst=EthAddr('20:00:00:00:00:01')
                pkt[IPv4].dst=self.blasteeIp
                pkt[Ethernet].src=EthAddr('10:00:00:00:00:01')
                pkt[IPv4].src=IPv4Address('192.168.100.1')
                self.RHS = self.seq
                queue.append(Node(pkt,self.seq))
                self.seq = self.seq + 1
                self.net.send_packet(self.net.interfaces()[0],pkt)
                
        elif len(queue) == 0:
            endTime = time.time()
            totalTime = endTime - startTime
            print("Total TX time (in seconds)",totalTime)
            print("Number of reTX",self.reTX)
            print("Number of coarse TOs",self.TOs)
            print("Throughput (Bps)",(self.reTX + self.num) * self.length / totalTime)
            print("Goodput (Bps)",self.num * self.length / totalTime)

        




    def start(self):
        '''A running daemon of the blaster.
        Receive packets until the end of time.
        '''
        queue = []
        startTime = time.time()
        tempTime = time.time()

        while True:
            print(self.LHS,self.RHS)
            try:
                recv = self.net.recv_packet(timeout=self.recvTimeout)
            except NoPackets:
                self.handle_no_packet(queue, startTime, tempTime)
                continue
            except Shutdown:
                break

            self.handle_packet(recv, queue, tempTime)

        self.shutdown()

    def shutdown(self):
        self.net.shutdown()


def main(net, **kwargs):
    blaster = Blaster(net, **kwargs)
    blaster.start()
