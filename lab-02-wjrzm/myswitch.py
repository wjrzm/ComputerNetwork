'''
Ethernet learning switch in Python.

Note that this file currently has the code to implement a "hub"
in it, not a learning switch.  (I.e., it's currently a switch
that doesn't learn.)
'''
import switchyard
from switchyard.lib.userlib import *


def main(net: switchyard.llnetbase.LLNetBase):
    my_interfaces = net.interfaces()
    mymacs = [intf.ethaddr for intf in my_interfaces]
    MAC_addr = []
    port = []

    while True:
        try:
            _, fromIface, packet = net.recv_packet()
        except NoPackets:
            continue
        except Shutdown:
            break

        log_debug (f"In {net.name} received packet {packet} on {fromIface}")
        eth = packet.get_header(Ethernet)
        if eth is None:
            log_info("Received a non-Ethernet packet?!")
            return
        if eth.dst in mymacs:
            log_info("Received a packet intended for me")
        else:
            if eth.dst == "ff:ff:ff:ff:ff:ff":
                if fromIface in port:
                    log_info("Received a boardcast which src already is saved")
                else:
                    log_info("Received a boardcast which src is not saved")
                    MAC_addr.append(eth.src)
                    port.append(fromIface)
                for intf in my_interfaces:
                    if fromIface!= intf.name:
                        log_info (f"Broadcasting packet {packet} to {intf.name}")
                        net.send_packet(intf.name, packet)
            else:
                index = 0
                flag = 0
                if fromIface in port:
                    log_info("Received a packet which src already is saved")
                else:
                    log_info("Received a packet which src is not saved")
                    MAC_addr.append(eth.src)
                    port.append(fromIface)
                for addr in MAC_addr:
                    if eth.dst == addr:
                        net.send_packet(port[index], packet)
                        log_info(f"Flooding packet {packet} to {port[index]}")
                        flag = 1
                        break
                    index = index + 1
                if flag != 1:
                    log_info("The dst port is not saved")
                    for intf in my_interfaces:
                        if fromIface!= intf.name:
                            log_info (f"Flooding packet {packet} to {intf.name}")
                            net.send_packet(intf.name, packet)

    net.shutdown()
