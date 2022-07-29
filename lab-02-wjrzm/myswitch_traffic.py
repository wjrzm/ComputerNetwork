'''
Ethernet learning switch in Python.

Note that this file currently has the code to implement a "hub"
in it, not a learning switch.  (I.e., it's currently a switch
that doesn't learn.)
'''
import switchyard
import time
from switchyard.lib.userlib import *
class table:
    def __init__(self,macs,ports,vols):
        self.mac = macs
        self.port = ports
        self.vol = vols

def main(net: switchyard.llnetbase.LLNetBase):
    my_interfaces = net.interfaces()
    mymacs = [intf.ethaddr for intf in my_interfaces]
    list_table = []
    max_len = 5
    

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
                save_flag = 0
                for index in list_table:
                    if eth.src == index.mac:
                        if fromIface != index.port:
                           index.port = fromIface
                            
                        log_info("Received a boardcast which src already is saved")
                        save_flag = 1
                        break
                if save_flag == 0:
                    log_info("Received a boardcast which src is not saved")
                    
                    if len(list_table) == max_len:
                        index = 0
                        vol_min = list_table[index].vol
                        for i in range(0,len(list_table)):
                            if list_table[i].vol < vol_min:
                                index = i
                                vol_min = list_table[i].vol
                        del(list_table[index])
                    list_table.append(table(eth.src,fromIface,0))

                for intf in my_interfaces:
                    if fromIface!= intf.name:
                        log_info (f"Broadcasting packet {packet} to {intf.name}")
                        net.send_packet(intf.name, packet)
            else:
                flag = 0
                save_flag = 0
                for index in list_table:
                    if eth.src == index.mac:
                        if fromIface != index.port:
                           index.port = fromIface
                    
                        log_info("Received a packet which src already is saved")
                        save_flag = 1
                        break
                if save_flag == 0:
                    log_info("Received a packet which src is not saved")
                    
                    if len(list_table) == max_len:
                        index = 0
                        vol_min = list_table[index].vol
                        for i in range(0,len(list_table)):
                            if list_table[i].vol < vol_min:
                                index = i
                                vol_min = list_table[i].vol
                        del(list_table[index])
                    list_table.append(table(eth.src,fromIface,0))
                
                for index in list_table:
                    if eth.dst == index.mac:
                        index.vol += 1
                        net.send_packet(index.port, packet)
                        log_info(f"Flooding packet {packet} to {index.port}")
                        flag = 1
                        break
                if flag != 1:
                    log_info("The dst port is not saved")
                    for intf in my_interfaces:
                        if fromIface!= intf.name:
                            log_info (f"Flooding packet {packet} to {intf.name}")
                            net.send_packet(intf.name, packet)
                            
        for i in range(len(list_table)):
            log_info(f"{list_table[i].mac}  {list_table[i].port}  {list_table[i].vol}")

    net.shutdown()
