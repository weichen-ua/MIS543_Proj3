from pox.core import core
from pox.openflow import *
import pox.openflow.libopenflow_01 as of
from pox.lib.packet.arp import arp
from pox.lib.packet.ipv4 import ipv4
from pox.lib.packet.ethernet import ethernet, ETHER_BROADCAST
from pox.lib.addresses import EthAddr, IPAddr
import time
import random

"""
Run it with --ip=<Service IP> --servers=IP1,IP2,...
"""

log = core.getLogger()
FLOW_TIMEOUT = 2

class SimpleLoadBalancer(object):
    def __init__(self, service_ip, server_ips = []): #initialize
        core.openflow.addListeners(self)
        self.lb_ip = service_ip
        self.server_ips = server_ips
        self.client_arp_table = {} # IP -> MAC,port
        self.server_arp_table = {} # IP -> MAC,port
        self.flow_table = {} # Client IP -> Server IP, last updated

    def _handle_ConnectionUp(self, event): #new switch connection
        self.lb_mac = EthAddr("0A:00:00:00:00:01") #fake mac of load balancer
        self.connection = event.connection

        self.probe_servers()
        log.info("IP Load Balancer Ready.")

    def probe_servers(self):
        # ask for the MAC addresses of the servers
        for server_ip in self.server_ips:
            # construct arp packet  
            r = arp()
            r.hwtype = r.HW_TYPE_ETHERNET
            r.prototype = r.PROTO_TYPE_IP
            r.opcode = r.REQUEST
            r.hwdst = ETHER_BROADCAST
            r.protodst = server_ip
            r.hwsrc = self.lb_mac   # 
            r.protosrc = self.lb_ip
            e = ethernet(type=ethernet.ARP_TYPE, src=self.lb_mac,
                         dst=ETHER_BROADCAST)
            e.set_payload(r)

            # broadcast the arp request
            msg = of.ofp_packet_out()
            msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
            msg.data = e.pack()
            msg.in_port = of.OFPP_NONE
            self.connection.send(msg)

    #update load balancing mapping
    def update_lb_mapping(self, client_ip): 
        ### write your code here ###
        # update the load-balance mapping here
        # 1. IF no flow for client_ip, THEN randomly choose a server from existing servers
        # 2. IF the flow for client_ip has expired, THEN randomly choose a server from existing servers
        # 3. IF the flow for client_ip has not expired, THEN update the latest time for the flow
        log.info("called function: update_lb_mapping")
        pass
        ### your code ends here ###
        
    # update server_arp_table using arp message from the server
    def update_server_arp_table(self, server_ip, server_mac, inport):
        if (self.server_arp_table.get(server_ip, (None,None)) != (server_mac,inport)):
            self.server_arp_table[server_ip] = server_mac,inport
            log.info("Server %s (MAC %s) is connected at port %s." % (server_ip, server_mac, inport))

    # update client_arp_table using mac 
    def update_client_arp_table(self, client_ip, client_mac, inport):
        ### write your code here ###
        # code is similar to update_server_arp_table
        # make changes that you see proper
        log.info("called function: update_client_arp_table")
        pass 
        ### your code ends here ###

    # Answer to ARP requests from the servers searching the MAC addresses of clients
    def send_proxied_arp_reply_to_server(self, arp_pkt):
        ### write your code here ###
        # construct the arp reply to the server 
        # code is similar to send_proxied_arp_reply_to_client
        # make changes that you see proper
        log.info("called function: send_proxied_arp_reply_to_server")
        pass 
        ### your code ends here ###
    
    # reply to arp requests from clients
    def send_proxied_arp_reply_to_client(self, arp_pkt):
        client_ip = arp_pkt.protosrc
        # construct arp reply to clients
        r = arp()
        r.hwtype = r.HW_TYPE_ETHERNET
        r.prototype = r.PROTO_TYPE_IP
        r.opcode = r.REPLY
        r.hwdst = ETHER_BROADCAST
        r.protodst = client_ip          # the destination IP in arp reply 
        r.hwsrc = self.lb_mac           # the source MAC in arp reply
        r.protosrc = self.lb_ip         # the source IP in arp reply
        e = ethernet(type=ethernet.ARP_TYPE, src=self.lb_mac,
                     dst=ETHER_BROADCAST)
        e.set_payload(r)

        # construct and send the OpenFlow message
        msg = of.ofp_packet_out()
        msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
        msg.data = e.pack()
        msg.in_port = of.OFPP_NONE
        self.connection.send(msg)
    
    # Direct flows from the clients to the servers.
    def forward_client_to_server(self, event, client_ip):
        ### write your code here ###
        # code is similar to forward_server_to_client
        # make changes that you see proper
        log.info("called function: forward_client_to_server")
        pass 
        ### your code ends here ###
    
    # Direct flows from the servers to the clients. 
    def forward_server_to_client(self, event, server_ip, client_ip):
        # obtain the client mac address and switch port from client_arp_table
        mac,port = self.client_arp_table.get(client_ip) 

        
        actions = []
        # set the correct mac and port
        actions.append(of.ofp_action_dl_addr.set_dst(mac))
        # from the client's perspective, the packet should be from lb IP and MAC
        actions.append(of.ofp_action_dl_addr.set_src(self.lb_mac))
        actions.append(of.ofp_action_nw_addr.set_src(self.lb_ip))
        actions.append(of.ofp_action_output(port = port))
        
        # send the message
        msg = of.ofp_packet_out()
        msg.actions = actions
        msg.data = event.ofp
        msg.in_port = of.OFPP_NONE

        self.connection.send(msg)
        log.info("Packet from server %s forwarded to client %s." % (server_ip, client_ip))

    

    def _handle_PacketIn(self, event):
        packet = event.parsed
        connection = event.connection
        inport = event.port
        if packet.type == packet.ARP_TYPE:

            arp_pkt = packet.find("arp")

            if arp_pkt.protosrc in self.server_ips: # arp request/reply from the servers
                if arp_pkt.protodst == self.lb_ip:  # if the MAC destination is lb_ip, it means it's reply to the lb's probes
                    server_ip = arp_pkt.protosrc
                    server_mac = arp_pkt.hwsrc
                    self.update_server_arp_table(server_ip, server_mac, inport)
                else:                               # otherwise, request for client MAC
                    self.send_proxied_arp_reply_to_server(arp_pkt)

            elif arp_pkt.protodst == self.lb_ip:    # arp from the clients aiming for the service IP
                client_ip = arp_pkt.protosrc
                client_mac = arp_pkt.hwsrc
                self.update_client_arp_table(client_ip, client_mac, inport)
                self.send_proxied_arp_reply_to_client(arp_pkt)
                
        
        elif packet.type == packet.IP_TYPE:
            
            ip_pkt = packet.find("ipv4")

            if ip_pkt.dstip == self.lb_ip: # a client visiting server
                client_ip = ip_pkt.srcip

                # we may need to add a new client_ip in the client arp table
                if not self.client_arp_table.has_key(client_ip):
                    client_mac = packet.src
                    self.update_client_arp_table(client_ip, client_mac, inport)
                
                self.update_lb_mapping(client_ip)
                self.forward_client_to_server(event, client_ip)
                
            elif ip_pkt.srcip in self.server_ips: # a server replying to a client
                client_ip = ip_pkt.dstip
                server_ip = ip_pkt.srcip
                self.forward_server_to_client(event, server_ip, client_ip)

        return

#launch application with following arguments:   
#ip: public service ip, servers: ip addresses of servers (in string format)
def launch(ip, servers): 
    log.info("Loading Simple Load Balancer module")
    server_ips = servers.replace(","," ").split()
    server_ips = [IPAddr(x) for x in server_ips]
    service_ip = IPAddr(ip)
    core.registerNew(SimpleLoadBalancer, service_ip, server_ips)