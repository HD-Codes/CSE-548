from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.revent import *
from pox.lib.util import dpidToStr
from pox.lib.addresses import EthAddr
from collections import namedtuple
import os
''' New imports here ... '''
import csv
import argparse
from pox.lib.packet.ethernet import ethernet, ETHER_BROADCAST
from pox.lib.addresses import IPAddr
import pox.lib.packet as pkt
from pox.lib.packet.arp import arp
from pox.lib.packet.ipv4 import ipv4
from pox.lib.packet.icmp import icmp

log = core.getLogger()
priority = 50000

l2config = "l2firewall.config"
l3config = "l3firewall.config"


class Firewall (EventMixin):
    def __init__ (self,l2config,l3config):
        self.listenTo(core.openflow)
        self.disbaled_MAC_pair = [] # Shore a tuple of MAC pair which will be installed into the flow table of each switch.
        self.SpoofingTable = dict ()    # Corrispondence of MAC addresses with IPs and ports
        self.BlockedTable = dict ()     # Table of blocked attacks
        self.fw_blocked_macs = list()   # Blocked MAC addresses
        self.fw_blocked_ips  = list()   # Blocked IP addresses
        '''
	    	Read the CSV file
	    '''
        if l2config == "":
            l2config="l2firewall.config"
        if l3config == "":
            l3config="l3firewall.config" 
        with open(l2config, 'rb') as rules:
            csvreader = csv.DictReader(rules) # Map into a dictionary
            for line in csvreader:
				# Read MAC address. Convert string to Ethernet address using the EthAddr() function.
                                if line['mac_0'] != 'any':
				    mac_0 = EthAddr(line['mac_0'])
                                else:
                                    mac_0 = None

                                if line['mac_1'] != 'any':
        				mac_1 = EthAddr(line['mac_1'])
                                else:
                                    mac_1 = None
				# Append to the array storing all MAC pair.
				self.disbaled_MAC_pair.append((mac_0,mac_1))

		with open(l3config) as csvfile:
			log.debug("Reading log file !")
			self.rules = csv.DictReader(csvfile)
			for row in self.rules:
				log.debug("Saving individual rule parameters in rule dict !")
				prio = row['priority']
				s_mac = row['src_mac']
				d_mac = row['dst_mac']
				s_ip = row['src_ip']
				d_ip = row['dst_ip']
				s_port = row['src_port']
				d_port = row['dst_port']
				nw_proto = row['nw_proto']
				print ("src_ip, dst_ip, src_port, dst_port", s_ip,d_ip,s_port,d_port)
                                # Add to firewall rules in memory
				log.debug("Keep firewall rules in memory")
                                if s_mac != "any" and d_mac == "any" and s_ip == "any" and d_ip != "any" and s_port == "any" and d_port == "any" and nw_proto == "any":
                                    self.SpoofingTable [s_mac] = [s_ip, d_ip, 'any']
                                if s_mac == "any" and d_mac == "any" and s_ip != "any" and d_ip != "any" and s_port == "any" and d_port == "any" and nw_proto == "any":
                                    self.SpoofingTable [s_mac] = [s_ip, d_ip, 'any']
                                # Install OVS flow
                                #self.installFlow(event, prio, s_mac, d_mac, s_ip, d_ip, s_port, d_port, nw_proto)

		log.debug("Enabling Firewall Module")

	def replyToARP(self, packet, match, event):
		r = arp()
		r.opcode = arp.REPLY
		r.hwdst = match.dl_src
		r.protosrc = match.nw_dst
		r.protodst = match.nw_src
		r.hwsrc = match.dl_dst
		e = ethernet(type=packet.ARP_TYPE, src = r.hwsrc, dst=r.hwdst)
		e.set_payload(r)
		msg = of.ofp_packet_out()
		msg.data = e.pack()
		msg.actions.append(of.ofp_action_output(port=of.OFPP_IN_PORT))
		msg.in_port = event.port
		event.connection.send(msg)

	def allowOther(self, event, action=None):
                log.debug ("Execute allowOther")
		msg = of.ofp_flow_mod()
		match = of.ofp_match()
		#action = of.ofp_action_output(port = of.OFPP_NORMAL)
		msg.actions.append(action)
		event.connection.send(msg)

	def installFlow(self, event, offset, srcmac, dstmac, srcip, dstip, sport, dport, nwproto):
                log.debug ("Execute installFlow")
		msg = of.ofp_flow_mod()
		match = of.ofp_match()
		if(srcip != None):
			match.nw_src = IPAddr(srcip)
		if(dstip != None):
			match.nw_dst = IPAddr(dstip)	
                if(nwproto):
                        match.nw_proto = int(nwproto)
		match.dl_src = srcmac
		match.dl_dst = dstmac
		match.tp_src = sport
		match.tp_dst = dport
		match.dl_type = pkt.ethernet.IP_TYPE
		msg.match = match
		msg.hard_timeout = 0
		msg.idle_timeout = 200
                #msg.actions.append(None)
                if priority + offset <= 65535:
                    msg.priority = priority + offset		
                else:
                    msg.priority = 65535

		event.connection.send(msg)

	def replyToIP(self, packet, match, event):
        log.debug ("Execute replyToIP")
		srcmac = str(match.dl_src)
		dstmac = str(match.dl_src)
		sport = str(match.tp_src)
		dport = str(match.tp_dst)
		nwproto = str(match.nw_proto)

                with open(l3config) as csvfile:
                    log.debug("Reading log file !")
                    self.rules = csv.DictReader(csvfile)
                    for row in self.rules:
                        prio = row['priority']
                        srcmac = row['src_mac']
                        dstmac = row['dst_mac']
                        s_ip = row['src_ip']
                        d_ip = row['dst_ip']
                        s_port = row['src_port']
                        d_port = row['dst_port']
                        nw_proto = row['nw_proto']
                        
                        log.debug("You are in original code block ...")
                        srcmac1 = EthAddr(srcmac) if srcmac != 'any' else None
                        dstmac1 = EthAddr(dstmac) if dstmac != 'any' else None
                        s_ip1 = s_ip if s_ip != 'any' else None
                        d_ip1 = d_ip if d_ip != 'any' else None
                        s_port1 = int(s_port) if s_port != 'any' else None
                        d_port1 = int(d_port) if d_port != 'any' else None
                        prio1 = int(prio) if prio != None else priority
                        if nw_proto == "tcp":
                            nw_proto1 = pkt.ipv4.TCP_PROTOCOL
                        elif nw_proto == "icmp":
                            nw_proto1 = pkt.ipv4.ICMP_PROTOCOL
                            s_port1 = None
                            d_port1 = None
                        elif nw_proto == "udp":
                            nw_proto1 = pkt.ipv4.UDP_PROTOCOL
                        else:
                            nw_proto1 = None
                            #log.debug("PROTOCOL field is mandatory, Choose between ICMP, TCP, UDP")
                        print (prio1, srcmac1, dstmac1, s_ip1, d_ip1, s_port1, d_port1, nw_proto1)
                        self.installFlow(event, prio1, srcmac1, dstmac1, s_ip1, d_ip1, s_port1, d_port1, nw_proto1)

                #self.allowOther(event)

	def _handle_ConnectionUp (self, event):
		''' Add your logic here ... '''

		'''
		Iterate through the disbaled_MAC_pair array, and for each
		pair we install a rule in each OpenFlow switch
		'''
		self.connection = event.connection
        for spoof_mac, spoof_values in self.SpoofingTable.items():
            srcmac = spoof_mac
            srcip = spoof_values[0]
            dstip = spoof_values[1]
            log.debug ('Loading blocked flows: srcmac=%s, srcip=%s, dstip=%s' %(str(srcmac), str(srcip), str(dstip)))
            message = of.ofp_flow_mod()     # OpenFlow massage. Instructs a switch to install a flow
            match = of.ofp_match()          # Create a match
            if srcmac == 'any':
                match.dl_src = None         # Source MAC
            else:
                match.dl_src = srcmac       # Source MAC
            if srcip == 'any':
                match.nw_src = None         # Source IP address
            else:
                match.nw_src = IPAddr(srcip)    # Source IP address
            if dstip == 'any':
                match.nw_dst = None         # Destination IP address
            else:
                match.nw_dst = IPAddr(dstip)    # Destination IP address
			message.priority = 65535 # Set priority (between 0 and 65535)
            match.dl_type = ethernet.IP_TYPE
			message.match = match			
			event.connection.send(message) # Send instruction to the switch

		log.debug("Firewall rules installed on %s", dpidToStr(event.dpid))

        

	def _handle_PacketIn(self, event):

		packet = event.parsed
		match = of.ofp_match.from_packet(packet)

		if(match.dl_type == packet.ARP_TYPE and match.nw_proto == arp.REQUEST):

		    self.replyToARP(packet, match, event)

		if(match.dl_type == packet.IP_TYPE):

                    # Verify Port Security before processing further
                    if self.port_security_verification(packet, match, event):
                        log.debug("No Attack detected - flow to be allowed")
                    else:
                        log.debug("Attack detected - flow to be blocked")
   
		    self.replyToIP(packet, match, event)

    def port_security_verification(self, packet, match=None, event=None):

            log.debug("Into port_security_verification")

            srcmac = None
            srcip = None
            dstip = None

            if packet.type == packet.IP_TYPE:
                ip_packet = packet.payload
                if ip_packet.srcip == None or ip_packet.dstip == None:
                    log.debug("Packet meaningless for Port Security (likely IPv6)")
                    return True
                if packet.src not in self.SpoofingTable:        
                    for spoof_mac, spoof_values in self.SpoofingTable.items():
                        if str(spoof_values[0]) == str(ip_packet.srcip):
                            log.debug("*** MAC spoofing attempt! IP %s already present for MAC %s and port %s, Requested: from %s on port %s ***" %
                                (str(ip_packet.srcip), str(spoof_mac), str(spoof_values[1]), str(packet.src), str(event.port)))
                            srcmac = None
                            srcip = str(ip_packet.srcip)
                            dstip = str(ip_packet.dstip)
                            self.add_ovs_rule_to_CSV ('any', srcip, dstip)
                    self.SpoofingTable [packet.src] = [ip_packet.srcip, ip_packet.dstip, event.port]
                    log.debug("Adding Port Security entry: %s, %s, %s, %s" %
                        (str(packet.src), str(ip_packet.srcip), str(ip_packet.dstip), str(event.port)))
                    return True
                else:                                          
                    if self.SpoofingTable.get(packet.src) == [ip_packet.srcip, ip_packet.dstip, event.port]:
                        log.debug("Port Security entry already present: %s, %s, %s, %s" %
                            (str(packet.src), str(ip_packet.srcip), str(ip_packet.dstip), str(event.port)))
                        return True
                    else:
                        new_ip = self.SpoofingTable.get(packet.src)[0]
                        new_port = self.SpoofingTable.get(packet.src)[1]
                        if new_ip != ip_packet.srcip:
                            log.debug("*** IP spoofing attempt! MAC %s already present for: IP %s on port %s; Requested: %s on port %s ***" %
                                (str(packet.src), str(new_ip), str(new_port), str(ip_packet.dstip), str(event.port)))
                            srcmac = str(packet.src)
                            srcip = None
                            dstip = str(ip_packet.dstip)
                            self.add_ovs_rule_to_CSV (srcmac, 'any', dstip)
                        if new_port != event.port:
                            log.debug("*** Port has changed for the same MAC address: new port %s, MAC %s: it was IP %s on port %s], Requested: %s ***" %
                                (str(new_port), str(packet.src), str(ip_packet.srcip), str(event.port), str(ip_packet.dstip)))
                            return True
                        log.debug("You should never get here. If you do, I did something wrong!")
                        return True

            if packet.type == packet.ARP_TYPE:
                log.debug("ARP security - for future extension")
                return True
            nwproto = str(match.nw_proto)
            log.debug("port_security_verification - installFlow")
            self.installFlow(event, 32768, srcmac, None, srcip, dstip, None, None, nwproto)
            return False

        def add_ovs_rule_to_CSV(self, srcmac='any', srcip='any', dstip='any'):
            
            log.debug("Entered add_ovs_rule_to_CSV")

            # Check if the rule is not already saved
            # If not, add to firewall rules in memory and then in the CSV file

            to_add = True
            for spoof_mac, spoof_values in self.BlockedTable.items():
                if spoof_mac == str(srcmac) and spoof_values[0] == str(srcip) and spoof_values[1] == str(dstip):
                    log.debug("No need to write log file - entry already present")
                    to_add = False
                    break

            if to_add: 
                self.BlockedTable [str(srcmac)] = [str(srcip), str(dstip)]
                # Open in append mode
                with open(l3config, 'a') as csvfile:
                    log.debug("Writing log file !")

                    csvwriter = csv.DictWriter(csvfile, fieldnames=[
                        'priority','src_mac','dst_mac','src_ip','dst_ip','src_port','dst_port','nw_proto',])
                    log.debug("Saving individual rule parameters in rule dict !")
                    csvwriter.writerow({
                        'priority': 32768,
                        'src_mac' : str(srcmac),
                        'dst_mac' : 'any',
                        'src_ip'  : str(srcip),
                        'dst_ip'  : str(dstip),
                        'src_port': 'any',
                        'dst_port': 'any',
                        'nw_proto': 'any',
                        })
                    log.debug("Saved: srcip=%s dstip=%s srcmac=%s" % (str(srcip), str(dstip), str(srcmac)))


       


def launch (l2config="l2firewall.config",l3config="l3firewall.config"):
	'''
	Starting the Firewall module
	'''
	parser = argparse.ArgumentParser()
	parser.add_argument('--l2config', action='store', dest='l2config',
					help='Layer 2 config file', default='l2firewall.config')
	parser.add_argument('--l3config', action='store', dest='l3config',
					help='Layer 3 config file', default='l3firewall.config')
	core.registerNew(Firewall,l2config,l3config)

 def add_ovs_rule_to_CSV(self, srcmac='any', srcip='any', dstip='any'):
            
            log.debug("Entered add_ovs_rule_to_CSV")

            # Check if the rule is not already saved
            # If not, add to firewall rules in memory and then in the CSV file

            to_add = True
            for spoof_mac, spoof_values in self.BlockedTable.items():
                if spoof_mac == str(srcmac) and spoof_values[0] == str(srcip) and spoof_values[1] == str(dstip):
                    log.debug("No need to write log file - entry already present")
                    to_add = False
                    break

            if to_add: 
                self.BlockedTable [str(srcmac)] = [str(srcip), str(dstip)]
                # Open in append mode
                with open(l3config, 'a') as csvfile:
                    log.debug("Writing log file !")

                    csvwriter = csv.DictWriter(csvfile, fieldnames=[
                        'priority','src_mac','dst_mac','src_ip','dst_ip','src_port','dst_port','nw_proto',])
                    log.debug("Saving individual rule parameters in rule dict !")
                    csvwriter.writerow({
                        'priority': 32768,
                        'src_mac' : str(srcmac),
                        'dst_mac' : 'any',
                        'src_ip'  : str(srcip),
                        'dst_ip'  : str(dstip),
                        'src_port': 'any',
                        'dst_port': 'any',
                        'nw_proto': 'any',
                        })
                    log.debug("Saved: srcip=%s dstip=%s srcmac=%s" % (str(srcip), str(dstip), str(srcmac)))

        
