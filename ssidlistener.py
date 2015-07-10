#!/usr/bin/env python

'''

Created by Tim Wilkes <gitspamrepo@php-systems.com>

Listens for an SSID to be broadcast as either a probe request or Beacon,
Then exits. Intended to be used as a delay to start another program.


'''

import os
import optparse
from scapy.all import *
from pprint import pprint

ssid = None

def detectSSID(pkts):

	mgttypes = (0, 2, 4)

	print "[!] Hunting for SSID: " + ssid

	for pkt in pkts:
		if pkt.haslayer(Dot11):
			if pkt.type == 0 and pkt.subtype in mgttypes: 		
				print pkt.addr2 + " " + pkt.info
				if str(pkt.info) == str(ssid):
					print "[+] SSID Found. Exitiing."
					exit(0)
	

def main():
	global ssid
	parser = optparse.OptionParser('usage %prog '+ '-C <capture file> -E <ESSID> -i <interface>')
	parser.add_option('-C', dest='pcapfile', type='string', help='specify pcap file to examine')
	parser.add_option('-E', dest='ssid', type='string', help='specify ssid to look for')
	parser.add_option('-i', dest='interface', type='string', help='specify interface to listen on')

	(options, args) = parser.parse_args()

	pcapfile 	= options.pcapfile
	interface 	= options.interface
	ssid		= options.ssid

	if (pcapfile == None) & (interface == None):
		print parser.usage
		exit(1)
	if (pcapfile != None) & (interface != None):
		print "[-] Specifying pcap and interface not permitted."
                print parser.usage
                exit(1)
	if (ssid == None):
                print parser.usage
                exit(1)
	
	if pcapfile is not None:
		print "[+] Loading Pcap file"
		pkts = rdpcap(pcapfile)
		detectSSID(pkts)
	if interface is not None:
		print "[+] Using wifi interface: " + interface
		sniff(iface=interface, prn=detectSSID)
	
	print "[-] Packet not detected."
	exit(2)

if __name__ == '__main__':
	main()





