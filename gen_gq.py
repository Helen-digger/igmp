
#! /usr/bin/env python

import logging
logging.getLogger("scapy").setLevel(1)


from scapy.all import *
import sys

iface = sys.argv[1]

class IGMP(Packet):
	name = "IGMP"
	fields_desc = [ ByteField("type", 0x11),
	                     ByteField("mrtime",100),
	                    XShortField("chksum", None),
	                        IPField("gaddr", "0.0.0.0")]
	
	def _post_build_(self, p, pay):
		p += pay
		if self.chksum is None:
			ck = checksum(p)
			p = p[:2]+chr(ck>>8)+chr(ck&0xff)+p[4:]
			p = IGMP(chksum)
		return p

x=10
numi=2
numj=10	
print("%s",iface)
c=IGMP()
a=Ether()
b= IP(dst="224.0.0.1",ttl =1,  options=[IPOption_Router_Alert()], tos=0xc0)
a1=Ether()
b1= IP(ttl =1,  options=[IPOption_Router_Alert()], tos=0xc0)
c1=IGMP()	
for i in range(1, numi+1, 1):
	for j in range(1, numj+1, 1):
		b.src="192.168." + str(i) + "." + str(j)
		a.src="00:11:22:33:%02X:%02X" % (i, j) 
		bind_layers( IP, IGMP, frag=0, proto=2) 
		pack=a/b/c
		sendp(pack, iface= iface)
		time.sleep(.10)
 