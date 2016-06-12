#!/usr/bin/python

#GNU GPLv3
# nWatch.py - handy tool for host discovery, portscanning and operating system fingerprinting.
#    Copyright (C) <2014>  <M U Suraj>
#
#    This program is free software; you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation; either version 2 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License along
#    with this program; if not, write to the Free Software Foundation, Inc.,
#    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

import sys
import logging
from colorama import Fore, init, Style
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
import time
import nmap
from socket import AF_INET, AF_INET6, inet_ntop
from ctypes import *
import ctypes, ctypes.util

#c-lib load
libc = ctypes.cdll.LoadLibrary(ctypes.util.find_library('c'))
#structs
class struct_sockaddr(Structure):
    _fields_ = [
        ('sa_family', c_ushort),('sa_data', c_byte * 14),]

class struct_sockaddr_in(Structure):
    _fields_ = [
        ('sin_family', c_ushort),('sin_port', c_uint16),('sin_addr', c_byte * 4)]

class struct_sockaddr_in6(Structure):
    _fields_ = [
        ('sin6_family', c_ushort),
        ('sin6_port', c_uint16),
        ('sin6_flowinfo', c_uint32),
        ('sin6_addr', c_byte * 16),
        ('sin6_scope_id', c_uint32)]

class union_ifa_ifu(Union):
    _fields_ = [('ifu_broadaddr', POINTER(struct_sockaddr)),('ifu_dstaddr', POINTER(struct_sockaddr)),]

class struct_ifaddrs(Structure):
	pass
struct_ifaddrs._fields_ = [
    ('ifa_next', POINTER(struct_ifaddrs)),
    ('ifa_name', c_char_p),
    ('ifa_flags', c_uint),
    ('ifa_addr', POINTER(struct_sockaddr)),
    ('ifa_netmask', POINTER(struct_sockaddr)),
    ('ifa_ifu', union_ifa_ifu),
    ('ifa_data', c_void_p),]

class IFAGTR(object):
    def __init__(self, name):
        self.name = name
        self.addresses = {}

    def __str__(self):
        return "%s<splitter>%s<splitter>%s" % (
            self.name,
            self.addresses.get(AF_INET)[0],
            self.addresses.get(AF_INET6)[0])


def ARPscan(interface,target):
	hosts = {}
	try:
		ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=target), timeout=4, verbose=0, iface=interface)
		for i in range(0,len(ans)):
			hosts[str(ans[i][1].psrc)] = str(ans[i][1].hwsrc)
	except Exception, ex:
		try:
			print "["+Fore.RED+"-"+Style.RESET_ALL+"] Exception('%s') occured\n\t%s-> Errno : %d\n\t-> Error : %s"%(type(ex).__name__,Style.DIM,ex.args[0],ex.args[1])
		except:
			print "["+Fore.RED+"-"+Style.RESET_ALL+"] %s"%(str(ex))
		sys.exit()
	return hosts

def RFA(sa):
    SA_FAMILY, SIN_ADDR= sa.sa_family, None
    if SA_FAMILY == AF_INET:
        sa = cast(pointer(sa), POINTER(struct_sockaddr_in)).contents
        SIN_ADDR = inet_ntop(SA_FAMILY, sa.sin_addr)
    elif SA_FAMILY == AF_INET6:
        sa = cast(pointer(sa), POINTER(struct_sockaddr_in6)).contents
        SIN_ADDR = inet_ntop(SA_FAMILY, sa.sin6_addr)
    return SA_FAMILY, SIN_ADDR

def DHCPDiscover():
	DHCPlst=[]
	conf.checkIPaddr = False
	fam,hw = get_if_raw_hwaddr(conf.iface)
	dhcp_discover = Ether(dst="ff:ff:ff:ff:ff:ff")/IP(src="0.0.0.0",dst="255.255.255.255")/UDP(sport=68,dport=67)/BOOTP(chaddr=hw)/DHCP(options=[("message-type","discover"),"end"])
	ans, unans = srp(dhcp_discover, multi=False, verbose=False)
	for i in ans: DHCPlst.append(i[1][IP].src)
	return DHCPlst

def pIFGen(ifap):
    ifa = ifap.contents
    while True:
        yield ifa
        if not ifa.ifa_next:break
        ifa = ifa.ifa_next.contents


def getInterfaces():
    ifap = POINTER(struct_ifaddrs)()
    if libc.getifaddrs(pointer(ifap)):raise OSError(get_errno())
    try:
        IFADCT = {}
        for ifa in pIFGen(ifap):
            name = ifa.ifa_name.decode("UTF-8")
            i = IFADCT.get(name)
            if not i:i = IFADCT[name] = IFAGTR(name)
            SA_FAMILY, SIN_ADDR = RFA(ifa.ifa_addr.contents)
            if SIN_ADDR:
                if SA_FAMILY not in i.addresses:i.addresses[SA_FAMILY] = list()
                i.addresses[SA_FAMILY].append(SIN_ADDR)
        return IFADCT.values()
    finally:
        libc.freeifaddrs(ifap)

def pgrntIF():
	count = 1
	LIF = getInterfaces()
	print ""
	print "-"*90
	print "|"+Fore.YELLOW+" Sl-no"+Style.RESET_ALL+" | "+Fore.YELLOW+"Interface name "+Style.RESET_ALL+"|     "+\
			Fore.YELLOW+"IPv4-address"+Style.RESET_ALL+"     |%s"%(" "*14)+Fore.YELLOW+"IPv6-address%s"%(" "*14)+Style.RESET_ALL+"|"
	print "-"*90

	for i in LIF:
		rdata = str(i).split("<splitter>")	
		rdata[0] = rdata[0].center(16,' ')
		rdata[1] = rdata[1].center(22,' ')
		rdata[2] = rdata[2].center(40,' ')
		if '127.' in rdata[1]:rdata.append(Fore.RED+"<= DO NOT USE LOCALHOST"+Style.RESET_ALL)
		else:rdata.append(" ")
		rdata = '|'.join(rdata)
		print '|'+str(count).center(7,' ')+'|'+rdata
		count += 1
	print "-"*90
	choice = ""
	while 1:
		try:
			choice = int(raw_input("choose an interface> "))
			if(choice<=len(LIF)):
				print "["+Fore.YELLOW+"*"+Style.RESET_ALL+"] Interface => %s"%(str(LIF[choice-1]).split('<splitter>')[0].replace(' ', ''))
				break
			else:
				print "["+Fore.RED+"-"+Style.RESET_ALL+"] Invalid choice"
		except KeyboardInterrupt:
			print "\n["+Fore.YELLOW+"!"+Style.RESET_ALL+"] Exiting..."
			sys.exit()
		except:
			print "["+Fore.RED+"-"+Style.RESET_ALL+"] Invalid choice"
	return str(LIF[choice-1]).split("<splitter>")[0].replace(' ',''), str(LIF[choice-1]).split("<splitter>")[1].replace(' ','') 

		
def prettyPrint(host,mac, nFP, isdhcp):
	print "-"*(len(host)+4)
	print ("| "+Fore.GREEN+str(host)+Style.RESET_ALL+" |")
	print "-"*(len(host)+4)

	print (" "*((len(host)+4)/2) + "|_ "+Fore.GREEN+Style.DIM+"MAC"+Style.RESET_ALL+" : %s"%(mac))

	hostname=Fore.YELLOW+"-unknown-"
	if(nFP[host].hostname()!=""):
		hostname=nFP[host].hostname()
	print (" "*((len(host)+4)/2) + "|_ "+Fore.GREEN+Style.DIM+"Hostname"+Style.RESET_ALL+" : %s"%(hostname))
	if isdhcp:
		print (" "*((len(host)+4)/2) + "|_ "+Fore.GREEN+Style.DIM+"DHCP server"+Style.RESET_ALL+" : True")
	print (" "*((len(host)+4)/2) + "|_ "+Fore.GREEN+Style.DIM+"State"+Style.RESET_ALL+" : %s"%(nFP[host].state()))

	if nFP[host].all_protocols():
		print (" "*((len(host)+4)/2) + "|_ "+Fore.GREEN+Style.DIM+"Ports"+Style.RESET_ALL)
		for proto in nFP[host].all_protocols():	
		
			ports = list(nFP[host][proto].keys())
			ports.sort()
			print(" "*((len(host)+4)/2) + "|"+'\t'+"["+Fore.GREEN+Style.DIM+"+"+Style.RESET_ALL+'] Protocol : %s' % proto)
			print(" "*((len(host)+4)/2) + "|"+'\t\tPort\t\tState')
			print(" "*((len(host)+4)/2) + "|"+'\t\t====\t\t=====')
			for port in ports:
				print(" "*((len(host)+4)/2) + "|"+'\t\t%s\t\t%s' % (port, nFP[host][proto][port]['state']))
	else:
		print (" "*((len(host)+4)/2) + "|_ "+Fore.GREEN+Style.DIM+"Ports"+Style.RESET_ALL+Style.RESET_ALL+" : %s"%((Fore.YELLOW+"-none-")))
		

	print (" "*((len(host)+4)/2) + "|_ "+Fore.GREEN+Style.DIM+"OS fingerprinting"+Style.RESET_ALL)
	if nFP[host].has_key('osclass'):
		for osclass in nFP[host]['osclass']:
			print('\t\t'+"["+Fore.GREEN+Style.DIM+"+"+Style.RESET_ALL+"] Type : {0}".format(osclass['type']))
		   	print('\t\t    Vendor : {0}'.format(osclass['vendor']))
		  	print('\t\t    OS-Family : {0}'.format(osclass['osfamily']))
		   	print('\t\t    OS-Gen : {0}'.format(osclass['osgen']))
		   	print('\t\t    Accuracy : {0}%'.format(osclass['accuracy']))
		return True

	elif nFP[host].has_key('osmatch'):
		for osmatch in nFP[host]['osmatch']:
			print('\t\t'+"["+Fore.GREEN+Style.DIM+"+"+Style.RESET_ALL+"] Name : {0} (accuracy {1}%)".format(osmatch['name'],osmatch['accuracy']))
		return True
	elif nFP[host].has_key('fingerprint'):
		print('\t\t* Fingerprint : {0}'.format(nFP[host]['fingerprint']))
		return True


def postAS(hostslist):
	hosts = [host for host, x in hostslist.items()]
	macs = [mac for x, mac in hostslist.items()]
	try:
   		nm = nmap.PortScanner()         
	except nmap.PortScannerError:
    		print("["+Fore.RED+"-"+Style.RESET_ALL+'] Nmap not found', sys.exc_info()[0])
    		sys.exit(0)
	except Exception, ex:
		try:
			print "["+Fore.RED+"-"+Style.RESET_ALL+"] Exception('%s') occured\n\t%s-> Errno : %d\n\t-> Error : %s"%(type(ex).__name__,Style.DIM,ex.args[0],ex.args[1])
		except:
			print "["+Fore.RED+"-"+Style.RESET_ALL+"] %s"%(str(ex))
		sys.exit(0)
	try:
		FiFlag, isDHCP = False, False
		isDHCPlst = []
		try: 
			isDHCPlst=DHCPDiscover()
		except:
			pass
		for host, mac in hostslist.items():
			if host in isDHCPlst:
				isDHCP = True
			else:
				isDHCP = False
				
			nm.scan(str(host), arguments="-O")
			FiFlag = prettyPrint(host,mac, nm, isDHCP)

			if not(FiFlag):
				print "["+Fore.YELLOW+"*"+Style.RESET_ALL+"] Warning : couldn't detect to OS"

	except Exception, ex:
		print "["+Fore.RED+"-"+Style.RESET_ALL+"] Error in OS fingerprinting, continuing..."

if __name__ == '__main__':
	
	init(autoreset=True)

	print '''
		 888       888          888            888      
		 888   o   888          888            888      
		 888  d8b  888          888            888      
	88888b.  888 d888b 888  8888b.  888888 .d8888b 88888b.  
	888 "88b 888d88888b888     "88b 888   d88P"    888 "88b 
	888  888 88888P Y88888 .d888888 888   888      888  888 
	888  888 8888P   Y8888 888  888 Y88b. Y88b.    888  888 
	888  888 888P     Y888 "Y888888  "Y888 "Y8888P 888  888 

					'''+'['+Fore.YELLOW+'&'+Style.RESET_ALL+'] Created by suraj ('+Fore.RED+'#r00t'+Style.RESET_ALL+')'	


	print "["+Fore.GREEN+"+"+Style.RESET_ALL+"] Started at %s"%(time.strftime("%X"))
	print "["+Fore.YELLOW+"*"+Style.RESET_ALL+"] Choose a network interface"

	iface, ip_addr = pgrntIF()
	if not(ip_addr.startswith("127.")):
		subnet = ip_addr+"/24"
	else:
		print "["+Fore.RED+"-"+Style.RESET_ALL+"] Cannot scan localhost("+Fore.YELLOW+"%s"%(ip_addr)+Style.RESET_ALL+"), exiting..."
		sys.exit()
	t1 = time.time()
	print "["+Fore.YELLOW+"*"+Style.RESET_ALL+"] Scanning subnet(%s) on %s interface"%(subnet,iface)
	hosts = ARPscan(iface,subnet)
	postAS(hosts)
	t2 = time.time()
	print "\n["+Fore.YELLOW+"*"+Style.RESET_ALL+"] Scanning took %d seconds, task completed at %s."%(t2-t1,time.strftime('%X'))
	sys.exit()
