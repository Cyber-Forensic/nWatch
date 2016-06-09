#!/usr/bin/python

import sys
import logging
from colorama import Fore, init, Style
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
import time
import nmap

def checkARGS(args):
	if(len(args)==3):return 1
	else:return 0

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
		
def prettyPrint(host,mac, nFP):
	
	print "-"*(len(host)+4)
	print ("| "+Fore.GREEN+str(host)+Style.RESET_ALL+" |")
	print "-"*(len(host)+4)

	print (" "*((len(host)+4)/2) + "|_ "+Fore.GREEN+"MAC"+Style.RESET_ALL+" : %s"%(mac))

	hostname=Fore.YELLOW+"-unknown-"
	if(nFP[host].hostname()!=""):
		hostname=nFP[host].hostname()
	print (" "*((len(host)+4)/2) + "|_ "+Fore.GREEN+"Hostname"+Style.RESET_ALL+" : %s"%(hostname))
	print (" "*((len(host)+4)/2) + "|_ "+Fore.GREEN+"State"+Style.RESET_ALL+" : %s"%(nFP[host].state()))
	print (" "*((len(host)+4)/2) + "|_ "+Fore.GREEN+"Ports"+Style.RESET_ALL)
	for proto in nFP[host].all_protocols():
		print(" "*((len(host)+4)/2) + "|"+'\t'+"["+Fore.GREEN+"+"+Style.RESET_ALL+'] Protocol : %s' % proto)
		ports = list(nFP[host][proto].keys())
        	ports.sort()
		print(" "*((len(host)+4)/2) + "|"+'\t\tPort\t\tState')
		print(" "*((len(host)+4)/2) + "|"+'\t\t====\t\t=====')
		for port in ports:
            		print(" "*((len(host)+4)/2) + "|"+'\t\t%s\t\t%s' % (port, nFP[host][proto][port]['state']))

	print (" "*((len(host)+4)/2) + "|_ "+Fore.GREEN+"OS fingerprinting"+Style.RESET_ALL)
	if nFP[host].has_key('osclass'):
		for osclass in nFP[host]['osclass']:
			print('\t\t'+"["+Fore.GREEN+"+"+Style.RESET_ALL+"] Type : {0}".format(osclass['type']))
		   	print('\t\t    Vendor : {0}'.format(osclass['vendor']))
		  	print('\t\t    OS-Family : {0}'.format(osclass['osfamily']))
		   	print('\t\t    OS-Gen : {0}'.format(osclass['osgen']))
		   	print('\t\t    Accuracy : {0}%'.format(osclass['accuracy']))
		return True

	elif nFP[host].has_key('osmatch'):
		for osmatch in nFP[host]['osmatch']:
			print('\t\t'+"["+Fore.GREEN+"+"+Style.RESET_ALL+"] Name : {0} (accuracy {1}%)".format(osmatch['name'],osmatch['accuracy']))
		return True
	elif nFP[host].has_key('fingerprint'):
		print('\t\t* Fingerprint : {0}'.format(nFP[host]['fingerprint']))
		return True
	else:
		print('\t\t*'+Fore.YELLOW+' -unknown-')
		return False


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
		FiFlag = False
		for host, mac in hostslist.items():
			nm.scan(str(host), arguments="-O")
			FiFlag = prettyPrint(host,mac, nm)

			if not(FiFlag):
				print "["+Fore.YELLOW+"*"+Style.RESET_ALL+"] Warning : couldn't detect to OS"

	except Exception, ex:
		print "["+Fore.RED+"-"+Style.RESET_ALL+"] Error in OS fingerprinting, continuing..."

if __name__ == '__main__':
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
	t1 = time.time()
	init(autoreset=True)
	if checkARGS(sys.argv):
		print "["+Fore.YELLOW+"*"+Style.RESET_ALL+"] Scanning %s on %s interface"%(sys.argv[2],sys.argv[1])
		hosts = ARPscan(sys.argv[1],sys.argv[2])
		print "["+Fore.YELLOW+"*"+Style.RESET_ALL+"] Scanning ports and fingerprinting operating system..."
		postAS(hosts)
		t2 = time.time()
		print "["+Fore.YELLOW+"*"+Style.RESET_ALL+"] Finished(at %s) in %d seconds"%(time.strftime('%X'),t2-t1)
	else:
		print "["+Fore.YELLOW+"*"+Style.RESET_ALL+"] Usage : %s <iface> <subnet>"%sys.argv[0]
		sys.exit()


