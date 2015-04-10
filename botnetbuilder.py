#
# botnetbuilder.py 
#
# Dane Fichter - 4/18/15
#
# This tool is intended to automate the steps a crude attacker might take 
# upon gaining access to a subnet. We begin by performing an nmap scan to
# discover hosts and services. Then we use the msfconsole to deploy 
# exploits in the background according to premade .rc files 

import nmap
import os
import sys

# Performs a scan on a given subnet.
# Returns a python-nmap scan result object.
def scan(subnet):

  #stealth scan#
  print "Starting scan on subnet " + subnet + "...."
  nm = nmap.PortScanner()
  nm.scan(hosts=subnet, arguments='-sS')
  host_info = {}

  #print out scan results#
  for host in nm.all_hosts():
    
    #print and track live hosts#
    if nm[host].state() == 'up':
      print "FOUND LIVE HOST: " + host
      host_info[host] = []

      #list all service info#
      #iterate over all protocols and ports#
      for proto in nm[host].all_protocols():
      	lport = list(nm[host][proto].keys())
      	lport.sort()

      	for port in lport:
      		print('port: %s \tstate: %s \tname: %s' % (port, nm[host][proto][port]['state'], nm[host][proto][port]['name']))
      		host_info[host].append(nm[host][proto][port]['name'])

  return host_info

#Given a path to an .rc file which lists msfconsole commands,#
#deploy the attack and pause if attack is successful#
def deploy_attack(attack_file):
	#TODO: IMPLEMENT THIS#

#Given a dictionary of python-nmap scan results#
#Iterate through all .rc files in the attacks/ #
#folder and deploy them using msfconsole. Stop #
#once an attack is successful # 
def attack(scan_info):

	for host in scan_info.keys():
		print "BEGINNING ATTACK ON: " + host

		#first, look for .rc file matching the service#
		for name in scan_info[host]:
		
			print('Searching for matching attack files for service: %s' % name)

			#Search 'attacks' folder for matching service folder#
			path = "attacks/"+name+"/"
			if(os.path.isdir(path)):

				#get .rc files from directory#
				attack_files = [ f for f in os.listdir(path) if (os.path.isfile(join(path,f)) and (".rc" in f))]
				print('Found %i matching attacks for service" %s' % len(attack_files) , name)

				#call helper func to deploy attacks#
				for f in attack_files:
					deploy_attack(f)
			else:
				print('No matching attacks for service: %s' % name)

if __name__ == "__main__":

  #one CLARG of interest, the subnet specifier#
  if len(sys.argv) != 2:
    print "USAGE: python botnetbuilder.py subnet"
    print "Example: python botnetbuilder.py 192.168.1.1/24"
    sys.exit()

  subnet = sys.argv[1]
  scan_info = scan(subnet)
  attack(scan_info)
    
