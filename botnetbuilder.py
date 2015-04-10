#
# botnetbuilder.py 
#
# Dane Fichter - 4/18/15
#
# This tool is intended to automate the steps a crude attacker might take 
# upon gaining access to a subnet. We begin by performing an nmap scan to
# discover hosts and services. We then exhaustively deploy exploits until 
# we gain a session. We then install persistent access tools and save the 
# credentials

import nmap
import sys

# Performs a scan on a given subnet.
# Returns a python-nmap scan result object.
def scan(subnet):

  #stealth scan#
  print "Starting scan on subnet " + subnet + "...."
  nm = nmap.PortScanner()
  nm.scan(hosts=subnet, arguments='-sS')

  #print out scan results#
  live_hosts = []
  for host in nm.all_hosts():
    
    #print and track live hosts#
    if nm[host].state() == 'up':
      live_hosts.append(nm[host])
      print "FOUND LIVE HOST: " + host

      #list all service info#
      #iterate over all protocols and ports#
      for proto in nm[host].all_protocols():
      	lport = list(nm[host][proto].keys())
      	lport.sort()

      	for port in lport:
      		print('port: %s \tstate: %s \tname: %s' % (port, nm[host][proto][port]['state'], nm[host][proto][port]['name']))


  return live_hosts

# Given a list of python-nmap objects, #
# parse the msfconsole output and return #
# a list of exploits for us to try#
def get_exploit_list(live_hosts):

	os_strings = ['linux', 'windows']



if __name__ == "__main__":

  #one CLARG of interest, the subnet specifier#
  if len(sys.argv) != 2:
    print "USAGE: python botnetbuilder.py subnet"
    print "Example: python botnetbuilder.py 192.168.1.1/24"
    sys.exit()

  subnet = sys.argv[1]
  live_hosts = scan(subnet)
  exploits = get_exploit_list(live_hosts)
    
