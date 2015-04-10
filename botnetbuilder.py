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

  return live_hosts



if __name__ == "__main__":

  #one CLARG of interest, the subnet specifier#
  if len(sys.argv) != 2:
    print "USAGE: python botnetbuilder.py subnet"
    print "Example: python botnetbuilder.py 192.168.1.1/24"
    sys.exit()

  subnet = sys.argv[1]
  scan(subnet)
    
