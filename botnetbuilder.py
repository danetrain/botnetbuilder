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

if __name__ == "__main__":

  print "hi dane."
