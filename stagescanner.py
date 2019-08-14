#!bin/python2

import subprocess as sp #writes to command line
import sys #system arguments
from grepfunc import grep #search in files for ports
import socket #to check for valid IP addresse

#error variables
num_sys_arg = 4
arg_error = False

#port variables
open_tcp = []
open_udp = []

#system argument variables
ip_addresse = None
file_name = None
port_type = None

#print out error message
def error(error_message):
	print("Stagescanner by Kai Schmidt:")
	print(" ")
	print("Syntax: python3 stagescanner.py <IP> <file-name> <tcp/udp capitalization does NOT matter>") 	
	print("Example: python3 stagescanner.py 255.255.255.255 example tcp")
	print(" ")
	print("Error:")
	print(error_message)
	sys.exit()

#check command line arguments
def valid_sys_argv():
	if len(sys.argv) != num_sys_arg:
		error("Not enough Command Line arguments. You need {} Arguments for the script to work".format(num_sys_arg - 1))
	else:
		global ip_addresse, file_name, port_type
		ip_addresse = sys.argv[1]
		file_name = sys.argv[2]
		port_type = sys.argv[3]
		port_type = port_type.lower()

#check for valid ip addresse
def valid_ipv4():
	try:
		socket.inet_pton(socket.AF_INET, ip_addresse)
	except socket.error:
		error("Invalid IP-Format: <num>.<num>.<num>.<num>\nExample: 255.255.255.255")
		
#check for valid filename
def valid_filename():
	if "/" in file_name:
		error("Filename not supported.\nYou cannot use '/' or '\\0' in the filename.")

#actual staged port scanner
def port_scanner():
	global open_tcp, open_udp
	
	#create directories to store the scan results
	sp.call("mkdir {}".format(file_name), shell = True)
	sp.call("mkdir {}/XML".format(file_name), shell = True)
	sp.call("mkdir {}/nmap".format(file_name), shell = True)
	sp.call("mkdir {}/gnmap".format(file_name), shell = True)
	
	###############################################tcp scan#######################################
	
	if port_type == "tcp":
		#stage 1
		sp.call("nmap -T4 -sT -Pn -p- {} -oX {}/XML/tcp_scan1.xml -oN {}/nmap/tcp_scan1.nmap -oG {}/gnmap/tcp_scan1.gnmap".format(ip_addresse, file_name, file_name, file_name), shell = True)
	
		with open("{}/nmap/tcp_scan1.nmap".format(file_name), "r") as port_file:			
			for line in port_file:
				line = str(grep(line, "open")).split(" ")[0].translate(None, "/tcp")
				if line != "[]":
					line = line.translate(None, "['")
					open_tcp.append(line)
		
		open_tcp = ",".join(open_tcp)
	
		#stage 2
		sp.call("nmap -T4 -A -p{} {}".format(open_tcp, ip_addresse), shell = True)
	
	#############################################udp scan###########################################
	
	elif port_type == "udp":
		#stage 1
		sp.call("nmap -T4 -sU -p- {} -oX {}/XML/udp_scan1.xml -oN {}/nmap/udp_scan1.nmap -oG {}/gnmap/udp_scan1.gnmap".format(ip_addresse, file_name, file_name, file_name), shell = True)
		
		with open("{}/nmap/udp_scan1.nmap".format(file_name), "r") as port_file:			
			for line in port_file:
				line = str(grep(line, "open")).split(" ")[0].translate(None, "/udp")
				if line != "[]":
					line = line.translate(None, "['")
					open_udp.append(line)
		
		#stage 2
		sp.call("nmap -T4 -sU -A -p{} {}".format(open_tcp, ip_addresse), shell = True)
	
#main function
def main():	
	#error handling
	valid_sys_argv()
	valid_ipv4()
	valid_filename()
	
	#stage scanning
	port_scanner()
						
if __name__ == '__main__':
	main()
	
	
