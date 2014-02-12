import socket
import time
from threading import Timer
from thread import *
from ip_addr import *
from mac_addr import *
from consistenthash import *

ip=["", "", "", ""]

last_published_ip=["", "", "", ""]

ch=HashRing([S1,S2,S3])			# initialize HashRing object with three nodes comprising of 3 laptops acting as switch

def hash_ip(ip):
	return ch.get_node(ip)		# call to the get_node function of HashRing class in consistenthash.py

def insert_ip(ip,switch_port):
	if ip=="":
		return
	else:
		#create an INET, STREAMing socket
		s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
		print "Socket created for insertion"
		
		host=hash_ip(ip)

		port=32000	# using port 32000 given in ques
		
		s.connect((host,port))
		
		print "Established connection to "+host+" at "+str(port)
		
		message="insert "+ip+" "+mac[S1]+" "+mac[ip]
	
		reply_message=""
				
		while reply_message!="ok":
			try:
				s.sendall(message)
				print "Message sent"
				reply_message=s.recv(4096)
				if reply_message=="ok":	
					print "Reply message received"
			except socket.error:
				continue
		
		print "Entry inserted for host connected to switch port ",switch_port
		
		last_published_ip[switch_port]=ip	# update last_published_ip for the port of the switch to which new host connected 




def remove_ip(ip,switch_port):
	if ip=="":
		return
	else:
		s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
		print "Socket created for remove message "
		
		host=hash_ip(ip)
		
		port=32000
		
		s.bind(("10.200.200.177",0))
		s.connect((host,port))

		print "Established connection to "+host+" at "+str(port)
		
		message="remove "+ip
		reply_message=""
				
		while reply_message!="ok":
			try:
				s.sendall(message)
				print "Message sent"
				reply_message=s.recv(4069)
			except socket.error:
				continue
		print "Entry removed for host connected to switch port ",switch_port
		last_published_ip[switch_port]=""

		

def send_keepalive(ip_addr):
	
	#create an INET, STREAMing socket
	s=socket.socket(socket.AF_INET,socket.SOCK_STREAM) 	
	print "socket created for keep alive"


	host=hash_ip(ip_addr) 	# call to hash_ip function to get the switch's hash value in the hash ring 
	port=32000
				# now connect to the switch on port 32000
	s.connect((host,port))
	print "connected keep alive"
	message="keepalive "+ip_addr	#to maintain the <key,value> binding in the switch for the host with IP ip_addr, we send keep 						alive message to that switch
	reply_message=""
	while reply_message!="ok":	# if reply == ok then keep alive message has been received
				# keep sending the keep alive message until we receive the reply signalled by OK
		try:
			s.sendall(message)
			print "keep alive Message sent ",ip_addr

				# The maximum amount of data to be received is 4096 bytes
			reply_message=s.recv(4096)
			if reply_message=="ok":	
				print "keep alive reply received "
		except socket.error:
			continue	


			
		
def keep_alive():
	while 1:
		for i in ip:
			if i!="":
				start_new_thread(send_keepalive,(i,))
				
		time.sleep(150)


def test_1min():	#create function for configuring in accordance to conditions at time =1 min
	ip[0]=h8
	ip[1]=h9

def test_5min():	#create function for configuring in accordance to conditions at time =5 min
	ip[0]=""

def test_8min():	#create function for configuring in accordance to conditions at time =8 min
	ip[2]=h10
	ip[3]=h11

def test_12min():	#create function for configuring in accordance to conditions at time =12 min
	ip[0]=h4

Timer(60,test_1min,()).start()
Timer(300,test_5min,()).start()
Timer(480,test_8min,()).start()
Timer(720,test_12min,()).start()

start_new_thread(keep_alive,())

while 1:
	if ip[0]!=last_published_ip[0]:		# if a new host arrives at port 1 then remove the last_published_ip value for that port 						and insert new value of ip

		print "port 1"
		remove_ip(last_published_ip[0],0)
		insert_ip(ip[0],0)
	
	if ip[1]!=last_published_ip[1]:
		print "port 2"
		remove_ip(last_published_ip[1],1)
		insert_ip(ip[1],1)
	
	if ip[2]!=last_published_ip[2]:
		print "port 3"
		remove_ip(last_published_ip[2],2)
		insert_ip(ip[2],2)
		
	if ip[3]!=last_published_ip[3]:
		print "port 4"
		remove_ip(last_published_ip[3],3)
		insert_ip(ip[3],3)
	#time.sleep(10)
