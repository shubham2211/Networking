import socket
import sys
from thread import *
from ip_addr import *
from mac_addr import *
from threading import Timer

ip_mac={}
ip_loc={}
ip_ttl={}

def insert_ip(conn,data):
	
		ip_ttl[data.split(" ")[1]]=180			#  initial value of TTL is 3 minutes.

		ip_loc[data.split(" ")[1]]=(data.split(" ")[2])	# create < ip , location binding >

		ip_mac[data.split(" ")[1]]=(data.split(" ")[3]) # create < ip , mac > binding

		start_new_thread(time_to_live,(data.split(" ")[1],))

		reply="ok"
		conn.sendall(reply)
		print '<IP , MAC> bindings ',ip_mac
		print '<IP , LOCATIONS> bindings ',ip_loc
		print '<IP , TIME TO LIVE> bindings ',ip_ttl

		print "#############    inserted     #############"
		conn.close()



def remove_ip(conn,data):
	if data.split(" ")[1] in ip_mac:

		del ip_ttl[data.split(" ")[1]]		# delete ttl entry

		del ip_mac[data.split(" ")[1]]		# delete < ip , mac  >

		del ip_loc[data.split(" ")[1]]		# delete < ip , location >

		reply="ok"
		conn.sendall(reply)
		print '<IP , MAC> bindings ',ip_mac
		print '<IP , LOCATIONS> bindings ',ip_loc
		print '<IP , TIME TO LIVE> bindings ',ip_ttl

		print "#############    removed     #############"
		conn.close()
	else:
		reply="ok"
		conn.sendall(reply)
		conn.close()

	

def keep_alive(conn,data):

	if data.split(" ")[1] in ip_mac:

		ip_ttl[data.split(" ")[1]]=ip_ttl[data.split(" ")[1]]+180	#update the TTL value whenever keep alive is called so 											that entry doesnot expire after 3 minutes
		start_new_thread(time_to_live,(data.split(" ")[1],))
		reply="ok"
		
		conn.sendall(reply)

		conn.close()

	else:
		reply="ok"
		print reply,"cannot find ",data.split(" ")[1]
		conn.sendall(reply)
		conn.close()

def time_to_live(ip):
	t=[]
	for i in range(5,185,5):
		p=Timer(i,decrement_ttl,(ip,))
		t.append(p)
	
	for p in t:
		p.start() 

def decrement_ttl(ip):

	if ip in ip_mac and ip in ip_loc and ip in ip_ttl:
		ip_ttl[ip]=ip_ttl[ip]-5			# decrement time to live value by 5
		
	else:
		sys.exit()
	
	if ip_ttl[ip]<=0:
		
		del ip_ttl[ip]		
		del ip_mac[ip]
		del ip_loc[ip]
		

		print '<IP , MAC> bindings ',ip_mac
		print '<IP , LOCATIONS> bindings ',ip_loc
		print '<IP , TIME TO LIVE> bindings ',ip_ttl

		print "#############    time to live expired     #############"


while 1:
	try:
		s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
		break
	except socket.error,msg:
		continue

print "Socket created"

host=S2
port=32000

while 1:
	try:
		s.bind((host,port))
		break
	except socket.error,msg:
		continue

print "Completed creating Bindings "

s.listen(50)

print "Socket listening"
print "##############################"

while 1:
	conn,addr=s.accept()
	
	data=conn.recv(4096)
	
	if (data.split(" ")[0]=="remove"):

		start_new_thread(remove_ip,(conn,data,))

	elif (data.split(" ")[0]=="insert"):

		start_new_thread(insert_ip,(conn,data,))
	
	elif (data.split(" ")[0]=="keepalive"):

		start_new_thread(keep_alive,(conn,data,))
	
	else:
		reply="Invalid messege"
		conn.sendall(reply)
		conn.close()
	
s.close()
