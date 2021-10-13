from scapy.all import *
import time

# an object to save now and later time in
timer = {}

# initializing now and later
timer["now"] = time.time()
timer["later"] = time.time()

# an object to save how many packets sent for each IP
packets = {}
packets["p"] = {}

# call back method called from sniff on every sniffed packet
def pkt_callback(pkt):

    # calculating the time difference between now and the last time sniffing a packet
    timer["later"] = time.time()
    difference = int(timer["later"]-timer["now"])

    # every one second, print how many packets each SOURCE IP have sent and reset the number of packets.
    if difference > 1:

        # print info
        if(len(packets["p"])>0):
            print("------------------------------------------------")
            print("In one second:")
            for syns_source in packets["p"]:
                print("IP: "+str(syns_source)+" sent "+str(packets["p"][syns_source])+" syn packets")
            print("-------------------------------------------------")

        # reset packets sent from each IP
        packets["p"] = {}
        timer["now"] = time.time()

    # get packet info 
    src = pkt.sprintf("%IP.src%")
    dst = pkt.sprintf("%IP.dst%")
    flags = pkt.sprintf("%TCP.flags%")


    if flags == 'S':
        pkt_addtoDict(dst, src)
		#print pkt.summary()

def pkt_addtoDict(dst, src):
	if src in packets["p"]:
		packets["p"][src] += 1
	else:#add
		packets["p"][src] = 1
            
	if src in packets["p"] and packets["p"][src] > 500:
		print("A SYN attack has been detected from IP: "+ str(src) +"!")


#SYN FLAG
#flags = 'S'
sniff(prn=pkt_callback, filter="tcp", store=0)
#prn: function to apply to each packet. If something is returned, it is displayed
#filter: filtering necessary packets
#store=0: doesn't store anything in memory

