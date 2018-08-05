import dpkt
import sys
import time
import collections
import math
f = open("assignment2.pcap","rb")
packets = dpkt.pcap.Reader(open('assignment2.pcap','rb'))
class Solution:
    #PACKET FORMAT
    def __init__(self,elem):
        packetarray = []
        self.length=len(elem[1])
        for character in bytes(elem[1]):
            packetarray.append(ord(character))
        self.timestamp=elem[0]
        self.startipheader = 14
        ipheader=(hex(packetarray[self.startipheader]))
        pointertcpheader=ipheader[-1]
        starttcp=self.startipheader+int(pointertcpheader, 16)*4
        startdestport=starttcp+2
        self.totallength=hex(packetarray[self.startipheader+2])[2:]+hex(packetarray[self.startipheader+3])[2:]
        self.a=(int(pointertcpheader,16)+int(hex(packetarray[startdestport+10])[2],16))*4
        self.datalen1=int(self.totallength,16)-self.a
        self.startsourceip=self.startipheader+12
        self.startdestip=self.startipheader+16
        self.sourceip=str((packetarray[self.startsourceip]))
        for i in range(1,4):
            self.sourceip=self.sourceip+'.'+(str(packetarray[self.startsourceip+i]))
        self.destip=str((packetarray[self.startdestip]))
        for i in range(1,4):
            self.destip=self.destip+'.'+(str(packetarray[self.startdestip+i]))
        self.sourceport = int(((hex(packetarray[starttcp])[2:]) + (hex(packetarray[starttcp + 1])[2:])), 16)
        self.destport=int(((hex(packetarray[startdestport])[2:]) +(hex(packetarray[startdestport + 1])[2:])), 16)
        self.seqno=hex(packetarray[startdestport+2])[2:]
        for i  in range(1,4):
            self.seqno=self.seqno+hex(packetarray[startdestport+2+i])[2:].zfill(2)
        self.ackno=hex(packetarray[startdestport+6])[2:]
        for i  in range(1,4):
            self.ackno=self.ackno+hex(packetarray[startdestport+6+i])[2:].zfill(2)
        self.flag=(hex(packetarray[startdestport+11])[2:])
        if len(self.flag)==1:
            self.flag='0'+self.flag
        self.ackflag=bin(int(self.flag[0]))[2:].zfill(4)[-1]
        self.synflag=bin(int(self.flag[1]))[2:].zfill(4)[-2]
        self.finflag=bin(int(self.flag[1]))[2:].zfill(4)[-1]
        self.windowsize=(hex(packetarray[startdestport+12])[2:])
        for i  in range(1,2):
            self.windowsize=self.windowsize+hex(packetarray[startdestport+12+i])[2:]
        self.windowsize=int(self.windowsize,16)

sendlist1=[]
objlist=[]
lossrate=[]
counter=0
for i in packets:
    f = Solution(i)
    objlist.append((f.timestamp,f))
    counter=counter+1
totalsentpackets=0
flows=[]
for j in objlist:
    if j[1].sourceip=='130.245.145.12' and j[1].synflag=='1' and j[1].ackflag=='0' :
        flows.append(j)
list1=[]
uniquelist=[]
totalcount=[]
counter=0
for i in range(len(flows)):
    sublist=[]
    sublist1=[]
    sendlist=[]
    seen=set()
    for j in objlist:
        if (flows[i][1].sourceport==j[1].sourceport and flows[i][1].destport==j[1].destport) :
            sublist.append(j)
            sendlist.append(j)
            totalsentpackets+=1
        if ( flows[i][1].destport==j[1].sourceport and flows[i][1].sourceport==j[1].destport):
            sublist.append(j)
    list1.append(sublist)
    sendlist1.append(sendlist)
    totalcount.append(totalsentpackets)
count=0
duplicatesend=[]
#no of flows
for i in range(len(list1)):
    for j in range(0,3):
        if list1[i][j][1].synflag=='1':
            if list1[i][j][1].synflag=='1' and list1[i][j][1].ackflag=='1':
                if list1[i][j][1].ackflag=='1':
                    count=count+1
print "No of Flows:",count
print " "
print (len(sendlist1))

#First 2 transactions for each flow
for i in range(len(list1)):
    count=0
    k=len(list1[i])
    m = 3
    print "For",flows[i][1].sourceport
    for j in range(3,len(list1[i])):
        m=m+1
        for m in range(m,k):
            if count<2:
                if list1[i][j][1].sourceport==list1[i][m][1].destport and list1[i][j][1].destport==list1[i][m][1].sourceport:
                    print "Transaction No:",count+1
                    print  "   "
                    print "Seq no:",int(list1[i][j][1].seqno,16),"Ack No:",int(list1[i][j][1].ackno,16),"Window Size:",int(list1[i][j][1].windowsize)*16384
                    print  "   "
                    print  "Seq no:",int(list1[i][m][1].seqno,16),"Ack No:",int(list1[i][m][1].ackno,16),"Window Size:",int(list1[i][m][1].windowsize)*16384
                    print  "   "
                    count=count+1
                    break
        if count>=2:
            break
    print "#####################################################################"

#Empirical Throughput
for i in range(len(list1)):
    totalbytes=0
    # print len(list1[i])
    for j in list1[i]:
        totalbytes+=j[1].length
    print "Throughput for flow",i+1,":",(totalbytes/(list1[i][len(list1[i])-1][0]-list1[i][0][0]))/1000000,"Mbps"

#Loss Rate
for i in range(len(sendlist1)):
    a = collections.OrderedDict()
    keylist=[]
    valcount=1
    for j in range(3,len(sendlist1[i])):
        if sendlist1[i][j][1].seqno in a:
            a[sendlist1[i][j][1].seqno]=valcount+1
        else:
            a[sendlist1[i][j][1].seqno]=valcount
    for k in a.keys():
        if a[k]>1:
            keylist.append(k)
    duplicatesend.append(keylist)
    lossrate.append(float(len(duplicatesend[i]))/ float(len(sendlist1[i])-3))

for i in range(len(sendlist1)):
    print "Lossrate for flow",i+1,":",lossrate[i]

for i in range(len(list1)):
    sublist1=[]
    seen=set()
    for j in range(3,len(list1[i])):
        if list1[i][j][1].sourceip=='130.245.145.12':
            if list1[i][j][1].seqno not in seen:
                sublist1.append(list1[i][j])
                seen.add(list1[i][j][1].seqno)
    uniquelist.append(sublist1)
rttlist=[]

#average rtt
avglist=[]
for i in range(len(uniquelist)):
    rtt=0
    rttlist=[]
    k=3
    for j in range(len(uniquelist[i])):
        timestamp1=uniquelist[i][j][0]
        for k in range(len(list1[i])):
            if list1[i][k][1].sourceport==80:
                if int(list1[i][k][1].ackno,16)==int(uniquelist[i][j][1].seqno,16)+uniquelist[i][j][1].datalen1:
                    timestamp2= list1[i][k][0]
                    rtt=(timestamp2-timestamp1)
                    rttlist.append(rtt)
                    break
    avglist.append(sum(rttlist)/len(rttlist))

for i in range(len(avglist)):
    print "Average Rtt for Flow",i+1,":",avglist[i]

#theoretical Throughput
value=math.sqrt(3/2)
MSS=1460
for i in range(len(lossrate)):
    try:
        theoreticalthroughput=(value*MSS)/(lossrate[i]*avglist[i])
        print "Theoretical Throughput for flow",i+1,":",theoreticalthroughput/1000000,"Mbps"
    except ZeroDivisionError:
        print "Infinity"
