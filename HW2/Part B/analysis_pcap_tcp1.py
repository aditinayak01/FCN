import dpkt
import sys
import time
import collections
import math
f = open("assignment2.pcap","rb")
packets = dpkt.pcap.Reader(open('assignment2.pcap','rb'))
class Solution:
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
        # print "tl",int(self.totallength,16)
        self.a=(int(pointertcpheader,16)+int(hex(packetarray[startdestport+10])[2],16))*4
        # print "a",self.a
        self.datalen1=int(self.totallength,16)-self.a
        # print "datalen1",self.datalen1
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
acklist1=[]
for i in range(len(flows)):
    sublist=[]
    sublist1=[]
    sendlist=[]
    acklist=[]
    seen=set()
    for j in objlist:
        if (flows[i][1].sourceport==j[1].sourceport and flows[i][1].destport==j[1].destport) :
            sublist.append(j)
            sendlist.append(j)
            totalsentpackets+=1
        if ( flows[i][1].destport==j[1].sourceport and flows[i][1].sourceport==j[1].destport):
            sublist.append(j)
            acklist.append(j)
    list1.append(sublist)
    sendlist1.append(sendlist)
    acklist1.append(acklist)
    totalcount.append(totalsentpackets)
duplicatesend=[]
alldata={}
MSS=1460
icwnd=1
for i in range(len(list1)):
    sendlist={}
    cwnd=icwnd
    acklist={}
    sval=1
    aval=1
    counter=0
    tcount=0
    rtcount=0
    print "for Flow",flows[i][1].sourceport
    for j in range(3,len(list1[i])):
        rwnd=list1[i][1][1].windowsize/MSS
        ssthreshold=rwnd/2
        if list1[i][j][1].sourceip=='130.245.145.12':
            if list1[i][j][1].seqno in sendlist:
                sendlist[list1[i][j][1].seqno]+=1
            else:
                sendlist[list1[i][j][1].seqno]=sval
            if sendlist[list1[i][j][1].seqno]==2:   #timeout
                if list1[i][j][1].seqno in acklist and acklist[list1[i][j][1].seqno]<3:
                    ssthreshold=cwnd/2
                    cwnd=icwnd
                    print "Congestion Window",cwnd
                    counter+=1
                    tcount+=1
                elif list1[i][j][1].seqno not in acklist:                               #timeout
                    ssthreshold=cwnd/2
                    cwnd=icwnd
                    print "Congestion Window",cwnd
                    counter+=1
                    tcount+=1
        elif list1[i][j][1].sourceip=='128.208.2.198':
            if list1[i][j][1].ackno in acklist:
                acklist[list1[i][j][1].ackno]+=1
            else:
                acklist[list1[i][j][1].ackno]=aval
            if acklist[list1[i][j][1].ackno]==3 and sendlist[list1[i][j][1].ackno]<2: #triple dup ack
                ssthreshold=ssthreshold/2
                cwnd=cwnd/2
                print "Congestion Window",cwnd
                counter+=1
                rtcount+=1
            else:
                if cwnd==rwnd:
                    cwnd=ssthreshold
                    print "Congestion Window",cwnd
                    counter+=1
                elif cwnd>ssthreshold:
                    cwnd=cwnd+1
                    print "Congestion Window",cwnd
                    counter+=1               #slow start
                else:
                    cwnd=cwnd*2
                    print "Congestion Window",cwnd
                    counter+=1                   #no loss
        if counter>14: #leaving three packets from start
            break
    print  "#####################################################################"






for i in range(len(flows)):
    sublist=[]
    sublist1=[]
    sendlist=[]
    acklist=[]
    seen=set()
    for j in objlist:
        if (flows[i][1].sourceport==j[1].sourceport and flows[i][1].destport==j[1].destport) :
            sublist.append(j)
            sendlist.append(j)
            totalsentpackets+=1
        if ( flows[i][1].destport==j[1].sourceport and flows[i][1].sourceport==j[1].destport):
            sublist.append(j)
            acklist.append(j)
    list1.append(sublist)
    sendlist1.append(sendlist)
    acklist1.append(acklist)
    totalcount.append(totalsentpackets)
duplicatesend=[]
alldata={}
MSS=1460
icwnd=1
for i in range(len(list1)):
    sendlist={}
    cwnd=icwnd
    acklist={}
    sval=1
    aval=1
    counter=0
    tcount=0
    rtcount=0
    if i==len(flows):
        break
    print "For Flow",flows[i][1].sourceport
    for j in range(3,len(list1[i])):
        rwnd=list1[i][1][1].windowsize/MSS
        ssthreshold=rwnd/2
        if list1[i][j][1].sourceip=='130.245.145.12':
            if list1[i][j][1].seqno in sendlist:
                sendlist[list1[i][j][1].seqno]+=1
            else:
                sendlist[list1[i][j][1].seqno]=sval
            if sendlist[list1[i][j][1].seqno]==2:   #timeout
                if list1[i][j][1].seqno in acklist and acklist[list1[i][j][1].seqno]<3:
                    ssthreshold=cwnd/2
                    cwnd=icwnd
                    tcount+=1
                elif list1[i][j][1].seqno not in acklist:                               #timeout
                    ssthreshold=cwnd/2
                    cwnd=icwnd                           #timeout
                    tcount+=1
        elif list1[i][j][1].sourceip=='128.208.2.198':
            if list1[i][j][1].ackno in acklist:
                acklist[list1[i][j][1].ackno]+=1
            else:
                acklist[list1[i][j][1].ackno]=aval
            if acklist[list1[i][j][1].ackno]==3 and sendlist[list1[i][j][1].ackno]<2: #triple dup ack
                ssthreshold=ssthreshold/2
                cwnd=cwnd/2
                rtcount+=1
            else:
                if cwnd==rwnd:
                    cwnd=ssthreshold
                elif cwnd>ssthreshold:
                    cwnd=cwnd+1               #slow start
                else:
                    cwnd=cwnd*2               #no loss
    print "Retransmissions:",rtcount,"Timeouts":tcount
