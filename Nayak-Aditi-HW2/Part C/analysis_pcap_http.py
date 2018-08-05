import dpkt
import sys
import time
import collections
import math
packet= dpkt.pcap.Reader(open('http_1080.pcap','rb'))
packets1=dpkt.pcap.Reader(open('http_1081.pcap','rb'))
packets2=dpkt.pcap.Reader(open('http_1082.pcap','rb'))
class Solution:
    def __init__(self,elem):
        packetarray = []
        httpflag=0
        self.data=''
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

        self.ethheaderlen=14
        self.ipheaderlen=int((pointertcpheader),16)*4
        self.tcpheaderlen=int(hex(packetarray[startdestport+10])[2],16)*4
        self.headerlen=self.ethheaderlen+self.ipheaderlen+self.tcpheaderlen
        if (self.length-self.headerlen)>=6:
            httpflag=1
            # print self.destip
            self.data=str(elem[1][startdestport+18])+str(elem[1][startdestport+19])+str(elem[1][startdestport+20])+str(elem[1][startdestport+21])
        self.httpflag=httpflag



objlist=[]
counter0=0
totalbytes=0
for i in packet:
    f = Solution(i)
    objlist.append((f.timestamp,f))
    counter0=counter0+1
    totalbytes+=f.datalen1
flows=[]
for j in objlist:
    if j[1].synflag=='1' and j[1].ackflag=='0' :
        flows.append(j)
list1=[]
for i in range(len(flows)):
    sublist=[]
    for j in objlist:
        if (flows[i][1].sourceport==j[1].sourceport and flows[i][1].destport==j[1].destport) :
            sublist.append(j)
        if ( flows[i][1].destport==j[1].sourceport and flows[i][1].sourceport==j[1].destport):
            sublist.append(j)
    list1.append(sublist)
for i in range(len(list1)):
    count=0
    print "HTTP flow for:",flows[i][1].sourceport
    print  " "
    for j in range(len(list1[i])):
        if list1[i][j][1].httpflag==1:
                if  list1[i][j][1].data=="GET ":
                    print "GET Requests",(list1[i][j][1].data,list1[i][j][1].sourceip,list1[i][j][1].destip,list1[i][j][1].seqno,list1[i][j][1].ackno)
                    print " "
                    print "Http Responses"
                for k in range(j+1,len(list1[i])):
                    if list1[i][k][1].httpflag==1 and list1[i][k][1].data=="HTTP":
                        print (list1[i][k][1].data,list1[i][k][1].sourceip,list1[i][k][1].destip,list1[i][k][1].seqno,list1[i][k][1].ackno)
                        count=1
                    elif list1[i][k][1].httpflag==1 and list1[i][k][1].data!="GET " and count==1:
                        print (list1[i][k][1].sourceip,list1[i][k][1].destip,list1[i][k][1].seqno,list1[i][k][1].ackno)
                    break
    break
a = {}
objlist1=[]
countera=0
counterb=0
count=0
totalbytesa=0
totalbytesb=0
b={}
for i in packets1:
    f = Solution(i)
    objlist1.append((f.timestamp,f))
    countera=countera+1
    totalbytesa+=f.datalen1
    if f.length >66:
        if f.sourceport in a:
            a[f.sourceport]+=1
        else:
            a[f.sourceport]=count
if len(a)==1:
    print "for File http_1081"
    versiona="HTTP version 2.0"
    print "HTTP version 2.0"
else:
    print "for File http_1081"
    versionb="HTTP version 1.1"
    print "HTTP version 1.1"

objlist2=[]
for i in packets2:
    f = Solution(i)
    objlist2.append((f.timestamp,f))
    counterb=counterb+1
    totalbytesb+=f.datalen1
    if f.length >66:
        if f.sourceport in b:
            b[f.sourceport]+=1
        else:
            b[f.sourceport]=count
if len(b)<len(a):
    print "for File http_1082"
    versionb="HTTP version 2.0"
    print "HTTP version 2.0"
else:
    print "for File http_1082"
    versionb="HTTP version 1.1"
    print "HTTP version 1.1"

timestamp1=objlist[0][0]
timestamp2=objlist[len(objlist)-1][0]
print "Time Required to load Site ",timestamp2-timestamp1,"packets",counter0,"raw bytes",totalbytes


timestamp3=objlist1[0][0]
timestamp4=objlist1[len(objlist1)-1][0]
print "Time Required to load Site ",timestamp4-timestamp3,"packets",countera,"raw bytes",totalbytesa

timestamp5=objlist2[0][0]
timestamp6=objlist2[len(objlist2)-1][0]
print "Time Required to load Site ",timestamp6-timestamp5,"packets",counterb,"raw bytes",totalbytesb
