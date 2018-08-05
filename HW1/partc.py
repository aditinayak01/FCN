import time
import dns.query
import matplotlib.pyplot as plt
import numpy as np
import dns.resolver
sites=['Google.com','Youtube.com','Facebook.com','Baidu.com','Wikipedia.org','Reddit.com','Yahoo.com',
'Google.co.in','Qq.com','Taobao.com','Amazon.com','Tmall.com','Twitter.com','Google.co.jp','Instagram.com','Live.com',
'Vk.com','Sohu.com','Sina.com.cn','Jd.com','Weibo.com','360.cn','Google.de','Google.co.uk','Google.com.br']
rootservers1=['198.41.0.4','199.9.14.201','192.33.4.12', '199.7.91.13','192.203.230.10','192.5.5.241',
                 '192.112.36.4', '198.97.190.53', '192.36.148.17', '192.58.128.30','193.0.14.129'
                 ,'199.7.83.42','202.12.27.33']

def getpropername(type,domain):
    if type == "MX" or type == "NS":
        domain1 = domain.replace("www.", "")
        name = dns.name.from_text(domain1)
    else:
        name = dns.name.from_text(domain)
    return name

#Creating query and response and gettinf lfag value of response
def preprocess(name,type,root):
    query = dns.message.make_query(name, type)
    response = dns.query.udp(query, root, timeout=1)
    flag = dns.flags.to_text(response.flags)
    flag = flag.split(" ")[1]
    return response,flag

#Resolve Function Checking for various records
def resolve(domain,type,rootservers):
    try:
        name=getpropername(type,domain)
        #looping for all rootservers
        for root in rootservers:
            response, flag = preprocess(name,type,root)
            # Looping while answer section is empty
            while len(response.answer)==0:
                # first checking and resolving entries in additional section
                if (len(response.additional))>0:
                    for i in response.additional:
                        for j in i:
                            if (dns.rdatatype.to_text(j.rdtype) == 'A' or dns.rdatatype.to_text(j.rdtype) == 'MX' or dns.rdatatype.to_text(j.rdtype) == 'NS'):
                                answer1=resolve(domain,type,[j.address])
                                if answer1!=None:
                                    return answer1
                # if additional section empty rresolving for authority section entries
                elif (len(response.authority))>0:
                    # resolving if responses have SOA records
                    if (dns.rdatatype.to_text(response.authority[0].rdtype)=='SOA'):
                        return response,1,1
                    #Resolving for records other than SOA
                    for i in response.authority:
                        for j in i:
                            r = resolve(str(j), "A", rootservers1)
                            if r != None:
                                for i in r[0].answer:
                                    for j in i:
                                        r = resolve(domain, type, [str(j)])
                                    if r != None:
                                        return r

            # Enter if answer section is not empty and its a authoritative response
            if (flag == 'AA') and len(response.answer)>0:
                for i in response.answer:
                    #if A,MX,NS records return the response
                    if (dns.rdatatype.to_text(i.rdtype) == 'A' or dns.rdatatype.to_text(i.rdtype) == 'MX' or dns.rdatatype.to_text(i.rdtype) == 'NS'):
                        return response,1,1
                    # if Response have Cname resolve it
                    elif (dns.rdatatype.to_text(i.rdtype) == 'CNAME'):
                        canname = str(i.items[0])
                        # query rootservers again with cname
                        response1 = resolve(canname, type, rootservers1)
                        if response1 != None:
                            return response1,i,canname
                break
    except dns.exception.Timeout:
        pass
timelist=[]
for i in sites:
    sum=0
    for j in range(10):
        t1 =int(round(time.time()*1000))
        resolve(i,'A',rootservers1)
        t2=int(round(time.time()*1000))
        dif=t2-t1
        sum=sum+dif
    average=sum/10
    #print "The average time for:",domain,"is",average,"msec"  #..... remove comment to print average time
    timelist.append(round(average,1))

res=dns.resolver.Resolver(configure=False)
res.nameservers=['8.8.8.8','8.8.4.4']
timelist1=[]
for i in sites:
    t1 = time.time()
    domain=i
    sum=0
    for j in range(10):
        t1 =int(round(time.time()*1000))
        res.query(i, 'A')
        t2=int(round(time.time()*1000))
        dif=t2-t1
        sum=sum+dif
    average=sum/10
    timelist1.append(round(average,1))

res2=dns.resolver.Resolver(configure=False)
res2.nameservers=['207.244.82.25']
timelist2=[]
for i in sites:
    t1 = time.time()
    domain=i
    sum=0
    for j in range(10):
        t1 =int(round(time.time()*1000))
        res2.query(i, 'A')
        t2=int(round(time.time()*1000))
        dif=t2-t1
        sum=sum+dif
    average=sum/10
    timelist2.append(round(average,2))

sortedtime = np.sort(timelist)
sortedtime1=np.sort(timelist1)
sortedtime2=np.sort(timelist2)
p = 1. * np.arange(len(timelist))/(len(timelist) - 1)
p1=1. * np.arange(len(timelist1))/(len(timelist1) - 1)
p2=1. * np.arange(len(timelist2))/(len(timelist2) - 1)
plt.axis([0,1000, 0, 1])
plt.plot(sortedtime1,p1,sortedtime,p,sortedtime2,p2)
plt.margins(0.02)
plt.xlabel('Time(milliseconds)')
plt.ylabel('CDF')
plt.show()


