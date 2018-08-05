import sys
import dns.query
import time
import datetime
t1=int(round(time.time()*1000))
rootservers1=['198.41.0.4','199.9.14.201','192.33.4.12', '199.7.91.13','192.203.230.10','192.5.5.241',
                 '192.112.36.4', '198.97.190.53', '192.36.148.17', '192.58.128.30','193.0.14.129'
                 ,'199.7.83.42','202.12.27.33']

domain=sys.argv[1]
rtype=sys.argv[2]

#Print Answer Section
def printanswer(answer, i, canname, t2, t1,rlen):
    if answer != None:
        if not isinstance(answer, tuple):
            if len(answer.answer) > 0:
                for r in answer.answer:
                    result = str(r).split(" ")
                    if canname != 1:
                        print ";QUESTION SECTION"
                        print domain, "IN", rtype
                        print ";ANSWER SECTION"
                        print domain,i
                        print canname, ' '.join(result[1:])
                        print";WHEN:", datetime.date.today().strftime("%A"), datetime.date.today().strftime("%B"), datetime.date.today().strftime("%d"), datetime.datetime.now(), datetime.date.today().strftime("%Y")
                        print ";QUERY TIME :", t2 - t1, "msec"

                        print ";MSG SIZE  rcvd : ",rlen
                    else:
                        print ";QUESTION SECTION"
                        print domain, "IN", rtype
                        print ";ANSWER SECTION"
                        print domain, ' '.join(result[1:])
                        print ";QUERY TIME :", t2 - t1, "msec"
                        print";WHEN:",datetime.date.today().strftime("%A"),datetime.date.today().strftime("%B"),datetime.date.today().strftime("%d"),datetime.datetime.now(),datetime.date.today().strftime("%Y")
                        print ";MSG SIZE  rcvd : ", rlen
                        break
            else:
                for r in answer.authority:
                    result = str(r).split(" ")
                    print ";QUESTION SECTION"
                    print domain, "IN", rtype
                    print ";AUTHORITY SECTION"
                    print domain, ' '.join(result[1:])
                    print ";QUERY TIME :", t2 - t1, "msec"
                    print";WHEN:", datetime.date.today().strftime("%A"), datetime.date.today().strftime(
                        "%B"), datetime.date.today().strftime(
                        "%d"), datetime.datetime.now(), datetime.date.today().strftime("%Y")

                    print ";MSG SIZE  rcvd : ", rlen
                    break


        else:
            if not isinstance(answer[0], tuple):
                if len(answer[0].answer) != 0:
                    for r in answer[0].answer:
                        result = str(r).split(" ")
                        if canname != 1:
                            print ";QUESTION SECTION"
                            print domain, "IN", rtype
                            print ";ANSWER SECTION"
                            print domain, i
                            print canname, ' '.join(result[1:])
                            print ";QUERY TIME :", t2 - t1, "msec"
                            print";WHEN:", datetime.date.today().strftime("%A"), datetime.date.today().strftime(
                                "%B"), datetime.date.today().strftime(
                                "%d"), datetime.datetime.now(), datetime.date.today().strftime("%Y")

                            print ";MSG SIZE  rcvd : ", rlen
                        else:
                            print ";QUESTION SECTION"
                            print domain, "IN", rtype
                            print ";ANSWER SECTION"
                            print domain, i
                            print";QUERY TIME :", t2 - t1, "msec"
                            print";WHEN:", datetime.date.today().strftime("%A"), datetime.date.today().strftime(
                                "%B"), datetime.date.today().strftime(
                                "%d"), datetime.datetime.now(), datetime.date.today().strftime("%Y")

                            print ";MSG SIZE  rcvd : ", rlen
                else:
                    for r in answer[0].authority:
                        result = str(r).split(" ")
                        print ";QUESTION SECTION"
                        print domain, "IN", rtype
                        print ";AUTHORITY SECTION"
                        print domain, ' '.join(result[1:])
                        print ";QUERY TIME :", t2 - t1, "msec"
                        print";WHEN:",datetime.date.today().strftime("%A"),datetime.date.today().strftime("%B"),datetime.date.today().strftime("%d"),datetime.datetime.now(),datetime.date.today().strftime("%Y")

                        print ";MSG SIZE  rcvd : ", rlen
                        break

            elif answer[0][0].answer != None:
                for r in answer[0][0].answer:
                    result = str(r).split(" ")
                    if canname != 1:
                        print ";QUESTION SECTION"
                        print domain, "IN", rtype
                        print ";ANSWER SECTION"
                        print domain, i
                        print canname, ' '.join(result[1:])
                        print ";QUERY TIME :", t2 - t1, "msec"
                        print";WHEN:",datetime.date.today().strftime("%A"),datetime.date.today().strftime("%B"),datetime.date.today().strftime("%d"),datetime.datetime.now(),datetime.date.today().strftime("%Y")

                        print ";MSG SIZE  rcvd : ", rlen
                    else:
                        print ";QUESTION SECTION"
                        print domain, "IN", rtype
                        print ";ANSWER SECTION"
                        print domain, i
                        print";QUERY TIME :", t2 - t1, "msec"
                        print";WHEN:", datetime.date.today().strftime("%A"), datetime.date.today().strftime(
                            "%B"), datetime.date.today().strftime(
                            "%d"), datetime.datetime.now(), datetime.date.today().strftime("%Y")

                        print ";MSG SIZE  rcvd : ", rlen
                        break

#Send Proper Name depending on type
def getname(domain):
    name = dns.name.from_text(domain)
    return name

#Creating query and response and getting flag value of response
def preprocess(name,rtype,root):
    query = dns.message.make_query(name, rtype)
    response = dns.query.udp(query, root, timeout=1)
    flag = dns.flags.to_text(response.flags)
    flag = flag.split(" ")[1]
    return response,flag

#Resolve Function Checking for various records
def resolve(domain,rtype,rootservers):
    try:
        name=getname(domain)
        #looping for all rootservers
        for root in rootservers:
            response, flag = preprocess(name,rtype,root)
            # Looping while answer section is empty
            while len(response.answer)==0:
                # first checking and resolving entries in additional section
                if (len(response.additional))>0:
                    for i in response.additional:
                        for j in i:
                            if (dns.rdatatype.to_text(j.rdtype) == 'A'):
                                answer1=resolve(domain,rtype,[j.address])
                                if answer1!=None:
                                    return answer1
                            elif (dns.rdatatype.to_text(j.rdtype) == 'MX'):
                                answer1=resolve(domain,rtype,[j.address])
                                if answer1!=None:
                                    return answer1
                            elif (dns.rdatatype.to_text(j.rdtype) == 'NS'):
                                answer1 = resolve(domain,rtype, [j.address])
                                if answer1 != None:
                                    return answer1
                # if additional section empty rresolving for authority section entries
                elif (len(response.authority))>0:
                    # Resolving if responses have SOA records
                    if (dns.rdatatype.to_text(response.authority[0].rdtype)=='SOA'):
                        return response,1,1
                    #Resolving for records other than SOA
                    for i in response.authority:
                        for j in i:
                            r = resolve(str(j), "A", rootservers1)
                            if r != None:
                                for i in r[0].answer:
                                    for j in i:
                                        r = resolve(domain, rtype, [str(j)])
                                    if r != None:
                                        return r

            # Enter if answer section is not empty and its a authoritative response
            if (flag == 'AA') and len(response.answer)>0:
                for i in response.answer:
                    #if A,MX,NS records return the response
                    if (dns.rdatatype.to_text(i.rdtype) == 'A'):
                        return response,1,1
                    elif (dns.rdatatype.to_text(i.rdtype) == 'MX'):
                        return response, 1, 1
                    elif (dns.rdatatype.to_text(i.rdtype) == 'NS'):
                        return response, 1, 1
                    # if Response have Cname resolve it
                    elif (dns.rdatatype.to_text(i.rdtype) == 'CNAME'):
                        canname = str(i.items[0])
                        # query rootservers again with cname
                        response1 = resolve(canname, rtype, rootservers1)
                        if response1 != None:
                            return response1,i,canname
                break
    except dns.exception.Timeout:
        pass

answer,i,canname= resolve(domain, rtype, rootservers1)
rlen = 0
ralen = 0
raddlen = 0
rqlen=0

# Calculating message size
if answer != None:
    if not isinstance(answer, tuple):
        if len(answer.question)>0:
            for r in answer.question:
                result = str(r).split(" ")
                rqlen += len(str(result))
        if len(answer.answer) > 0:
            for r in answer.answer:
                rlen +=len(str(r))
        if len(answer.authority) > 0:
            for r in answer.authority:
                result = str(r).split(" ")
                ralen += len(str(result))
        if len(answer.additional) > 0:
            for r in answer.additional:
                result = str(r).split(" ")
                raddlen += len(str(result))
        rlen += raddlen + ralen+rqlen
    elif not isinstance(answer[0], tuple):
        if len(answer[0].question)>0:
            for r in answer[0].question:
                result = str(r).split(" ")
                rqlen += len(str(result))
        if len(answer[0].answer) > 0:
            for r in answer[0].answer:
                rlen +=len(str(r))
        if len(answer[0].authority) > 0:
            for r in answer[0].authority:
                result = str(r).split(" ")
                ralen += len(str(result))
        if len(answer[0].additional) > 0:
            for r in answer[0].additional:
                result = str(r).split(" ")
                raddlen += len(str(result))
        rlen += raddlen + ralen+rqlen
    elif not isinstance(answer[0][0], tuple):
        if len(answer[0][0].question) > 0:
            for r in answer[0][0].question:
                result = str(r).split(" ")
                rqlen += len(str(result))
        if len(answer[0][0].answer) > 0:
            for r in answer[0][0].answer:
                rlen += len(str(r))
        if len(answer[0][0].authority) > 0:
            for r in answer[0][0].authority:
                result = str(r).split(" ")
                ralen += len(str(result))
        if len(answer[0][0].additional) > 0:
            for r in answer[0][0].additional:
                result = str(r).split(" ")
                raddlen += len(str(result))
        rlen += raddlen + ralen + rqlen
t2=int(round(time.time()*1000))
printanswer(answer,i,canname,t2,t1,rlen)

