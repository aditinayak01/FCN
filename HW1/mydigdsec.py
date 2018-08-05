import sys
import dns.query
import dns.rdtypes.ANY.NSEC
import dns.rdtypes.ANY.NSEC3
import time
rootservers1=['198.41.0.4','199.9.14.201','192.33.4.12', '199.7.91.13','192.203.230.10','192.5.5.241',
                 '192.112.36.4', '198.97.190.53', '192.36.148.17', '192.58.128.30','193.0.14.129'
                 ,'199.7.83.42','202.12.27.33']

domain=sys.argv[1]
rtype=sys.argv[2]
def getname(domain):
    name = dns.name.from_text(domain)
    return name

# Validation Method
def validate(response1,response2,zone):
    dnskey = response1.answer[0]
    rrsigdns = response1.answer[1]
    ns=''
    if len(response1.answer) > 0:
        try:
            dns.dnssec.validate(dnskey, rrsigdns, {zone: dnskey})
        except Exception as e:
            print (e)
            print("DNSSEC is configured but failed here")
            exit()

    if len(response2.answer) > 0:
        dels = response2.answer[0]
        rrsig = response2.answer[1]
        if (isinstance(dels[0], dns.rdtypes.ANY.NSEC.NSEC) or isinstance(dels[0], dns.rdtypes.ANY.NSEC3.NSEC3)):
            print("DNSEC is not supported")
            exit()
        else:
            try:
                dns.dnssec.validate(dels, rrsig, {zone: dnskey})
            except Exception as e:
                print(e)
                print("DNSSEC is configured but failed here")
                exit()
    else:
        ns = response2.authority[0]
        dels = response2.authority[1]
        rrsig = response2.authority[2]
        if (isinstance(dels[0], dns.rdtypes.ANY.NSEC.NSEC) or isinstance(dels[0], dns.rdtypes.ANY.NSEC3.NSEC3)):
            print("DNSEC is not supported")
            exit()
        else:
            try:
                dns.dnssec.validate(dels, rrsig, {zone: dnskey})
            except Exception as e:
                print(e)
                print("DNSSEC is configured but failed here")
                exit()

    return ns,dels

def preprocess(name,rtype,root):
    query = dns.message.make_query(name, rtype,use_edns=True)
    response = dns.query.udp(query, root, timeout=1)
    flag = dns.flags.to_text(response.flags)
    flag = flag.split(" ")[1]
    return response,flag

def resolve(domain, rtype, rootservers,zone,ds_parent):
    name = getname(domain)
    # looping for all rootservers
    for root in rootservers:
        zone = str(zone)
        zone = dns.name.from_text(zone)
        query1 = dns.message.make_query(zone, dns.rdatatype.DNSKEY, want_dnssec=True)
        response1 = dns.query.tcp(query1, root, timeout=1)
        query2 = dns.message.make_query(name, 'A', want_dnssec=True)
        response2 = dns.query.tcp(query2, root, timeout=1)

        ns,dels=validate(response1,response2,zone)
        #chain of trust
        if ds_parent is not None:
            for i in response1.answer[0]:
                if str(i).split(" ")[0] == '257':
                    if dns.dnssec.make_ds(zone, i, "SHA256") == ds_parent[0]:
                        print("Chain of trust validated")
                        break
                    else:
                        print("Validation Failed")
                        exit()

        response, flag = preprocess(name, rtype, root)
        # Looping while answer section is empty
        while len(response.answer) == 0:
            # first checking and resolving entries in additional section
            if (len(response.additional)) > 0:
                for i in response.additional:
                    for j in i:
                        if (dns.rdatatype.to_text(j.rdtype) == 'A'):
                            for i in response2.authority:
                                i = str(i)
                                k = i.split(" ")
                            zsk = k[0]
                            answer1 = resolve(domain, rtype, [j.address], zsk, dels)
                            if answer1 != None:
                                return answer1
                        elif (dns.rdatatype.to_text(j.rdtype) == 'MX'):
                            for i in response2.authority:
                                i = str(i)
                                k = i.split(" ")
                            zsk = k[0]
                            answer1 = resolve(domain, rtype, [j.address], zsk, dels)
                            if answer1 != None:
                                return answer1
                        elif (dns.rdatatype.to_text(j.rdtype) == 'NS'):
                            for i in response2.authority:
                                i = str(i)
                                k = i.split(" ")
                            zsk = k[0]
                            answer1 = resolve(domain, rtype, [j.address], zsk, dels)
                            if answer1 != None:
                                return answer1
            # if additional section empty rresolving for authority section entries
            elif (len(response.authority)) > 0:
                # Resolving if responses have SOA records
                if (dns.rdatatype.to_text(response.authority[0].rdtype) == 'SOA'):
                    return response, 1, 1
                # Resolving for records other than SOA
                for i in response.authority:
                    for j in i:
                        for i in response2.authority:
                            i = str(i)
                            k = i.split(" ")
                        zsk = k[0]
                        r = resolve(str(j), "A", rootservers1, zsk, dels)
                        if r != None:
                            for i in r[0].answer:
                                for j in i:
                                    for i in response2.authority:
                                        i = str(i)
                                        k = i.split(" ")
                                    zsk = k[0]
                                    r = resolve(domain, rtype, [str(j)], zsk, dels)
                                if r != None:
                                    return r

        # Enter if answer section is not empty and its a authoritative response
        if (flag == 'AA') and len(response.answer) > 0:
            for i in response.answer:
                # if A,MX,NS records return the response
                if (dns.rdatatype.to_text(i.rdtype) == 'A'):
                    return response, 1, 1
                elif (dns.rdatatype.to_text(i.rdtype) == 'MX'):
                    return response, 1, 1
                elif (dns.rdatatype.to_text(i.rdtype) == 'NS'):
                    return response, 1, 1
                # if Response have Cname resolve it
                elif (dns.rdatatype.to_text(i.rdtype) == 'CNAME'):
                    canname = str(i.items[0])
                    # query rootservers again with cname
                    for i in response2.authority:
                        print i
                        i = str(i)
                        k = i.split(" ")
                    zsk = k[0]
                    response1 = resolve(canname, rtype, rootservers1, zsk, dels)
                    if response1 != None:
                        return response1, i, canname
            break

answer,i,canname= resolve(domain, rtype, rootservers1,'.',None)
print(answer)