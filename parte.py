from scapy.all import *



nocookies = 0
yescookies=0
notworking=0



def E(add):
    global ipcount,nocookies,yescookies,notworking
    print("address is:"+add)
    print(ipcount)
    ipcount = ipcount + 1
    x=IP(dst=add)/TCP(dport=80)
    ans, y=sr(x,timeout = 60, multi=True , verbose=0)
    if ans is not None:
        print("what is received "+str(ans.__len__()))
        if ans.__len__() > 1:
            nocookies=nocookies+1
        elif ans.__len__() == 1:
            yescookies=yescookies+1
        else:
            notworking=notworking+1
#    print("no cookies:"+str(nocookies)+"   yes cookies:"+str(yescookies)+"   no longer working:"+str(notworking))


ipcount=1
def starter(list1):
    #f = open("output/FORPART_E.txt", "r")
    i=0
    ipcount = 1
    q=''
    for x in list1:
        E(x.strip("\n"))
    print("PART E: no cookies: "+str(nocookies)+"/186   yes cookies: "+str(yescookies)+"/186   no longer working: "+str(notworking)+"/186")