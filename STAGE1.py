from scapy.all import *
import parte as e








#####################STORED VARIABLES#######################
#done PART A:
ICMPisresponsive=[]
#done PART F
TTLdictF={}
#done PART B
ICMPIDCOUNTER=[]
#done PART C
TCPport80=[]
#done PART F
WINDOWdict={}
#done PART D
TCPIDCOUNTER=[]
#done PART E
FOR_E=[]
#####################STORED VARIABLES#######################
























#############################PART A###################################################

ipcount=0
#A. Device is responsive [yes/no]: <obtained answer> 
def A(add):
    global ipcount
    ipcount = ipcount + 1
    print("BEGINNING ANALYSIS OF  #%d/186 :  %s" %(ipcount, add))
    #print("----------PART A----------: %s" %(add))
    x=IP(dst=add)/ICMP(id=100)
    y=sr1(x,timeout = .2, verbose=0)
    if y is not None:
        w=y.id
        #print("THIS WORKS: %s " % (add))
        ICMPisresponsive.append(add)
        TTLdictF[add]=y.ttl
        B(add)
        #F("THIS IS TTL FOR  "+add+" : "+str(y.ttl))
        # (y.show())
    # else:
    #     print("THIS FAILED: %s" % (add))









###################################PART B###################################################






#B. IP-ID counter deployed by device (in ICMP pkts) [zero/incremental/random]: <obtained answer>

def B(add):
    qq=[]
    #print("----------PART B----------: %s" %(add))
    #print("THIS IS : %s TURN" % (add))
    for  x in range(5):
        x=IP(dst=add)/ICMP(id=1)
        y=sr1(x,timeout = .2, verbose=0)
        # w=y.id        
        #print("IP: %s----AND THIS IS ID %d" % (add, y.id))
        if y is not None:
            qq.append(int(y.id))
    if isIncremental(qq):
        #print("IT SEEMS THIS IS INCREMENTAL")
        ICMPIDCOUNTER.append("incremental")
    elif isConstant(qq):
        #print("IT SEEMS THIS IS CONSTANT")
        ICMPIDCOUNTER.append("constant")
    else:
        #print("IT SEEMS THIS IS RANDOM")
        ICMPIDCOUNTER.append("random")
    C(add)











###################################PART C###################################################


#C. Port 80 on device is open [yes/no]: <obtained answer>
def C(add):
    x=IP(dst=add)/TCP(dport=80)
    y=sr1(x,timeout = .2, verbose=0)
    #print("----------PART C----------: %s" %(add))
    if y is not None:
        w=y.id
        TCPport80.append(add)
        #print("THIS WORKS: %s " % (add))
        D(add)
        #if TCP in y:
        #F("THIS IS WINDOW FOR  "+add+" : "+str(y[TCP].window))
        WINDOWdict[add] = str(y.window)
        #y.show()
    # else:
    #     print("THIS FAILED: %s" % (add))
















###################################PART D###################################################

#D. IP-ID counter deployed by device (in TCP pkts) [zero/incremental/random]: <obtained answer> 
def D(add):
    qq=[]
   # print("----------PART D----------: %s" %(add))
   # print("THIS IS : %s TURN" % (add))
    for  x in range(5):
        x=IP(dst=add)/TCP(dport=80)
        y=sr1(x,timeout = .2, verbose=0)
        #w=x.payload.id
        if y is not None:
            #print("IP: %s----AND THIS IS ID %s" % (add, y[IP].id))
            qq.append(int(y.id))
    if isIncremental(qq):
        #print("IT SEEMS THIS IS INCREMENTAL")
        TCPIDCOUNTER.append("incremental")
    elif isConstant(qq):
        #print("IT SEEMS THIS IS CONSTANT")
        TCPIDCOUNTER.append("constant")
    else:
        #print("IT SEEMS THIS IS RANDOM")
        TCPIDCOUNTER.append("random")

    FOR_E.append(add)





###################################PART E###################################################    
#E. SYN cookies deployed by device [yes/no]: <obtained answer>
#PART E WAS DONE IN THE FILE parte.py









###################PART F ALREADY COMPLETED IN PART A AND PART C###########################
#F. Likely OS system deployed on the device [Linux/Windows]: <obtained answer> 
#PART F WAS RETAINED DURING THE TCP AND SYN ACK REQUESTS AND ICMP ECHO REPLIES























####################################IP-ID COUNTER IS CONSTANT OR INCREMENTAL ###############################

def isIncremental(tt):
    if tt.__len__()>1:
        if tt == list(range(tt[0],(tt[-1] + 1))):
            return True


def isConstant(tt):
    result = len(set(tt)) == 1
    return result






#########################READING FROM ADDRESSES IN THE addresses.txt########################################
ipcount=0
f = open("addresses.txt", "r")
i=0
q=''
for x in f:
    A(x.strip("\n"))






















####################################WRITING TO OUTPUT FILES IN FOLDER output############################################

'''

f = open("output/ICMPresponsive.txt", "w")
for i in ICMPisresponsive:
    f.write(i+"\n")

f = open("output/TTL_DICT.txt", "w")
for i in TTLdictF:
    f.write(i+","+str(TTLdictF[i])+"\n")

f = open("output/ICMPIDCOUNTER.txt", "w")
for i in ICMPIDCOUNTER:
    f.write(i+"\n")

f = open("output/TCPport80.txt", "w")
for i in TCPport80:
    f.write(i+"\n")

f = open("output/WINDOW_DICT.txt", "w")
for i in WINDOWdict:
    f.write(i+","+str(WINDOWdict[i])+"\n")

f = open("output/TCPIDCOUNT.txt", "w")
for i in TCPIDCOUNTER:
    f.write(i+"\n")

f = open("output/FORPART_E.txt", "w")
for i in FOR_E:
    f.write(i+"\n")
'''
















####################################PRINTIN OUT CONCLUSIONS TO STDOUT############################################



#Printing Totals:
print(" PART A: How many ICMP requests are responsive: "+str(ICMPisresponsive.__len__())+"/186 \n")
'''
f=open("output/ICMPIDCOUNTER.txt","r")
'''

cons=0
incr=0
ran=0
for x in ICMPIDCOUNTER:
    if x.__contains__("constant"):
        cons = cons+1
    if x.__contains__("random"):
        ran = ran+1
    if x.__contains__("incremental"):
        incr = incr+1

print(" PART B: constant:"+str(cons)+"/186 incremental:"+str(incr)+"/186 random:"+str(ran)+"/186 \n")


print(" PART C: How many TCP requests are responsive: "+str(TCPport80.__len__())+"/186\n")


'''
f=open("output/TCPIDCOUNT.txt","r")
'''
cons1=0
incr1=0
ran1=0
for x in TCPIDCOUNTER:
    if x.__contains__("constant"):
        cons1 = cons1+1
    if x.__contains__("random"):
        ran1 = ran1+1
    if x.__contains__("incremental"):
        incr1 = incr1+1

print(" PART D: constant:"+str(cons1)+"/186 incremental:"+str(incr1)+"/186 random:"+str(ran1)+"/186 \n")

ttlwithwin=[]
ttlwithoutwin=[]
for x in TTLdictF:
    if x in WINDOWdict:
        ttlwithwin.append((TTLdictF[x], WINDOWdict[x]))
    else:
        ttlwithoutwin.append(TTLdictF[x])

ttl255=0
ttl128=0
ttl64=0

for i in ttlwithoutwin:
    #print(str(i)+"\n")
    if i>128:
        ttl255=ttl255+1
    if i>64 and i<128:
        ttl128=ttl128+1
    if i<64:
        ttl64=ttl64+1
print("tll is 255: "+str(ttl255)+",  tll is 128: "+str(ttl128)+",  ttl is 64: "+str(ttl64))
xx=0
for i in ttlwithwin:
    xx=xx+1
    print(str(i[0])+","+str(i[1]))


print("TTL with WINDOW AMOUNT:"+str(xx))
















####################################PART E############################################
e.starter(FOR_E)



