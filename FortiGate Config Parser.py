"""
Fortinet Config Parse Tool v0.3

This tool is used to parse a Fortinet Fortigate configuration file into a human readable TSV format.

"""
import os.path
import re

#Create category ratings dictionary from the static file
ratings = {}
ratingFile = open('Categories.txt','r')
for line in ratingFile:
    tempLine = line.strip().split('=')
    if len(tempLine) >1:
        ratings[tempLine[0]] = tempLine[1]
ratingFile.close()


confFile = open('config.conf','r')

configLine_re = re.compile('\W*?config (.*)\n')
endLine_re = re.compile('\s*?(end)\n')
finalEnd_re = re.compile('(end)\n')

def printLine(line,secType):
    tempFile=open(secType + '.txt','a')
    print(line[:-1],file=tempFile)
    tempFile.close()

#Read the configuration file, and sort out the appropriate sections.
#Use defined printing function to separate sections into their own files.
secType = ''
for line in confFile:
    if configLine_re.match(line) is not None:
        secType = (configLine_re.findall(line)[0])

    if secType == "firewall policy":
        if finalEnd_re.match(line) or configLine_re.match(line):
            continue
        printLine(line,secType)
    elif secType == "identity-based-policy":
        if endLine_re.match(line) is not None:
            secType = "firewall policy"
            printLine(line,secType)
            continue
        secType = "firewall policy"
        printLine(line,secType)
    elif secType == "firewall address":
        if finalEnd_re.match(line) or configLine_re.match(line):
            continue
        printLine(line,secType)
    elif secType == "firewall addrgrp":
        if finalEnd_re.match(line) or configLine_re.match(line):
            continue
        printLine(line,secType)
    elif secType =="router static":
        if finalEnd_re.match(line) or configLine_re.match(line):
            continue
        printLine(line,secType)
    elif secType == "webfilter ftgd-local-cat":
        if finalEnd_re.match(line) or configLine_re.match(line):
            continue
        printLine(line,secType)
    elif secType == "webfilter ftgd-local-rating":
        if finalEnd_re.match(line) or configLine_re.match(line):
            continue
        printLine(line,secType)
    elif secType == "vpn ipsec phase2-interface":
        if finalEnd_re.match(line) or configLine_re.match(line):
            continue
        printLine(line,secType)
    else:
        continue
confFile.close()

#Compiled regexes which will find specific key/value pairs - likely not necessary to have one of each
srcint_re = re.compile('set srcintf "(.*?)"')
dstint_re = re.compile('set dstintf "(.*?)"')
srcaddr_re = re.compile('set srcaddr (".*")')
dstaddr_re = re.compile('set dstaddr (".*")')
action_re = re.compile('set action (.*?)\n')
schedule_re = re.compile('set schedule (".*")')
svc_re = re.compile('set service (".*")')
utmstatus_re = re.compile('set utm-status (.*?)\n')
logtraffic_re = re.compile('set logtraffic (.*?)\n')
applist_re = re.compile('set application-list (".*")')
avprofile_re = re.compile('set av-profile (".*")')
webfilterprofile_re = re.compile('set webfilter-profile (".*")')
ipssensor_re = re.compile('set ips-sensor (".*")')
sslportal_re = re.compile('set sslvpn-portal (".*")')
ppo_re = re.compile('set profile-protocol-options (".*")')
dio_re = re.compile('set deep-inspection-options (".*")')
nat_re = re.compile('set nat (.*?)\n')
fsso_re = re.compile('set fsso (.*?)\n')
group_re = re.compile('set groups (.*?)\n')
identitybased_re = re.compile('set identity-based (.*?)\n')
comments_re = re.compile('set comments (".*")')
sslcipher_re = re.compile('set sslvpn-cipher (.*?)\n')
ippool_re = re.compile('set ippool (.*?)\n')
poolname_re = re.compile('set poolname "(.*?)"\n')

if os.path.isfile("firewall policy.txt"):
    file = open('firewall policy.txt', 'r')
    policyfile = open('./policy.tsv', 'w+')

    #Print the header row for our TSV file, and initialize the variables used.
    print ("Rule #\tInterfaces\tSources\tDestinations\tIdentity Based\tServices\tAction\tSchedule\tLog Traffic\tNAT\tIP-Pool\tPoolName\tUTM-Status\tFSSO\tGroups\tApplicaiton List\tAV Profile\tWebfilter Profile\tIPS Sensor\tProfile Protocol\tDeep Inspection\tSSL-Cipher\tSSL-Portal\tComments",file=policyfile)
    rule=srcint=dstint=srcaddrStr=dstaddrStr=ident=svcStr=action=schedule=utm=log=groupStr=appList=av=web=ips=ppo=dio=nat=fsso=comment=sslPortal=sslCipher=ippool=poolname = ''

    #Begin looping through each line. We will grouping policies together based on the 'edit' and 'next' keywords - with an exception for identity based policies (which should be 'nested' in the spreadsheet)
    for line in file:
        #check for conditions which trigger the current line to print, and then reset all variables. 
        #We want identity based policies on their own line, the phrase 'config identity-based-policy' can trigger this.
        if ("next" in line) or ("config identity-based-policy" in line):
            #Stops an extra line from being printed after identity based sections
            if rule == '':
                    continue
            print ("%s\t%s:%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s" % (rule,srcint,dstint,srcaddrStr,dstaddrStr,ident,svcStr,action,schedule,log,nat,ippool,poolname,utm,fsso,groupStr,appList,av,web,ips,ppo,dio,sslCipher,sslPortal,comment),file=policyfile)
            rule=srcint=dstint=srcaddrStr=dstaddrStr=ident=svcStr=action=schedule=utm=log=groupStr=appList=av=web=ips=ppo=dio=nat=fsso=comment=sslPortal=sslCipher=ippool=poolname = ''
            continue
        #Find the policy number being worked on
        newRule = re.search("edit ([0-9]+.*?)\n",line)
        if newRule:
            rule = newRule.group(1)
            continue

        
        #Begin checking what key/value this line contains (if not one of the 'processing' keys from above.) If one is found, evaluate it, and stop checking - moving onto the next line in the file. 
        #*******NOTE: SOME PROPERTY TYPES MAY BE MISSING IF I'M NOT AWARE OF THEM*******
        #Some of these may return multiple values; If so, they are enumerated and compiled into a comma separated string. 
        if "set srcintf" in line:
            tmp = srcint_re.findall(line)
            srcint = tmp[0]
            continue
        if "set dstintf" in line:
            tmp = dstint_re.findall(line)
            dstint = tmp[0]
            continue
        if "set srcaddr" in line:
            srcaddr = srcaddr_re.findall(line)
            srcaddrStr = ''.join(map(str,srcaddr))
            srcaddrStr = srcaddrStr.replace('"','')
            continue
        if "set dstaddr" in line:
            dstaddr = dstaddr_re.findall(line)
            dstaddrStr = ''.join(map(str,dstaddr))
            dstaddrStr = dstaddrStr.replace('"','')
            continue
        if "set action" in line:
            tmp = (action_re.findall(line)[0])
            action = tmp
            continue
        if "set schedule" in line:
            tmp = (schedule_re.findall(line)[0])
            schedule = tmp[1:-1]
            continue
        if "set service" in line: 
            svc = svc_re.findall(line)
            svcStr = ''.join(map(str,svc))
            svcStr = svcStr.replace('"','')
            continue
        if "set logtraffic" in line:
            log = (logtraffic_re.findall(line)[0])
            continue
        if "set nat" in line:
            nat = (nat_re.findall(line)[0])
            continue
        if "set utm-status" in line:
            utm = (utmstatus_re.findall(line)[0])
            continue
        if "application-list" in line:
            appList = (applist_re.findall(line)[0])
            appList = appList[1:-1]
            continue
        if "profile-protocol-options" in line:
            ppo = (ppo_re.findall(line)[0])
            ppo = ppo[1:-1]
            continue
        if "set comments" in line:
            comment = (comments_re.findall(line)[0])
            comment = comment[1:-1]
            continue
        if "set av-profile" in line:
            av = (avprofile_re.findall(line)[0])
            av = av[1:-1]
            continue
        if "set ips-sensor" in line:
            ips = (ipssensor_re.findall(line)[0])
            ips = ips[1:-1]
            continue
        if "set webfilter-profile" in line:
            web = (webfilterprofile_re.findall(line)[0])
            web = web[1:-1]
        if "set deep-inspection-options" in line:
            dio = (dio_re.findall(line)[0])
            dio = dio[1:-1]
            continue
        if "set identity-based" in line:
            ident = (identitybased_re.findall(line)[0])
            continue
        if "config identity-based-policy" in line:
            continue
        if "set groups" in line:
            groups = group_re.findall(line)
            groupStr = ''.join(map(str,groups))
            groupStr = groupStr.replace('"','')
            continue
        if "set sslvpn-portal" in line:
            sslPortal = (sslportal_re.findall(line)[0])
            sslPortal = sslPortal[1:-1]
            continue
        if "set sslvpn-cipher" in line:
            sslCipher = (sslcipher_re.findall(line)[0])
            continue
        if "set fsso" in line:
            fsso = (fsso_re.findall(line)[0])
            continue
        if "set ippool" in line:
            ippool = (ippool_re.findall(line)[0])
            continue
        if "set poolname" in line:
            poolame = (poolname_re.findall(line)[0])
            print(poolname)
            continue
    file.close()
    policyfile.close()
    os.remove('firewall policy.txt')

type_re = re.compile('set type (.*?)\n')
endIP_re = re.compile('set end-ip (\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})')
startIP_re = re.compile('set start-ip (\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})')
subnet_re = re.compile('set subnet (\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3} \d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})')
interface_re = re.compile('set associated-interface "(.*?)"')
comment_re = re.compile('set comment "(.*?)"\n')
fqdn_re = re.compile('set fqdn "(.*?)"\n')

if os.path.exists("firewall address.txt"):
    file = open('firewall address.txt', 'r')
    addrFile = open('./addresses.tsv', 'w+')

    print ("Address\tType\tSubnet\tInterface\tFQDN\tStart IP\tEnd IP\tComment",file=addrFile)
    addr=addrInt=addrType=endIP=startIP=subnet=fqdn=comment = ""

    for line in file:
        if "next" in line:
            print("%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s" %(addr,addrType,subnet,addrInt,fqdn,startIP,endIP,comment),file=addrFile)
            addr=addrInt=addrType=endIP=startIP=subnet=fqdn=comment = ""
            continue
        newAddr = re.search('edit "(.*?)"\n',line)
        if newAddr:
            addr = newAddr.group(1)
            continue
        if "set associated-interface" in line:
            tmp = interface_re.findall(line)
            addrInt = tmp[0]
            continue
        if "set type" in line:
            tmp = type_re.findall(line)
            addrType = tmp[0]
            continue
        if "set end-ip" in line:
            tmp = endIP_re.findall(line)
            endIP = tmp[0]
            continue
        if "set start-ip" in line:
            tmp = startIP_re.findall(line)
            startIP = tmp[0]
            continue
        if "set fqdn" in line:
            tmp = fqdn_re.findall(line)
            fqdn = tmp[0]
            continue
        if "set comment" in line:
            tmp = comment_re.findall(line)
            comment = tmp[0]
            continue
        if "set subnet" in line:
            tmp = subnet_re.findall(line)
            subnet = tmp[0]
            continue
    file.close()
    addrFile.close()
    os.remove('firewall address.txt')

#Address Groups
member_re = re.compile('set member (.*?)\n')     
if os.path.exists("firewall addrgrp.txt"):
    file = open('firewall addrgrp.txt', 'r')
    groupFile = open('./groups.tsv', 'w+')

    print ("Group\tMembers",file=groupFile)
    group = ""

    for line in file:
        if "next" in line:
            print("%s\t%s" %(group,member),file=groupFile)
            group = ""
            continue
        newGroup = re.search('edit "(.*?)"\n',line)
        if newGroup:
            group = newGroup.group(1)
            continue
        if "set member" in line:
            member = (member_re.findall(line)[0])
            member = member.replace('"','')
            member = member.replace(' ','\t')
    file.close()
    groupFile.close()
    os.remove('firewall addrgrp.txt')

#Static Routes
if os.path.exists("router static.txt"):
    """
    Router Parsing
    """
    os.remove("router static.txt")

#Add local categories to ratings dictionary
catID_re = re.compile('set id (.*?)\n')
if os.path.exists("webfilter ftgd-local-cat.txt"):
    file = open("webfilter ftgd-local-cat.txt")

    for line in file:
        if "next" in line:
            ratings[ID]= cat
        newCat = re.search('edit "(.*?)"\n',line)
        if newCat:
            cat = newCat.group(1)
            continue
        if "set id" in line:
            ID = (catID_re.findall(line)[0])
    file.close()
    os.remove("webfilter ftgd-local-cat.txt")

#Web rating overrides
ratingID_re = re.compile('set rating (.*?)\n')
if os.path.exists("webfilter ftgd-local-rating.txt"):
    file = open("webfilter ftgd-local-rating.txt",'r')
    ratingFile = open('./ratings.tsv', 'w+')

    print("URL\tOverride Category",file=ratingFile)

    for line in file:
        if "next" in line:
            print("%s\t%s" %(url,rating), file=ratingFile)
        newURL = re.search('edit "(.*?)"\n',line)
        if newURL:
            url = newURL.group(1)
            continue
        if "set rating" in line:
            ID = (ratingID_re.findall(line)[0])
            rating = ratings[ID]
    file.close()
    ratingFile.close()
    os.remove("webfilter ftgd-local-rating.txt")

#IPSec Tunnels
    
p1_re = re.compile('set phase1name (.*?)\n')
srcName_re = re.compile('set src-name (.*?)\n')
dstName_re = re.compile('set dst-name (.*?)\n')
encrypt_re = re.compile('set proposal (.*?)\n')
keylife_re = re.compile('set keylifeseconds (.*?)\n')
keepalive_re = re.compile('set keepalive (.*?)\n')
autonego_re = re.compile('set auto-negotiate (.*?)\n')
pfs_re = re.compile('set pfs (.*?)\n')
dhgrp_re = re.compile('set dhgrp (.*?)\n')
replay_re = re.compile('set replay (.*?)\n')

if os.path.exists("vpn ipsec phase2-interface.txt"):
    file = open('vpn ipsec phase2-interface.txt', 'r')
    p2File = open('./phase2.tsv', 'w+')

    print ("Phase2\tP1\tSrc Name\tDst Name\tProposal\tKeylife\tKeep Alive?\tAuto-Negotiate?\tPFS?\tDH Group\tReplay Detection",file=p2File)
    name=p1=srcName=dstName=encrypt=keylife=keepalive=autonego=pfs=dhgrp=replay = ""

    for line in file:
        if "next" in line:
            print("%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s" %(name,p1,srcName,dstName,encrypt,keylife,keepalive,autonego,pfs,dhgrp,replay),file=p2File)
            name=p1=srcName=dstName=encrypt=keylife=keepalive=autonego=pfs=dhgrp=replay = ""
            continue
        newP2 = re.search('edit "(.*?)"\n',line)
        if newP2:
            name = newP2.group(1)
            continue
        if "set phase1name" in line:
            tmp = p1_re.findall(line)
            p1 = tmp[0]
            continue
        if "set src-name" in line:
            tmp = srcName_re.findall(line)
            srcName = tmp[0]
            continue
        if "set dst-name" in line:
            tmp = dstName_re.findall(line)
            dstName = tmp[0]
            continue
        if "set proposal" in line:
            tmp = encrypt_re.findall(line)
            encrypt = tmp[0]
            continue
        if "set keylifeseconds" in line:
            tmp = keylife_re.findall(line)
            keylife = tmp[0]
            continue
        if "set keepalive" in line:
            tmp = keepalive_re.findall(line)
            keepalive = tmp[0]
            continue
        if "set auto-negotiate" in line:
            tmp = autonego_re.findall(line)
            autonego = tmp[0]
            continue
        if "set pfs" in line:
            tmp = pfs_re.findall(line)
            pfs = tmp[0]
            continue
        if "set dhgrp" in line:
            tmp = dhgrp_re.findall(line)
            dhgrp = tmp[0]
            continue
        if "set replay" in line:
            tmp = replay_re.findall(line)
            replay = tmp[0]
            continue
    file.close()
    p2File.close()
    os.remove('vpn ipsec phase2-interface.txt')




