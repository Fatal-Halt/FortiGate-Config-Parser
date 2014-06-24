"""
Fortinet Config Parse Tool v0.1.1

This tool is used to parse a Fortinet Fortigate configuration file into a human readable TSV format.

Currently, three types of objects are parsed:
-Addresses
-Groups
-Policies (Rules)
Planned types:
-Vips
-Routes
-Users

For each type, the tool looks for an appropriate input file (eg: policy.txt to process policies). 
These input files should contain only the objects, and not the 'config firewall xxxxxx' / 'end' statements.
Example (While this example is a policy, the same structure should be used for the address and group files)
----------------
edit 1
   set srcintf "port1"
   set dstintf "port2"
   ....
   ....
next
edit 2
   ....
----------------
"""
import os.path
import re

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

if os.path.isfile("policy.txt"):
        file = open('policy.txt', 'r')
        policyfile = open('./policy.tsv', 'w+')

        #Print the header row for our TSV file, and initialize the variables used.
        print ("Rule #\tInterfaces\tSources\tDestinations\tIdentity Based\tServices\tAction\tSchedule\tLog Traffic\tNAT\tUTM-Status\tFSSO\tGroups\tApplicaiton List\tAV Profile\tWebfilter Profile\tIPS Sensor\tProfile Protocol\tDeep Inspection\tSSL-Cipher\tSSL-Portal\tComments",file=policyfile)
        rule=srcint=dstint=srcaddrStr=dstaddrStr=ident=svcStr=action=schedule=utm=log=groupStr=appList=av=web=ips=ppo=dio=nat=fsso=comment=sslPortal=sslCipher = ''

        #Begin looping through each line. We will grouping policies together based on the 'edit' and 'next' keywords - with an exception for identity based policies (which should be 'nested' in the spreadsheet)
        for line in file:
                #check for conditions which trigger the current line to print, and then reset all variables. 
                #We want identity based policies on their own line, the phrase 'config identity-based-policy' can trigger this.
                if ("next" in line) or ("config identity-based-policy" in line):
                        #Stops an extra line from being printed after identity based sections
                        if rule == '':
                                continue
                        print ("%s\t%s:%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s" % (rule,srcint,dstint,srcaddrStr,dstaddrStr,ident,svcStr,action,schedule,log,nat,utm,fsso,groupStr,appList,av,web,ips,ppo,dio,sslCipher,sslPortal,comment),file=policyfile)
                        rule=srcint=dstint=srcaddrStr=dstaddrStr=ident=svcStr=action=schedule=utm=log=groupStr=appList=av=web=ips=ppo=dio=nat=fsso=comment=sslPortal=sslCipher = ''
                        continue
                #Find the policy number being worked on
                newRule = re.search("edit ([0-9]+.*?)\n",line)
                if newRule:
                        rule = newRule.group(1)
                        continue

                
                #Begin checking what key/value this line contains (if not one of the 'processing' keys from above.) If one is found, evaluate it, and stop checking - moving onto the next line in the file. 
                #*******NOTE: SOME PROPERTY TYPES MAY BE MISSING IF I'M NOT AWARE OF THEM*******
                #Some of these may return multiple values; If so, they are enumerated and compiled into a comma seperated string. 
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
        file.close()
        policyfile.close()

type_re = re.compile('set type (.*?)\n')
endIP_re = re.compile('set end-ip (\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})')
startIP_re = re.compile('set start-ip (\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})')
subnet_re = re.compile('set subnet (\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3} \d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})')
interface_re = re.compile('set associated-interface "(.*?)"')
comment_re = re.compile('set comment "(.*?)"\n')
fqdn_re = re.compile('set fqdn "(.*?)"\n')

if os.path.exists("addresses.txt"):
        file = open('addresses.txt', 'r')
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

member_re = re.compile('set member (.*?)\n')
        
if os.path.exists("groups.txt"):
        file = open('groups.txt', 'r')
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
                        tmp = member_re.findall(line)
                        member = tmp[0]
                        member = member.replace('"','')
                        member = member.replace(' ','\t')
        file.close()
        groupFile.close()
