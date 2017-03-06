import sys
import re
import ipaddress


def expand_range(iprangestr):
    if is_ip_range(iprangestr):
        split = iprangestr.split('-')
        start_ip = split[0]
        iprange = (iprangestr.split('.')[-1]).split('-')
        iprange = list(range(int(iprange[0]),int(iprange[1])+1))
        netobj = ipaddress.IPv4Network(start_ip+'/24', strict=False)
        iprange = ([str(netobj[i]) for i in iprange])
        expanded_ips = None
        for l in iprange :
            if expanded_ips is None :
                expanded_ips = l
            expanded_ips += ',' + l
        return expanded_ips

def is_ip_range(teststr):
    return True if '-' in teststr else False


def Filter_Policies(configfilename):
    config_mode = 'ExecMode'
    with open(configfilename,'r') as fd , open(configfilename + '_tempfile', 'w') as out:
        for line in fd :
            if 'config firewall policy6' in line :
                continue
            elif 'config firewall policy' in line :
                config_mode = 'FIREWALLPOLICY'
                out.write('------------------------------START PHASE I------------------------------\n')
            elif 'edit' in line and config_mode is 'FIREWALLPOLICY' :
                config_mode = 'FIREWALLPOLICYEDIT'
                MatchedElement = re.search('\d[0-9]*',line)
                out.write(MatchedElement.group(0) + ';')
            elif 'next' in line and config_mode is 'FIREWALLPOLICYEDIT':
                config_mode = 'FIREWALLPOLICY'
                out.write('\n')
            elif 'set srcaddr ' in line and config_mode is 'FIREWALLPOLICYEDIT' :
                line = line.strip()
                line = line.lstrip()
                MatchedElement = re.search('(".*"$)', line)
                CSV = (MatchedElement.group(0)).replace('" "',',')
                ipliststr = Process_AddrGroups(CSV,configfilename)
                out.write(ipliststr + ';')
            elif 'set dstaddr ' in line and config_mode is 'FIREWALLPOLICYEDIT':
                line = line.strip()
                line = line.lstrip()
                MatchedElement = re.search('(".*"$)', line)
                CSV = (MatchedElement.group(0)).replace('" "',',')
                ipliststr = Process_AddrGroups(CSV,configfilename)
                out.write(ipliststr + ';')
            elif 'end' in line and config_mode is 'FIREWALLPOLICY' :
                config_mode = 'ExecMode'
                out.write('------------------------------END PHASE I------------------------------\n')
    out.close()
    fd.close()


def Process_AddrGroups(ListOfIPs,configfilename):
    expanded_ips = None
    CSV = ListOfIPs.replace('"','')
    list = CSV.split(',')
    for l in list :
        if is_ip_range(l) :
            if expanded_ips is None :
                expanded_ips = l
            expanded_ips += ',' + expand_range(l)
        else :
            Return_Addr_From_IP_Groups(l,configfilename)
    return expanded_ips


def Return_Addr_From_IP_Groups(AddrGroup,configfilename):
    ListofIPs = None
    Matched = False
    config_mode = 'ExecMode'
    sys.stdout.write(AddrGroup + '\n')
    with open(configfilename, 'r') as fd :
        for line in fd:
            if 'config firewall addrgrp6' in line :
                continue
            elif 'config firewall addrgrp' in line :
                config_mode = 'FIREWALLPOLICY'
            elif 'edit "' + AddrGroup in line and config_mode is 'FIREWALLPOLICY' :
                config_mode = 'FIREWALLPOLICYEDIT'
            elif 'next' in line and config_mode is 'FIREWALLPOLICYEDIT':
                config_mode = 'FIREWALLPOLICY'
            elif 'set member ' in line and config_mode is 'FIREWALLPOLICYEDIT' :
                line = line.strip()
                line = line.lstrip()
                MatchedElement = re.search('(".*"$)', line)
                ListofIPs = MatchedElement.group(0)
                Matched = True
                break
            elif 'end' in line and config_mode is 'FIREWALLPOLICY' :
                config_mode = 'ExecMode'
        if Matched is False :
            ListofIPs = AddrGroup
        sys.stdout.write(ListofIPs + '\n\n')
    return ListofIPs




if __name__ == '__main__':
    Filter_Policies('FWRY02-VDOM-FWRY13')
