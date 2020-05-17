import requests
import sys
import xml.etree.ElementTree as ET
import re

#Perform "test nat-policy-match" determine correct NAT rule
def test_nat_rule(fw_auth, fw_dnsname, srcadd, dstadd, protocol, dstport, tozone, tointerface):
   
    url = "https://" + fw_dnsname + "/api/"
    querystring_aws = ({"type":"op","cmd": 
    "<test>" 
    "<nat-policy-match>" 
    "<source>" + srcadd + "</source>" 
    "<destination>" + dstadd + "</destination>" 
    "<protocol>" + protocol + "</protocol>" 
    "<destination-port>" + dstport + "</destination-port>" 
    "<to>" + tozone + "</to>" 
    "<to-interface>" + tointerface + "</to-interface>"
    "</nat-policy-match>" 
    "</test>"
    ,"key":fw_auth
    })

    headers = {
    'cache-control': "no-cache",
    }
    
    resp = requests.request("POST", url, headers=headers, params=querystring_aws, verify=False)      

    try:
        root = ET.fromstring(resp.text)

        for entry in root.iter('entry'):
            nat_rule = entry.text

    except:
        print ("Error: Assigning NAT rule:", sys.exc_info()[0])

    return nat_rule

#Perform lookup information lookup of specific NAT rule
def get_nat_rule(fw_auth, fw_dnsname, nat_rule):

    url = "https://" + fw_dnsname + "/api/"
    querystring = ({"type":"op","cmd": 
    "<show>"
    "<running>" 
    "<nat-policy>" 
    "</nat-policy>"
    "</running>" 
    "</show>" 
    ,"key":fw_auth
    })

    headers = {
    'cache-control': "no-cache",
    }
    
    resp = requests.request("POST", url, headers=headers, params=querystring, verify=False)
    root = ET.fromstring(resp.text)
    all_nat_policies = re.split('\n',resp.text)
    all_nat_policies = [x.strip(' ').strip('"') for x in all_nat_policies]
        
    for i in all_nat_policies:
        if re.search(nat_rule,i):
            nat_rule_index = all_nat_policies.index(i)

    for i in all_nat_policies[nat_rule_index:]:
        if i.startswith('translate-to '):
            if re.search(r'translate-to .*?\)',i) != None:
                trans_addr = re.search(r'translate-to .*?\)',i)
                break
            elif re.search(r'translate-to .*;',i) != None:
                trans_addr = re.search(r'translate-to .*;',i)
                break
            else:
                trans_addr = ("Error retrieving address translation")
                break
    return trans_addr        
   

def get_dst_interface(fw_auth, fw_dnsname, virtual_router, dstadd):

    url = "https://" + fw_dnsname + "/api/"
    querystring = ({"type":"op","cmd": 
    "<test>"
    "<routing>" 
    "<fib-lookup>" 
    "<virtual-router>" + virtual_router + "</virtual-router>"
    "<ip>" + dstadd + "</ip>"
    "</fib-lookup>"
    "</routing>" 
    "</test>" 
    ,"key":fw_auth
    })

    headers = {
    'cache-control': "no-cache",
    }

    resp = requests.request("POST", url, headers=headers, params=querystring, verify=False)
    root = ET.fromstring(resp.text)
    for entry in root.iter('interface'):
        interface_name = entry.text
    return interface_name


def get_interface_zone(fw_auth, fw_dnsname, tointerface):

    url = "https://" + fw_dnsname + "/api/"
    querystring = ({"type":"op","cmd": 
    "<show>"
    "<interface>" + tointerface + "</interface>"
    "</show>" 
    ,"key":fw_auth
    })
    headers = {
    'cache-control': "no-cache",
    }
    resp = requests.request("POST", url, headers=headers, params=querystring, verify=False)
    root = ET.fromstring(resp.text)
    for entry in root.iter('zone'):
        interface_zone = entry.text
    return interface_zone


def list_firewall_addresses(fw_auth, fw_dnsname):

    url = "https://" + fw_dnsname + "/api/"
    querystring = ({"type":"op","cmd": 
    "<show><interface>all</interface></show>"
    ,"key":fw_auth
    })

    headers = {
    'cache-control': "no-cache",
    }
    fw_addresses = []
    resp = requests.request("POST", url, headers=headers, params=querystring, verify=False)
    root = ET.fromstring(resp.text)
    for entry in root.iter('ip'):
        if re.search(r'([0-9]*\.){3}[0-9]*',entry.text):
            a = re.search(r'[0-9]*\.[0-9]*\.[0-9]*\.[0-9]*',entry.text)
            fw_addresses.append(a[0])
    return fw_addresses

def get_vr_route_table(fw_auth, fw_dnsname, virtual_router):
#Return unformated route table for specified virtual router. 
    url = "https://" + fw_dnsname + "/api"
    querystring = ({"type":"op","cmd": 
    "<show><routing><route></route></routing></show>"
    ,"key":fw_auth
    })
    headers = {
    'cache-control': "no-cache",
    }
    response = requests.request("POST", url, headers=headers, params=querystring, verify=False)
    return response.text

def get_bgp_locrib(fw_auth, fw_dnsname, virtual_router, peer):
#Return bgp local rib for specified virtual router. 
    url = "https://" + fw_dnsname + "/api"
    querystring = ({"type":"op","cmd": 
    "<show><routing><protocol><bgp><loc-rib><peer>" + peer + "</peer></loc-rib></bgp></protocol></routing></show>"
    ,"key":fw_auth
    })
    headers = {
    'cache-control': "no-cache",
    }
    response = requests.request("POST", url, headers=headers, params=querystring, verify=False)
    return response.text

def get_bgp_ribout(fw_auth, fw_dnsname, virtual_router, peer):
#Return bgp rib out for specified virtual router. 
    url = "https://" + fw_dnsname + "/api"
    querystring = ({"type":"op","cmd": 
    "<show><routing><protocol><bgp><rib-out><peer>" + peer + "</peer></rib-out></bgp></protocol></routing></show>"
    ,"key":fw_auth
    })
    headers = {
    'cache-control': "no-cache",
    }
    response = requests.request("POST", url, headers=headers, params=querystring, verify=False)
    return response.text