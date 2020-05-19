import requests
import sys
import xml.etree.ElementTree as ET
import re

# ------------------------------------------------------------------------------------------------------
# Parameter descriptions and examples
#
# apiKey:           apiKey generated on the firewall
# fwAddress:        IP or DNS address of the firewall to query ("192.168.1.1" or "firewall1")
# srcAdd:           Source ip address for the NAT test ("192.168.1.1")
# dstAdd:           Destination ip address for the NAT ("192.168.2.1")
# protocol:         Protocol number for the NAT test ("6")
# dstPort:          Destination port number for the NAT test ("443")
# toZone:           Destination zone for the NAT test ("Untrust")
# toInterface:      Destination interface for the NAT test ("ae1.220")
# virtualRouter:    Virtual router to use for FIB lookup ("default")
# peer:             BGP peer name ("isp-peer-01")
# natRule:          Name of the NAT rule ("company-outbound-overload")
# ------------------------------------------------------------------------------------------------------

# Purpose:  Perform "test nat-policy-match" determine NAT rule being used to translate traffic and return the name of the rule.
# Returns:  String
def test_natRule(apiKey, fwAddress, srcAdd, dstAdd, protocol, dstPort, toZone, toInterface):
   
    url = "https://" + fwAddress + "/api/"
    querystring = {"type":"op","cmd": 
    "<test>" 
    "<nat-policy-match>" 
    "<source>" + srcAdd + "</source>" 
    "<destination>" + dstAdd + "</destination>"
    "<protocol>" + protocol + "</protocol>" 
    "<destination-port>" + dstPort + "</destination-port>" 
    "<to>" + toZone + "</to>" 
    "<to-interface>" + toInterface + "</to-interface>"
    "</nat-policy-match>" 
    "</test>","key":apiKey
    }

    headers = {
    'cache-control':"no-cache",
    }
    
    response = requests.request("GET", url, headers=headers, params=querystring, verify=False)      

    try:
        root = ET.fromstring(response.text)

        for entry in root.iter('entry'):
            natRule = entry.text
        return natRule
    except:
        print ("Error: Assigning NAT rule:", sys.exc_info()[0])

# Purpose:  Return information of the NAT rule including translated address, interface, type.
# Returns   String
def get_natRule(apiKey, fwAddress, natRule):

    url = "https://" + fwAddress + "/api/"
    querystring = {"type":"op","cmd": 
    "<show>"
    "<running>" 
    "<nat-policy>" 
    "</nat-policy>"
    "</running>" 
    "</show>","key":apiKey
    }

    headers = {
    'cache-control':"no-cache",
    }

    response = requests.request("GET", url, headers=headers, params=querystring, verify=False)
    root = ET.fromstring(response.text)
    all_nat_policies = re.split('\n',response.text)
    all_nat_policies = [x.strip(' ').strip('"') for x in all_nat_policies]
        
    for i in all_nat_policies:
        if re.search(natRule,i):
            natRule_index = all_nat_policies.index(i)

    for i in all_nat_policies[natRule_index:]:
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
    return trans_addr[0]      
   

# Purpose:  Return name of the egress interface from FIB for specific destination.
# Returns:  String
def get_dstInterface(apiKey, fwAddress, virtualRouter, dstAdd):
    url = "https://" + fwAddress + "/api/"
    querystring = {"type":"op","cmd": 
    "<test>"
    "<routing>" 
    "<fib-lookup>" 
    "<virtual-router>" + virtualRouter + "</virtual-router>"
    "<ip>" + dstAdd + "</ip>"
    "</fib-lookup>"
    "</routing>"
    "</test>","key":apiKey
    }

    headers = {
    'cache-control':"no-cache",
    }

    response = requests.request("GET", url, headers=headers, params=querystring, verify=False)
    root = ET.fromstring(response.text)
    for entry in root.iter('interface'):
        interface_name = entry.text
    return interface_name

# Purpose:  Return the name of the zone that the toInterface is assigned to.
# Returns:  String
def get_interfaceZone(apiKey, fwAddress, toInterface):

    url = "https://" + fwAddress + "/api/"
    querystring = {"type":"op","cmd": 
    "<show>"
    "<interface>" + toInterface + "</interface>"
    "</show>","key":apiKey
    }
    headers = {
    'cache-control':"no-cache",
    }
    response = requests.request("GET", url, headers=headers, params=querystring, verify=False)
    root = ET.fromstring(response.text)
    for entry in root.iter('zone'):
        interface_zone = entry.text
    return interface_zone

# Purpose:  Returns a list of all IP addresses configured on the firewall. 
# Returns:  List
def list_fwAddresses(apiKey, fwAddress):

    url = "https://" + fwAddress + "/api/"
    querystring = {"type":"op","cmd": 
    "<show><interface>all</interface></show>"
    ,"key":apiKey
    }

    headers = {
    'authorization': "Basic " + apiKey,
    'cache-control':"no-cache",
    }
    fw_addresses = []
    response = requests.request("GET", url, headers=headers, params=querystring, verify=False)
    root = ET.fromstring(response.text)
    for entry in root.iter('ip'):
        if re.search(r'([0-9]*\.){3}[0-9]*',entry.text):
            a = re.search(r'[0-9]*\.[0-9]*\.[0-9]*\.[0-9]*',entry.text)
            fw_addresses.append(a[0])
    return fw_addresses

# Purpose: Return the entire route table for specified virtual router. 
# Returns: String
def get_vr_routeTable(apiKey, fwAddress, virtualRouter):
    url = "https://" + fwAddress + "/api"
    querystring = {"type":"op","cmd": 
    "<show><routing><route></route></routing></show>","key":apiKey
    }
    headers = {
    'cache-control':"no-cache",
    }
    response = requests.request("GET", url, headers=headers, params=querystring, verify=False)
    return response.text


# Purpose:  Return the bgp local rib/prefixes sent by the specified peer. 
# Returns:  String
def get_bgp_locrib(apiKey, fwAddress, virtualRouter, peer):

    url = "https://" + fwAddress + "/api"
    querystring = {"type":"op","cmd": 
    "<show><routing><protocol><bgp><loc-rib><peer>" + peer + "</peer></loc-rib></bgp></protocol></routing></show>"
    ,"key":apiKey
    }
    headers = {
    'cache-control':"no-cache",
    }
    response = requests.request("GET", url, headers=headers, params=querystring, verify=False)
    return response.text

# Purpose:  Return bgp rib-out/prefixes sent to the specified peer.  
# Returns:  String
def get_bgp_ribout(apiKey, fwAddress, virtualRouter, peer):
    url = "https://" + fwAddress + "/api"
    querystring = {"type":"op","cmd": 
    "<show><routing><protocol><bgp><rib-out><peer>" + peer + "</peer></rib-out></bgp></protocol></routing></show>"
    ,"key":apiKey
    }
    headers = {
    'cache-control':"no-cache",
    }
    response = requests.request("GET", url, headers=headers, params=querystring, verify=False)
    return response.text