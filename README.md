# PaloAltoNetworks-Modules  
Palo Alto Networks python modules for common tasks.  
Descriptions of the required parameters for each function are documented within `pan_modules.py`

## Instructions  
Authentication uses API key generated on each firewall pair.  
`curl -k -X GET 'https://<firewall>/api/?type=keygen&user=<username>&password=<password>'  `

Import the module into your python script.  
`import pan_modules`  

## List of modules  

### test_natRule(apiKey, fwAddress, srcAdd, dstAdd, protocol, dstPort, toZone, toInterface)  
    Purpose:  Perform "test nat-policy-match" determine NAT rule being used to translate traffic and return the name of the rule.
    Returns:  String  

### get_natRule(apiKey, fwAddress, natRule)  
    Purpose:  Return information of the NAT rule including translated address, interface, type.
    Returns   String  

### get_dstInterface(apiKey, fwAddress, virtualRouter, dstAdd)  
    Purpose:  Return name of the egress interface from FIB for specific destination.  
    Returns:  String  

### get_interfaceZone(apiKey, fwAddress, toInterface)  
    Purpose:  Return the name of the zone that the toInterface is assigned to.  
    Returns:  String  

### list_fwAddresses(apiKey, fwAddress)  
    Purpose:  Returns a list of all IP addresses configured on the firewall.  
    Returns:  List  

### get_vr_routeTable(apiKey, fwAddress, virtualRouter)  
    Purpose: Return the entire route table for specified virtual router.  
    Returns: String  

### get_bgp_locrib(apiKey, fwAddress, virtualRouter, peer)  
    Purpose:  Return the bgp local rib/prefixes sent by the specified peer.  
    Returns:  String  

### get_bgp_ribout(apiKey, fwAddress, virtualRouter, peer)  
    Purpose:  Return bgp rib-out/prefixes sent to the specified peer.  
    Returns:  String  