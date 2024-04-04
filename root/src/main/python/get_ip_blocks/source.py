"""
Copyright (c) 2020 VMware, Inc.

This product is licensed to you under the Apache License, Version 2.0 (the "License").
You may not use this product except in compliance with the License.

This product may include a number of subcomponents with separate copyright notices
and license terms. Your use of these subcomponents is subject to the terms and
conditions of the subcomponent's license, as noted in the LICENSE file.
"""

"""
The get IP Blocks uses the Aria Automation passed properties:
    - None
Whilst the Aria Automation system will only know the PHP IPAM information:
    - Subnet ID
    - Subnet Name
    - Subnet CIDR
    - Subnet IP version
    - Subnet parent name
    - Subnet description
    - Subnet gateway
    - Subnet DNS Search domains
    - Subnet domains

The get IP blocks has links to the following IPAM Actions:
    - Allocate IP range
        - To allocate a range of IP addresses from the IP block
        - Required information for get IP blocks:
            - IP block ID
            - IP Block Name
            - IP Block Prefixlength

As all subnets in PHP IPAM can become either IP Block or IP Range, only subnets that can have an IP address assigned to them are considered as IP Range.
However any IP Range can become an IP Block if a child subnet is created within it.
A IP Block can only become an IP Range if all child subnets are deleted.
Any subnet converted to a IP Block will have orphaned IP addresses that can be moved through re-creation of the IP address.
As such any IP address that is orphaned should not be touched or moved as a IP Block that is converted back to an IP range will un-orphan the IP addresses.
"""

"""
Example payload:

"inputs": {
    "endpoint": {
      "id": "f097759d8736675585c4c5d272cd",
      "authCredentialsLink": "/core/auth/credentials/13c9cbade08950755898c4b89c4a0",
      "endpointProperties": {
        "hostName": "sampleipam.sof-mbu.eng.vmware.com",
        "certificate": "-----BEGIN CERTIFICATE-----\nMIID0jCCArqgAwIBAgIQQaJF55UCb58f9KgQLD/QgTANBgkqhkiG9w0BAQUFADCB\niTELMAkGA1UEBhMCVVMxEzARBgNVBAgTCkNhbGlmb3JuaWExEjAQBgNVBAcTCVN1\nbm55dmFsZTERMA8GA1UEChMISW5mb2Jsb3gxFDASBgNVBAsTC0VuZ2luZWVyaW5n\nMSgwJgYDVQQDEx9pbmZvYmxveC5zb2YtbWJ1LmVuZy52bXdhcmUuY29tMB4XDTE5\nMDEyOTEzMDExMloXDTIwMDEyOTEzMDExMlowgYkxCzAJBgNVBAYTAlVTMRMwEQYD\nVQQIEwpDYWxpZm9ybmlhMRIwEAYDVQQHEwlTdW5ueXZhbGUxETAPBgNVBAoTCElu\nZm9ibG94MRQwEgYDVQQLEwtFbmdpbmVlcmluZzEoMCYGA1UEAxMfaW5mb2Jsb3gu\nc29mLW1idS5lbmcudm13YXJlLmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCC\nAQoCggEBAMMLNTqbAri6rt/H8iC4UgRdN0qj+wk0R2blmD9h1BiZJTeQk1r9i2rz\nzUOZHvE8Bld8m8xJ+nysWHaoFFGTX8bOd/p20oJBGbCLqXtoLMMBGAlP7nzWGBXH\nBYUS7kMv/CG+PSX0uuB0pRbhwOFq8Y69m4HRnn2X0WJGuu+v0FmRK/1m/kCacHga\nMBKaIgbwN72rW1t/MK0ijogmLR1ASY4FlMn7OBHIEUzO+dWFBh+gPDjoBECTTH8W\n5AK9TnYdxwAtJRYWmnVqtLoT3bImtSfI4YLUtpr9r13Kv5FkYVbXov1KBrQPbYyp\n72uT2ZgDJT4YUuWyKpMppgw1VcG3MosCAwEAAaM0MDIwMAYDVR0RBCkwJ4cEChda\nCoIfaW5mb2Jsb3guc29mLW1idS5lbmcudm13YXJlLmNvbTANBgkqhkiG9w0BAQUF\nAAOCAQEAXFPIh00VI55Sdfx+czbBb4rJz3c1xgN7pbV46K0nGI8S6ufAQPgLvZJ6\ng2T/mpo0FTuWCz1IE9PC28276vwv+xJZQwQyoUq4lhT6At84NWN+ZdLEe+aBAq+Y\nxUcIWzcKv8WdnlS5DRQxnw6pQCBdisnaFoEIzngQV8oYeIemW4Hcmb//yeykbZKJ\n0GTtK5Pud+kCkYmMHpmhH21q+3aRIcdzOYIoXhdzmIKG0Och97HthqpvRfOeWQ/A\nPDbxqQ2R/3D0gt9jWPCG7c0lB8Ynl24jLBB0RhY6mBrYpFbtXBQSEciUDRJVB2zL\nV8nJiMdhj+Q+ZmtSwhNRvi2qvWAUJQ==\n-----END CERTIFICATE-----\n"
      }
    },
    "pagingAndSorting": {
      "maxResults": 1000,
      "pageToken": "87811419dec2112cda2aa29685685d650ac1f61f"
    }
  }
"""

# Import the requests library to be used for the rest call
import requests
# Import the IPAM class from the ipam.py file
from vra_ipam_utils.ipam import IPAM
# Import the logging library to be used for logging
import logging
# Import the make_request function from the VMware vRealize Automation IPAM SDK utilities.
from vra_ipam_utils.request_handler import RequestHandler
# Import the re module to be used for regex
import re

# Boiler plate function, also initial function that is called by vRA
def handler(context, inputs):

    ipam = IPAM(context, inputs)
    IPAM.do_get_ip_blocks = do_get_ip_blocks

    return ipam.get_ip_blocks()

# Function to validate the API key using the IPAM service.
def do_api_key_check(base_url, auth_credentials, cert):
    # Construct the URL to check the API key against the IPAM service.
    url = f"{base_url}/user/"

    # Set up the headers for authentication.
    headers = {
        "token": auth_credentials["privateKey"],
        "Content-Type": "application/json"
    }
    
    # Initialize the request handler, which will be used to make the API call.
    request = RequestHandler()

    # Make a GET request to validate the API key.
    request.make_request("GET", url, headers=headers, verify=cert)

    # Log the successful API key check.
    logging.info("API key check successful")

    # Return the headers for use in subsequent API calls.
    return headers

# Function that orchestrates the collection of IP blocks from the IPAM service.
def do_get_ip_blocks(self, auth_credentials, cert):
    # Initialize the base PHP IPAM URL to be used for the rest call
    base_url = f"https://{self.inputs['endpoint']['endpointProperties']['hostName']}/api/{auth_credentials['privateKeyId']}"

    # Validate the API key and return the headers for use in subsequent API calls.
    headers = do_api_key_check(base_url, auth_credentials, cert)

    # Return the result of the collect_ip_blocks function
    return collect_ip_blocks(base_url, headers, cert)

# Function that get subnets that can be converted to IP Blocks or are already IP blocks
def get_ip_blocks(base_url, headers, cert, request):
    # Initialize the subnets variable.
    subnets = []
    
    # Get all subnets from IPAM
    # URL to get all subnets from IPAM
    url = f"{base_url}/subnets/"

    # Make a GET request to get all subnets from IPAM.
    response = request.make_request("GET", url, headers=headers, verify=cert)

    # Loop through each subnet within response['data']
    for subnet in response['data']:
        # Set url for subnet usage information
        url = f"{base_url}/subnets/{str(subnet['id'])}/usage/"

        # Make a GET request to get the subnet usage information
        response = request.make_request("GET", url, headers=headers, verify=cert)
        
        # Check if the subnet is equal to or greater than 2 maxhosts as these subnets can be converted to IP Blocks
        if response['data']['maxhosts'] >= 2:
            # Set url to get the subnet information
            url = f"{base_url}/subnets/{str(subnet['id'])}/"

            # Make a GET request to get the subnet information
            response = request.make_request("GET", url, headers=headers, verify=cert)

            # Append the subnet information to the subnets variable
            subnets.append(response['data'])
    
    # Return the subnets variable
    return subnets

# Function that collects IP blocks from the IPAM service.
def collect_ip_blocks(base_url, headers, cert):
    # Initialize the request handler, which will be used to make API calls.
    request = RequestHandler()

    # Initialize the ipBlocks variable.
    ipBlocks = []

    # Log the fact that collection of IP blocks has started.
    logging.info("Collecting ip blocks (all subnets are IP Blocks as subnets can be converted to IP Blocks)")

    # Get all subnets that can be converted to IP Blocks or are already IP Blocks
    subnets = get_ip_blocks(base_url, headers, cert, request)

    # Loop through each subnet within the subnets variable to create a dictionary variable
    for subnet in subnets:
        # Initialize the ipBlock dictionary
        ipBlock = {
            "id": str(subnet['id']),
            "name": str(subnet['subnet']),
            "ipBlockCIDR": str(f"{subnet['calculation']['Network']}/{subnet['calculation']['Subnet bitmask']}"),
            "ipVersion": str(subnet['calculation']['Type'])
        }

        # If the subnet is linked to a section
        if 'sectionId' in subnet:
            # Set the url to get the section information
            url = f"{base_url}/sections/{subnet['sectionId']}/"

            # Make a GET request to get the section information
            response = request.make_request("GET", url, headers=headers, verify=cert)

            # Set the addressSpace with the name of the section that the subnet is linked to
            ipBlock["addressSpace"] = str(response['data']['name'])

        # If description key exists within the subnet variable
        if 'description' in subnet:
            # Set the description key with the subnet description
            ipBlock['description'] = str(subnet['description'])

        # If gateway key exisits then set the gatewayAddress key for the ipBlock variable
        if 'gateway' in subnet:
            # Set the gatewayAddress key with the subnet gateway IP address
            ipBlock['gatewayAddress'] = str(subnet['gateway']['ip_addr'])

        # If nameservers key exisits within the subnet variable
        if 'nameservers' in subnet:
            # Split the "namesrv1" string into an array using semicolon as the delimiter
            namesrv1_values = subnet["nameservers"]["namesrv1"].split(";")
            
            # Initialize arrays for IP addresses and non-IP addresses
            ip_addresses = []
            non_ip_addresses = []

            # Regular expression to match an IP address pattern
            ip_pattern = r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b"

            # Check each value and categorize them into IP or non-IP
            for value in namesrv1_values:
                # If value matches the IP address pattern
                if re.match(ip_pattern, value):
                    # Append the value to the ip_addresses variable
                    ip_addresses.append(str(value))
                # Else the value does not match the IP address pattern
                else:
                    # Append the value to the non_ip_addresses variable
                    non_ip_addresses.append(str(value))

            # Set the dnsServerAddresses list <string> key for the ipBlock variable
            ipBlock['dnsServerAddresses'] = ip_addresses

            # If non ip addresses exist
            if non_ip_addresses:
                # Set the dnsSearchDomains list <string> key for the ipBlock variable
                ipBlock['dnsSearchDomains'] = non_ip_addresses

                # Set the domain key for the ipBlock variable, as the first non-IP address
                ipBlock['domain'] = str(non_ip_addresses[0])

        # Append the ipBlock variable to the result variable
        ipBlocks.append(ipBlock)

    # Wrap the ipBlocks list within a dictoinary under the key "ipBlocks"
    result = {"ipBlocks": ipBlocks}

    # Return the result of all IP blocks.
    return result