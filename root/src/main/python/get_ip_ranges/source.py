"""
Copyright (c) 2020 VMware, Inc.

This product is licensed to you under the Apache License, Version 2.0 (the "License").
You may not use this product except in compliance with the License.

This product may include a number of subcomponents with separate copyright notices
and license terms. Your use of these subcomponents is subject to the terms and
conditions of the subcomponent's license, as noted in the LICENSE file.
"""

'''
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
      "pageToken": "789c55905d6e02310c84df7d91452a456481168ec04b55950344f9db55dadd384abc056e5f3b42adfa12299f279ec9ac7c5670e9b0045a4ad2430c93af7a465f3bc83d4f9e3aa8976e6681ce660c827770de2aa1a68c72dfc3cae74393999b2e4df302e72691373aa60199bd827398efac18810f87a952591c61817c849513999df0b6c11436d6d400effcfacc14f2099cd6768913c5a435a0fd0c8e20ab2dbcd147564a2228c93b60b99ae2d94efde6ac640a09d9331130c539367078c41c915067ac9122268dc350439bf3379e9bc01b32025e9bd111aa65c829e89e83f0135ba740572c5f525c73f95faa608e39e55e62c6fcbd37de9775b891212a758d59bceb7a0eb30d7c7f6cd35c1399984291053b30f29fc5feed6cedf7adfe21962ab17b8ebde5089b1fec0d97d7-e5c4e5a1d726f600c22ebfd9f186148a1449755fd79a69ceabfe2aa"
    }
  }
'''

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
    IPAM.do_get_ip_ranges = do_get_ip_ranges

    return ipam.get_ip_ranges()

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

# Function that orchestrates the collection of IP ranges from the IPAM service.
def do_get_ip_ranges(self, auth_credentials, cert):
    # Initialize the base PHP IPAM URL to be used for the rest call
    base_url = f"https://{self.inputs['endpoint']['endpointProperties']['hostName']}/api/{auth_credentials['privateKeyId']}"

    # Validate the API key and return the headers for use in subsequent API calls.
    headers = do_api_key_check(base_url, auth_credentials, cert)

    # Set the result ranges and next page token by calling the collect_ranges function
    result_ranges = collect_ranges(base_url, headers, cert)

    # Return the result object to vRA.
    return result_ranges

# Function that collects IP ranges from the IPAM service.
def collect_ranges(base_url, headers, cert):
    # Initialize the request handler, which will be used to make API calls.
    request = RequestHandler()

    # Initialize the subnetsIds array
    subnetIds = []

    # Initialize the subnet_classification dictionary
    subnet_classification = {
        "ipBlock": [],
        "ipRange": []
    }

    # Initialize the subnets array
    subnets = []

    # Initialize the ipRanges array
    ipRanges = []

    # Log the start of the IP range collection.
    logging.info("Collecting ranges")

    # URL to get all subnets from IPAM
    url = f"{base_url}/subnets/"

    # Make a GET request to get all subnets from IPAM.
    response = request.make_request("GET", url, headers=headers, verify=cert)

    # Loop through each subnet within response['data'] to get the subnet ID
    for subnet in response['data']:
        # Append the subnet ID to the subnets variable
        subnetIds.append(str(subnet['id']))

    # Loop through each subnetId within the subnetIds array
    for subnetId in subnetIds:
        # Set the url to get the subnet type e.g. IP Block or IP Range, based on wether or not the subnet can have IP addresses assigned to it
        url = f"{base_url}/subnets/{str(subnetId)}/first_free"

        # Make a GET request to get the subnet type
        response = request.make_request("GET", url, headers=headers, verify=cert)

        # If the subnet type is an IP Range
        if response['success'] == True:
            # Append the subnet ID to the subnet_classification['ipRange'] variable
            subnet_classification['ipRange'].append(str(subnetId))

    # Loop through each ipRange ID within the subnet_classification['ipRange'] variable
    for ipRangeId in subnet_classification['ipRange']:
        # Set the url to get the subnet information
        url = f"{base_url}/subnets/{str(ipRangeId)}/"

        # Make a GET request to get the subnet information.
        response = request.make_request("GET", url, headers=headers, verify=cert)

        # Append the subnet information to the subnets variable
        subnets.append(response['data'])

    # Loop through each subnet within the subnets variable to create a dictionary variable
    for subnet in subnets:
        # Initialize the ipRanges dictionary
        ipRanges = {
            "id": str(subnet['id']),
            "name": str(subnet['subnet']),
            "startIPAddress": str(subnet['calculation']['Min host IP']),
            "endIPAddress": str(subnet['calculation']['Max host IP']),
            "ipVersion": subnet['calculation']['Type'],
            "subnetPrefixLength": int(subnet['calculation']['Subnet bitmask'])
        }

        # If the subnet is linked to a section
        if 'sectionId' in subnet:
            # Set the url to get the section information
            url = f"{base_url}/sections/{str(subnet['sectionId'])}/"

            # Make a GET request to get the section information
            response = request.make_request("GET", url, headers=headers, verify=cert)

            # Set the addressSpaceId with the name of the section that the subnet is linked to
            ipRanges["addressSpaceId"] = str(response['data']['name'])

        # If description key exists within the subnet variable
        if 'description' in subnet:
            # Set the description key with the subnet description
            ipRanges['description'] = str(subnet['description'])

        # If gateway key exisits then set the gatewayAddress key for the ipRanges variable
        if 'gateway' in subnet:
            # Set the gatewayAddress key with the subnet gateway IP address
            ipRanges['gatewayAddress'] = str(subnet['gateway']['ip_addr'])

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

            # Set the dnsServerAddresses list <string> key for the ipRanges variable
            ipRanges['dnsServerAddresses'] = ip_addresses

            # If non ip addresses exist
            if non_ip_addresses:
                # Set the dnsSearchDomains list <string> key for the ipRanges variable
                ipRanges['dnsSearchDomains'] = non_ip_addresses

                # Set the domain key for the ipRanges variable, as the first non-IP address
                ipRanges['domain'] = str(non_ip_addresses[0])
        
        # Append the ipRanges variable to the result variable
        ipRanges.append(ipRanges)

    # Wrap the ipRanges variable in a dictionary and set the key as "ipRanges"
    result = {"ipRanges": ipRanges}
    
    # Return the result.
    return result