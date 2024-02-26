"""
Copyright (c) 2020 VMware, Inc.

This product is licensed to you under the Apache License, Version 2.0 (the "License").
You may not use this product except in compliance with the License.

This product may include a number of subcomponents with separate copyright notices
and license terms. Your use of these subcomponents is subject to the terms and
conditions of the subcomponent's license, as noted in the LICENSE file.
"""

"""
Example payload

"inputs": {
    "resourceInfo": {
      "id": "/resources/sub-networks/255ac10c-0198-4a92-9414-b8e0c23c0204",
      "name": "net1-mcm223-126361015194",
      "type": "SUBNET",
      "orgId": "e0d6ea3a-519a-4308-afba-c973a8903250",
      "owner": "jason@csp.local",
      "properties": {
        "networkType": "PRIVATE",
        "datacenterId": "Datacenter:datacenter-21",
        "__networkCidr": "192.168.197.0/28",
        "__deploymentLink": "/resources/deployments/f77fbe4d-9e78-4b1b-93b0-024d342d0872",
        "__infrastructureUse": "true",
        "__composition_context_id": "f77fbe4d-9e78-4b1b-93b0-024d342d0872",
        "__isInfrastructureShareable": "true"
      }
    },
    "ipRangeAllocation": {
      "name": "net1-mcm223-126361015194",
      "ipBlockIds": [
        "block1",
        "block2"
      ],
      "properties": {
        "networkType": "PRIVATE",
        "datacenterId": "Datacenter:datacenter-21",
        "__networkCidr": "192.168.197.0/28",
        "__deploymentLink": "/resources/deployments/f77fbe4d-9e78-4b1b-93b0-024d342d0872",
        "__infrastructureUse": "true",
        "__composition_context_id": "f77fbe4d-9e78-4b1b-93b0-024d342d0872",
        "__isInfrastructureShareable": "true"
      },
      "subnetCidr": "192.168.197.0/28",
      "addressSpaceId": "default"
    },
    "endpoint": {
      "id": "f097759d8736675585c4c5d272cd",
      "endpointProperties": {
        "hostName": "sampleipam.sof-mbu.eng.vmware.com",
        "projectId": "111bb2f0-02fd-4983-94d2-8ac11768150f",
        "providerId": "d8a5e3f2-d839-4365-af5b-f48de588fdc1",
        "certificate": "-----BEGIN CERTIFICATE-----\nMIID0jCCArqgAwIBAgIQQaJF55UCb58f9KgQLD/QgTANBgkqhkiG9w0BAQUFADCB\niTELMAkGA1UEBhMCVVMxEzARBgNVBAgTCkNhbGlmb3JuaWExEjAQBgNVBAcTCVN1\nbm55dmFsZTERMA8GA1UEChMISW5mb2Jsb3gxFDASBgNVBAsTC0VuZ2luZWVyaW5n\nMSgwJgYDVQQDEx9pbmZvYmxveC5zb2YtbWJ1LmVuZy52bXdhcmUuY29tMB4XDTE5\nMDEyOTEzMDExMloXDTIwMDEyOTEzMDExMlowgYkxCzAJBgNVBAYTAlVTMRMwEQYD\nVQQIEwpDYWxpZm9ybmlhMRIwEAYDVQQHEwlTdW5ueXZhbGUxETAPBgNVBAoTCElu\nZm9ibG94MRQwEgYDVQQLEwtFbmdpbmVlcmluZzEoMCYGA1UEAxMfaW5mb2Jsb3gu\nc29mLW1idS5lbmcudm13YXJlLmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCC\nAQoCggEBAMMLNTqbAri6rt/H8iC4UgRdN0qj+wk0R2blmD9h1BiZJTeQk1r9i2rz\nzUOZHvE8Bld8m8xJ+nysWHaoFFGTX8bOd/p20oJBGbCLqXtoLMMBGAlP7nzWGBXH\nBYUS7kMv/CG+PSX0uuB0pRbhwOFq8Y69m4HRnn2X0WJGuu+v0FmRK/1m/kCacHga\nMBKaIgbwN72rW1t/MK0ijogmLR1ASY4FlMn7OBHIEUzO+dWFBh+gPDjoBECTTH8W\n5AK9TnYdxwAtJRYWmnVqtLoT3bImtSfI4YLUtpr9r13Kv5FkYVbXov1KBrQPbYyp\n72uT2ZgDJT4YUuWyKpMppgw1VcG3MosCAwEAAaM0MDIwMAYDVR0RBCkwJ4cEChda\nCoIfaW5mb2Jsb3guc29mLW1idS5lbmcudm13YXJlLmNvbTANBgkqhkiG9w0BAQUF\nAAOCAQEAXFPIh00VI55Sdfx+czbBb4rJz3c1xgN7pbV46K0nGI8S6ufAQPgLvZJ6\ng2T/mpo0FTuWCz1IE9PC28276vwv+xJZQwQyoUq4lhT6At84NWN+ZdLEe+aBAq+Y\nxUcIWzcKv8WdnlS5DRQxnw6pQCBdisnaFoEIzngQV8oYeIemW4Hcmb//yeykbZKJ\n0GTtK5Pud+kCkYmMHpmhH21q+3aRIcdzOYIoXhdzmIKG0Och97HthqpvRfOeWQ/A\nPDbxqQ2R/3D0gt9jWPCG7c0lB8Ynl24jLBB0RhY6mBrYpFbtXBQSEciUDRJVB2zL\nV8nJiMdhj+Q+ZmtSwhNRvi2qvWAUJQ==\n-----END CERTIFICATE-----\n"
      },
      "authCredentialsLink": "/core/auth/credentials/13c9cbade08950755898c4b89c4a0"
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
    IPAM.do_allocate_ip_range = do_allocate_ip_range

    return ipam.allocate_ip_range()

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

# Function that orchestrates the allocation of an IP range.
def do_allocate_ip_range(self, auth_credentials, cert):
    # Initialize the base PHP IPAM URL to be used for the rest call
    base_url = f"https://{self.inputs['endpoint']['endpointProperties']['hostName']}/api/{auth_credentials['privateKeyId']}"

    # Validate the API key and return the headers for use in subsequent API calls.
    headers = do_api_key_check(base_url, auth_credentials, cert)
    
    # Set the ipRange variable with the allocate function.
    ipRange = allocate(self.inputs["resourceInfo"], self.inputs["ipRangeAllocation"], base_url, headers, cert)

    # Return the IP range that was allocated.
    return {
        "ipRange": ipRange
    }

# Function to iterate each IP Block ID in the allocation and attempt to allocate from it.
def allocate(resource, allocation, base_url, headers, cert):
    # Initialize the last_error variable to None.
    last_error = None

    # Loop through each IP block ID in the allocation.
    for ip_block_id in allocation["ipBlockIds"]:
        # Log the IP block ID that is being allocated from.
        logging.info(f"Allocating from ip block {ip_block_id}")

        # Try to allocate from the IP block.
        try:
            # Return the result of the allocate_in_ip_block function.
            return allocate_in_ip_block(ip_block_id, resource, allocation, base_url, headers, cert)
        # If the allocation fails, log the error and continue to the next IP block.
        except Exception as e:
            # Set the last_error variable to the error that occurred.
            last_error = e

            # Log the error that occurred.
            logging.error(f"Failed to allocate from ip block {ip_block_id}: {str(e)}")
    # If all IP blocks have been allocated from, but the function reaches this point, raise the last error.
    logging.error("No more ip blocks. Raising last error")

    # Raise the last error.
    raise last_error

# Function to allocate an IP range from an IP block.
def allocate_in_ip_block(ip_block_id, resource, allocation, base_url, headers, cert):
    # Initialize the target subnet mask to be used for creation of subnet
    target_subnet_mask = allocation["subnetPrefixLength"]

    # Initialize the target nameserverId to be used for creation of subnet
    target_nameserverId = None

    # Initialize the target descrtiption to be used for creation of subnet
    target_description = allocation["name"]

    # Initialize the ip address is gateway variable
    target_ip_address_is_gateway = 1

    # Initialize the ip address description variable
    target_ip_address_description = "gateway"

    # Initialize the ip address owner variable
    target_ip_address_owner = "vRA"

    # Initialize the ip address note variable
    target_ip_address_note = "gateway"

    # Initialize the payload to be used for the creation of a child subnet
    createChildSubnetPayload = {
        "description": str(target_description),
        "nameserverId": str(target_nameserverId)
    }

    # Initialize the payload to be used for the creation of the gayway IP address
    createGatewayIPAddressPayload = {
        "description": str(target_ip_address_description),
        "owner": str(target_ip_address_owner),
        "note": str(target_ip_address_note),
        "is_gateway": int(target_ip_address_is_gateway)
    }

    # Initialize the result variable to None.
    result = None

    # Initialize the request handler, which will be used to make API calls.
    request = RequestHandler()

    # URL to get the IP block information.
    url = f"{base_url}/subnets/{str(ip_block_id)}/"

    # Make a GET request to get the IP block information.
    response = request.make_request("GET", url, headers=headers, verify=cert)

    # Store the IP Block nameserverId in the target nameserverId variable
    target_nameserverId = response["data"]["nameservers"]["id"]

    # Set the url to be used for the creation of a child subnet
    url = f"{base_url}/subnets/{str(ip_block_id)}/first_subnet/{str(target_subnet_mask)}/"

    # Make a POST request to create a child subnet of the IP block.
    createdSubnetResponse = request.make_request("POST", url, headers=headers, verify=cert, data=createChildSubnetPayload)

    # Confirm that the success key is True in the response.
    if createdSubnetResponse["success"] == True:
        # Log the successful creation of the child subnet.
        logging.info(f"Successfully created child subnet {str(createdSubnetResponse['id'])} : {str(createdSubnetResponse['data'])}")

        # Set the url to be used for the creation of the gateway IP address
        url = f"{base_url}/addresses/first_free/{str(createdSubnetResponse['id'])}/"

        # Make a POST request to create the gateway IP address.
        createdGatewayIPAddressResponse = request.make_request("POST", url, headers=headers, verify=cert, data=createGatewayIPAddressPayload)
    else:
        # If the success key is not True, raise an error.
        raise Exception(f"Failed to create child subnet {createdSubnetResponse['id']} : {createdSubnetResponse['data']}")
    
    # Get created child subnet information
    url = f"{base_url}/subnets/{str(createdSubnetResponse['id'])}/"

    # Make a GET request to get the child subnet information.
    createdSubnetResponse = request.make_request("GET", url, headers=headers, verify=cert)

    # store the ['data'] information for the created child subnet
    createdSubnetResponse = createdSubnetResponse['data']

    # Create the result dictionary to be returned.
    result = {
        "id": str(createdSubnetResponse['id']),
        "name": str(createdSubnetResponse['subnet']),
        "startIPAddress": str(createdSubnetResponse['calculation']['Min host IP']),
        "endIPAddress": str(createdSubnetResponse['calculation']['Max host IP']),
        "ipVersion": createdSubnetResponse['calculation']['Type'],
        "subnetPrefixLength": int(createdSubnetResponse['calculation']['Subnet bitmask']),
        "tags": [],
        "properties": {}
    }

    # If the subnet is linked to a section
    if 'sectionId' in createdSubnetResponse:
        # Set the url to get the section information
        url = f"{base_url}/sections/{str(createdSubnetResponse['sectionId'])}/"

        # Make a GET request to get the section information
        response = request.make_request("GET", url, headers=headers, verify=cert)

        # Set the addressSpaceId with the name of the section that the subnet is linked to
        result["addressSpaceId"] = str(response['data']['name'])
    
    # If description key exists within the subnet variable
    if 'description' in createdSubnetResponse:
        # Set the description key with the subnet description
        result["description"] = str(createdSubnetResponse['description'])
    
    # If gateway key exisits then set the gatewayAddress key for the ipRanges variable
    if 'gateway' in createdSubnetResponse:
        # Set the gatewayAddress key with the subnet gateway IP address
        result["gatewayAddress"] = str(createdSubnetResponse['gateway']['ip_addr'])
    
    # If nameservers key exisits within the subnet variable
    if 'nameservers' in createdSubnetResponse:
        # Split the "namesrv1" string into an array using semicolon as the delimiter
        namesrv1_values = createdSubnetResponse["nameservers"]["namesrv1"].split(";")

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
        result['dnsServerAddresses'] = ip_addresses

        # If non ip addresses exist
        if non_ip_addresses:
            # Set the dnsSearchDomains list <string> key for the ipRanges variable
            result['dnsSearchDomains'] = non_ip_addresses

            # Set the domain key for the ipRanges variable, as the first non-IP address
            result['domain'] = str(non_ip_addresses[0])

    # Return the result of the allocation.
    return result