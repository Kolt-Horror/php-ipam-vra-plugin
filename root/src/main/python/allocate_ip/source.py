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
      "id": "11f912e71454a075574a728848458",
      "name": "external-ipam-it-mcm-323412",
      "description": "test",
      "type": "VM",
      "owner": "mdzhigarov@vmware.com",
      "orgId": "ce811934-ea1a-4f53-b6ec-465e6ca7d126",
      "properties": {
        "osType": "WINDOWS",
        "vcUuid": "ff257ed9-070b-45eb-b2e7-d63926d5bdd7",
        "__moref": "VirtualMachine:vm-288560",
        "memoryGB": "4",
        "datacenter": "Datacenter:datacenter-2",
        "provisionGB": "1",
        "__dcSelfLink": "/resources/groups/b28c7b8de065f07558b1612fce028",
        "softwareName": "Microsoft Windows XP Professional (32-bit)",
        "__computeType": "VirtualMachine",
        "__hasSnapshot": "false",
        "__placementLink": "/resources/compute/9bdc98681fb8b27557252188607b8",
        "__computeHostLink": "/resources/compute/9bdc98681fb8b27557252188607b8"
      }
    },
    "ipAllocations": [
      {
        "id": "111bb2f0-02fd-4983-94d2-8ac11768150f",
        "ipRangeIds": [
          "network/ZG5zLm5ldHdvcmskMTAuMjMuMTE3LjAvMjQvMA:10.23.117.0/24/default"
        ],
        "nicIndex": "0",
        "isPrimary": "true",
        "size": "1",
        "properties": {
          "__moref": "DistributedVirtualPortgroup:dvportgroup-307087",
          "__dvsUuid": "0c 8c 0b 50 46 b6 1c f2-e8 63 f4 24 24 d7 24 6c",
          "__dcSelfLink": "/resources/groups/abe46b8cfa663a7558b28a6ffe088",
          "__computeType": "DistributedVirtualPortgroup",
          "__portgroupKey": "dvportgroup-307087"
        }
      }
    ],
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
# Import the ipaddress library to be used for checking the IP address version (not standard added at the requirements.txt file)
import ipaddress
# Import the make_request function from the VMware vRealize Automation IPAM SDK utilities.
from vra_ipam_utils.request_handler import RequestHandler
# Import the re module to be used for regex
import re
# Import the json module to be used for json parsing
import json

# Boiler plate function, also initial function that is called by vRA
def handler(context, inputs):

    ipam = IPAM(context, inputs)
    IPAM.do_allocate_ip = do_allocate_ip

    return ipam.allocate_ip()

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

# Function that is called by the handler function to allocate an IP address
def do_allocate_ip(self, auth_credentials, cert):
    # Initialize the base PHP IPAM URL to be used for the rest call
    base_url = f"https://{self.inputs['endpoint']['endpointProperties']['hostName']}/api/{auth_credentials['privateKeyId']}"

    # Validate the API key and return the headers for use in subsequent API calls.
    headers = do_api_key_check(base_url, auth_credentials, cert)

    """
      Rest of do_allocate_ip function is boiler plate code (see VMware IPAM SDK)
    """
    
    # Initialize the allocation result list
    allocation_result = []

    # Try block to catch any exceptions that may occur during the allocation process
    try:
        # Loop through each allocation in the inputs
        for allocation in self.inputs["ipAllocations"]:
            # Call the allocate function to allocate an IP address and append the result to the allocation result list
            allocation_result.append(allocate(self.inputs["resourceInfo"], allocation, base_url, headers, cert))
    except Exception as e:
        try:
            # If an exception occurs during the allocation process then call the rollback function to rollback any previously allocated addresses
            rollback(allocation_result, base_url, headers, cert)
        except Exception as rollback_e:
            # Log the allocation result that failed to be rolled back
            logging.error(f"Error during rollback of allocation result {str(allocation_result)}")
            
            # Log the error that occurred during the rollback process
            logging.error(rollback_e)
        raise e

    # Assert that the allocation result list is not empty
    assert len(allocation_result) > 0

    # Return the allocation result list
    return {
        "ipAllocations": allocation_result
    }

# Function that is called by the do_allocate_ip function to allocate an IP address
def allocate(resource, allocation, base_url, headers, cert):
    # Initialize the last error variable
    last_error = None

    # Initialize result array
    result = []

    # Loop through each range in the allocation
    for range_id in allocation["ipRangeIds"]:
        # Log that the allocation is being attempted
        logging.info(f"Allocating from range {range_id}")
        try:
            # Call the allocate_in_range function to allocate an IP address and append the result to the result list
            result.append(allocate_in_range(range_id, resource, allocation, base_url, headers, cert))
        except Exception as e:
            # Initialize the last error variable to the exception that occurred
            last_error = e

            # Log that the allocation failed
            logging.error(f"Failed to allocate from range {range_id}: {str(e)}")
    # If the result list is empty
    if not result:
        # Raise the last error that occurred
        raise last_error
    else:
        # Return the result list
        return result

# Function that is called by the allocate function to allocate an IP address
def allocate_in_range(range_id, resource, allocation, base_url, headers, cert):
    # Initialize the payload to be used for the rest call
    payload = {
        'hostname': str(resource["name"]),
        'owner': str(resource["owner"]),
        'note': str('vRA deployment')
    }

    # Convert the payload to a JSON string
    payload = json.dumps(payload)

    # Initialize the PHP IPAM URL to be used for the rest call
    url = f"{base_url}/addresses/first_free/{str(range_id)}/"

    # Initialize the request handler, which will be used to make the API call.
    request = RequestHandler()

    # Perform the post rest call to the PHP IPAM API
    response = request.make_request("POST", url, headers=headers, data=payload, verify=cert)
    
    # Check the response code to see if the IP address was allocated successfully
    if response['success'] is True:
        # Log that the IP address was allocated successfully
        logging.info(f"IP address {response['data']['ip']} successfully allocated from range {range_id}")
    else:
        # IF false then raise an exception with the error message
        raise Exception(f"Failed to allocate IP address from range {range_id}: {response['message']}")    

    # Get the IP address version
    ipVersion = ipaddress.ip_address(response['data']).version

    # Currently ipAddressResult holds the mandatory properties needed by vRA
    ipAddressResult = {
        "ipAllocationId": str(response["id"]),
        "ipAddresses": [str(response["data"])],
        "ipRangeId": str(range_id),
        "ipVersion": f"IPv{str(ipVersion)}"
    }

    # Set the url to get subnet details
    url = f"{base_url}/subnets/{range_id}/"

    # Make a GET request to get the subnet details
    subnetResponse = request.make_request("GET", url, headers=headers, verify=cert)

    # Set the subnet response data to the subnetResponseData variable
    subnetResponse = subnetResponse['data']

    # Set the subnet prefix length key for the ipAddressResult variable
    ipAddressResult["subnetPrefixLength"] = int(subnetResponse['calculation']['Subnet bitmask'])

    # If subnetResponseData has a key called gateway
    if 'gateway' in subnetResponse:
        # Add the gateway to the ipAddressResult
        ipAddressResult["gatewayAddresses"] = [str(subnetResponse['gateway']['ip_addr'])]
    
    # If subnetResponseData has a key called nameservers
    if 'nameservers' in subnetResponse:
        # Split the "namesrv1" string into an array using semicolon as the delimiter
        namesrv1_values = subnetResponse["nameservers"]["namesrv1"].split(";")

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

        # Set the dnsServerAddresses list <string> key for the ipAddressResult variable
        ipAddressResult['dnsServerAddresses'] = ip_addresses

        # If non ip addresses exist
        if non_ip_addresses:
            # Set the dnsSearchDomains list <string> key for the ipAddressResult variable
            ipAddressResult['dnsSearchDomains'] = non_ip_addresses

            # Set the domain key for the ipAddressResult variable, as the first non-IP address
            ipAddressResult['domain'] = str(non_ip_addresses[0])

    # Return the allocation ipAddressResult payload for vRA to use
    return ipAddressResult

# Rollback any previously allocated addresses in case this allocation request contains multiple ones and failed in the middle
def rollback(allocation_result, base_url, headers, cert):
    # Initialize the request handler, which will be used to make the API call.
    request = RequestHandler()

    # For each allocation that was allocated
    for allocation in reversed(allocation_result):
        # Log that the allocation is being rolled back
        logging.info(f"Rolling back allocation {str(allocation)}")
        
        # Set the rollback url with the allocated IP address ID 
        rollback_url = f"{base_url}/addresses/{allocation['ipAllocationId']}/{allocation['ipRangeId']}"
        
        # Perform the delete rest call to the PHP IPAM API
        request.make_request("DELETE", rollback_url, headers=headers, verify=cert)

        # Log that the allocation was rolled back successfully
        logging.info(f"Allocation {str(allocation['ipAddresses'])} rolled back successfully")
    
    # Return nothing as this is a rollback function, and is expected to succeed
    return