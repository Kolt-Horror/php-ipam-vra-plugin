"""
Copyright (c) 2020 VMware, Inc.

This product is licensed to you under the Apache License, Version 2.0 (the "License").
You may not use this product except in compliance with the License.

This product may include a number of subcomponents with separate copyright notices
and license terms. Your use of these subcomponents is subject to the terms and
conditions of the subcomponent's license, as noted in the LICENSE file.
"""

"""
The deallocate IP uses the Aria Automation passed properties:
  - IP address
  - IP addresses subnet ID
Whilst the Aria Automation system will only know the PHP IPAM information:
  - NONE

The deallocate IP has links to the following IPAM Actions:
  - allocate IP
    - To assign an IP address
    - Required information for deallocate IP:
      - IP address
      - IP addresses subnet ID
"""

"""
Example payload:

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
    "ipDeallocations": [
      {
        "id": "111bb2f0-02fd-4983-94d2-8ac11768150f",
        "ipRangeId": "network/ZG5zLm5ldHdvcmskMTAuMjMuMTE3LjAvMjQvMA:10.23.117.0/24/default",
        "ipAddress": "10.23.117.5"
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

# Import the requests library to enable HTTP calls to external services.
import requests
# Import specific exceptions from requests to handle request-related errors.
from requests.exceptions import RequestException
# Import the logging module to enable logging of messages throughout the IPAM operations.
import logging
# Import the IPAM class from the VMware vRealize Automation IPAM SDK utilities.
from vra_ipam_utils.ipam import IPAM
# Import the make_request function from the VMware vRealize Automation IPAM SDK utilities.
from vra_ipam_utils.request_handler import RequestHandler

# Function that vRA invokes to start the IP deallocation process.
def handler(context, inputs):
  # Instantiate the IPAM class with the provided context and inputs for further IPAM operations.
  ipam = IPAM(context, inputs)

  # Dynamically bind our custom deallocation method to the IPAM class.
  IPAM.do_deallocate_ip = do_deallocate_ip

  # Invoke the patched deallocation method and return the results.
  return ipam.deallocate_ip()

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

# Function that orchestrates the deallocation of IPs.
def do_deallocate_ip(self, auth_credentials, cert):
  # Construct the base URL for the IPAM API call.
  base_url = f"https://{self.inputs['endpoint']['endpointProperties']['hostName']}/api/{auth_credentials['privateKeyId']}"

  # Validate the API key and return the headers for use in subsequent API calls.
  headers = do_api_key_check(base_url, auth_credentials, cert)
  
  # Initialize the result list.
  deallocation_result = []

  # Iterate through the list of IPs to deallocate.
  for deallocation in self.inputs["ipDeallocations"]:
    # Attempt to deallocate the IP address.
    result = deallocate(self.inputs["resourceInfo"], deallocation, base_url, headers, cert)

    if result:
      # Append the deallocation result to the list.
      deallocation_result.append(result)

  # If no IPs were deallocated, raise an exception.
  if not deallocation_result:
    # Log the error.
    raise ValueError("No IP deallocations were processed.")

  # Return the deallocation result.
  return {"ipDeallocations": deallocation_result}

def delete_ip_address(ip_address, subnet_id, base_url, headers, cert, request):
  # Log the IP deallocation.
  logging.info(f"Deallocating IP {ip_address} from range {subnet_id}")

  # Construct the URL to deallocate the IP address.
  url = f"{base_url}/addresses/{str(ip_address)}/{str(subnet_id)}"

  # Attempt to deallocate the IP and if successful, return the result.
  request.make_request("DELETE", url, headers=headers, verify=cert)
  
  # Log the successful deallocation.
  logging.info(f"Successfully deallocated target IP {str(ip_address)} from range {str(subnet_id)}")

# Function that makes an API call to deallocate a specific IP address.
def deallocate(resource, deallocation, base_url, headers, cert):
  # Initialize the request handler, which will be used to make the API call.
  request = RequestHandler()

  # Initialize IP to be deallocated.
  ip_address = deallocation['ipAddress']

  # Initialize Subnet ID that contains target IP address
  subnet_id = deallocation['ipRangeId']

  # Perform the IP address deallocation.
  delete_ip_address(ip_address, subnet_id, base_url, headers, cert, request)

  # Check that no other IP addresses exist for the IP address
  # Set the URL to check if the IP address exists
  url = f"{base_url}/addresses/{str(ip_address)}"

  try:
    # Make a GET request to check if the IP address exists
    response = request.make_request("GET", url, headers=headers, verify=cert)

    if response["success"] is True:
      # Iterate over IP address data
      for ip_address_data in response["data"]:
        if ip_address_data["description"] == "Orphaned IP address":
          # Get the IP address ID
          ip_address = ip_address_data["ip"]

          # Get the IP address subnet ID
          subnet_id = ip_address_data["subnetId"]

          # Perform the IP address deallocation
          delete_ip_address(ip_address, subnet_id, base_url, headers, cert, request)
    else:
      # Return the deallocation result.
      return {
        "ipDeallocationId": str(deallocation["id"]),
        "message": "Success"
      }
  except Exception as e:
    logging.error(f"IP address does not exist in IPAM: {str(e)}")
    # Return the deallocation result.
    return {
      "ipDeallocationId": str(deallocation["id"]),
      "message": "Success"
    }

  # Return the deallocation result.
  return {
      "ipDeallocationId": str(deallocation["id"]),
      "message": "Success"
    }