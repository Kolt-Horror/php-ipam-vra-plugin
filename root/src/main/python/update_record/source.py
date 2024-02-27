"""
Copyright (c) 2020 VMware, Inc.

This product is licensed to you under the Apache License, Version 2.0 (the "License").
You may not use this product except in compliance with the License.

This product may include a number of subcomponents with separate copyright notices
and license terms. Your use of these subcomponents is subject to the terms and
conditions of the subcomponent's license, as noted in the LICENSE file.
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
    "addressInfos": [
      {
        "nicIndex": 0,
        "address": "10.23.117.5",
        "macAddress": "00:30:26:a7:23:26"
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
# Import the make_request function from the VMware vRealize Automation IPAM SDK utilities.
from vra_ipam_utils.request_handler import RequestHandler
# Import the json library to be used for JSON parsing
import json

# Boiler plate function, also initial function that is called by vRA
def handler(context, inputs):

    ipam = IPAM(context, inputs)
    IPAM.do_update_record = do_update_record

    return ipam.update_record()

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

# Function that orchestrates the update of IPAM records.
def do_update_record(self, auth_credentials, cert):
    # Initialize the base PHP IPAM URL to be used for the rest call
    base_url = f"https://{self.inputs['endpointProperties']['hostname']}/api/{auth_credentials['privateKeyId']}"

    # Validate the API key and return the headers for use in subsequent API calls.
    headers = do_api_key_check(base_url, auth_credentials, cert)

    # Initialize the update result array
    update_result = []

    # Get the resource info
    resource = self.inputs["resourceInfo"]

    # Iterate over the addressInfos array
    for update_record in self.inputs["addressInfos"]:
        # Update the MAC address of the record
        update_result.append(update(resource, update_record, base_url, headers, cert))

    # Check if any records were updated
    if not update_result:
        # If no records were updated, raise an error
        raise ValueError("No records were updated")

    # Return the update results
    return {
        "updateResults": update_result
    }

# Function that makes the rest call to update IPAM records
def update(resource, update_record, base_url, headers, cert):
    # Initialize the request handler, which will be used to make the API call.
    request = RequestHandler()

    # Attempt the following code, and if it fails, log the error and raise the exception
    try:
        # Initialize the recordId variable, This will be used to store the ID of the record to update
        recordId = None

        # URL to search for target IP address records in PHP IPAM
        url = f"{base_url}/addresses/search/{str(update_record['address'])}/"

        # Make a GET request to get all records for target IP
        IpRecords = request.make_request("GET", url, headers=headers, verify=cert)

        # Confirm that the IpRecords contains a record or more
        if not IpRecords:
            raise ValueError("No record found for target IP")

        # URL to search for target Hostname records in PHP IPAM
        url = f"{base_url}/addresses/search_hostname/{str(resource['name'])}/"

        # Make a GET request to get all records for target Hostname
        HostRecords = request.make_request("GET", url, headers=headers, verify=cert)

        # Confirm that the HostRecords contains a record
        if not HostRecords:
            raise ValueError("No record found for target hostname")
        # Confirm that the HostRecords is not an array but a single record
        if len(HostRecords) > 1:
            raise ValueError("More than one record found for target hostname")
        else:
          # Loop through each IP record to check if the "ip" matches the target hostname "ip" record
          for ipRecord in IpRecords:
              # If the "ip" matches the target hostname "ip" record
              if ipRecord["ip"] == HostRecords["ip"] and ipRecord["hostname"] == HostRecords["hostname"]:
                  # Set the recordId to the ID of the record to update
                  recordId = str(ipRecord["id"])

                  # Break out of the loop
                  break
        
        # Verify that the recordId is set
        if not recordId:
            # Raise an error if the recordId is not set
            raise ValueError("No record found for update")

        # URL to update the record in PHP IPAM
        url = f"{base_url}/addresses/{str(recordId)}/"

        # Set the payload to update the record mac address
        payload = {
            "mac": str(update_record["macAddress"])
        }

        # Convert the payload to a JSON string
        payload = json.dumps(payload)

        # Make a PATCH request to update the record
        request.make_request("PATCH", url, headers=headers, data=payload, verify=cert)

        # Log the successful update of the record
        logging.info(f"Successfully updated record {update_record}")

        # Return Success
        return "Success"
    except Exception as e:
        # Log the error and raise the exception
        logging.error(f"Failed to update record {update_record}: {e}")

        # Raise the exception
        raise e