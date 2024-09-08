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
# Import the SSLError exception to handle SSL validation errors
from requests.exceptions import SSLError
# Import the InvalidCertificateException exception from the exceptions module
from vra_ipam_utils.exceptions import InvalidCertificateException

# Function to help outline each process
def handler(context, inputs):
    if ('allocate_ip'):
        ipam = IPAM(context, inputs)
        IPAM.do_allocate_ip = do_allocate_ip

        return ipam.allocate_ip()
    elif ('deallocate_ip'):
        # Instantiate the IPAM class with the provided context and inputs for further IPAM operations.
        ipam = IPAM(context, inputs)

        # Dynamically bind our custom deallocation method to the IPAM class.
        IPAM.do_deallocate_ip = do_deallocate_ip

        # Invoke the patched deallocation method and return the results.
        return ipam.deallocate_ip()
    elif ('update_record'):
        ipam = IPAM(context, inputs)
        IPAM.do_update_record = do_update_record

        return ipam.update_record()
    elif ('get_ip_ranges'):
        ipam = IPAM(context, inputs)
        IPAM.do_get_ip_ranges = do_get_ip_ranges

        return ipam.get_ip_ranges()
    elif ('validate_endpoint'):
        ipam = IPAM(context, inputs)
        IPAM.do_validate_endpoint = do_validate_endpoint

        return ipam.validate_endpoint()

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

    try:
        # Make a GET request to validate the API key.
        request.make_request("GET", url, headers=headers, verify=cert)
    except Exception as e:
        # Log the error and raise the exception
        logging.error(f"An unexpected error occurred when performing Authentication Check: {e}")

        # Raise the exception
        raise e

    # Log the successful API key check.
    logging.info("API key check successful")

    # Return the headers for use in subsequent API calls.
    return headers



"""
Function to Authenticate using API with the IPAM service
    REST API Call: /api/<API APP ID>/user/ (GET)
        API Token should be using: SSL with API Code Token
    Mandatory Information:
        Header: token : <API Token>

Function to Authenticate using User Account with the IPAM service
    REST API Call: /api/<API APP ID>/user/ (POST)
        API APP ID should be using: SSL with User token
    Mandatory Information:
        Header: Authorization : Basic <Base64 Encoded Username:Password>
    Returns:
        data {
            token : <API Token>
            expires : <Token Expiry Date>
        }

Function to Revoke authentication with the IPAM service
    REST API Call: /api/<API APP ID>/user/ (DELETE)
    Mandatory Information:
        Header:
            token : <API Token>

Function to create IP Records in the IPAM service (Static Allocation)
    REST API Call: /api/<API APP ID>/addresses/ (POST)
    Mandatory Information:
        subnetId
        ip
    Optional Information:
        hostname
        owner
        note
        description
        is_gateway
        mac
        excludePing

Function to create IP Record using first free within subnet in the IPAM service (Dynamic Allocation)
    REST API Call: /api/<API APP ID>/addresses/first_free/<subnetId>/ (GET)
    Mandatory Information:
        subnetId
    Optional Information:
        hostname
        owner
        note
        description
        is_gateway
        mac
        excludePing
        
Function to delete IP Record by subnet in the IPAM service
    REST API Call: /api/<API APP ID>/addresses/<ip>/<subnetId>/ (DELETE)
    Mandatory Information:
        ip
        subnetId

Function to delete IP Record by ID in the IPAM service
    REST API Call: /api/<API APP ID>/addresses/<id>/ (DELETE)
    Mandatory Information:
        id

Function to update IP Records in the IPAM service
    REST API Call: /api/<API APP ID>/addresses/<id>/ (PATCH)
    Mandatory Information:
        id
    Optional Information:
        is_gateway
        description
        hostname
        mac
        owner
        note
        excludePing

RULES:
    IP Ranges and IP Blocks are subnets in PHP IPAM
    Subnets that are considered IP Ranges can become IP Blocks
        - Any existing IP address in the subnet will become orphaned
        - Existing IP addresses can not be moved to another subnet
    Subnets that are considered IP Blocks can become IP Ranges
        - This occurs when no subnets exist within the subnet

    To Determine IP Range Subnet:
        - IF subnet already has IP addresses allocated then it is an IP Range
        - ELSE IF subnet can have IP addresses allocated then it is an IP Range
        - ELSE it is an IP Block
    
    To Determine IP Block Subnet:
        - Any subnet can become an IP Block
        - IF subnet has no IP addresses allocated then it is an IP Block
        - ELSE IF subnet cannot have IP addresses allocated then it is an IP Block
        - ELSE it is an IP Range
        
Function to get IP Range Subnet by ID from the IPAM service
    REST API Call: /api/<API APP ID>/subnets/<subnetId>/ (GET)
    Mandatory Information:
        subnetId
    

Function to get IP Block Subnets from the IPAM service


Function to allocate IP Range Subnets to the IPAM service


Function to deallocate IP Range Subnets from the IPAM service


"""

def do_validate_endpoint(self, auth_credentials, cert):
    # Initialize the base PHP IPAM URL to be used for the rest call
    base_url = f"https://{self.inputs['endpointProperties']['hostName']}/api/{auth_credentials['privateKeyId']}"

    # Try to make the rest call to the PHP IPAM API
    try:
        # Validate the API key and return the headers for use in subsequent API calls.
        do_api_key_check(base_url, auth_credentials, cert)

        # As the API key is valid and the do_api_key_check function will return any errors, we can proceed with returning the authorization message to vRA
        return {
                "message": "Validated successfully",
                "statusCode": "200"
            }
    # The following except block has been added to handle SSL validation errors
    except SSLError as ssl_error:
        """ In case of SSL validation error, a InvalidCertificateException is raised.
            So that the IPAM SDK can go ahead and fetch the server certificate
            and display it to the user for manual acceptance.
        """
        if "SSLCertVerificationError" in str(ssl_error) or "CERTIFICATE_VERIFY_FAILED" in str(ssl_error) or 'certificate verify failed' in str(ssl_error):
            # Raise an InvalidCertificateException
            raise InvalidCertificateException("Certificate verify failed", self.inputs["endpointProperties"]["hostName"], 443) from ssl_error
        else:
            # Log the error and raise the exception
            logging.error(f"SSL error occurred: {ssl_error}")

            # Raise the SSL exception
            raise ssl_error
    # The following except block has been added to handle all other errors
    except Exception as e:
        # Log the error and raise the exception
        logging.error(f"An unexpected error occurred during the validation process: {e}")

        # Raise the exception
        raise e

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

# Function that orchestrates the update of IPAM records.
def do_update_record(self, auth_credentials, cert):
    # Initialize the base PHP IPAM URL to be used for the rest call
    base_url = f"https://{self.inputs['endpoint']['endpointProperties']['hostName']}/api/{auth_credentials['privateKeyId']}"

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

# Function that orchestrates the collection of IP ranges from the IPAM service.
def do_get_ip_ranges(self, auth_credentials, cert):
    # Initialize the base PHP IPAM URL to be used for the rest call
    base_url = f"https://{self.inputs['endpoint']['endpointProperties']['hostName']}/api/{auth_credentials['privateKeyId']}"

    # Validate the API key and return the headers for use in subsequent API calls.
    headers = do_api_key_check(base_url, auth_credentials, cert)

    # Get the page token from the inputs
    pageToken = self.inputs['pagingAndSorting'].get('pageToken', None)

    # Get the max results from the inputs
    maxResults = self.inputs['pagingAndSorting'].get('maxResults', 25)

    # Set the result ranges and next page token by calling the collect_ranges function
    result_ip_ranges, next_page_token = collect_ranges(base_url, headers, cert, pageToken, maxResults) 

    # Set the result variable with the result ranges
    result = {
        "ipRanges": result_ip_ranges
    }

    # If the next page token is not None then add it to the result
    if next_page_token is not None:
        result["nextPageToken"] = next_page_token

    # Return the result
    return result

# Function that is called by the do_allocate_ip function to allocate an IP address
def allocate(resource, allocation, base_url, headers, cert):
    # Initialize the last error variable
    last_error = None

    # Initialize the allocate result variable
    allocateResult = None

    # Loop through each range in the allocation
    for range_id in allocation["ipRangeIds"]:
        # Log that the allocation is being attempted
        logging.info(f"Allocating from range {range_id}")
        try:
            # Call the allocate_in_range function to allocate an IP address and append the result to the result list
            allocateResult = allocate_in_range(range_id, resource, allocation, base_url, headers, cert)

            # If the allocation was successful
            if allocateResult:
                # Break the loop
                break
        except Exception as e:
            # Initialize the last error variable to the exception that occurred
            last_error = e

            # Log that the allocation failed
            logging.error(f"Failed to allocate from range {range_id}: {str(e)}")

    # If the result list is empty
    if not allocateResult:
        # Raise the last error that occurred
        raise last_error
    else:
        # Return the result list
        return allocateResult

# Create Function that does:
def check_ip_address(ip_address, range_id, resource, base_url, headers, cert, request):
    # Check if the IP address is already allocated within IPAM
    url = f"{base_url}/addresses/search/{ip_address}/"

    try:
        # Perform the get rest call to the PHP IPAM API
        response = request.make_request("GET", url, headers=headers, verify=cert)
        
        # IF IP address is already allocated
        if response["success"] is True:
            # For each IP address data in the response
            for ip_address_data in response["data"]:
                # IF IP address is already allocated in the target subnet
                if ip_address_data["subnetId"] == range_id:
                    # Raise an exception with the error message
                    raise Exception(f"IP address {ip_address} already allocated in range {range_id}")
                # ELSE
                else:
                    # Log that the IP address is already allocated as an orphaned IP address
                    logging.info(f"IP address {ip_address} already allocated as an orphaned IP address")
                    
                    # Mark the IP address as taken in the target subnet
                    ip_id = ip_address_data["id"]
                    subnet_id = ip_address_data["subnetId"]
                    hostname = ip_address_data["hostname"]
                    owner = ip_address_data["owner"]

                    # Mark the IP address as taken
                    mark_ip_address_as_taken(ip_address, range_id, hostname, base_url, owner, headers, cert, request, ip_id, subnet_id)

                    # Raise an exception with the error message
                    raise Exception(f"IP address {ip_address} already allocated in range {range_id} as an orphaned IP address")
        # ELSE post IP address
        else:
            # Create IP address allocation payload
            payload = {
                "subnetId": range_id,
                "ip": ip_address,
                "hostname": str(resource["name"]),
                "owner": str(resource["owner"]),
                "note": str("vRA deployment")
            }

            # If "description" is in the resource
            if "description" in resource:
                # Add the description to the payload
                payload["description"] = str(resource["description"])

            # Set API URL
            url = f"{base_url}/addresses/"

            # Set REST call method
            method = "POST"

            # Action the create IP address function
            response = create_ip_address(payload, url, method, headers, cert, request)

            # Return the IP address
            return ip_address
    except Exception as e:
        logging.error(f"Failed to check IP address: {str(e)}")

def mark_ip_address_as_taken(ip_address, range_id, hostname, base_url, owner, headers, cert, request, ip_id, subnet_id):
    # Initialize the payload to be used for the rest call
    payload = {
        "subnetId": range_id,
        "ip": ip_address,
        "hostname": str(hostname),
        "description": "Orphaned IP address",
        "owner": str(owner),
        "note": f"Original IP ID: {ip_id}, Original Subnet ID: {subnet_id}"
    }

    # Set API URL
    url = f"{base_url}/addresses/"

    # Set REST call method
    method = "POST"

    return create_ip_address(payload, url, method, headers, cert, request)


def create_ip_address(payload, url, method, headers, cert, request):
    # Convert the payload to a JSON string
    payload = json.dumps(payload)

    # Perform the post rest call to the PHP IPAM API
    response = request.make_request(method, url, headers=headers, data=payload, verify=cert)

    return response

# Function that is called by the allocate function to allocate an IP address
def allocate_in_range(range_id, resource, allocation, base_url, headers, cert):
    # Initialize the request handler, which will be used to make the API call.
    request = RequestHandler()

    response = None

    ipAddress = None

    # IF static allocation is to occur
    if allocation["start"]:
        try:
            # Perform IP Check
            response = check_ip_address(allocation['start'], range_id, resource, base_url, headers, cert, request)

            # Set the IP address to the statically allocated IP address
            ipAddress = response
        except Exception as e:
            logging.error(f"Failed to allocate IP address: {str(e)}")

            return e
    else:
        # Initialize the PHP IPAM URL to be used for the rest call
        url = f"{base_url}/addresses/first_free/{str(range_id)}/"

        # Initialize the loop variable
        loop_condition = True

        # While loop to iterate through the range and find the first available IP address
        while loop_condition:
            try:
                # Perform the post rest call to the PHP IPAM API
                response = request.make_request("GET", url, headers=headers, verify=cert)
            
                # Perform IP Check
                try:
                    # Perform IP Check / allocation
                    response = check_ip_address(response["data"], range_id, resource, base_url, headers, cert, request)

                    # Set the IP address that was dynamically allocated IP address
                    ipAddress = response

                    # Set the loop condition to False to break the loop
                    loop_condition = False
                except Exception as e:
                    logging.error(f"Failed to allocate IP address: {str(e)}")

                    return e
            except Exception as e:
                logging.error(f"Failed to get first free IP address: {str(e)}")

                return e

    # Perform IP Address check
    url = f"{base_url}/addresses/{ipAddress}/{range_id}/"

    # Perform the get rest call to the PHP IPAM API
    response = request.make_request("GET", url, headers=headers, verify=cert)

    # Check the response code to see if the IP address was allocated successfully
    if response["success"] is True:
        # Log that the IP address was allocated successfully
        logging.info(f"IP address {response['data']['ip']} successfully allocated from range {range_id}")
    else:
        # IF false then raise an exception with the error message
        raise Exception(f"Failed to allocate IP address from range {range_id}: {response['message']}")    

    # Get the IP address version
    ipVersion = ipaddress.ip_address(response["data"]["ip"]).version

    # Currently result holds the mandatory properties needed by vRA
    result = {
        "ipAllocationId": allocation["id"],
        "ipAddresses": [response["data"]["ip"]],
        "ipRangeId": range_id,
        "ipVersion": f"IPv{str(ipVersion)}"
    }

    # Set the url to get subnet details
    url = f"{base_url}/subnets/{range_id}/"

    # Make a GET request to get the subnet details
    subnetResponse = request.make_request("GET", url, headers=headers, verify=cert)

    # Set the subnet response data to the subnetResponseData variable
    subnetResponse = subnetResponse["data"]

    # Set the subnet prefix length key for the result variable
    result["subnetPrefixLength"] = int(subnetResponse["calculation"]["Subnet bitmask"])

    # If subnetResponseData has a key called gateway
    if "gateway" in subnetResponse:
        # Add the gateway to the result
        result["gatewayAddresses"] = [str(subnetResponse["gateway"]["ip_addr"])]
    
    # If subnetResponseData has a key called nameservers
    if "nameservers" in subnetResponse:
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

        # Set the dnsServerAddresses list <string> key for the result variable
        result["dnsServerAddresses"] = ip_addresses

        # If non ip addresses exist
        if non_ip_addresses:
            # Set the dnsSearchDomains list <string> key for the result variable
            result["dnsSearchDomains"] = non_ip_addresses

            # Set the domain key for the result variable, as the first non-IP address
            result["domain"] = str(non_ip_addresses[0])

    # Return the allocation result payload for vRA to use
    return result

# Rollback any previously allocated addresses in case this allocation request contains multiple ones and failed in the middle
def rollback(allocation_result, base_url, headers, cert):
    # Initialize the request handler, which will be used to make the API call.
    request = RequestHandler()

    # For each allocation that was allocated
    for allocation in reversed(allocation_result):
        # Log that the allocation is being rolled back
        logging.info(f"Rolling back allocation {str(allocation)}")

        # Check if the IP address that is already allocated has the same hostname as the one that is being rolled back
        url = f"{base_url}/addresses/{allocation['ipAllocationId']}/{allocation['ipRangeId']}"

        # Perform the get rest call to the PHP IPAM API
        response = request.make_request("GET", url, headers=headers, verify=cert)

        # If the IP address that is already allocated has the same hostname as the one that is being rolled back
        if response["data"]["hostname"] != allocation["name"]:
            # Log that the allocation was not rolled back
            logging.info(f"Allocation {str(allocation['ipAddresses'])} not rolled back as it has a different hostname")

            # Continue to the next allocation
            continue
        else:            
            # Set the rollback url with the allocated IP address ID 
            rollback_url = f"{base_url}/addresses/{allocation['ipAllocationId']}/{allocation['ipRangeId']}"
            
            # Perform the delete rest call to the PHP IPAM API
            request.make_request("DELETE", rollback_url, headers=headers, verify=cert)

            # Log that the allocation was rolled back successfully
            logging.info(f"Allocation {str(allocation['ipAddresses'])} rolled back successfully")
    
    # Return nothing as this is a rollback function, and is expected to succeed
    return

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

# Function that collects IP ranges from the IPAM service.
def collect_ranges(base_url, headers, cert, pageToken, maxResults):
    # Initialize the request handler, which will be used to make API calls.
    request = RequestHandler()

    # Initialize the ipRanges array
    ipRanges = []

    # Log the start of the IP range collection.
    logging.info("Collecting ranges")

    # Get all subnets from IPAM that are IP Ranges
    subnets = get_ip_ranges(base_url, headers, cert, request) # the function will also return the subnets in ascending order based on the subnet id

    # Sanitize and set a valid page token by converting it to an integer if it is not None else set it to 1
    pageToken = max(1, int(pageToken) if pageToken and str(pageToken).isdigit() else 1)

    # Determine the maximum number of pages based on the number of subnets and the max results
    num_pages = max(1, (len(subnets) + maxResults - 1) // maxResults)

    # Set the start variable for the subnets array
    start = (pageToken - 1) * maxResults

    # Set the end variable for the subnets array
    end = start + maxResults

    # Set the subnets variable to the subnets array within the start and end range
    subnets = subnets[start:end]

    # Loop through each subnet within the subnets variable to create a dictionary variable
    for subnet in subnets:
        # Initialize an empty ipRange for each IP Range subnet
        ipRange = {}

        # Function to get the required information for the IP Range
        ipRange = mandatory_ip_range_information(subnet, ipRange)

        # Function to get the optional information for the IP Range
        ipRange = optional_ip_range_information(ipRange, subnet, base_url, headers, cert, request)

        # Append the ipRange variable to the ipRanges variable
        ipRanges.append(ipRange)
    
    # Set the next page token to None if the pageToken is greater than or equal to the num_pages else set it to pageToken + 1
    next_page_token = None if pageToken > num_pages else pageToken + 1

    # Return the result.
    return ipRanges, next_page_token

# Function that gets ip range subnets from the IPAM service.
def get_ip_ranges(base_url, headers, cert, request):
    # Initialize the subnets variable.
    subnets = []
    
    # Get all subnets from IPAM
    # URL to get all subnets from IPAM
    url = f"{base_url}/subnets/"

    # Make a GET request to get all subnets from IPAM.
    response = request.make_request("GET", url, headers=headers, verify=cert)

    # Loop through each subnet within response['data']
    for subnet in response["data"]:
        # REST Call to check if the subnet is full or not
        url = f"{base_url}/subnets/{str(subnet['id'])}/usage/"
        subnet_check = request.make_request("GET", url, headers=headers, verify=cert)

        # If used_percent is greater than 0 then the subnet is a IP Range
        if subnet_check["data"]["Used_percent"] > 0:
            # Add subnet as it is a IP Range
            subnets.append(get_subnet_information(subnet, base_url, headers, cert, request))
        # ELSE perform the first_free check
        else:
            # Set URL to confirm if subnet can have IP addresses assigned to it
            url = f"{base_url}/subnets/{str(subnet['id'])}/first_free"

            # Try to make a GET request to get the subnet type as subnets that are IP Blocks will cause a failure
            try:
                # Make a GET request to confirm an IP address can be assigned to the subnet
                subnet_check = request.make_request("GET", url, headers=headers, verify=cert)

                # If the subnet can have an IP address assigned to it then it is an IP Range
                if subnet_check['success'] == True:
                    # Append the IP Range to the result variable
                    subnets.append(get_subnet_information(subnet, base_url, headers, cert, request))
                #else:
                    # Append the IP Block to the result variable
                    #result.append(str(subnetId))
            except Exception as e:
                # If the request fails, log the error message and continue to the next iteration
                logging.info(f"subnet ip range check failed as subnet is not a IP Range: {e}")
                continue

    # Put the subnets array in ascending order based on the subnet id
    subnets = sorted(subnets, key=lambda x: x["id"])

    # Return the subnets variable
    return subnets

# Function that gets the subnet information from the IPAM service.
def get_subnet_information(subnet, base_url, headers, cert, request):
    # Set url to get the subnet information
    url = f"{base_url}/subnets/{str(subnet['id'])}/"

    # Make a GET request to get the subnet information
    subnet_info_response = request.make_request("GET", url, headers=headers, verify=cert)

    # If the subnet is linked to a section
    if "sectionId" in subnet_info_response['data']:
        # Set the url to get the section information
        url = f"{base_url}/sections/{subnet_info_response['data']['sectionId']}/"

        # Make a GET request to get the section information
        addressSpace_response = request.make_request("GET", url, headers=headers, verify=cert)

        # Set the addressSpace with the name of the section that the subnet is linked to
        subnet_info_response["data"]["addressSpaceId"] = str(addressSpace_response["data"]["name"])
    
    # Return the subnet information
    return subnet_info_response['data']
    

# Function to get the required information for the IP Range
def mandatory_ip_range_information(subnet, ipRange):
    # Set the mandatory information for the IP Range
    ipRange["id"] = str(subnet['id'])
    ipRange["name"] = str(subnet['subnet'])
    ipRange["startIPAddress"] = str(subnet['calculation']['Min host IP'])
    ipRange["endIPAddress"] = str(subnet['calculation']['Max host IP'])
    ipRange["ipVersion"] = subnet['calculation']['Type']
    ipRange["subnetPrefixLength"] = int(subnet['calculation']['Subnet bitmask'])

    # Return the mandatory information for the IP Range
    return ipRange

# Function to get the optional information for the IP Range
def optional_ip_range_information(ipRange, subnet, base_url, headers, cert, request):
    # If the subnet is linked to a section
    if "sectionId" in subnet:
        # Set the addressSpaceId with the name of the section that the subnet is linked to
        ipRange["addressSpaceId"] = str(subnet["addressSpaceId"])

    # If description key exists within the subnet variable
    if "description" in subnet:
        # Set the description key with the subnet description
        ipRange["description"] = str(subnet["description"])

    # If gateway key exisits then set the gatewayAddress key for the ipRange variable
    if "gateway" in subnet:
        # Set the gatewayAddress key with the subnet gateway IP address
        ipRange["gatewayAddress"] = str(subnet["gateway"]["ip_addr"])

    # If nameservers key exisits within the subnet variable
    if "nameservers" in subnet:
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

        # Set the dnsServerAddresses list <string> key for the ipRange variable
        ipRange["dnsServerAddresses"] = ip_addresses

        # If non ip addresses exist
        if non_ip_addresses:
            # Set the dnsSearchDomains list <string> key for the ipRange variable
            ipRange["dnsSearchDomains"] = non_ip_addresses

            # Set the domain key for the ipRange variable, as the first non-IP address
            ipRange["domain"] = str(non_ip_addresses[0])
        
    # Return the optional IP Range information
    return ipRange