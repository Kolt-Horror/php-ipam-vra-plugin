"""
Copyright (c) 2020 VMware, Inc.

This product is licensed to you under the Apache License, Version 2.0 (the "License").
You may not use this product except in compliance with the License.

This product may include a number of subcomponents with separate copyright notices
and license terms. Your use of these subcomponents is subject to the terms and
conditions of the subcomponent's license, as noted in the LICENSE file.
"""

"""
The validate endpoint uses the Aria Automation passed properties:
    - API Key
    - API Secret
    - API hostname
Whilst the Aria Automation system will only know the PHP IPAM information:
    - Success
"""

"""
Example payload:

"inputs": {
    "authCredentialsLink": "/core/auth/credentials/13c9cbade08950755898c4b89c4a0",
    "endpointProperties": {
      "hostName": "sampleipam.sof-mbu.eng.vmware.com"
    }
  }
"""

# Import the requests library to make rest calls
import requests
# Import the SSLError exception to handle SSL validation errors
from requests.exceptions import SSLError
# Import the IPAM class from the ipam module
from vra_ipam_utils.ipam import IPAM
# Import the InvalidCertificateException exception from the exceptions module
from vra_ipam_utils.exceptions import InvalidCertificateException
# Import the logging module to log messages
import logging
# Import the make_request function from the VMware vRealize Automation IPAM SDK utilities.
from vra_ipam_utils.request_handler import RequestHandler

# The handler function is the entry point for the vRA system
def handler(context, inputs):

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

    # Make a GET request to validate the API key.
    request.make_request("GET", url, headers=headers, verify=cert)

    # Log the successful API key check.
    logging.info("API key check successful")

    # Return the headers for use in subsequent API calls.
    return headers

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
            raise InvalidCertificateException("certificate verify failed", self.inputs["endpointProperties"]["hostName"], 443) from ssl_error
        else:
            # Log the error and raise the exception
            logging.error(f"SSL error occurred: {ssl_error}")

            # Raise the SSL exception
            raise ssl_error
    # The following except block has been added to handle all other errors
    except Exception as e:
        # Log the error and raise the exception
        logging.error(f"An unexpected error occurred: {e}")

        # Raise the exception
        raise e