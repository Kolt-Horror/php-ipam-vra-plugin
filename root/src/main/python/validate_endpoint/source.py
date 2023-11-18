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
    "authCredentialsLink": "/core/auth/credentials/13c9cbade08950755898c4b89c4a0",
    "endpointProperties": {
      "hostName": "sampleipam.sof-mbu.eng.vmware.com"
    }
  }
'''

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

# The handler function is the entry point for the vRA system
def handler(context, inputs):

    ipam = IPAM(context, inputs)
    IPAM.do_validate_endpoint = do_validate_endpoint

    return ipam.validate_endpoint()

# The do_api_key_check function is a custom function that has been created to check the API key against the PHP IPAM API
def do_api_key_check(base_url, auth_credentials, cert):
    # Initialize the PHP IPAM URL to be used for the rest call
    url = f"{base_url}/user/"
    
    # Initialize the headers to be used for the rest call (Token using the api key and content type)
    headers = {
        "token": auth_credentials["privateKey"],
        "Content-Type": "application/json"
    }

    # Make the get rest call to the PHP IPAM API
    response = requests.get(url, headers=headers, verify=cert)

    return response

def do_validate_endpoint(self, auth_credentials, cert):
    # Setup the base url to be used for the rest call for the PHP IPAM API
    base_url = f"https://{self.inputs['endpointProperties']['hostName']}/api/{auth_credentials['privateKeyId']}"

    # Try to make the rest call to the PHP IPAM API
    try:
        # Call the do_api_key_check function to get the response from the rest call
        response = do_api_key_check(base_url, auth_credentials, cert) # Call the do_api_key_check function to get the response from the rest call

        # Perform the necessary checks on the response
        if response.status_code == 200:
            # Return the response
            return {
                "message": "Validated successfully",
                "statusCode": "200"
            }
        # Else if the response status code is 401, raise an exception
        elif response.status_code == 401:
            # Log the error and raise the exception
            logging.error(f"Invalid credentials error: {str(response.content)}")
            
            # Raise an exception
            raise Exception(f"Invalid credentials error: {str(response.content)}")
        else:
            raise Exception(f"Failed to connect: {str(response.content)}")
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