"""
Copyright (c) 2020 VMware, Inc.

This product is licensed to you under the Apache License, Version 2.0 (the "License").
You may not use this product except in compliance with the License.

This product may include a number of subcomponents with separate copyright notices
and license terms. Your use of these subcomponents is subject to the terms and
conditions of the subcomponent's license, as noted in the LICENSE file.
"""

"""
The validate endpoint uses the endpoint values listed in the endpoint-schema.json file

The validate endpoint process performs the following steps:
    - Performs a token check against the target PHP IPAM System
    - If the token check is successful, the process returns a success message
    - If there is a ssl error, the process raises an InvalidCertificateException 
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
# Import the base64 module to encode the authentication key
import base64

# The handler function is the entry point for the vRA system
def handler(context, inputs):

    ipam = IPAM(context, inputs)
    IPAM.do_validate_endpoint = do_validate_endpoint

    return ipam.validate_endpoint()

# Function to validate the endpoint
def do_validate_endpoint(self, auth_credentials, cert):
    # Get the PHP IPAM plugin default information
    phpIpamEndpointProperties = self.inputs['endpointProperties']

    # If a port number is provided, append it to the hostname
    if phpIpamEndpointProperties['portCheck'].lower() is "true":
        phpIpamEndpointProperties['hostName'] = f"{phpIpamEndpointProperties['hostName']}:{phpIpamEndpointProperties['port']}"

    # Initialize the base PHP IPAM URL to be used for the rest call
    base_url = f"https://{phpIpamEndpointProperties['hostName']}/api/{phpIpamEndpointProperties['appId']}"

    # Try to make the rest call to the PHP IPAM API
    try:
        # Check if the user account or token is being used for authentication
        if phpIpamEndpointProperties['serviceAccountCheck'] is None or phpIpamEndpointProperties['serviceAccountCheck'].lower() is "true":
            # Validate the API key and return the headers for use in subsequent API calls.
            api_headers = do_api_key_check(base_url, phpIpamEndpointProperties, cert)
        else:
            # Validate the user account and return the headers for use in subsequent API calls.
            api_headers = do_user_account_check(base_url, phpIpamEndpointProperties, cert)

        # IF the api_headers is a dictionary with a key "token", then the token is valid
        if "token" in api_headers:
            # If the service account check is True then the service account token revocation is required
            if phpIpamEndpointProperties['serviceAccountCheck'].lower() is "true":
                # If the user account check was successful, revoke the token.
                do_revoke_user_token(base_url, api_headers, cert)
            
            # As the token is valid, we can proceed with returning the authorization message to vRA
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
            raise InvalidCertificateException("Certificate verify failed", phpIpamEndpointProperties['hostName'], 443) from ssl_error
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

# Function to Authenticate using API with the IPAM service
def do_api_key_check(base_url, phpIpamEndpointProperties, cert):
    # Construct the URL to check the API key against the IPAM service.
    url = f"{base_url}/user/"

    # Verify that the API key is not empty.
    if phpIpamEndpointProperties['apiKey'] is None or phpIpamEndpointProperties['apiKey'] == "":
        # Log the error and raise the exception
        logging.error("API key is empty")

        # Raise an exception
        raise Exception("API key is empty")

    # Set up the headers for authentication.
    api_headers = {
        "token": phpIpamEndpointProperties["apiKey"],
        "Content-Type": "application/json"
    }

    # Initialize the request handler, which will be used to make the API call.
    request = RequestHandler()

    try:
        # Make a GET request to validate the API key.
        response = request.make_request("GET", url, headers=api_headers, verify=cert)
    except Exception as e:
        # Log the error and raise the exception
        logging.error(f"An unexpected error occurred when performing Authentication Check: {e}")

        # Raise the exception
        raise e

    # Log the successful API key check.
    logging.info("API key check successful")

    # Verify that the token was successfully authenticated.
    if response['success'] is True:
        # Return True if the token was revoked successfully.
        return api_headers
    else:
        # Log the unsuccessful API key check.
        logging.error("API key check unsuccessful as the response was not successful: " + str(response))

        # Raise an exception
        raise Exception("API key check response payload was not successful: " + str(response))

# Function to Authenticate using User Account with the IPAM service
def do_user_account_check(base_url, phpIpamEndpointProperties, cert):
    # Construct the URL to check the API key against the IPAM service.
    url = f"{base_url}/user/"

    # Verify that the service account username and password are not empty.
    if phpIpamEndpointProperties.get('serviceAccountUsername') is None or phpIpamEndpointProperties.get('serviceAccountUsername') == "" or phpIpamEndpointProperties.get('serviceAccountPassword') is None or phpIpamEndpointProperties.get('serviceAccountPassword') == "":
        # Log the error and raise the exception
        logging.error("Service account username or password is empty")

        # Raise an exception
        raise Exception("Service account username or password is empty")

    # Construct the authentication key for the request.
    authKey = phpIpamEndpointProperties.get('serviceAccountUsername') + ":" + phpIpamEndpointProperties.get('serviceAccountPassword')

    # Convert the string to bytes.
    authKey = authKey.encode("utf-8")

    # Convert the byte key to base64 encoding.
    authKey = base64.b64encode(authKey)

    # Set up the headers for authentication.
    api_headers = {
        "Authorization": authKey,
        "Content-Type": "application/json"
    }

    # Initialize the request handler, which will be used to make the API call.
    request = RequestHandler()

    try:
        # Make a GET request to validate the API key.
        response = request.make_request("POST", url, headers=api_headers, verify=cert)
    except Exception as e:
        # Log the error and raise the exception
        logging.error(f"An unexpected error occurred when performing Service Account Authentication Check: {e}")

        # Raise the exception
        raise e

    if response['success'] is True:
        # Log the successful API key check.
        logging.info("API user check successful")

        # Get the token and expiry time from the response
        token = request.response.json()['data']['token']

        # Create a dictionary that builds the base for further API calls.
        api_headers = {
            "token": token,
            "Content-Type": "application/json"
        }

        # Return the headers for use in subsequent API calls.
        return api_headers
    else:
        # Log the unsuccessful API key check.
        logging.error("Service Account response payload check failed: " + str(response))

        return Exception("Service Account response payload check failed: " + str(response))

# Function to revoke authentication for the user account token
def do_revoke_user_token(base_url, api_headers, cert):
    # Construct the URL to revoke the user token.
    url = f"{base_url}/user/"

    # Initialize the request handler, which will be used to make the API call.
    request = RequestHandler()

    try:
        # Make a DELETE request to revoke the user token.
        response = request.make_request("DELETE", url, headers=api_headers, verify=cert)
    except Exception as e:
        # Log the error and raise the exception
        logging.error(f"An unexpected error occurred when revoking the Service Account token: {e}")

        # Raise the exception
        raise e

    # Log the successful token revocation.
    logging.info("Service Account token revoked")

    # Verify that the token was successfully revoked.
    if response['success'] is True:
        # Return True if the token was revoked successfully.
        return True
    else:
        # Log the unsuccessful token revocation.
        logging.error("Service Account token revocation unsuccessful: " + str(response))

        return Exception("Service Account token revocation unsuccessful: " + str(response))