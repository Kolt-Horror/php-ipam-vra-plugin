# Import logging library to log errors.
import logging
# Import the requests library to make HTTP requests.
import requests
# Import the requests library exceptions to handle errors.
from requests.exceptions import RequestException


class RequestHandler:
    def __init__(self):
        pass

    @staticmethod
    def make_request(method, url, **kwargs):
        """
        Send a request using the requests library and handle any potential exceptions.

        Args:
            method (str): HTTP method to use for the request ('GET', 'POST', etc.).
            url (str): The URL to send the request to.
            **kwargs: Arbitrary keyword arguments that are passed to the request method.

        Returns:
            Response: The response object from the requests library.

        Raises:
            HTTPError: An error from the requests library for HTTP related issues.
            RequestException: A base class for all requests' exceptions.
        """
        try:
            # Perform the HTTP request with the provided method, URL, and parameters.
            response = requests.request(method, url, **kwargs)
            # Automatically raise an exception for HTTP error responses.
            response.raise_for_status()
            return response.json()
        except requests.exceptions.HTTPError as http_err:
            # Log HTTP related errors and re-raise them.
            logging.error(f'HTTP error occurred: {http_err}')
            raise
        except requests.exceptions.ConnectionError as conn_err:
            # Log connection related errors and re-raise them.
            logging.error(f'Connection error occurred: {conn_err}')
            raise
        except requests.exceptions.Timeout as timeout_err:
            # Log timeout related errors and re-raise them.
            logging.error(f'Timeout error occurred: {timeout_err}')
            raise
        except RequestException as err:
            # Log any other requests-related errors and re-raise them.
            logging.error(f'Unexpected error occurred: {err}')
            raise
