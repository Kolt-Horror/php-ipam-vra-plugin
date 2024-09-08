# Setup PHP IPAM API to use Service Account

## Overview
This document describes how to setup PHP IPAM API to use a Service Account.

## Prerequisites
PHP IPAM API must be ready to be used, along with a Service Account connected to the PHP IPAM system.

## Steps
1. Click on the 'Create API key' button in the API section of the Administration UI of PHP IPAM.
2. Fill in the required fields as follows:
    - **App id**: The service account username that would be used to login to the PHP IPAM system.
    - **App Security**: 'SSL with User token'.
3. Click on the 'Add' button.

## Conclusion
This will setup PHP IPAM API to use a Service Account.