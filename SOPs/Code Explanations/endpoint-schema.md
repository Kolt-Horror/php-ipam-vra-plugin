# endpoint-schema.json File Explained

## Overview
The `endpoint-schema.json` file is located in '/root/src/resources/' this file sets the UI schema for the endpoint creation form. The schema is used to generate the form fields and their properties. The schema is a JSON object that contains the following properties:
    - Hostname
    - Port
    - Service Account Check
    - Service Account Username
    - Service Account Password
    - API/APP ID/Key/Name
    - API Key/Secret
    - Sections Access Check
    - Authorized Sections
This file is also what sets the endpointProperties within the Endpoint entity.

## Schema Properties
### Hostname
This property is used to create the URL REST API calls will be made to. The property is a string and is required.

The property also has string regex validation to ensure the input is a valid hostname or IP address.

### Port
This property is not mandatory but if communication via REST API has to occur over a specific port, this property can be used to specify the port number.

The property also has number regex validation to ensure the input is a valid port number.

### Service Account Check
This property is a boolean that is used to determine if the plugin user wants to use a service account to authenticate with the REST API instead of using an API Key/Secret. This property also comes with the reccomendation to consult with the security team before using a service account.

This property is used by all actions that are available to the plugin to determine the authentication method.

### Service Account Username
This property is a string that is used to specify the username of the service account that will be used to authenticate with the REST API.

This property is only required if the Service Account Check property is set to true.

### Service Account Password
This property is a string that is used to specify the password of the service account that will be used to authenticate with the REST API.

This property is only required if the Service Account Check property is set to true.

### API/APP ID/Key/Name
This property is a string that is used to specify the API Key/Secret or App ID/Key/Name that will be used to authenticate with the REST API.

This property is always required as it is used to create the REST API url based on the PHP IPAM API documentation.

### API Key/Secret
This property is a secure string that is used to specify the API Key/Secret that will be used to authenticate with the REST API.

This property is only required if the Service Account Check property is set to false.

### Sections Access Check
This property is a boolean that is used to determine if the plugin user wants to restrict the plugin to only certain sections within the PHP IPAM system.

This property is used by all actions that are available to the plugin to determine if the plugin should restrict the user to certain sections.

### Authorized Sections
This property is an array of strings that is used to specify the sections that the plugin user is allowed to access.

This property is only required if the Sections Access Check property is set to true.