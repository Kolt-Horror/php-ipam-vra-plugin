# PHP IPAM vRA Plugin

## Overview
The PHP IPAM vRA Plugin repository is dedicated to integrating VMware's vRealize Automation (vRA) with PHP IP Address Management (IPAM) system. This integration facilitates efficient IPAM management directly from the vRA environment.

## Repository Structure
- `/root`: Contains the VMware IPAM SDK code for a PHP IPAM plugin for vRA, ready for a Maven build.
- `/PHP-IPAM.zip`: A ready-to-deploy build of the PHP IPAM vRA Plugin for integration with vRA systems.
- `/SOPs`: Standard Operating Procedures for configuring Maven and Java on Windows machines.

## Pre-Requisites
Before using this plugin, ensure you have the following installed:
- Java JDK (version 8 or above)
- Maven
- Python (version 3.11 or above)
- Docker

## Build
To build the PHP IPAM vRA Plugin from scratch, follow these steps:
1. Clone the repository to your local machine.
2. Navigate to the folder called root and build the VMware IPAM SDK using Maven:
    - `mvn package -PcollectDependencies`
3. Access the successfully built plugin in the `.\target\PHP-IPAM.zip` folder within the folder called root.

## Configuration
Refer to the SOPs folder for detailed instructions on configuring:
    - Windows environment
        - Maven
        - Java
This setup is essential for building and maintaining the VMware IPAM SDK.
Within the SOPs folder you will also find the references.txt file with has links tot he VMware IPAM SDK documentation.

For configuration of the PHP IPAM vRA Plugin, refer to the `.\root\README.md` file which is provided by the base VMware SDK.

## Usage
Once installed and configured, the PHP IPAM vRA Plugin allows for seamless IP address management from within the vRA environment.
This plugin enables the full feature of the VMware IPAM SDK, including:
- IP address allocation:
    - Allocates first free IP addresses in a subnet defined as a IP range.
- IP range allocation
    - Allocates a subnet from an IP block (These subnets are UI identified as subnets where the user can allocate IP addresses from).
    - Creates the first available subnet for a subnet prefix mask.
- IP address deallocation
    - Deallocates an IP address from a subnet.
    - Does this by using the ip address followed by the subnet id.
- IP range deallocation
    - Deallocates a subnet from an IP block.
    - Does this by using the subnet id, when this occurs everything within the subnet is deleted.
- Get IP blocks
    - Gets all IP blocks from the IPAM system.
    - Does this by checking if the subnet will provide the first free IP address, within all subnets, if it cant provide an IP address it means the subnet is an IP block.
- Get IP ranges
    - Gets all IP ranges from the IPAM system.
    - Does this by checking if the subnet will provide the first free IP address, within all subnets, if it can provide an IP address it means the subnet is an IP range.
- Update record
    - Updates an IP address record.
    - Does this by using the ip addresses and hostname, and confirming the hostnames match the matched IP address.
        This is done to ensure the correct IP address is updated, as duplicate hostnames shouldnt exist.
- Validate endpoint
    - Validates the endpoint is correct.
    - Does this by checking if the endpoint authentication is correct using the API key name and API key.


## Contributing
Contributions to enhance the PHP IPAM vRA Plugin are welcome. Please submit pull requests for review.

## Support
For support, please open an issue in the GitHub repository.

## Acknowledgments
VMware for providing the IPAM SDK and documentation.
PHP IPAM for providing the IPAM system and documentation and having the system open source.
For a PHP IPAM testing contianer, please refer to the following link: https://github.com/Kolt-Horror/php-ipam-container