# SOC & Automation Project with Wazuh and Shuffler.io

This repository contains a project report on SOC (Security Operations Center) automation, demonstrating the integration of Wazuh, Alienvault OTX, and Shuffler.io to detect and respond to Indicators of Compromise (IOCs) automatically. The project simulates a threat scenario, detects malicious activity using Wazuh, and responds automatically via Shuffler.io.

## Files in this Repository

- **SOC_Automation_Report.pdf**: A comprehensive report on configuring Wazuh to detect a specific IOC and setting up Shuffler.io for automated incident response. It details the configuration, testing, and results of the SOC automation setup.

## Project Overview

SOC & Automation
In this assignment, your task is to create an automated response to an observed IOC within an environment managed by Wazuh. You will leverage Alienvault OTX as a threat intel source, Wazuh as your SIEM & EDR and Shuffler.io as your SOAR. The primary focus here is to demonstrate your ability to contribute to SOC automation, bringing together threat intel, EDR, SIEM and SOAR.

Research and IOC Identification
Sign up for Alienvault OTX:
Go to https://otx.alienvault.com/ and sign up for an account
Log in to the main dashboard and navigate to the Indicators tab
Identify an IOC:
Browse through the indicators to identify a specific Indicator of Compromise (IOC) such as a hash, IP address, or domain.
Automated Security Response Setup
Set Up Wazuh:
Install and configure the Wazuh manager and agent in a VM. The image is provided here:
UTM Image
VirtualBox Image
Wazuh in UTM
Start the VM in UTM and get the IP address from the console.
Take note of the ip address of the non-loopback interface
Access the virtual machine using the following user and password. You can use the virtualization platform or access it via SSH.
user: wazuh-user
password: wazuh
You can access the web interface from a browser on your local machine at https://<ubuntu-vm-ip>:443
User: admin
Password: HwhG.y*8GxmFBeEA9eQuLjDfQoS1iu?*
Wazuh in Virtual Box
Set the VMSVGA graphic controller. Setting another graphic controller freezes the VM window.
Select the imported VM.
Click Settings > Display
In Graphic controller, select the VMSVGA option.
Access the virtual machine using the following user and password. You can use the virtualization platform or access it via SSH.
user: wazuh-user
password: wazuh
Shortly after starting the VM, the Wazuh dashboard can be accessed from the web interface by using the following credentials:
URL: https://<wazuh_server_ip>
user: admin
password: admin
You can find <wazuh_server_ip> by typing the following command in the VM:
ip a
Create a Wazuh Rule:
Develop a Wazuh rule to detect the IOC identified in Part 1. Specify the conditions that trigger the rule and define the corresponding actions.
Integrate Shuffler.io:
Sign up for an account on Shuffler.io
Create a workflow or automation rule on shuffler.io to respond to the detection of the IOC in Wazuh. Define the actions to be taken automatically. Integrate Shuffler.io and Wazuh following the steps outlined here. A summary is provided below:
Create Shuffle Workflow:
Create a workflow in Shuffle and add a webhook trigger.
Copy the webhook URI generated and start the webhook.
Configure Wazuh Server:
Edit the Wazuh server configuration file (ossec.conf) and add the Shuffle integration settings.
Specify the Shuffle webhook URI, rule ID, rule group, or alert level for events to be forwarded.
Wazuh Server Restart:
Restart the Wazuh manager service to apply the configuration changes.
Shuffle Workflow Configuration:
Create a complete workflow in Shuffle to define actions on alerts received from Wazuh.
Additional Notes:
The webhook trigger may be configured with other Shuffle apps to perform various functions in a workflow.
Testing and Documentation
Simulate Threat Scenario:
Manually simulate a threat scenario by injecting the IOC into your test environment. Ensure that the Wazuh rule is triggered.
Observe Automated Response:
Monitor the shuffler.io dashboard to observe the automated response triggered by the IOC detection in Wazuh.
Document the Process:
Prepare a detailed document using the template provided that includes:
Overview of the selected IOC.
Steps for setting up Wazuh and creating a rule.
Shuffler.io configuration for automated response.
Results and observations from the threat simulation.

### 1. Selected IOC

- **IOC**: IP address `185.220.101.52`, associated with anonymization services and potential Command and Control (C2) infrastructure.
- **Threat Characteristics**: The IP is part of the Tor network, often linked to malware distribution, phishing, and C2 activities.

### 2. Wazuh Setup and Rule Creation

- **Installation and Configuration**: Wazuh was installed and configured on a virtual machine to monitor network activity.
- **Custom Rule Creation**: A rule was created to detect the specific IP address `185.220.101.52`:
   ```xml
   <group name="alienvault_otx">
      <rule id="100001" level="10">
         <decoded_as>json</decoded_as>
         <field name="data.srcip">185.220.101.52</field>
         <description>Suspicious IP detected from Alienvault OTX IOC: 185.220.101.52</description>
      </rule>
   </group>


   
