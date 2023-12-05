# Azure-Sentinel-Incident-Response-Lab
![Incident response infographic](https://github.com/TherealvictorIT/Azure-Sentinel-Incident-Response-Lab/assets/125538763/8e11b5bb-dfa0-475a-a890-f28e574a6722)


## Introduction
Over a 24-hour period, we intentionally exposed our virtual machines (VMs) to potential online threats. To simulate a vulnerable scenario, we disabled the Microsoft Defender firewall on the VMs and the Network Security Group on Azure, making it easier for the machines to be discoverable on the internet. The objective was to subject the VMs to potential attacks, allowing for the generation of security incidents within Microsoft Sentinel based on predefined rules. 

## Incident: Brute Force SUCCESS - Windows 
The following query rule is designed to identify cases of brute-force attacks on Windows systems.This rule detects Windows brute-force attacks by analyzing failed and successful logon attempts within the last hour. It flags instances where an actor makes multiple unsuccessful login attempts before succeeding, indicating a successful brute-force attack.   

**Query Rule:**  
![Brute Force Success Query](https://github.com/TherealvictorIT/Azure-Sentinel-Incident-Response-Lab/assets/125538763/78c43a55-dc07-4694-be7d-dfa2a038d271)

The provided query is written in KQL and is used in Microsoft Sentinel. The query consists of three parts and it reads as follows:

**FailedLogons:**    

     let FailedLogons = SecurityEvent  
     | where EventID == 4625 and LogonType == 3  
     | where TimeGenerated > ago(1h)  
     | summarize FailureCount = count() by AttackerIP = IpAddress, EventID, Activity, LogonType, DestinationHostName = Computer  
     | where FailureCount >= 5;    

The query starts by filtering the SecurityEvent table to select events with EventID 4625 (indicating a failed logon attempt) and LogonType 3 (network logon).
It further filters events that occurred within the last hour using ago(1h).
The results are then summarized by counting the occurrences (FailureCount) grouped by AttackerIP, EventID, Activity, LogonType, and DestinationHostName.
Finally, it filters to include only those entries where the failure count is greater than or equal to 5.

**SuccessfulLogons:**   

     let SuccessfulLogons = SecurityEvent  
     | where EventID == 4624 and LogonType == 3  
     | where TimeGenerated > ago(1h)  
     | summarize SuccessfulCount = count() by AttackerIP = IpAddress, LogonType, DestinationHostName = Computer, AuthenticationSuccessTime = TimeGenerated;  

This part of the query filters the SecurityEvent table to select events with EventID 4624 (indicating a successful logon) and LogonType 3 (network logon).
It filters events that occurred within the last hour using ago(1h).
The results are summarized by counting the occurrences (SuccessfulCount) grouped by AttackerIP, LogonType, DestinationHostName, and AuthenticationSuccessTime.

**Join and Projection:**    

     SuccessfulLogons  
     | join kind = inner FailedLogons on DestinationHostName, AttackerIP, LogonType  
     | project AuthenticationSuccessTime, AttackerIP, DestinationHostName, FailureCount, SuccessfulCount  

The join kind = inner in this query is performing an inner join, combining the results from SuccessfulLogons and FailedLogons only for the rows where there is a match on the specified fields. This ensures that only entries with corresponding values in all specified fields are included in the final result. The final result is projected to include the AuthenticationSuccessTime, AttackerIP, DestinationHostName, FailureCount, and SuccessfulCount.

## Incident Response  
*Incidents generated within Azure Sentinel, will be worked in accordance with the NIST 800-61 Incident Management Lifecycle. ## Architecture After Hardening / Security Controls*    
<p align="center">
  <img src="https://github.com/TherealvictorIT/Azure-Sentinel-Incident-Response-Lab/assets/125538763/2b3cb36b-c677-414f-9828-e8c42cbca4ea" alt="NIST 800-61">
</p>

**Step 1: Preparation**  
According to NIST 800-61 the first step is Preparation. This was already initiated by ingesting all of the logs into the Log Analytics Workspace and Sentinel and configuring alert rules. A CUSTOM: Brute Force SUCCESS - Windows Incident was triggered 11/21/2023 at 8:22:32 PM with a High Severity level. 

**Step 2: Detection & Analysis**  
1. The severity was set to high, status set to Active
2. When viewing full details and observing the Activity log of the Incident and observing the Incident timeline not much useful information was found 
3. When observing the Entities section the attackers IP address is found and some Geolocation information can be acquired 
4. When Investigating the incident and clicking on the attackers related alerts it seems the attacker is:
a. Seems like attacker is involved in another brute force success  
b. Attacker involved in a brute force attempt- unsuccessfully  
c. Attacker involved in possible privilege escalation 
5. When the Windows-VM related alerts it seems the VM is: 
a. computer involved in 2 brute force success for windows
b. computer involved in multiple other brute force attempts
c. computer involved in malware detected 
d. computer involved in windows firewall tampering
e. computer involved in brute force attempt- MS SQL server
f. It makes sense the VM is involved in multiple attacks since it is opened to the internet
6. When trying to investigate if this is a legitimate brute force attempt we performed a query in Log Analytics Workspace to figure out if the attacker logged onto a user account within the VM. A simple query is performed to find failed and successful logins from a specific IP address:

**Query:**

     SecurityEvent  
     | where EventID == 4624 or EventID == 4625  
     | where IpAddress == "XX.XX.XX.XXX"  

Based on our findings the attacker was able to successfully login into the VM. The user logged into a user account within the VM.   

**Step 3: Containment, Eradication and Recovery**  
Next step would be to use the Incident Response Playbook to resolve the incident. The Incident Response workbook was created using ChatGPT for this specific lab. According to the workbook we have to perform the following tasks:  
* Verify the authenticity of the alert or report.  
  * *In this case the alert is a True Positive, there were initial brute force attempts and a successful login into the a user account associated with the VM*     
* Immediately isolate the machine and change the password of the affected user  
  * *Password of affected user was changed*      
* Identify the origin of the attacks and determine if they are attacking or involved with anything else  
  * *Seems like attacker is involved in another brute force success*    
  * *Attacker involved in a brute force attempt- unsuccessfully*    
  * *Attacker involved in possible privilege escalation*   
* Determine how and when the attack occurred
  * Are the NSGs not being locked down? If so, check other NSGs
    * *Attack occurred at 11/21/2023, 8:22:32 PM*
    * *There was about 12 brute force attempts before a successful login into the VM user account*
    * *The NSG is Opened to the internet*  
* Assess the potential impact of the incident.
  * What type of account was it? Permissions?  
    * *The potential impact is minimal, the user account was a new user account with no administrative privileges or access to corporate network.*  
For the Containment and Recovery portion the following task need to be performed: 
* Reset the affected user’s password
  * *Users password was changed*  
* Enable MFA
  * *MFA is not a possibility for this type of VM*  
* Lock down the NSG assigned to that VM/Subnet, either entirely, or to allow only necessary traffic
  * *The task of hardening the NSG is in process and only certain IP addresses will be able to access the VM*  

**Step 4: Document Findings/Info and close out the Incident in Sentinel**  
Notes have been included in the ticket and now that the incident is solved the ticket has been closed out in Sentinel


![Architecture Diagram](https://github.com/TherealvictorIT/Azure-Sentinel-Honey-net-Lab-/assets/125538763/97899627-2aed-4629-84ab-03ea88a1def0">)

The structure of the honeynet in Azure comprises the following components:

- Virtual Network (VNet)
- Network Security Group (NSG)
- Virtual Machines (2 windows, 1 linux)
- Log Analytics Workspace
- Azure Key Vault
- Azure Storage Account
- Microsoft Sentinel

For the “Before” metrics, all resources were deployed with exposure to the internet. The Virtual Machines had both their Network Security Groups and built-in firewalls wide open, and all other resources were deployed with public endpoints visible to the Internet; aka, no use for Private Endpoints.  

For the "AFTER" metrics, Network Security Groups were hardened by blocking ALL traffic with the exception of an admin workstation, and all other resources were protected by their built-in firewalls as well as Private Endpoint  


## Attack Maps Before Hardening / Security Controls
![NSG Allowed Inbound Malicious Flows](https://github.com/TherealvictorIT/Azure-Sentinel-Honey-net-Lab-/assets/125538763/c58454a2-5887-43c7-9e92-f6fb0f012f03)<br>
![Linux Syslog Auth Failures](https://github.com/TherealvictorIT/Azure-Sentinel-Honey-net-Lab-/assets/125538763/3594d3bd-9b1c-4796-8572-b9854a04ecfb)<br>
![Windows RDP/SMB Auth Failures](https://github.com/TherealvictorIT/Azure-Sentinel-Honey-net-Lab-/assets/125538763/0187de7a-0249-411c-ba4c-ac235f168848)<br>
![MSSQL Auth Faiures](https://github.com/TherealvictorIT/Azure-Sentinel-Honey-net-Lab-/assets/125538763/1420d52c-54d1-4d20-beac-14bc3c0f3957)<br> 


## Metrics Before Hardening / Security Controls

The following table shows the metrics we measured in our insecure environment for 24 hours:
Start Time 2023-11-21 T15:37
Stop Time 2023-11-22 T15:37

| Metric                   | Count
| ------------------------ | -----
| SecurityEvent            | 22476
| Syslog                   | 7747
| SecurityAlert            | 11
| SecurityIncident         | 168
| AzureNetworkAnalytics_CL | 3777

## Attack Maps After Hardening / Security Controls

```All map queries actually returned no results due to no instances of malicious activity for the 24 hour period after hardening.```

## Metrics After Hardening / Security Controls

The following table shows the metrics we measured in our environment for another 24 hours, but after we have applied security controls:
Start Time 2023-11-21 15:37
Stop Time	2023-11-21 15:37

| Metric                   | Count
| ------------------------ | -----
| SecurityEvent            | 8778
| Syslog                   | 25
| SecurityAlert            | 0
| SecurityIncident         | 0
| AzureNetworkAnalytics_CL | 0

## Conclusion

In this project, a mini honeynet was constructed in Microsoft Azure and log sources were integrated into a Log Analytics workspace. Microsoft Sentinel was employed to trigger alerts and create incidents based on the ingested logs. Additionally, metrics were measured in the insecure environment before security controls were applied, and then again after implementing security measures. It is noteworthy that the number of security events and incidents were drastically reduced after the security controls were applied, demonstrating their effectiveness.

It is worth noting that if the resources within the network were heavily utilized by regular users, it is likely that more security events and alerts may have been generated within the 24-hour period following the implementation of the security controls.
