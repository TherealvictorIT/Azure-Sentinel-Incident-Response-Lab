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
*Incidents generated within Azure Sentinel, will be worked in accordance with the NIST 800-61 Incident Management Lifecycle.    
<p align="center">
  <img src="https://github.com/TherealvictorIT/Azure-Sentinel-Incident-Response-Lab/assets/125538763/2b3cb36b-c677-414f-9828-e8c42cbca4ea" alt="NIST 800-61">
</p>

**Step 1: Preparation**  
According to NIST 800-61 the first step is Preparation. This was already initiated by ingesting all of the logs into the Log Analytics Workspace and Sentinel and configuring alert rules. A CUSTOM: Brute Force SUCCESS - Windows Incident was triggered 11/21/2023 at 8:22:32 PM with a High Severity level. 

**Step 2: Detection & Analysis**  
1. The severity was set to high, status set to Active
2. When examining the complete details and reviewing the Activity log of the incident, as well as analyzing the incident timeline, not much valuable information was discovered.  
3. When observing the Entities section the attackers IP address is found and some Geolocation information can be acquired
4. When Investigating the incident and clicking on the attackers related alerts it seems the attacker is:     
a. Attacker involved in another brute force success    
b. Attacker involved in a brute force attempt- unsuccessfully    
c. Attacker involved in possible privilege escalation  

<p align="center"> 
      <img src="https://github.com/TherealvictorIT/Azure-Sentinel-Incident-Response-Lab/assets/125538763/b8b5e9f6-8127-43fe-bdff-4e13ba3d4e7b" alt="Brute force Success- Windows VM related attacks" width="800">
</p>

6. When the clicking the Windows-VM related alerts, it seems the VM is:     
a. computer involved in 2 brute force success for windows  
b. computer involved in multiple other brute force attempts  
c. computer involved in malware detected   
d. computer involved in windows firewall tampering  
e. computer involved in brute force attempt- MS SQL server  
f. It makes sense the VM is involved in multiple attacks since it is opened to the internet

<p align="center"> 
     <img src="https://github.com/TherealvictorIT/Azure-Sentinel-Incident-Response-Lab/assets/125538763/cdfe7813-491e-4b62-a8b5-842ceba7d6e4" alt="Brute force Success- Windows VM related attacks" width="800">
</p>

8. When trying to investigate if this is a legitimate brute force attempt we performed a query in Log Analytics Workspace to figure out if the attacker logged onto a user account within the VM. A simple query is performed to find failed and successful logins from a specific IP address:  

**Query Rule:**

     SecurityEvent  
     | where EventID == 4624 or EventID == 4625  
     | where IpAddress == "XX.XX.XX.XXX"  

Based on our findings the attacker was able to successfully login into the VM. The user logged into a user account within the VM.   
![Brute force Success - Windows Successful and failed logins](https://github.com/TherealvictorIT/Azure-Sentinel-Incident-Response-Lab/assets/125538763/b32d37db-3aaf-4050-b6ef-5997d7b8460e)

**Step 3: Containment, Eradication and Recovery**  
Next step would be to use the Incident Response Playbook to resolve the incident. The Incident Response workbook was created using ChatGPT for this specific lab. According to the workbook we have to perform the following tasks: 

<p align="center">
<img width="802" alt="Brute force success _ incident recovery palybook" src="https://github.com/TherealvictorIT/Azure-Sentinel-Incident-Response-Lab/assets/125538763/323507d9-79d6-4558-88f7-89b6e2c5a92c">
</p>  

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

![Windows Brute Force Success Step 4](https://github.com/TherealvictorIT/Azure-Sentinel-Incident-Response-Lab/assets/125538763/4e7e08b9-c5a3-46ca-8f6d-61cc1d370e4c)


## Incident: Possible Privilege Escalation (Azure Key Vault Critical Credential Retrieval or Update)
The following query is designed to monitor the Azure Key Vault for operations related to accessing or updating a specific password named "Tenant-Global-Admin-Password." It offers visibility into activities involving this critical password.  

**Query Rule:**   

     // Updating a specific existing password Success  
     let CRITICAL_PASSWORD_NAME = "Tenant-Global-Admin-Password";  
     AzureDiagnostics  
     | where ResourceProvider == "MICROSOFT.KEYVAULT"  
     | where OperationName == "SecretGet" or OperationName == "SecretSet"  
     | where id_s contains CRITICAL_PASSWORD_NAME  

## Incident Response  
**Step 1: Preparation**     
Preparation was already initiated by ingesting all of the logs into the Log Analytics Workspace and Sentinel and configuring alert rules.  A CUSTOM: Possible Privilege Escalation Incident was triggered at 11/21/2023, 7:46:33 PM with High Severity.  

**Step 2: Detection & Analysis**    
1. The severity was set to high, status set to Active  
2. When looking at the Incident Timeline we can observe that the password is being viewed multiple times within a small time frame  
3. The password is being viewed by Victor Garcia (victor.garcia_gmail.com#EXT#@victorgarciagmail.onmicrosoft.com)  
4. Upon further investigation it seems like the user was involved in excessive password reset incident and also involved in a global role assignment  
*The alert was intentionally triggered to illustrate the resolution process. The following content outlines how the situation would unfold if it were an actual scenario.*

<p align="center"> 
<img width="539" alt="possible privilage escalation Josh prt2" src="https://github.com/TherealvictorIT/Azure-Sentinel-Incident-Response-Lab/assets/125538763/53316931-2fdc-4016-b038-3b926f42ae1c">
</p>
   
5. In this incident it was determined that it is a false positive  
6. Upon contacting the individual and asking why he viewed the password so many times the user indicated that he was working on a project as described in ticket INC123456. User also assigned a global role to a user as described in INC123457. These tasks were confirmed by the users manager. Written confirmation is included in tickets.  

**Step 4: Document Findings/Info and close out the Incident in Sentinel**  
Step 3 will be skipped since this is a false positive and no Containment, Eradication and Recovery needs to be performed. User was doing his normal job duties so the ticket will be closed out as a false positive.  
![Possible privilage escalation Step 4](https://github.com/TherealvictorIT/Azure-Sentinel-Incident-Response-Lab/assets/125538763/f088e752-7144-4e4a-9fe0-c0d8d110be41)  


## Incident: Malware Detected
This query rule is targeting events from the Microsoft Windows Defender log and specifically focusing on events with Event IDs "1116" (scan started) or "1117" (scan complete). These events are part of the logging mechanism of Windows Defender Antivirus and can be used to keep track of when antivirus scans start and finish on a system. Monitoring these events helps in understanding the security activities and performance of the antivirus software on a Windows system.  

**Query Rule:**  
    
     Event
     | where EventLog == "Microsoft-Windows-Windows Defender/Operational"
     | where EventID == "1116" or EventID == "1117"  
     
## Incident Response 
**Step 1: Preparation** 
Preparation was already initiated by ingesting all of the logs into the Log Analytics Workspace and Sentinel and configuring alert rules.  Alert CUSTOM: Malware Detected Incident was triggered at 11/21/2023, 7:36:29 PM with High Severity.  

**Step 2: Detection & Analysis** 
1. The severity was set to high, status set to Active
2. Seven similar alerts were triggered within a short timeframe and it also seems like the VM is involved in other incidents including several brute force attempts and successes as well as a Windows Host Firewall Tampering.

![Malware Detected related incidents](https://github.com/TherealvictorIT/Azure-Sentinel-Incident-Response-Lab/assets/125538763/bbab2b25-c5d6-43e0-bb78-70e3d9ae39e8)

3. When observing the individual incidents that triggered the alert all incidents lead to a Microsoft knowledge document: (https://www.microsoft.com/en-us/wdsi/threats/malware-encyclopedia-description?name=Virus%3ADOS%2FEICAR_Test_File&threatid=2147519003&enterprise=0)

![Malware detected LAW Query](https://github.com/TherealvictorIT/Azure-Sentinel-Incident-Response-Lab/assets/125538763/5d2cda5e-e024-4049-9ba0-c4aae11bc277)

The document indicated that the file triggered by the system was an DOS/EICAR_Test_File and it’s used to check that your security software is working properly.

![Malware detected Microsoft article](https://github.com/TherealvictorIT/Azure-Sentinel-Incident-Response-Lab/assets/125538763/091d8dbf-4c29-4793-a18a-a8be8580ecb7)

6. User and manager were contacted and tickets INC123458 indicates that user was performing test on environment
7. Ticket will be closed out as false positive 

**Step 4: Document Findings/Info and close out the Incident in Sentinel**  
Step 3 will be skipped since this is a false positive and no Containment, Eradication and Recovery needs to be performed. User was doing his normal job duties so the ticket will be closed out as a false positive.

![malware detected Ticket](https://github.com/TherealvictorIT/Azure-Sentinel-Incident-Response-Lab/assets/125538763/1801895d-1df8-4ff0-afe3-ddeea8f4a35d)

