# Azure-Sentinel-Incident-Response-Lab
![Incident response infographic](https://github.com/TherealvictorIT/Azure-Sentinel-Incident-Response-Lab/assets/125538763/8e11b5bb-dfa0-475a-a890-f28e574a6722)


## Introduction

Over a 24-hour period, we intentionally exposed our virtual machines (VMs) to potential online threats. To simulate a vulnerable scenario, we disabled the Microsoft Defender firewall on the VMs and the Network Security Group on Azure, making it easier for the machines to be discoverable on the internet. The objective was to subject the VMs to potential attacks, allowing for the generation of security incidents within Microsoft Sentinel based on predefined rules. 

## Incident: Brute Force SUCCESS - Windows 
The following query rule is designed to identify cases of brute-force attacks on Windows systems.This rule detects Windows brute-force attacks by analyzing failed and successful logon attempts within the last hour. It flags instances where an actor makes multiple unsuccessful login attempts before succeeding, indicating a successful brute-force attack.   

Query Rule:  
![Brute Force Success Query](https://github.com/TherealvictorIT/Azure-Sentinel-Incident-Response-Lab/assets/125538763/78c43a55-dc07-4694-be7d-dfa2a038d271)

The provided query is written in KQL and is used in Microsoft Sentinel. The query consists of three parts and it reads as follows:

FailedLogons:  
let FailedLogons = SecurityEvent  
| where EventID == 4625 and LogonType == 3  
| where TimeGenerated > ago(1h)  
| summarize FailureCount = count() by AttackerIP = IpAddress, EventID, Activity, LogonType, DestinationHostName = Computer  
| where FailureCount >= 5;  

The query starts by filtering the SecurityEvent table to select events with EventID 4625 (indicating a failed logon attempt) and LogonType 3 (network logon).
It further filters events that occurred within the last hour using ago(1h).
The results are then summarized by counting the occurrences (FailureCount) grouped by AttackerIP, EventID, Activity, LogonType, and DestinationHostName.
Finally, it filters to include only those entries where the failure count is greater than or equal to 5.

SuccessfulLogons:  
let SuccessfulLogons = SecurityEvent  
| where EventID == 4624 and LogonType == 3  
| where TimeGenerated > ago(1h)  
| summarize SuccessfulCount = count() by AttackerIP = IpAddress, LogonType, DestinationHostName = Computer, AuthenticationSuccessTime = TimeGenerated;  

This part of the query filters the SecurityEvent table to select events with EventID 4624 (indicating a successful logon) and LogonType 3 (network logon).
It filters events that occurred within the last hour using ago(1h).
The results are summarized by counting the occurrences (SuccessfulCount) grouped by AttackerIP, LogonType, DestinationHostName, and AuthenticationSuccessTime.

Join and Projection:  
SuccessfulLogons  
| join kind = inner FailedLogons on DestinationHostName, AttackerIP, LogonType  
| project AuthenticationSuccessTime, AttackerIP, DestinationHostName, FailureCount, SuccessfulCount  

The join kind = inner in this query is performing an inner join, combining the results from SuccessfulLogons and FailedLogons only for the rows where there is a match on the specified fields. This ensures that only entries with corresponding values in all specified fields are included in the final result. The final result is projected to include the AuthenticationSuccessTime, AttackerIP, DestinationHostName, FailureCount, and SuccessfulCount.


## Architecture After Hardening / Security Controls
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
