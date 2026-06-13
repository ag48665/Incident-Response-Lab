# Threat Hunting Lab

## Overview

This project demonstrates proactive threat hunting using Splunk Enterprise and Sysmon telemetry.

The goal is to identify suspicious activity, investigate potential threats, and validate findings using real Windows event logs collected from a monitored endpoint.

---

## Environment

| Component           | Details                |
| ------------------- | ---------------------- |
| SIEM                | Splunk Enterprise 10.4 |
| Endpoint Monitoring | Sysmon                 |
| Operating System    | Windows 11             |
| Framework           | MITRE ATT&CK           |

---

# Hunting Scenarios

## 1. PowerShell Execution Hunt

### Objective

Identify PowerShell execution activity that may indicate malicious scripting or attacker behavior.

### SPL Query

```spl
index=* sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
| search "powershell.exe"
```

### Findings

PowerShell process execution events were successfully identified within Sysmon logs.

### Evidence

![PowerShell Hunt](screenshots/powershell_hunt.png)

---

## 2. Command Shell Hunt (T1059.003)

### Objective

Detect command prompt activity that could be associated with attacker execution techniques.

### SPL Query

```spl
index=* sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
| search "cmd.exe"
```

### Findings

Command Prompt execution events were identified and reviewed.

### Evidence

![CMD Hunt](screenshots/cmd_hunt.png)

---

## 3. Account Discovery Hunt (T1087)

### Objective

Detect account enumeration activity commonly used during reconnaissance.

### SPL Query

```spl
index=* sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
("whoami.exe" OR "net.exe")
```

### Findings

Account discovery activity was detected through execution of native Windows utilities.

### Evidence

![Account Discovery Hunt](screenshots/account_discovery_hunt.png)

---

## 4. Network Connection Hunt (Sysmon Event ID 3)

### Objective

Identify outbound network connections initiated by processes on the endpoint.

### SPL Query

```spl
index=* sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
| search "<EventID>3</EventID>"
```

### Findings

Network connection events were successfully identified and analyzed.

### Evidence

![Network Connection Hunt](screenshots/network_connections_hunt.png)

---

## 5. File Creation Hunt (T1105)

### Objective

Identify file creation events that could indicate payload staging or malware delivery.

### SPL Query

```spl
index=* sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
| search "<EventID>11</EventID>"
```

### Findings

File creation activity was detected using Sysmon Event ID 11.

### Evidence

![File Creation Hunt](screenshots/t1105_file_creation_hunt.png)

---

# MITRE ATT&CK Mapping

| Technique ID | Technique                            |
| ------------ | ------------------------------------ |
| T1059.001    | PowerShell                           |
| T1059.003    | Windows Command Shell                |
| T1087        | Account Discovery                    |
| T1049        | System Network Connections Discovery |
| T1105        | Ingress Tool Transfer                |

---

# Skills Demonstrated

* Threat Hunting
* Splunk SPL
* Sysmon Analysis
* Windows Log Analysis
* MITRE ATT&CK Mapping
* Security Monitoring
* Detection Engineering
* Incident Investigation
* Threat Analysis

---

# Author

**Agata Gabara**

Cybersecurity Analyst | SOC Analyst | Threat Hunter

GitHub: https://github.com/ag48665
