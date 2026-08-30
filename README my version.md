# windows-dfir-lab66-amsi-tampering-investigation
## Overview

AMSI (Antimalware Scan Interface) is a Windows security interface that allows applications such as PowerShell and other scripting components to submit content for inspection by an antimalware provider.

From an investigation perspective, AMSI tampering is important because an attacker may attempt to interfere with security inspection before executing suspicious scripts. The analyst therefore should not only ask “Was a suspicious script executed?”, but also:

- Was AMSI-related configuration or functionality modified?
- When did the modification occur?
- Which process or user was responsible?
- Was PowerShell activity observed around the same time?
- Did Sysmon or Wazuh record supporting activity?
- Is there evidence that the tampering actually affected subsequent execution?

This lab focuses on the defensive investigation of potential **Antimalware Scan Interface (AMSI)** tampering on a Windows endpoint.

AMSI is an important Windows security interface that allows applications and scripting environments such as PowerShell to submit content for inspection by antimalware providers. From a SOC and DFIR perspective, attempts to interfere with AMSI are important because they may indicate an effort to weaken security inspection before suspicious script execution.

The investigation therefore focuses on establishing a reliable baseline, examining AMSI-related components and configuration, reviewing PowerShell and Sysmon telemetry, correlating activity with Wazuh, and reconstructing the available timeline.

The lab was intentionally performed as a **benign and controlled investigation**. No real malware or operational AMSI bypass payload was deployed.

---

## Lab Objectives

- Understand the role of AMSI in Windows script and PowerShell security.
- Establish a baseline for amsi.dll, including file metadata, version information, and SHA256 hash.
- Examine AMSI-related registry configuration for potential changes.
- Review PowerShell Event ID 4104 for script-block activity.
- Analyze Sysmon Event ID 1 for process creation activity.
- Analyze Sysmon Event ID 13 for registry modifications.
- Correlate endpoint activity across PowerShell, Sysmon, and Wazuh.
- Investigate whether observed registry modifications are actually related to AMSI or legitimate Windows services.
- Identify the impact of the Windows Event Log service remaining in START_PENDING on forensic telemetry collection.
- Document troubleshooting steps and evidence limitations encountered during the investigation.
- Build an evidence-based conclusion distinguishing confirmed findings, supporting evidence, and inconclusive observations.

---

## Environment

| Component | Details |
|---|---|
| Hostname | `DESKTOP-9MMM37V` |
| User | `DESKTOP-9MMM37V\dell` |
| Operating System | Windows 10.0.22621 |
| PowerShell | 7.6.5 |
| PowerShell Edition | Core |
| Wazuh Agent | Windows endpoint agent |
| Sysmon | Installed and generating telemetry |
| Investigation Directory | `C:\AMSITamperingLab` |

---

## Investigation Structure

```text
C:\AMSITamperingLab\
├── Evidence\
├── Payload\
└── Output\
```

### Evidence

Contains collected investigation data such as:

- Baseline information
- Execution policy baseline
- AMSI registry information
- Sysmon registry events
- Evidence hashes
- Other forensic notes

### Payload

Reserved for benign laboratory test material.

### Output

Reserved for generated investigation results.

---

## Investigation Workflow

```text
Environment Verification
        |
        v
Lab Directory Creation
        |
        v
Baseline Collection
        |
        v
AMSI DLL Identification
        |
        v
AMSI Registry Inspection
        |
        v
PowerShell Telemetry Review
        |
        v
Sysmon Telemetry Review
        |
        v
Wazuh Correlation
        |
        v
Event Log Troubleshooting
        |
        v
Timeline Reconstruction
        |
        v
Evidence-Based Assessment
```

---

## AMSI Baseline

The investigation identified:

```text
C:\WINDOWS\System32\amsi.dll
```

Observed baseline:

```text
File Version:    10.0.22621.3527
Product Version: 10.0.22621.3527
Company:         Microsoft Corporation
File Size:       114688 bytes
```

SHA256:

```text
744097215C1CD3B7EEC2B5161DD59020FA3D614C8DA62EC0482AA11A30F17CD9
```

The file metadata and hash were recorded to provide an integrity reference for subsequent investigation.

---

## AMSI Registry Baseline

The following registry location was examined:

```text
HKLM\SOFTWARE\Microsoft\AMSI
```

The key existed and contained:

```text
Providers
Providers2
UacProviders
```

The AMSI root key reported:

```text
FeatureBits : 1
```

The registry information was saved to:

```text
C:\AMSITamperingLab\Evidence\amsi-registry.txt
```

The existence or absence of a particular AMSI registry value was not treated as proof of malicious activity by itself.

---

## PowerShell Telemetry

PowerShell-related event logs were available, including:

```text
Windows PowerShell
Microsoft-Windows-PowerShell/Operational
Microsoft-Windows-PowerShell/Admin
```

PowerShell Script Block Logging Event ID `4104` was observed.

Examples of observed timestamps included:

```text
29-08-2026 09:25:17
27-08-2026 21:05:15
27-08-2026 20:50:18
```

These events provide useful context for investigating script execution around a suspected security-control modification.

---

## Sysmon Telemetry

Two Sysmon event types were reviewed extensively.

### Event ID 1 — Process Creation

Event ID 1 was used to review process creation activity and identify processes that could potentially be associated with configuration changes or PowerShell activity.

A large number of recent Event ID 1 records were observed during the investigation.

### Event ID 13 — Registry Value Set

Event ID 13 was used to identify registry value modifications.

Numerous Event ID 13 events were observed.

However, the presence of Event ID 13 alone does **not** establish AMSI tampering.

One Wazuh-correlated example involved:

```text
HKLM\System\CurrentControlSet\Services\WpnUserService_11bbe3\ImagePath
```

The associated process was:

```text
C:\WINDOWS\system32\services.exe
```

The user context was:

```text
NT AUTHORITY\SYSTEM
```

This event was therefore treated as **registry activity requiring contextual analysis**, rather than as confirmed AMSI tampering.

---

## Wazuh Correlation

Wazuh was used as the centralized monitoring and correlation layer.

The endpoint information observed during the investigation identified:

```text
Computer: DESKTOP-9MMM37V
Channel:  Microsoft-Windows-Sysmon/Operational
Event ID: 13
```

Wazuh provided useful visibility into Windows Sysmon events and exposed individual event fields such as:

- Target object
- User
- UTC timestamp
- Computer
- Event ID
- Process image
- Process ID
- Process GUID
- Rule information

This demonstrated the value of correlating local Windows evidence with SIEM telemetry.

---

## Windows Event Log Troubleshooting

During the investigation, Windows Event Log functionality became unavailable.

Both PowerShell and the native Windows Event Log utility returned:

```text
The interface is unknown.
```

Examples included failures from:

```powershell
Get-WinEvent
```

and:

```powershell
wevtutil
```

Investigation showed that the Windows Event Log service was stuck in:

```text
START_PENDING
```

The service process was:

```text
svchost.exe
PID 6676
```

The Event Log service configuration remained present and pointed to:

```text
C:\WINDOWS\System32\svchost.exe -k LocalServiceNetworkRestricted -p
```

The Event Log service DLL was also present:

```text
C:\WINDOWS\System32\wevtsvc.dll
```

Because the Event Log service had not completed initialization, both `Get-WinEvent` and `wevtutil` were unable to access event channels.

This became an important troubleshooting finding because Windows telemetry collection depends on the underlying Event Log infrastructure.

---

## Key Findings

### Finding 1 — AMSI DLL baseline established

`amsi.dll` was identified and its metadata and SHA256 hash were recorded.

No evidence provided in this investigation demonstrated that the file itself had been replaced or modified.

### Finding 2 — AMSI registry configuration was present

The AMSI registry location existed and contained provider-related subkeys.

No direct evidence was provided showing a malicious modification to an AMSI-specific registry value.

### Finding 3 — PowerShell telemetry was available

PowerShell Operational logging was enabled and Event ID `4104` events were observed.

This provides useful telemetry for future correlation between PowerShell execution and security-control modifications.

### Finding 4 — Sysmon registry telemetry was active

Sysmon Event ID `13` generated registry modification telemetry.

However, the observed Wazuh example concerned `WpnUserService`, not AMSI.

Therefore, it should not be classified as confirmed AMSI tampering.

### Finding 5 — Windows Event Log experienced an availability issue

The Windows Event Log service was observed in `START_PENDING`, causing:

```text
Get-WinEvent
wevtutil
```

to fail with:

```text
The interface is unknown.
```

This was a significant telemetry availability issue encountered during the lab.

---

## Final Assessment

**AMSI tampering was not conclusively established from the collected evidence.**

The investigation successfully demonstrated the methodology required to investigate such a scenario:

```text
Baseline
    +
File Integrity
    +
Registry State
    +
PowerShell Telemetry
    +
Sysmon Telemetry
    +
Wazuh Correlation
    +
Timeline
    =
Evidence-Based Assessment
```

The investigation also demonstrated an important SOC principle:

> A suspicious-looking event should not automatically be classified as malicious without validating the affected object, initiating process, user context, timestamp, and surrounding activity.

---


## MITRE ATT&CK Relevance

Potentially relevant ATT&CK areas include:

- **T1059.001 — PowerShell**
- **T1112 — Modify Registry**
- **T1562.001 — Impair Defenses: Disable or Modify Tools**

These techniques represent investigative context only. The lab does not claim that any of these techniques were successfully performed maliciously.

---

