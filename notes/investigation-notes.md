# Investigation Notes — Lab 66

## Investigation Title

**AMSI-Related Tampering Investigation**

---

## 1. Investigation Context

The objective of this investigation was to examine a Windows endpoint for evidence that AMSI-related security functionality may have been modified or interfered with.

The investigation was performed as a controlled DFIR exercise. The focus was placed on evidence collection, validation, telemetry correlation, and timeline reconstruction rather than executing a real AMSI bypass.

The investigation endpoint was:

```text
DESKTOP-9MMM37V
```

The investigation was performed using PowerShell 7.6.5 with Sysmon and Wazuh available for telemetry collection.

---

## 2. Initial System Context

Initial environment information was collected at:

```text
30 August 2026 09:38:09
```

Observed values:

```text
Hostname:
DESKTOP-9MMM37V

User:
desktop-9mmm37v\dell

PowerShell:
7.6.5

PowerShell Edition:
Core

Operating System:
Microsoft Windows 10.0.22621
```

This information establishes the system and user context for the investigation.

---

## 3. Evidence Directory

The investigation workspace was created at:

```text
C:\AMSITamperingLab
```

Directory structure:

```text
C:\AMSITamperingLab\
├── Evidence\
├── Payload\
└── Output\
```

The directory was created at approximately:

```text
30 August 2026 09:39
```

---

## 4. Baseline Collection

The baseline was collected at approximately:

```text
30 August 2026 09:40:08
```

The lab directory contents were recorded using:

```powershell
Get-ChildItem "C:\AMSITamperingLab" -Recurse -Force |
Select-Object FullName, Length, CreationTime, LastWriteTime
```

The result was saved to:

```text
C:\AMSITamperingLab\Evidence\baseline.txt
```

PowerShell execution policy information was also collected and stored in:

```text
C:\AMSITamperingLab\Evidence\execution-policy-baseline.txt
```

---

## 5. AMSI DLL Examination

The primary AMSI component examined was:

```text
C:\WINDOWS\System32\amsi.dll
```

Observed properties:

```text
Length:
114688 bytes

Creation Time:
15-05-2024 07:39:24

Last Write Time:
15-05-2024 07:39:24
```

File version:

```text
10.0.22621.3527
```

Product:

```text
Microsoft® Windows® Operating System
```

Company:

```text
Microsoft Corporation
```

The file metadata reported:

```text
Patched: False
```

---

## 6. AMSI Hash

The SHA256 hash recorded for `amsi.dll` was:

```text
744097215C1CD3B7EEC2B5161DD59020FA3D614C8DA62EC0482AA11A30F17CD9
```

This value should be treated as the investigation baseline.

A hash comparison is useful when investigating possible file replacement or modification.

However, the hash alone does not establish whether AMSI functionality was bypassed or interfered with at runtime.

---

## 7. AMSI Registry Examination

The following registry location was inspected:

```text
HKLM:\SOFTWARE\Microsoft\AMSI
```

The key existed.

Observed subkeys included:

```text
Providers
Providers2
UacProviders
```

The AMSI root key returned:

```text
FeatureBits : 1
```

The registry information was exported to:

```text
C:\AMSITamperingLab\Evidence\amsi-registry.txt
```

No evidence in the collected output demonstrated a malicious modification to an AMSI-specific registry value.

---

## 8. PowerShell Logging

PowerShell-related logs were checked during the investigation.

Available logs included:

```text
Windows PowerShell
Microsoft-Windows-PowerShell/Operational
Microsoft-Windows-PowerShell/Admin
Microsoft-Windows-PowerShell-DesiredStateConfiguration-FileDownloadManager/Operational
```

The PowerShell Operational log was enabled.

Event ID `4104` records were observed at:

```text
29-08-2026 09:25:17
27-08-2026 21:05:15
27-08-2026 20:50:18
```

These records demonstrate that Script Block Logging was providing telemetry.

The available evidence did not establish that these events represented AMSI tampering.

---

## 9. Sysmon Event ID 13

Sysmon Event ID `13` was queried to identify registry value modifications.

A significant number of events were returned, including activity around:

```text
30-08-2026 10:26
30-08-2026 10:27
30-08-2026 10:29
30-08-2026 10:32
30-08-2026 10:38
30-08-2026 10:39
```

The events were exported to:

```text
C:\AMSITamperingLab\Evidence\sysmon-registry-events.txt
```

The high volume of Event ID 13 records demonstrates that registry modifications are common on an active Windows endpoint.

Therefore, registry modification events must be filtered by:

- Target object
- Value name
- Process image
- User
- Timestamp
- Parent process
- Surrounding events

---

## 10. Wazuh Event Correlation

A Wazuh alert was examined containing Sysmon Event ID `13`.

Observed target object:

```text
HKLM\System\CurrentControlSet\Services\WpnUserService_11bbe3\ImagePath
```

User:

```text
NT AUTHORITY\SYSTEM
```

Computer:

```text
DESKTOP-9MMM37V
```

Channel:

```text
Microsoft-Windows-Sysmon/Operational
```

Event ID:

```text
13
```

UTC timestamp:

```text
2026-08-30 04:47:23.491
```

Process:

```text
C:\WINDOWS\system32\services.exe
```

Process ID:

```text
1056
```

The activity was therefore associated with Windows service management rather than directly with AMSI.

This is an important false-positive/contextual-analysis example.

---

## 11. Sysmon Event ID 1

Sysmon Event ID `1` was queried for process creation.

A large number of process creation events were observed around:

```text
30-08-2026 10:50
30-08-2026 10:51
```

The available screenshot output showed truncated event messages, so the exact process names and command lines could not be reliably extracted from that output.

Therefore, no specific process was attributed to AMSI tampering based solely on the truncated Event ID 1 listing.

---

## 12. Windows Event Log Failure

During the investigation, Windows Event Log functionality became unavailable.

The following command failed:

```powershell
Get-WinEvent -ListLog *PowerShell*
```

with:

```text
Get-WinEvent: The interface is unknown.
```

The native Windows utility also failed:

```powershell
wevtutil el
```

with:

```text
Failed to open channel enumeration.
The interface is unknown.
```

Direct event queries also failed:

```text
Failed to open event query.
The interface is unknown.
```

This occurred even when querying the System log.

Therefore, the issue was determined to be broader than the PowerShell Operational log or Event ID 4104.

---

## 13. Event Log Service Investigation

The Windows Event Log service was queried with:

```powershell
sc.exe queryex EventLog
```

Observed state:

```text
STATE : 2 START_PENDING
```

The service process was:

```text
PID : 6676
```

The process mapping confirmed:

```text
svchost.exe 6676 EventLog
```

The service was therefore present but had not completed startup.

Attempting:

```powershell
net start EventLog
```

returned:

```text
The service is starting or stopping.
Please try again later.
```

---

## 14. Event Log Service Configuration

The Event Log service configuration was inspected.

Observed configuration:

```text
START_TYPE:
AUTO_START
```

Service account:

```text
NT AUTHORITY\LocalService
```

Binary path:

```text
C:\WINDOWS\System32\svchost.exe -k LocalServiceNetworkRestricted -p
```

The service registry configuration was present.

The Event Log service DLL was:

```text
C:\WINDOWS\System32\wevtsvc.dll
```

The file existed with:

```text
Length:
1339392 bytes
```

This indicated that the primary Event Log service components were present even though the service remained stuck in `START_PENDING`.

---

## 15. Investigation Interpretation

The available evidence supports the following conclusions:

### Confirmed

- AMSI DLL identified.
- AMSI DLL baseline metadata collected.
- AMSI DLL SHA256 hash collected.
- AMSI registry location identified.
- PowerShell Operational logging was available before the Event Log issue.
- PowerShell Event ID 4104 events existed.
- Sysmon Event ID 13 telemetry was available.
- Sysmon Event ID 1 telemetry was available.
- Wazuh was receiving Sysmon telemetry.
- Windows Event Log subsequently became stuck in `START_PENDING`.

### Not Confirmed

- AMSI DLL replacement.
- AMSI DLL modification.
- Malicious AMSI registry modification.
- Successful AMSI bypass.
- Malicious PowerShell execution associated with AMSI tampering.

---

## 16. Analyst Assessment

The investigation should be classified as:

```text
AMSI Tampering:
Not conclusively established
```

The most important reason is that the available registry modification evidence did not directly identify an AMSI-related target.

The observed Wazuh Event ID 13 concerned:

```text
WpnUserService
```

and was associated with:

```text
services.exe
```

Therefore, it should not be misclassified as an AMSI tampering event.

The lab nevertheless successfully demonstrated how an analyst would validate such a hypothesis using multiple evidence sources.

---

## 17. Recommended Follow-Up

For a production investigation, the following additional evidence would be valuable:

- Full Sysmon Event ID 1 XML.
- Full Sysmon Event ID 13 XML.
- Parent process information.
- Command-line arguments.
- User/session context.
- Process hashes.
- PowerShell 4104 message contents.
- Windows Defender operational telemetry.
- Security event log correlation.
- Wazuh rule metadata.
- File integrity comparison against a known-good Windows image.

The investigation should then correlate the exact modification timestamp with process execution and subsequent script activity.
