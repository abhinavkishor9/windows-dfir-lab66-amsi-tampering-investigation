# Timeline 

## 30 August 2026

### 09:38:09 — Investigation Environment Verified

Initial environment information was collected.

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

This established the endpoint and execution context.

---

### 09:39 — Investigation Workspace Created

The investigation directory was created:

```text
C:\AMSITamperingLab
```

Subdirectories:

```text
C:\AMSITamperingLab\Evidence
C:\AMSITamperingLab\Payload
C:\AMSITamperingLab\Output
```

The directory structure separated evidence, benign laboratory material, and generated output.

---

### 09:40:08 — Baseline Collection

The initial investigation baseline was collected.

The lab directory contents were recorded and saved to:

```text
C:\AMSITamperingLab\Evidence\baseline.txt
```

PowerShell execution policy information was also collected and stored in:

```text
C:\AMSITamperingLab\Evidence\execution-policy-baseline.txt
```

---

### AMSI DLL Baseline — Investigation Phase

The following file was examined:

```text
C:\WINDOWS\System32\amsi.dll
```

Observed:

```text
File Size:
114688 bytes

Creation Time:
15-05-2024 07:39:24

Last Write Time:
15-05-2024 07:39:24

File Version:
10.0.22621.3527

Company:
Microsoft Corporation
```

SHA256:

```text
744097215C1CD3B7EEC2B5161DD59020FA3D614C8DA62EC0482AA11A30F17CD9
```

This established the AMSI file integrity baseline.

---

### AMSI Registry Baseline — Investigation Phase

The following registry location was examined:

```text
HKLM\SOFTWARE\Microsoft\AMSI
```

Observed subkeys:

```text
Providers
Providers2
UacProviders
```

Observed root value:

```text
FeatureBits : 1
```

The registry information was saved to:

```text
C:\AMSITamperingLab\Evidence\amsi-registry.txt
```

---

### PowerShell Telemetry Review — Investigation Phase

PowerShell Operational logging was confirmed to be enabled.

Event ID `4104` records were observed at:

```text
29-08-2026 09:25:17
27-08-2026 21:05:15
27-08-2026 20:50:18
```

These events provided historical PowerShell Script Block Logging telemetry.

---

### 10:26:31 — Sysmon Registry Activity Observed

Multiple Sysmon Event ID `13` records were observed around:

```text
30-08-2026 10:26:31
```

These events represented registry value modifications.

The high volume required contextual analysis rather than automatic classification as malicious.

---

### 10:27:35 — Additional Registry Activity

Multiple Sysmon Event ID `13` events were observed around:

```text
30-08-2026 10:27:35
```

The events were retained for investigation and later exported.

---

### 10:29:15 — Additional Registry Activity

Multiple Sysmon Event ID `13` events were observed around:

```text
30-08-2026 10:29:15
```

The repeated registry activity reinforced the importance of identifying the exact registry target and initiating process.

---

### 10:29:50 — Registry Activity

Another Sysmon Event ID `13` record was observed around:

```text
30-08-2026 10:29:50
```

---

### 10:32:23 — Burst of Registry Modifications

Multiple Sysmon Event ID `13` records were observed at:

```text
30-08-2026 10:32:23
```

These were collected as part of the registry activity evidence.

---

### 10:38:57 — Registry Modification

A Sysmon Event ID `13` record was observed around:

```text
30-08-2026 10:38:57
```

---

### 10:39:02 — Registry Modification

Another Sysmon Event ID `13` record was observed around:

```text
30-08-2026 10:39:02
```

The Event ID 13 output was saved to:

```text
C:\AMSITamperingLab\Evidence\sysmon-registry-events.txt
```

---

### 10:50:01–10:51:50 — Process Creation Activity

A large number of Sysmon Event ID `1` records were observed between approximately:

```text
10:50:01
```

and:

```text
10:51:50
```

These events represented process creation activity.

The screenshot output contained truncated event messages, so the exact process names and command lines were not used as definitive evidence.

---

### 04:47:23.491 UTC — Wazuh Sysmon Event Correlation

Wazuh recorded a Sysmon Event ID `13` event with the following UTC timestamp:

```text
2026-08-30 04:47:23.491
```

Target object:

```text
HKLM\System\CurrentControlSet\Services\WpnUserService_11bbe3\ImagePath
```

User:

```text
NT AUTHORITY\SYSTEM
```

Process:

```text
C:\WINDOWS\system32\services.exe
```

Process ID:

```text
1056
```

This event was assessed as registry activity associated with Windows service management and **not confirmed AMSI tampering**.

---

## Event Log Troubleshooting Phase

### Investigation Phase — Get-WinEvent Failure

The following PowerShell query failed:

```powershell
Get-WinEvent -ListLog *PowerShell*
```

Error:

```text
The interface is unknown.
```

The specific Event ID 4104 query also failed.

---

### Investigation Phase — wevtutil Failure

The native Windows Event Log utility was tested:

```powershell
wevtutil el
```

Result:

```text
Failed to open channel enumeration.
The interface is unknown.
```

Direct event queries also failed.

This established that the issue was broader than the PowerShell cmdlet.

---

### Investigation Phase — Event Log Service Identified as START_PENDING

The Event Log service was queried:

```powershell
sc.exe queryex EventLog
```

Observed:

```text
STATE : 2 START_PENDING
PID   : 6676
```

The service-host process was confirmed:

```text
svchost.exe 6676 EventLog
```

---

### Investigation Phase — Event Log Service Configuration Checked

The Event Log service configuration was inspected.

Observed:

```text
Start Type:
AUTO_START

Service Account:
NT AUTHORITY\LocalService

Binary:
C:\WINDOWS\System32\svchost.exe -k LocalServiceNetworkRestricted -p
```

The Event Log service DLL was confirmed to exist:

```text
C:\WINDOWS\System32\wevtsvc.dll
```

---

