# Troubleshooting Notes 

## 1. Issue: Get-WinEvent Returned "The interface is unknown"

### Symptom

The following command failed:

```powershell
Get-WinEvent -ListLog *PowerShell* |
Select-Object LogName, IsEnabled
```

Error:

```text
Get-WinEvent: The interface is unknown.
```

The Event ID 4104 query failed with the same error:

```powershell
Get-WinEvent -FilterHashtable @{
    LogName = "Microsoft-Windows-PowerShell/Operational"
    Id = 4104
}
```

### Initial Assessment

Because both log enumeration and specific event queries failed, the problem did not appear to be caused by the Event ID filter.

The investigation was expanded to the underlying Windows Event Log infrastructure.

---

## 2. Issue: Event Log Service Could Not Be Started Normally

The following command was attempted:

```powershell
Start-Service EventLog
```

The system returned:

```text
Service 'Windows Event Log (EventLog)' cannot be started
due to the following error:
Cannot open 'EventLog' service on computer '.'.
```

A subsequent test showed that the service was not simply stopped.

---

## 3. Issue: Native wevtutil Also Failed

To determine whether the problem was specific to PowerShell, the native Windows Event Log utility was tested.

Command:

```powershell
wevtutil el | findstr /i "PowerShell"
```

Result:

```text
Failed to open channel enumeration.
The interface is unknown.
```

A direct query against the System log also failed:

```powershell
wevtutil qe System /c:5 /f:text
```

Result:

```text
Failed to open event query.
The interface is unknown.
```

### Conclusion

Because both:

```text
Get-WinEvent
```

and:

```text
wevtutil
```

failed, the issue was considered a Windows Event Log subsystem problem rather than a PowerShell cmdlet problem.

---

## 4. Event Log Service State

The service was examined using:

```powershell
sc.exe query EventLog
```

Observed:

```text
STATE : 2 START_PENDING
```

The extended query showed:

```text
PID : 6676
```

The service-host process was confirmed with:

```powershell
tasklist /svc | findstr /i "eventlog"
```

Result:

```text
svchost.exe 6676 EventLog
```

### Interpretation

The Event Log service process existed, but the service had not completed initialization.

This explains why the Event Log API was unavailable.

---

## 5. Event Log Service Configuration

The service configuration was checked using:

```powershell
sc.exe qc EventLog
```

Observed:

```text
START_TYPE:
AUTO_START

BINARY_PATH_NAME:
C:\WINDOWS\System32\svchost.exe -k LocalServiceNetworkRestricted -p

SERVICE_START_NAME:
NT AUTHORITY\LocalService
```

The configuration appeared present and consistent with the expected Windows Event Log service structure.

---

## 6. Event Log Service DLL Verification

The service DLL was checked:

```powershell
Get-Item "$env:SystemRoot\System32\wevtsvc.dll" |
Select-Object FullName, Length, LastWriteTime
```

Observed:

```text
FullName:
C:\WINDOWS\System32\wevtsvc.dll

Length:
1339392
```

The DLL was present.

The service registry configuration also referenced:

```text
%SystemRoot%\System32\wevtsvc.dll
```

Therefore, a simple missing-DLL explanation was not supported by the collected evidence.

---

## 7. Event Log Registry Configuration

The service registry location was inspected:

```powershell
reg query "HKLM\SYSTEM\CurrentControlSet\Services\EventLog"
```

The following configuration was present:

```text
ImagePath:
%SystemRoot%\System32\svchost.exe -k LocalServiceNetworkRestricted -p

ObjectName:
NT AUTHORITY\LocalService

Start:
0x2

Type:
0x20
```

The Parameters key contained:

```text
ServiceDLL:
%SystemRoot%\System32\wevtsvc.dll

ServiceDllUnloadOnStop:
0x1

ServiceMain:
ServiceMain
```

### Interpretation

The Event Log service configuration was present even though the service remained stuck in `START_PENDING`.

---

## 8. Wazuh Was Not the Immediate Cause

The investigation initially involved Wazuh because the lab uses Wazuh for telemetry correlation.

However, the failure occurred directly on the Windows endpoint.

Both:

```text
Get-WinEvent
```

and:

```text
wevtutil
```

failed locally.

Therefore, restarting or reinstalling Wazuh would not directly resolve the Windows Event Log API failure.

The problem was treated as an endpoint telemetry infrastructure issue.

---

## 9. Important Lesson: Do Not Misclassify Sysmon Event ID 13

A large number of Sysmon Event ID 13 events were observed.

Event ID 13 means:

```text
Registry value set
```

It does not automatically mean:

```text
Malicious registry modification
```

One Wazuh event showed:

```text
Target:
HKLM\System\CurrentControlSet\Services\WpnUserService_11bbe3\ImagePath

User:
NT AUTHORITY\SYSTEM

Process:
C:\WINDOWS\system32\services.exe
```

This activity is not evidence of AMSI tampering by itself.

### Correct investigative approach

```text
Event ID 13
     |
     v
Identify target registry key
     |
     v
Identify value
     |
     v
Identify process
     |
     v
Identify user
     |
     v
Check timestamp
     |
     v
Correlate surrounding activity
     |
     v
Determine whether the change is suspicious
```

---

## 10. PowerShell 4104 Interpretation

Event ID `4104` was observed in the PowerShell Operational log.

The existence of Event ID 4104 proves that Script Block Logging was producing events.

It does not automatically prove:

```text
AMSI bypass
```

The actual Script Block message must be examined to determine whether the script contains suspicious behavior.

---

## 11. AMSI DLL Integrity Interpretation

The AMSI DLL was hashed:

```text
744097215C1CD3B7EEC2B5161DD59020FA3D614C8DA62EC0482AA11A30F17CD9
```

The file reported:

```text
Patched: False
```

This is useful baseline evidence.

However, file integrity alone cannot establish that AMSI was never interfered with at runtime.

An AMSI investigation therefore requires correlation with:

- Process activity
- Memory-related evidence where available
- PowerShell telemetry
- Registry changes
- Security product telemetry
- File integrity

---

## 12. Recommended Recovery Path

Because the Event Log service was stuck in:

```text
START_PENDING
```

the safest immediate troubleshooting step was a normal Windows restart rather than manually terminating the Event Log `svchost.exe` process.

The intended validation after restart is:

```powershell
sc.exe query EventLog
```

Expected healthy state:

```text
STATE : 4 RUNNING
```

Then test:

```powershell
Get-WinEvent -LogName System -MaxEvents 1
```

and:

```powershell
wevtutil qe System /c:5 /f:text
```

If these succeed, the Event Log subsystem has recovered.

---

