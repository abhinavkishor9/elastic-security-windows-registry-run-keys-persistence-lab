# Investigation Notes — Windows Persistence: Registry Run Keys

## Investigation Summary

This investigation examined Windows Registry Run Key persistence on `DESKTOP-9MMM37V`.

The investigation began with a baseline review of existing startup entries under the current user's Run Key. A controlled value named `ElasticLab05` was then created to launch `C:\Windows\System32\notepad.exe`.

Elastic Registry telemetry and process telemetry were subsequently reviewed to determine whether the persistence configuration and related execution could be observed.

## Baseline Registry Review

The following command was used:

```powershell
Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
```

Existing entries included:

```text
Adobe Acrobat Synchronizer
MicrosoftEdgeAutoLaunch_*
OneDrive
Mozilla-Firefox-*
MEmuSVC
MicrosoftCopilotAutoLaunch_*
```

An existing value named:

```text
SOCLab
```

was also present with:

```text
notepad.exe
```

This baseline was important because it demonstrated that the endpoint already contained multiple legitimate startup entries.

## Controlled Run Key Creation

The controlled value was created using:

```powershell
New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "ElasticLab05" -Value "C:\Windows\System32\notepad.exe" -PropertyType String -Force
```

The resulting value was:

```text
ElasticLab05 : C:\Windows\System32\notepad.exe
```

## Local Validation

The value was verified with:

```powershell
Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "ElasticLab05"
```

PowerShell confirmed:

```text
ElasticLab05 : C:\Windows\System32\notepad.exe
```

The Registry location was:

```text
HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run
```

## Registry Telemetry Query

The initial useful Elastic query was:

```esql
FROM logs-*
| WHERE registry.key LIKE "*CurrentVersion*Run*"
| KEEP @timestamp, host.name, user.name, registry.key, registry.value, registry.data.strings
| SORT @timestamp DESC
```

This returned multiple Run Key events.

The controlled event appeared at:

```text
Sep 24, 2026 @ 06:55:34.324
```

Observed fields included:

```text
Host: desktop-9mmm37v
User: Dell
Registry Value: ElasticLab05
Registry Data: C:\Windows\System32\notepad.exe
```

## Focused Registry Query

A second query focused specifically on the test value:

```esql
FROM logs-*
| WHERE registry.value LIKE "*ElasticLab05*"
| KEEP @timestamp, host.name, user.name, registry.key, registry.value, registry.data.strings
| SORT @timestamp DESC
```

This returned the controlled Registry event.

This was stronger evidence than relying only on the local PowerShell output because the Elastic event independently showed the Registry modification in endpoint telemetry.

## Process Investigation

The following query was used:

```esql
FROM logs-*
| WHERE process.name == "notepad.exe"
| KEEP @timestamp, host.name, user.name, process.pid, process.parent.name, process.parent.pid, process.command_line, process.executable
| SORT @timestamp DESC
```

Observed event:

```text
Timestamp: Sep 24, 2026 @ 07:04:26.882
Host: desktop-9mmm37v
User: Dell
PID: 13988
Parent: explorer.exe
Parent PID: 21680
Command Line: "C:\Windows\System32\notepad.exe"
Executable: C:\Windows\System32\notepad.exe
```

## Process Context

The observed process relationship was:

```text
explorer.exe
    |
    +-- notepad.exe
```

The process executed as:

```text
Dell
```

and from:

```text
C:\Windows\System32\notepad.exe
```

## Persistence Correlation

The available evidence establishes the following sequence:

```text
06:55:34
ElasticLab05 Run Key observed
        |
        v
C:\Windows\System32\notepad.exe
        |
        v
07:04:26
notepad.exe observed
```

The timestamps provide useful correlation.

However, the available telemetry does not contain a direct field stating that the Run Key caused the specific Notepad process event. Therefore, the investigation records the relationship as **consistent with the intended persistence simulation**, rather than claiming direct causal proof.

## File Validation

The executable was checked locally using:

```powershell
Get-Item "C:\Windows\System32\notepad.exe"
```

Observed:

```text
Directory: C:\Windows\System32
Name: notepad.exe
Length: 360448
```

This confirmed that the referenced executable existed at the expected Windows path.

## Message Field Investigation

The following query was tested:

```esql
FROM logs-*
| WHERE message LIKE "*ElasticLab05*"
| KEEP @timestamp, host.name, user.name, message
| SORT @timestamp DESC
```

Result:

```text
No results match your search criteria
```

This did not contradict the Registry telemetry.

The structured Registry fields successfully returned the expected event.

## Remediation

The controlled value was removed using:

```powershell
Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "ElasticLab05"
```

The Run Key was then inspected again.

The controlled value was also recreated later during the investigation to validate the Registry telemetry again.

## Analyst Assessment

### Observed

- Existing Run Key entries were present.
- `ElasticLab05` was created under the user's Run Key.
- Elastic captured the Registry value.
- The value pointed to `C:\Windows\System32\notepad.exe`.
- `notepad.exe` executed as user `Dell`.
- `explorer.exe` was reported as the Notepad parent.
- The executable path was `C:\Windows\System32\notepad.exe`.
- The generic `message` field did not contain the controlled value in the queried events.

### Confirmed

- The controlled Run Key existed locally.
- Elastic captured the Registry modification.
- The referenced executable existed.
- A Notepad process event was captured.
- The controlled Registry value was removed during remediation.

### Unknown

- Whether the specific `notepad.exe` event was directly triggered by Windows processing `ElasticLab05`.
- Why the generic `message` search did not return the Registry event.

## Malicious Activity Assessment

The controlled activity does not demonstrate malicious persistence.

The test value intentionally referenced a legitimate Windows executable and was created for the purpose of this lab.

No evidence was demonstrated for:

- Malware execution
- Credential access
- Privilege escalation
- Command-and-control
- Defense evasion
- Confirmed compromise

## MITRE ATT&CK

### T1547.001 — Registry Run Keys / Startup Folder

The lab demonstrates a Run Key persistence mechanism by creating a user-level Registry value that references an executable.

## Conclusion

This investigation demonstrated that Elastic can expose Registry Run Key modifications through structured Registry telemetry and that process telemetry can provide additional context about the referenced executable.

The most important analytical lesson is to correlate the Registry artifact with process execution while clearly distinguishing correlation from direct causal proof.
