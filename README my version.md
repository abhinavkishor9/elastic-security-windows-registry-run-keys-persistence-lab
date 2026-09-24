# elastic-security-windows-registry-run-keys-persistence-lab
## Overview
Windows provides Registry locations that can cause programs to start automatically when a user logs on. One common persistence mechanism is the Run Key.

Common locations include:

HKCU\Software\Microsoft\Windows\CurrentVersion\Run

and:

HKLM\Software\Microsoft\Windows\CurrentVersion\Run

A Run Key entry is not automatically malicious. Legitimate software can use these locations for startup functionality. The SOC investigation should therefore examine:

Registry Key
    ↓
Value Name
    ↓
Value Data
    ↓
User Context
    ↓
Referenced File
    ↓
File Location
    ↓
Process Execution


This lab investigates **Windows Registry Run Key persistence** using Elastic Security and Elastic Defend.

Registry Run Keys can be used by legitimate applications to start programs automatically when a user logs on. The same mechanism can also be abused for persistence. Therefore, the existence of a Run Key should not automatically be treated as malicious.

The investigation focuses on identifying Registry Run Key entries, determining what executable they reference, validating the associated Registry telemetry, and correlating the persistence configuration with endpoint process activity.

A controlled Run Key named `ElasticLab05` was created under the current user's Run Key location and configured to launch `notepad.exe`.

## Lab Environment

| Component | Details |
|---|---|
| Endpoint | Windows 10 Pro 22H2 |
| Host | `DESKTOP-9MMM37V` |
| User | `Dell` |
| Elastic Platform | Elastic Security Serverless |
| Endpoint Integration | Elastic Defend |
| Elastic Agent | `9.5.4` |
| Agent Policy | `Windows-SOC-Lab` |
| Investigation Interface | Discover / ES|QL |
| Shell | PowerShell 7.6.6 |

## Lab Objectives

The objectives of this lab are to:

- Understand how **Windows Registry Run Keys** can be used to establish application startup persistence.
- Identify and document existing entries under the user-level and system-level `CurrentVersion\Run` Registry locations.
- Establish a baseline of legitimate startup applications before introducing controlled lab activity.
- Create a temporary and reversible Run Key entry for `ElasticLab05`.
- Validate the Registry value and confirm the executable configured for startup.
- Identify Registry modification telemetry in Elastic using structured Registry fields.
- Investigate the relationship between a Run Key entry and related process execution.
- Correlate Registry evidence with process name, parent process, user context, executable path, and timestamps.
- Distinguish controlled persistence activity from pre-existing legitimate startup configuration.
- Investigate differences between structured Registry telemetry and generic message-field searches.
- Document situations where telemetry provides correlation but does not directly prove causation.
- Practice evidence-driven analysis of Windows persistence without automatically classifying every Run Key as malicious.
- Remove the controlled persistence entry and validate the remediation.
- Identify relevant MITRE ATT&CK coverage for Registry Run Key persistence.
- Document observed evidence, confirmed findings, unknowns, and telemetry limitations.

## Lab Scenario

A SOC analyst is investigating a Windows endpoint for signs of **persistence through Registry Run Keys**. The analyst first reviews the existing startup configuration to understand what applications are already configured to run automatically and to establish a baseline before introducing controlled activity.

During the investigation, a temporary user-level Run Key named `ElasticLab05` is created under:

```text
HKCU\Software\Microsoft\Windows\CurrentVersion\Run
```

The value is configured to launch:

```text
C:\Windows\System32\notepad.exe
```

The analyst then uses Elastic telemetry to determine whether the Registry modification is visible and whether the referenced executable can be correlated with subsequent process activity.

The investigation focuses on:

- Identifying the Run Key modification and its value data
- Validating the referenced executable and its location
- Correlating Registry telemetry with `notepad.exe` process activity
- Reviewing the process parent, user, timestamp, and command line
- Distinguishing the controlled persistence entry from existing startup entries
- Identifying limitations when different telemetry fields produce different results

The activity is intentionally benign and reversible. The test Registry value is removed after the investigation and can be recreated for telemetry validation.

The scenario is designed to demonstrate how a SOC analyst investigates a persistence artifact from **Registry modification to process activity**, while clearly separating observed evidence, correlation, and assumptions.

## Existing Run Key Baseline

The initial local inspection showed multiple existing entries, including:

```text
Adobe Acrobat Synchronizer
MicrosoftEdgeAutoLaunch_*
OneDrive
Mozilla-Firefox-*
MemuSVC
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

These entries demonstrate that Run Keys can contain legitimate startup configuration and that the presence of a startup entry alone is not sufficient to establish malicious persistence.

## Controlled Persistence Entry

The controlled entry was created with:

```powershell
New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "ElasticLab05" -Value "C:\Windows\System32\notepad.exe" -PropertyType String -Force
```

The resulting value was verified locally:

```powershell
Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "ElasticLab05"
```

Observed value:

```text
ElasticLab05 : C:\Windows\System32\notepad.exe
```

## Registry Telemetry

The following ES|QL query successfully identified Run Key activity:

```esql
FROM logs-*
| WHERE registry.key LIKE "*CurrentVersion*Run*"
| KEEP @timestamp, host.name, user.name, registry.key, registry.value, registry.data.strings
| SORT @timestamp DESC
```

An observed event for the controlled value was recorded at:

```text
Sep 24, 2026 @ 06:55:34.324
```

The Registry value was:

```text
ElasticLab05
```

and the associated data was:

```text
C:\Windows\System32\notepad.exe
```

## Focused Registry Hunt

The controlled value was also identified directly with:

```esql
FROM logs-*
| WHERE registry.value LIKE "*ElasticLab05*"
| KEEP @timestamp, host.name, user.name, registry.key, registry.value, registry.data.strings
| SORT @timestamp DESC
```

This returned the controlled Registry event.

The event showed:

```text
Host: desktop-9mmm37v
User: Dell
Value: ElasticLab05
Data: C:\Windows\System32\notepad.exe
```

## Process Correlation

A process search for `notepad.exe` returned:

```esql
FROM logs-*
| WHERE process.name == "notepad.exe"
| KEEP @timestamp, host.name, user.name, process.pid, process.parent.name, process.parent.pid, process.command_line, process.executable
| SORT @timestamp DESC
```

Observed event:

```text
Sep 24, 2026 @ 07:04:26.882
```

The event showed:

```text
Host: desktop-9mmm37v
User: Dell
PID: 13988
Parent: explorer.exe
Parent PID: 21680
Command Line: "C:\Windows\System32\notepad.exe"
Executable: C:\Windows\System32\notepad.exe
```

This provides process-level evidence for `notepad.exe` execution after the controlled Run Key was created.

The timing and execution context are consistent with startup-related execution, but the available telemetry does not independently prove that the Run Key was the direct cause of this particular process event.

## Telemetry Limitation

The following search returned no results:

```esql
FROM logs-*
| WHERE message LIKE "*ElasticLab05*"
| KEEP @timestamp, host.name, user.name, message
| SORT @timestamp DESC
```

This did not indicate that the Registry change failed.

The dedicated Registry fields successfully exposed the modification, demonstrating that the appropriate Registry telemetry was available through structured fields.

## Remediation

The controlled entry was removed with:

```powershell
Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "ElasticLab05"
```

The Run Key was subsequently inspected again.

The controlled entry was also recreated during the investigation for additional telemetry validation.

## Key Findings

### Observed

- Multiple existing Run Key entries were present on the endpoint.
- A controlled value named `ElasticLab05` was created.
- Elastic captured the controlled Registry modification.
- The value data pointed to `C:\Windows\System32\notepad.exe`.
- `notepad.exe` execution was observed at `07:04:26.882`.
- The observed Notepad process ran as user `Dell`.
- The observed Notepad parent process was `explorer.exe`.
- The executable path was `C:\Windows\System32\notepad.exe`.

### Confirmed

- The controlled Run Key existed locally.
- Elastic captured the corresponding Registry value.
- The referenced executable was validated locally.
- A corresponding `notepad.exe` process event was observed.
- The test persistence entry was removed during remediation.

### Not Demonstrated

- Malicious persistence
- Malware execution
- Credential theft
- Privilege escalation
- Command-and-control
- Confirmed compromise

## MITRE ATT&CK

### T1547.001 — Registry Run Keys / Startup Folder

The controlled activity demonstrates the use of a Windows Registry Run Key to configure an executable for startup.

The technique mapping describes the persistence mechanism demonstrated by the lab and does not indicate that the controlled activity itself was malicious.

