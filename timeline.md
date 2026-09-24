# Timeline — Windows Persistence: Registry Run Keys

## Investigation Timeline

| Time | Activity | Evidence | Assessment |
|---|---|---|---|
| Initial review | Existing HKCU Run Key enumeration | Multiple legitimate application startup entries observed | Baseline established |
| Initial review | Existing `SOCLab` entry | `SOCLab : notepad.exe` | Existing startup configuration |
| 06:55:34.324 | Controlled `ElasticLab05` Registry event | Run Key value pointed to `C:\Windows\System32\notepad.exe` | Controlled persistence artifact observed |
| 07:04:26.882 | `notepad.exe` process event | Parent `explorer.exe`, user `Dell`, executable `C:\Windows\System32\notepad.exe` | Process execution observed |
| Investigation | Generic `message` search | No matching `ElasticLab05` event | Structured Registry fields preferred |
| Remediation | `ElasticLab05` removed | `Remove-ItemProperty` executed | Controlled persistence removed |
| Later validation | `ElasticLab05` recreated | Registry value restored for additional telemetry validation | Controlled persistence recreated |

## Initial Baseline

The endpoint contained multiple existing Run Key entries, including:

```text
Adobe Acrobat Synchronizer
MicrosoftEdgeAutoLaunch_*
OneDrive
Mozilla-Firefox-*
MicrosoftCopilotAutoLaunch_*
```

An existing entry named:

```text
SOCLab
```

also referenced:

```text
notepad.exe
```

This baseline was important for distinguishing pre-existing startup configuration from the controlled test artifact.

## 06:55:34.324 — Controlled Registry Event

Elastic recorded the controlled Registry value:

```text
ElasticLab05
```

under the user's Run Key.

Observed value data:

```text
C:\Windows\System32\notepad.exe
```

Observed context:

```text
Host: desktop-9mmm37v
User: Dell
```

The event was identified using:

```esql
FROM logs-*
| WHERE registry.key LIKE "*CurrentVersion*Run*"
| KEEP @timestamp, host.name, user.name, registry.key, registry.value, registry.data.strings
| SORT @timestamp DESC
```

## Registry-Specific Validation

A focused query confirmed the controlled value:

```esql
FROM logs-*
| WHERE registry.value LIKE "*ElasticLab05*"
| KEEP @timestamp, host.name, user.name, registry.key, registry.value, registry.data.strings
| SORT @timestamp DESC
```

Observed:

```text
ElasticLab05
C:\Windows\System32\notepad.exe
```

## 07:04:26.882 — Notepad Process Event

Elastic recorded:

```text
Process: notepad.exe
PID: 13988
Parent: explorer.exe
Parent PID: 21680
User: Dell
Command Line: "C:\Windows\System32\notepad.exe"
Executable: C:\Windows\System32\notepad.exe
```

The observed process relationship was:

```text
explorer.exe
    |
    +-- notepad.exe
```

The event occurred after the controlled Run Key modification.

## Persistence Correlation

The available evidence can be represented as:

```text
06:55:34
ElasticLab05 Run Key
        |
        +-- C:\Windows\System32\notepad.exe
        |
        v
07:04:26
notepad.exe observed
        |
        +-- Parent: explorer.exe
        +-- User: Dell
```

The sequence is consistent with the persistence simulation.

However, the process telemetry did not directly state that `ElasticLab05` caused the particular Notepad event. The timeline therefore records the relationship as **correlated activity**, not direct causal proof.

## Generic Message Search

The following query returned no results:

```esql
FROM logs-*
| WHERE message LIKE "*ElasticLab05*"
| KEEP @timestamp, host.name, user.name, message
| SORT @timestamp DESC
```

This demonstrated that the generic `message` field was not the correct search location for the Registry event.

The structured Registry fields provided the required evidence instead.

## Remediation

The controlled persistence value was removed:

```powershell
Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "ElasticLab05"
```

The Run Key was then reviewed to confirm the test value was no longer present.

## Re-creation

The controlled value was recreated later:

```powershell
New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "ElasticLab05" -Value "C:\Windows\System32\notepad.exe" -PropertyType String -Force
```

The resulting Registry value was:

```text
ElasticLab05 : C:\Windows\System32\notepad.exe
```

This provided an additional validation point for the Registry telemetry.

## Final Assessment

```text
Baseline Run Keys reviewed
        ↓
Controlled Run Key created
        ↓
Elastic Registry telemetry observed
        ↓
Referenced executable validated
        ↓
Notepad process observed
        ↓
Process context reviewed
        ↓
Telemetry limitations documented
        ↓
Controlled persistence removed
        ↓
Controlled value recreated for validation
```

No malicious persistence, malware execution, credential theft, privilege escalation, command-and-control, or confirmed compromise was demonstrated.

The investigation established how a SOC analyst can trace a Windows persistence artifact from Registry configuration to endpoint process telemetry while maintaining a clear distinction between **direct evidence, correlation, and assumptions**.
