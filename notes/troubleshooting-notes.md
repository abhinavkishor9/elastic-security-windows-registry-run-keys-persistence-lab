# Troubleshooting Notes — Windows Persistence: Registry Run Keys

## Issue 1 — Generic `message` Search Returned No Results

### Query

```esql
FROM logs-*
| WHERE message LIKE "*ElasticLab05*"
| KEEP @timestamp, host.name, user.name, message
| SORT @timestamp DESC
```

### Result

```text
No results match your search criteria
```

### Investigation

The controlled Run Key was verified locally and was also visible through structured Registry telemetry.

The generic `message` field therefore was not a reliable search location for this event.

### Resolution

Use the structured Registry fields instead:

```esql
FROM logs-*
| WHERE registry.value LIKE "*ElasticLab05*"
| KEEP @timestamp, host.name, user.name, registry.key, registry.value, registry.data.strings
| SORT @timestamp DESC
```

This successfully returned the controlled event.

### Lesson

When an event exists in a structured dataset, prefer the relevant ECS fields over a generic `message` search.

---

## Issue 2 — Registry Query Syntax Error

The initial Registry path pattern needed to be simplified.

The working query was:

```esql
FROM logs-*
| WHERE registry.key LIKE "*CurrentVersion*Run*"
| KEEP @timestamp, host.name, user.name, registry.key, registry.value, registry.data.strings
| SORT @timestamp DESC
```

### Lesson

The useful part of the path is the distinctive:

```text
CurrentVersion
Run
```

Using a simpler wildcard pattern avoids unnecessary escaping and is easier to troubleshoot.

---

## Issue 3 — `notepad.exe` Was Initially Expected to Appear Immediately

Creating the Run Key does not by itself prove that the referenced executable has executed at that moment.

The persistence entry was:

```text
ElasticLab05
    |
    +-- C:\Windows\System32\notepad.exe
```

The separate process query was therefore treated as a process-correlation step rather than an automatic consequence of Registry creation.

### Lesson

Persistence configuration and persistence execution are different pieces of evidence.

```text
Registry modification
        ≠
Process execution
```

Both should be investigated separately.

---

## Issue 4 — `notepad.exe` Process Telemetry Was Found Later

The following query returned a Notepad process event:

```esql
FROM logs-*
| WHERE process.name == "notepad.exe"
| KEEP @timestamp, host.name, user.name, process.pid, process.parent.name, process.parent.pid, process.command_line, process.executable
| SORT @timestamp DESC
```

Observed:

```text
Sep 24, 2026 @ 07:04:26.882
```

with:

```text
User: Dell
PID: 13988
Parent: explorer.exe
Parent PID: 21680
Executable: C:\Windows\System32\notepad.exe
```

### Lesson

The process event provides useful correlation but should not automatically be described as direct proof that the Run Key caused the process to start.

---

## Issue 5 — Existing Run Keys Added Context

The initial Registry review showed several existing Run Key entries, including:

```text
Adobe Acrobat Synchronizer
Microsoft Edge AutoLaunch
OneDrive
Mozilla Firefox
MEmuSVC
Microsoft Copilot AutoLaunch
SOCLab
```

This demonstrated that the endpoint already had startup configuration before the lab.

### Lesson

Baseline existing persistence mechanisms before investigating a newly created entry.

A Run Key is not suspicious solely because it exists.

---

## Issue 6 — Existing `SOCLab` Value

An existing value was observed:

```text
SOCLab : notepad.exe
```

This is relevant because the lab also used Notepad as its referenced executable.

### Investigation Principle

The same executable can appear in multiple startup configurations.

Therefore, analysts should correlate:

```text
Value Name
+
Registry Path
+
Value Data
+
Timestamp
+
Process Activity
+
User Context
```

rather than treating the executable name alone as the finding.

---

## Issue 7 — Controlled Entry Was Removed and Recreated

The controlled value was removed using:

```powershell
Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "ElasticLab05"
```

It was later recreated using:

```powershell
New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "ElasticLab05" -Value "C:\Windows\System32\notepad.exe" -PropertyType String -Force
```

### Lesson

The lab demonstrated that persistence artifacts can appear, disappear, and reappear during testing.

Timeline interpretation must therefore account for the actual state of the Registry at each point.

---

## Issue 8 — Registry Telemetry Used a SID-Based Key Representation

Elastic returned Registry keys in a representation similar to:

```text
S-1-5-21-...\Software\Microsoft\Windows\CurrentVersion\Run
```

rather than displaying only the PowerShell-style:

```text
HKCU:\Software\Microsoft\Windows\CurrentVersion\Run
```

### Lesson

Security telemetry may represent the same Windows Registry location differently from PowerShell.

The underlying Registry path should be interpreted using the available structured fields and context.

---

## Issue 9 — Time Range

The investigation used:

```text
Last 15 minutes
```

This was appropriate for controlled activity.

The important observed timestamps included:

```text
06:55:34.324
```

for the controlled Registry event and:

```text
07:04:26.882
```

for the Notepad process event.

### Lesson

A short time range is useful for controlled testing, but it must cover the entire sequence being investigated.

When correlating persistence with process execution, the time window must include both events.

---

## Investigation Lessons

### 1. Registry Evidence and Process Evidence Are Different

A Run Key proves that startup configuration exists.

A process event proves that a process executed.

The two should be correlated rather than treated as the same evidence.

### 2. Structured Fields Are Valuable

The Registry telemetry was successfully found through:

```text
registry.key
registry.value
registry.data.strings
```

while the generic `message` search returned no results.

### 3. Baseline First

Existing Run Keys can be legitimate.

Understanding the baseline makes it easier to identify newly introduced or unusual values.

### 4. Process Context Matters

The Notepad event included:

```text
process.name
process.pid
process.parent.name
process.parent.pid
process.command_line
process.executable
user.name
```

These fields provide stronger investigative context than the process name alone.

### 5. Correlation Is Not Always Causation

A Registry event followed by a process event can establish useful temporal correlation.

It should not automatically be described as direct causal proof unless the telemetry demonstrates that relationship.

### 6. Evidence Must Drive the Assessment

The investigation followed:

```text
Registry Artifact
      ↓
Telemetry Validation
      ↓
Process Correlation
      ↓
Context Analysis
      ↓
Assessment
```

rather than:

```text
Run Key Found
      ↓
Automatically Malicious
```
