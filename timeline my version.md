# Timeline

| Time | Activity | Evidence | Assessment |
|---|---|---|---|
| Initial review | Existing HKCU Run Key enumeration | Multiple legitimate application startup entries observed | Baseline established |
| Initial review | Existing `SOCLab` entry | `SOCLab : notepad.exe` | Existing startup configuration |
| 06:55:34.324 | Controlled `ElasticLab05` Registry event | Run Key value pointed to `C:\Windows\System32\notepad.exe` | Controlled persistence artifact observed |
| 07:04:26.882 | `notepad.exe` process event | Parent `explorer.exe`, user `Dell`, executable `C:\Windows\System32\notepad.exe` | Process execution observed |
| Investigation | Generic `message` search | No matching `ElasticLab05` event | Structured Registry fields preferred |
| Remediation | `ElasticLab05` removed | `Remove-ItemProperty` executed | Controlled persistence removed |
| Later validation | `ElasticLab05` recreated | Registry value restored for additional telemetry validation | Controlled persistence recreated |

