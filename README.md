# OneDriveDiag

A single-file, read-only PowerShell tool that collects a complete OneDrive health and error baseline from one
Windows PC, scores what it finds as PASS, INFO, WARN or FAIL, and packages the evidence for escalation.

Built for helpdesk staff: guided prompts with numbered choices, progress bars, plain-language results and advice.
Built for RMM shells too: an unattended mode, no hangs when there is no console, and correct results when the
shell carries the SYSTEM agent's environment.

- **Read-only.** It does not start, stop, reset, repair or unlink OneDrive. It only writes to its own output folder.
- **Client agnostic.** Every account, tenant, library and path is discovered at runtime.
- **No dependencies.** Windows PowerShell 5.1 or PowerShell 7 on Windows 10 or 11. No modules, no admin rights needed
  (a few extra checks run when elevated).

Full documentation: [OneDriveDiag_Guide.html](OneDriveDiag_Guide.html) (download it and open it in a browser).

## Quick start

Run these in Windows PowerShell **as the user who has the problem** (not as SYSTEM).

**1. Clean up and download the latest version to `C:\Temp`.** This creates the folder if needed, **deletes the
results of previous runs** (`C:\Temp\onedrivediag_*` folders and zips; nothing else), and replaces any older copy
of the script. Attach any result you still need to the ticket first.

```powershell
if (-not (Test-Path 'C:\Temp')) { New-Item -ItemType Directory -Path 'C:\Temp' | Out-Null }
Get-ChildItem -LiteralPath 'C:\Temp' -Filter 'onedrivediag_*' -ErrorAction SilentlyContinue | ForEach-Object { Remove-Item -LiteralPath $_.FullName -Recurse -Force -ErrorAction SilentlyContinue; if (Test-Path -LiteralPath $_.FullName) { 'Could not remove ' + $_.Name } else { 'Removed ' + $_.Name } }
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
Remove-Item -LiteralPath 'C:\Temp\OneDriveDiag.ps1' -Force -ErrorAction SilentlyContinue
Invoke-WebRequest -Uri ('https://raw.githubusercontent.com/gpablo-/OneDriveDiag/main/OneDriveDiag.ps1?t=' + [DateTime]::UtcNow.Ticks) -OutFile 'C:\Temp\OneDriveDiag.ps1' -UseBasicParsing
Unblock-File -Path 'C:\Temp\OneDriveDiag.ps1'
Get-Item 'C:\Temp\OneDriveDiag.ps1' | Select-Object FullName, Length, LastWriteTime
```

The `?t=` value stops a cached older copy being served. Use the `raw.githubusercontent.com` link, not the
`github.com/.../blob/...` page link, which downloads a web page instead of the script.

**2. Run it (guided):**

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\Temp\OneDriveDiag.ps1
```

Answer the numbered questions (Enter accepts the default; Standard is recommended). When it finishes, copy the
**HELPDESK NOTE** block printed at the end into the ticket, open `00_Report.html` for the full result, and attach the
zip to the ticket.

**Hands-free (RMM shell without prompts):**

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\Temp\OneDriveDiag.ps1 -Level Standard -Unattended -Zip
```

Results go to `C:\Temp\onedrivediag_<hostname>_<username>_<yyyyMMdd_HHmmss>\` (plus a `.zip` next to it when requested).

## What it collects

| Area | Highlights |
|---|---|
| Environment | Windows build, uptime, disks, antivirus, Defender Controlled Folder Access state and blocks, device join and Primary Refresh Token |
| OneDrive client | Installed copies and version, process state, update tasks |
| Accounts and sync roots | Every account, every synced library and folder shortcut with its real local folder, settings flags, free space |
| Sync engine counters | `SyncDiagnostics.log` error counters, stalls, queue depth, item totals |
| Registry and policy | `.reg` exports, policies in plain language, update ring, tenant allow and block lists |
| Cloud Files platform | CldFlt driver, filter drivers (elevated), overlay handlers |
| Event logs | OneDrive crashes, Cloud Files errors, power and boot timeline, disk and NTFS errors, sign-in events |
| Network | DNS and TCP 443 to Microsoft 365 and tenant hosts, proxy, time sync |
| File index | One streamed pass per library: each item's "in sync" mark (what draws the red cross), files waiting to upload, where the stuck items are and which program has them open, file states, long paths (local and the 400 character SharePoint limit), bad names, conflict copies, files OneDrive is not managing, junctions |
| Log signatures | Error words from OneDrive's binary ODL logs (all log folders, compressed logs included), de-duplicated and counted, with OneDrive error names and Windows error codes explained in plain language |
| Raw logs (Deep) | Settings files and the newest ODL logs |

Large libraries are never walked blindly. The tool reads the item count OneDrive reports and, above a threshold
(default 100,000), offers top level only, one chosen folder, everything (time limited) or skip.

## Collection levels

| Level | Adds | Typical time |
|---|---|---|
| Quick | Everything except the full file index and log signatures (top-level folder list only) | 1 to 3 minutes |
| Standard | Full file index (with the large library guard) and ODL log signatures | 3 to 20 minutes |
| Deep | Raw copies of settings files and the newest ODL logs; optional full index CSV | Standard plus copy time |

## Common options

```powershell
# One folder inside a very large SharePoint library
.\OneDriveDiag.ps1 -Level Standard -Unattended -Zip -SyncRoot 'C:\Users\jsmith\Contoso\Projects - Documents' -FocusPath 'Project A'

# Everything, delivered as a single zip
.\OneDriveDiag.ps1 -Level Deep -IncludeFullIndex -ZipOnly

# Full parameter help with examples
Get-Help .\OneDriveDiag.ps1 -Full
```

## Output

| File | Contents |
|---|---|
| `00_Report.html` | Start here. Colour-coded results, fix steps, where the stuck items are and what has them open, ticket note with a copy button |
| `00_TicketNote.txt` | Ready-to-paste helpdesk note (also printed at the end of the run) |
| `00_Summary.txt` | Text version: results, key facts, what to do next |
| `00_Findings.csv` | Every check with status, detail and advice |
| `00_RunLog.txt` | Time-stamped log, including every question and the answer used |
| `00_Manifest.json` | Parameters, timings, counts |
| `01_` to `13_` | Evidence by area (see the guide for the full map) |

## Privacy

The package contains the user's email, tenant and site names, library URLs, file and folder names and event log
text. Treat it as confidential and store it only in approved ticket or file storage.

## Files in this repo

| File | Purpose |
|---|---|
| `OneDriveDiag.ps1` | The tool |
| `OneDriveDiag_Guide.html` | Companion guide for the helpdesk (data map, findings reference, troubleshooting) |
| `docs/DataMap.md` | Design baseline and data map |
