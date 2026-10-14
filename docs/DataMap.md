# OneDriveDiag - Data Map and Design Baseline

Status: v1.0.0 built. All "must fix" items in section 6 are done, plus the first three additions
(Controlled Folder Access, update ring and tenant lists, free space per sync root drive).
Further fixes found in testing: empty CSVs failed to write, Read-Host returned $null with no console
(now switches to unattended), .odlgz has a 256-byte ODL header before the gzip data, zip entries used
backslashes on PowerShell 5.1, AAD and "Throttl" findings were false positives on a healthy PC,
and a step that stopped early is now reported as a WARN finding.

## 1. Source material and sanitisation

Imported from an earlier Copilot session (raw files kept in `Copilot Session/`, git-ignored, never committed):

- Session transcript (design reasoning, test notes).
- A draft collector script (about 2,250 lines, v1.0.0, never executed on Windows).
- A draft HTML companion guide.

Sanitised on ingestion. Removed or generalised: client and company names, tenant and SharePoint host names,
user names and UPNs, local paths containing user or company names, project and folder names, ticket context.
Only generic technical findings were carried forward. The tool must discover every tenant, path and
account value at runtime. No value may be hard-coded.

## 2. Requirements (from the brief)

| Requirement | Notes |
|---|---|
| Single `.ps1`, client agnostic | No modules, no external downloads. |
| Runs in user context | Detect SYSTEM and stop. Detect "elevated as a different admin account" and warn. |
| Finds the correct OneDrive path(s) | Every account and every sync root, including SharePoint libraries mounted outside the OneDrive folder. |
| Output to `C:\temp\onedrivediag_<hostname>_<username>_<DATETIME>\` | Fallback to `%TEMP%` if not writable. |
| Large dataset safety | Never walk huge trees blindly. Single pass, streamed index, capped exception lists, time limit. |
| Zip option | Folder only, folder + zip, or zip only. |
| Helpdesk friendly | Comment-based help with examples, code comments, progress bars, on-screen status, prompts with choice lists for unset values, unattended mode for RMM shells. |
| Companion HTML guide | Downloadable alongside the script. |

Style constraints carried over from the Copilot session (confirm):
Windows PowerShell 5.1 compatible, ASCII only, no backtick line continuations or escapes (RMM shell safe),
Australian English, no em dashes.

## 3. Data map

Level: Q = Quick, S = Standard, D = Deep. Cost: how expensive the collection is on a large library.

| # | Area | Source | What is collected | Signals it gives | Level | Cost | Admin |
|---|---|---|---|---|---|---|---|
| 1 | Run context | WindowsIdentity, explorer.exe owner | Running user, desktop user, elevation, session | Wrong-profile runs (SYSTEM, other admin) | Q | Low | No |
| 2 | Environment | CIM, registry | Windows build/UBR, uptime, Fast Startup, long paths, disks, memory, battery, power plan, language mode | Low disk, stale uptime, old build | Q | Low | No |
| 3 | Device and sign-in | `dsregcmd /status` | Join type, AzureAdPrt, SSO state | Missing PRT, token problems | Q | Low | No |
| 4 | Security and conflicts | SecurityCenter2, process list | AV products, other sync and backup clients | File locks, overlay competition | Q | Low | No |
| 5 | OneDrive client | Install paths, process, Run key, scheduled tasks, HKCU OneDrive | Version, per-user vs per-machine, running state, memory, update task result | Not running, not installed, crash loop, update failures | Q | Low | No |
| 6 | Accounts | `HKCU\...\OneDrive\Accounts\*` | Account keys, email, user folder, tenant | Not signed in, multiple accounts | Q | Low | No |
| 7 | Sync roots | `HKCU\Software\SyncEngines\Providers\OneDrive`, account `.ini` `libraryScope` and `libraryFolder` lines | Every mount point, library type, URL namespace, site and library titles, shortcut folders | Missing root folder, root on network drive, server path prefix for 400-char check | Q | Low | No |
| 8 | Known Folder Move | User Shell Folders, account KFM values | Desktop, Documents, Pictures redirection | KFM partially applied | Q | Low | No |
| 9 | Client state flags | `settings\<acct>\global.ini`, `<guid>.ini` | Placeholder/filter error flags, clean shutdown, mass delete, bandwidth limits, pending permission change | Files On-Demand disabled by filter error, unclean shutdown | Q | Low | No |
| 10 | Sync engine counters | `logs\<acct>\SyncDiagnostics.log` | All key = value counters, snapshot age, file/folder totals | Upload/download/hash/realizer errors, stalls, DB reset, queue depth, item-count estimate for the large-data guard | Q | Low | No |
| 11 | Registry and policy | `reg export` of OneDrive, SyncEngines, policy keys (HKCU/HKLM), CldFlt, overlays, Storage Sense | `.reg` files plus a plain-language policy list | Sync disabled by policy, FOD forced off, tenant restrictions | Q | Low | No |
| 12 | Cloud Files platform | CldFlt service key, `sc query cldflt`, `fltmc` | Driver start type and state, loaded filters, overlay handler list | Driver disabled/stopped, third-party filters, overlay slot exhaustion (15 limit) | Q | Low | fltmc only |
| 13 | Event logs | Application, System, CloudFiles-Filter/Operational, AAD/Operational | OneDrive crashes and hangs, Cloud Files errors, power/boot timeline (41, 1074, 6005, 6006, 6008), disk/NTFS errors, sign-in errors | Crash loops, unexpected shutdowns, disk faults, auth failures | Q | Low-Med | No |
| 14 | Network | DNS + TCP 443 to login, OneDrive service and tenant hosts; WinHTTP and user proxy; adapters; w32tm | Reachability, latency, proxy config, time sync | Blocked endpoints, proxy, clock skew | Q | Low | No |
| 15 | Settings and log listings | `settings\` and `logs\` folders | Names, sizes, dates only (no content) | Oversized DB, logs not being written | Q | Low | No |
| 16 | File system index | One pass over each chosen sync root | Counts, states, sizes, exceptions CSV, top-level table, optional full index CSV | See section 4 | Q (top level) / S (full) | High | fsutil sample only |
| 17 | Log signatures | Newest ODL logs (account and Common folders) | Keyword counts and normalised text signatures | FileSyncError, UpdatePHState, access denied, quota, throttling, name/path errors, hex error codes | S | Med | No |
| 18 | Raw copies | `.ini` files, SyncDiagnostics, newest ODL files | Files copied with shared-read access | Hand-off to L2 / Microsoft | D (or switch) | Med | No |
| 19 | Report | All of the above | `00_Summary.txt`, `00_Findings.csv`, `00_Manifest.json`, `00_RunLog.txt` | PASS / INFO / WARN / FAIL with plain-language advice | All | Low | No |

Never collected: `SyncEngineDatabase.db` (full file listing, very large), file contents, credentials or tokens.

## 4. File system index (the large-data design)

One streamed pass per sync root. Attributes, sizes and dates only. No file is opened or hydrated.

- Before scanning, the item count from SyncDiagnostics (`files` + `folders`) is compared with
  `-LargeDatasetThreshold` (default 100,000).
- Large library choices: top level only (default), one chosen folder, everything (time limited), or skip.
  Unattended mode defaults to top level only.
- `-FocusPath` scopes the scan to one folder; `-SyncRoot` accepts a sync root or any folder.
- Exceptions are streamed to CSV and capped per category (`-MaxExceptionsPerCategory`); totals are always full counts.
- A full index CSV of every item is optional (`-IncludeFullIndex`), created once, never re-parsed.
- Long paths: the `\\?\` prefix is used so paths over 260 characters are readable.

Per-item classification, from Cloud Files attribute bits:

| State | Attribute test |
|---|---|
| Online-only placeholder | ReparsePoint and any of Offline (0x1000), RecallOnOpen (0x40000), RecallOnDataAccess (0x400000) |
| Locally available | ReparsePoint, no recall bits, not Pinned |
| Always keep on device | ReparsePoint, Pinned (0x80000), no recall bits |
| Pinned but not yet downloaded | Pinned plus recall bits |
| Not managed by OneDrive | No ReparsePoint (new local file, excluded, or untracked); hidden+system files excluded |

Exception categories: local path >= 260, server path >= 400 (fail) or near limit (warn), leading/trailing space,
trailing period, Windows reserved names, `_vti_`, `Forms` at library root, Office lock files (`~$`), `.tmp`,
conflict copies (`-<COMPUTERNAME>[-n]`), zero-byte, very large (>= 10 GB), non-cloud reparse folders
(junctions/symlinks, fsutil sample), max depth, enumeration errors.

## 5. Verified against a live Windows 11 machine (read-only structural checks)

| Assumption | Result |
|---|---|
| Script parses under Windows PowerShell 5.1 and PowerShell 7 | Pass (0 errors on both, real parser) |
| `SyncDiagnostics.log` is `key = value` text | Pass (ASCII, key names as expected) |
| SyncEngines provider values (`MountPoint`, `UrlNamespace`, `LibraryType`, `WebUrl`) | Pass |
| Account `.ini` files readable with `Get-Content` | **Fail.** Files are UTF-16 LE with no BOM. Read as ANSI they never match, so library titles, `global.ini` flags and `<guid>.ini` flags are silently skipped. |
| `libraryScope` regex | **Fail** (consequence of the encoding). Also note `libraryFolder` lines (folder shortcuts) exist and are not parsed. |
| ODL logs contain readable ASCII | Pass (header `EBFGONED`, readable words present) |
| ODL file set | **Gap.** `logs\Common` (launcher/updater, many files) is not scanned. `.odlgz` (gzip) is skipped. `.odlsent` holds almost no readable text and can be skipped. |

## 6. Copilot draft: keep, fix, add

Keep (sound design): step runner with per-step isolation and timings, findings engine, single-pass streamed
index with caps and time limit, large-dataset guard, `\\?\` long-path handling, RMM unattended fallback,
user-mismatch detection, shared-read copies of locked files, zip options, plain-language summary.

Must fix:

1. Read OneDrive `.ini` files as UTF-16 (detect by null bytes) in one helper used everywhere.
2. Parse `libraryFolder` lines as well as `libraryScope`.
3. Include `logs\Common` in the ODL set; optionally decompress `.odlgz` with GZipStream.
4. Remove client-specific example values from the help block and guide (project folder and company path).
5. Run end to end on Windows (Quick, Standard, Deep, unattended) and fix runtime issues.

Proposed additions (for decision):

| Addition | Value | Cost |
|---|---|---|
| Defender Controlled Folder Access state | CFA silently blocks OneDrive writes into protected folders | Low |
| OneDrive update ring / tenant allow-list policy values in the summary | Explains version and sign-in restrictions | Low |
| Free space on each sync root drive (not just the system drive) | Libraries on D: etc. | Low |
| Optional compiled (C#) fast path for the index, with automatic PowerShell fallback in Constrained Language Mode | 5-10x faster on 400k+ item trees | Medium |
| Optional run of Microsoft's own `CollectSyncLogs.bat` (shipped with OneDrive) | Ready-made package for a Microsoft support case | Low |
| Summary rendered as a small HTML report as well as text | Easier for helpdesk to read | Medium |

## 7. Output layout (package folder)

```
onedrivediag_<host>_<user>_<yyyyMMdd_HHmmss>\
  00_Summary.txt  00_Findings.csv  00_Manifest.json  00_RunLog.txt
  01_Environment*.txt              02_OneDrive_Client.txt
  03_Accounts_and_SyncRoots.txt    03_SyncRoots.csv
  04_SyncDiagnostics_*             05_Registry\*.reg  05_Registry_and_Policy_Summary.txt
  06_CloudFiles_Platform.txt       07_Events_*.csv    07_Events_Summary.txt
  08_Network_*                     09_*_Folder_Listing.csv
  11_FileSystem_<n>_<root>_{Summary.txt,Exceptions.csv,TopLevel.csv[,FullIndex.csv]}
  12_ODL_Signatures.txt            13_RawLogs\ (Deep)
```
