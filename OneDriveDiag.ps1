<#
.SYNOPSIS
    OneDriveDiag. Collects a read-only health and error baseline for OneDrive sync problems.

.DESCRIPTION
    This script gathers evidence about the OneDrive sync client on a Windows PC and writes it to a
    time-stamped folder. It does NOT change, repair, reset or unlink OneDrive. It is safe to run while
    the user is working.

    Run it IN THE USER CONTEXT (the signed-in user). Do not run it as SYSTEM. OneDrive settings live in
    the user profile, so the data is only correct when the script runs as the user who has the problem.

    What is collected (see the HTML companion document for the full data map):
      1.  Environment      : Windows build, uptime, power, disks, security products, Controlled Folder Access,
                             join state, sign-in token state.
      2.  OneDrive client  : version, install type, process state, update tasks, startup entry.
      3.  Accounts/roots   : every OneDrive account and every synced library (sync root), with its real
                             local folder. SharePoint libraries are often mounted OUTSIDE the OneDrive folder.
      4.  Sync counters    : SyncDiagnostics.log parsed, with error counters flagged.
      5.  Registry/policy  : OneDrive, SyncEngines, policy keys, known folder locations, Storage Sense.
      6.  Cloud Files      : the Windows Cloud Files driver (CldFlt), shell overlay handlers, third-party filters.
      7.  Event logs       : OneDrive crashes, Cloud Files filter, sign-in (AAD), disk/NTFS and power events.
      8.  Network and auth : DNS and TCP 443 tests to Microsoft 365 and tenant hosts, proxy settings, time sync.
      9.  Settings/logs    : listing of OneDrive settings and log folders (names, sizes, dates only).
      10. File index       : ONE pass over each sync root that builds an index and a list of problem items
                             (long paths, local-only files, name problems, conflict copies, stuck items).
      11. Log signatures   : error text patterns pulled from the OneDrive binary logs (ODL files).
      12. Raw logs (Deep)  : copies of the small configuration files and the newest ODL files.

    All findings are scored PASS, INFO, WARN or FAIL and written to 00_Summary.txt in plain language.

    Large libraries: a library with hundreds of thousands of items is NOT scanned blindly. The script reads
    the item count that OneDrive already reports, and if it is large it asks what to do (scan all, scan one
    folder, top level only, or skip). A time limit stops any scan that runs too long.

.PARAMETER Level
    How much to collect. Quick = settings, counters, events, network and a top-level folder list (about 1 to 3 minutes).
    Standard = Quick plus a full file index and log signature scan (recommended). Deep = Standard plus raw log copies.
    If not supplied, you are asked to choose from a list.

.PARAMETER OutputRoot
    Parent folder for the diagnostic folder. Default is C:\temp. The package folder is named
    onedrivediag_<hostname>_<username>_<yyyyMMdd_HHmmss>.

.PARAMETER SyncRoot
    Which synced folders to index. Use All, or give one or more folder paths (a known sync root or ANY folder,
    for example a single project folder). If not supplied and more than one sync root exists, you are asked to choose.

.PARAMETER FocusPath
    Limit the file index to one folder. Give a full path, or a path relative to the sync root
    (for example "Projects\Project A"). Use this on very large libraries.

.PARAMETER LargeDatasetAction
    What to do when OneDrive reports more items than LargeDatasetThreshold.
    Prompt (default) asks you. Full scans everything. TopLevel lists top-level folders only. Skip does no file index.
    In -Unattended mode, Prompt behaves like TopLevel.

.PARAMETER LargeDatasetThreshold
    Item count (files plus folders) above which a library is treated as large. Default 100000.

.PARAMETER ScanTimeLimitMinutes
    Maximum minutes spent indexing each sync root. The scan stops cleanly and marks results as partial. Default 15.

.PARAMETER PathWarnLength
    Local path length flagged as too long. Default 260 (the classic Windows MAX_PATH limit).

.PARAMETER ServerPathWarnLength
    Estimated SharePoint path length flagged as near the 400 character limit. Default 360.

.PARAMETER EventDays
    How many days of event logs to read. Default 7.

.PARAMETER MaxEventsPerLog
    Maximum events exported per log. Default 300.

.PARAMETER MaxExceptionsPerCategory
    Maximum rows written per problem category in the exceptions index. Totals are always counted in full. Default 1000.

.PARAMETER OdlMaxFiles
    Number of newest OneDrive ODL log files to scan for error signatures, per log folder
    (each account folder and the shared Common folder). Compressed .odlgz files are included. Default 6.

.PARAMETER OdlMaxTotalMB
    Maximum total size of ODL files read or copied. Default 150.

.PARAMETER IncludeFullIndex
    Also write a CSV of EVERY file and folder scanned. Can be very large (about 100 MB per 400,000 items).

.PARAMETER IncludeRawLogs
    Copy configuration files and the newest ODL logs into the package (always on for Deep).

.PARAMETER Zip
    Create a .zip of the package next to the folder.

.PARAMETER ZipOnly
    Create the .zip and delete the unzipped folder.

.PARAMETER Unattended
    No prompts. Defaults are used. Use this from an RMM shell where Read-Host is not available.

.PARAMETER OpenOutput
    Open the output folder in File Explorer when finished.

.EXAMPLE
    .\OneDriveDiag.ps1
    Interactive run. You are guided through a list of choices.

.EXAMPLE
    .\OneDriveDiag.ps1 -Level Standard -Zip
    Standard collection with a zip file, asking only the questions that are still open.

.EXAMPLE
    .\OneDriveDiag.ps1 -Level Standard -Unattended -Zip -LargeDatasetAction TopLevel
    Hands-free run for an RMM shell. Large libraries get a top-level listing only.

.EXAMPLE
    .\OneDriveDiag.ps1 -Level Standard -SyncRoot 'C:\Users\jsmith\Contoso\Projects - Documents' -FocusPath 'Project A' -Unattended -Zip
    Index only one project folder inside a very large SharePoint library.

.EXAMPLE
    .\OneDriveDiag.ps1 -Level Deep -IncludeFullIndex -ZipOnly
    Everything, including a full file index and raw logs, delivered as a single zip.

.EXAMPLE
    powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\OneDriveDiag.ps1 -Level Quick -OutputRoot D:\Diag
    Start from a Command Prompt or shortcut when script execution is blocked by policy.

.NOTES
    Version  : 1.0.0
    Requires : Windows PowerShell 5.1 or later on Windows 10 or 11. Administrator rights are NOT required.
               Some checks (fltmc filter list) only run when the session is elevated and are skipped otherwise.
    Safety   : Read-only. The only writes are inside the output folder.
               Reading a OneDrive folder can make OneDrive list that folder from the cloud. This is normal.
    Privacy  : The package contains the user email, tenant and site names, and file and folder names.
               Handle it as confidential. Do not post it to public sites.
#>

[CmdletBinding()]
param(
    [ValidateSet('Quick', 'Standard', 'Deep')]
    [string]$Level,

    [string]$OutputRoot = 'C:\temp',

    [string[]]$SyncRoot,

    [string]$FocusPath,

    [ValidateSet('Prompt', 'Full', 'TopLevel', 'Skip')]
    [string]$LargeDatasetAction = 'Prompt',

    [int]$LargeDatasetThreshold = 100000,

    [int]$ScanTimeLimitMinutes = 15,

    [int]$PathWarnLength = 260,

    [int]$ServerPathWarnLength = 360,

    [int]$EventDays = 7,

    [int]$MaxEventsPerLog = 300,

    [int]$MaxExceptionsPerCategory = 1000,

    [int]$OdlMaxFiles = 6,

    [int]$OdlMaxTotalMB = 150,

    [switch]$IncludeFullIndex,

    [switch]$IncludeRawLogs,

    [switch]$Zip,

    [switch]$ZipOnly,

    [switch]$Unattended,

    [switch]$OpenOutput
)

# ----------------------------------------------------------------------------------------------
# SECTION 1. GLOBAL STATE
# Everything the steps share is kept in $script: variables so each step can add to the same picture.
# ----------------------------------------------------------------------------------------------
Set-StrictMode -Off
$ErrorActionPreference = 'Continue'
$ProgressPreference = 'Continue'

$script:ScriptVersion = '1.0.0'
$script:StartTime = Get-Date
$script:OutDir = $null            # package folder
$script:LogFile = $null           # 00_RunLog.txt
$script:Findings = New-Object System.Collections.ArrayList
$script:StepResults = New-Object System.Collections.ArrayList
$script:Facts = [ordered]@{}      # key facts shown at the top of the summary
$script:Accounts = @()            # OneDrive accounts found in the registry
$script:SyncRoots = @()           # every synced folder (OneDrive and SharePoint libraries)
$script:ScanResults = New-Object System.Collections.ArrayList
$script:EstimatedItems = [long]0  # files plus folders as reported by OneDrive SyncDiagnostics
$script:LevelName = $null
$script:LevelNum = 1
$script:IsUnattended = $false
$script:IsElevated = $false
$script:CurrentUser = $null
$script:DoZip = $false
$script:ZipKeepFolder = $true
$script:ZipPath = $null
$script:ScanFullIndex = $false
$script:OdlFilesRead = @()
$script:OdlFilesToCopy = @()
$script:BoundParams = @{}
$script:PendingLog = New-Object System.Collections.ArrayList   # log lines held until the run log exists
$script:CountFail = 0
$script:CountWarn = 0
$script:OutputParent = $null
$script:IncludeRaw = $false
$script:UserMismatch = $false
$script:ExplorerOwners = @()
$script:ZipPath = $null

# Windows file attribute bits. Cloud Files (OneDrive Files On-Demand) uses bits that .NET does not name.
$script:AttrNames = @(
    @(1, 'ReadOnly'), @(2, 'Hidden'), @(4, 'System'), @(16, 'Directory'), @(32, 'Archive'),
    @(256, 'Temporary'), @(512, 'SparseFile'), @(1024, 'ReparsePoint'), @(2048, 'Compressed'),
    @(4096, 'Offline'), @(8192, 'NotContentIndexed'), @(16384, 'Encrypted'), @(32768, 'NoScrubData'),
    @(131072, 'IntegrityStream'), @(262144, 'RecallOnOpen'), @(524288, 'Pinned'),
    @(1048576, 'Unpinned'), @(4194304, 'RecallOnDataAccess')
)

# ----------------------------------------------------------------------------------------------
# SECTION 2. HELPER FUNCTIONS (logging, findings, file output, prompts)
# ----------------------------------------------------------------------------------------------

function Write-Log {
    # Writes one time-stamped line to 00_RunLog.txt. Never shown on screen.
    # Lines written before the output folder exists (early questions, start-up checks) are held in memory
    # and written out by New-OutputFolder, so nothing is lost.
    param([string]$Message, [string]$Level = 'INFO')
    $line = '{0} [{1}] {2}' -f (Get-Date).ToString('yyyy-MM-dd HH:mm:ss'), $Level, $Message
    if ($script:LogFile) {
        try { Add-Content -LiteralPath $script:LogFile -Value $line -Encoding UTF8 -ErrorAction Stop } catch { }
    }
    else { [void]$script:PendingLog.Add($line) }
}

function Write-Choice {
    # Records a question and the answer used, so a reviewer can see what the helpdesk chose.
    param([string]$Question, [string]$Answer)
    $how = 'answered'
    if ($script:IsUnattended) { $how = 'default, unattended' }
    Write-Log -Message ('Choice: {0} -> {1} ({2})' -f $Question, $Answer, $how) -Level 'CHOICE'
}

function Write-Status {
    # Shows a coloured status line on screen and copies it to the run log.
    param([string]$Tag, [string]$Message)
    $colour = 'White'
    switch ($Tag) {
        'OK'   { $colour = 'Green' }
        'WARN' { $colour = 'Yellow' }
        'FAIL' { $colour = 'Red' }
        'SKIP' { $colour = 'DarkGray' }
        'INFO' { $colour = 'Cyan' }
    }
    Write-Host ('  [{0}] {1}' -f $Tag.PadRight(4), $Message) -ForegroundColor $colour
    Write-Log -Message $Message -Level $Tag
}

function Add-Finding {
    # Records a result that appears in 00_Summary.txt. WARN and FAIL are also shown on screen at once.
    param(
        [string]$Area,
        [string]$Check,
        [ValidateSet('PASS', 'INFO', 'WARN', 'FAIL')][string]$Status,
        [string]$Detail,
        [string]$Advice = ''
    )
    [void]$script:Findings.Add([pscustomobject]@{
            Status = $Status; Area = $Area; Check = $Check; Detail = $Detail; Advice = $Advice
        })
    if ($Status -eq 'WARN' -or $Status -eq 'FAIL') {
        Write-Status -Tag $Status -Message ('{0}: {1}' -f $Check, $Detail)
    }
    else {
        Write-Log -Message ('{0}: {1} - {2}' -f $Check, $Status, $Detail) -Level $Status
    }
}

function Save-Text {
    # Writes text lines to a file inside the package folder (creates sub folders when needed).
    param([string]$FileName, [object]$Content)
    $path = Join-Path $script:OutDir $FileName
    $parent = Split-Path -Parent $path
    if (-not (Test-Path -LiteralPath $parent)) { New-Item -ItemType Directory -Path $parent -Force | Out-Null }
    $Content | Out-File -LiteralPath $path -Encoding UTF8 -Width 4096
}

function Save-Csv {
    # Writes rows to a CSV file inside the package folder. Writes a short note when there are no rows.
    param([string]$FileName, [object]$Rows)
    $path = Join-Path $script:OutDir $FileName
    $parent = Split-Path -Parent $path
    if (-not (Test-Path -LiteralPath $parent)) { New-Item -ItemType Directory -Path $parent -Force | Out-Null }
    # An empty pipeline arrives as $null, and @($null) is an array holding one null item, so nulls are removed first.
    $arr = @($Rows | Where-Object { $null -ne $_ })
    if ($arr.Count -eq 0) { 'No rows.' | Out-File -LiteralPath $path -Encoding UTF8 }
    else { $arr | Export-Csv -LiteralPath $path -NoTypeInformation -Encoding UTF8 }
}

function ConvertTo-AttributeText {
    # Turns a numeric file attribute value into readable names, for example 4199968 -> Archive, SparseFile, ...
    param([int]$Attr)
    $parts = New-Object System.Collections.ArrayList
    $known = 0
    foreach ($pair in $script:AttrNames) {
        if (($Attr -band $pair[0]) -ne 0) { [void]$parts.Add($pair[1]); $known = $known -bor $pair[0] }
    }
    $rest = $Attr -band (-bnot $known)
    if ($rest -ne 0) { [void]$parts.Add(('0x{0:X}' -f $rest)) }
    if ($parts.Count -eq 0) { return 'None' }
    return ($parts -join ', ')
}

function Format-Bytes {
    # Human readable size, for example 1.5 GB.
    param([double]$Bytes)
    if ($Bytes -ge 1GB) { return ('{0:N2} GB' -f ($Bytes / 1GB)) }
    if ($Bytes -ge 1MB) { return ('{0:N1} MB' -f ($Bytes / 1MB)) }
    if ($Bytes -ge 1KB) { return ('{0:N0} KB' -f ($Bytes / 1KB)) }
    return ('{0:N0} B' -f $Bytes)
}

function Get-SafeName {
    # Makes text safe for use in a file name.
    param([string]$Text)
    $clean = ($Text -replace '[^A-Za-z0-9._-]+', '_').Trim('_')
    if ($clean.Length -gt 60) { $clean = $clean.Substring(0, 60) }
    if ([string]::IsNullOrEmpty($clean)) { $clean = 'item' }
    return $clean
}

# ---- Prompt helpers. In unattended mode they return the default without asking. ----

function Read-Answer {
    # Reads one line from the console. Returns $null when nobody can answer.
    # Read-Host returns an empty string when the user just presses Enter, but $null (or throws) when the
    # input stream is closed, which is what RMM shells and redirected sessions do. In that case the whole
    # run switches to unattended mode so no later question can hang or loop.
    param([string]$Prompt)
    $a = $null
    try { $a = Read-Host $Prompt } catch { $a = $null }
    if ($null -eq $a) {
        if (-not $script:IsUnattended) {
            $script:IsUnattended = $true
            Write-Status -Tag 'INFO' -Message 'No interactive console found (input is closed). Using defaults for all questions.'
        }
        return $null
    }
    return ("$a").Trim()
}

function Select-FromList {
    # Shows a numbered list and returns the chosen number(s) as an array of 1-based indexes.
    # The question and the chosen option text are written to the run log.
    param(
        [string]$Title,
        [string[]]$Options,
        [int]$DefaultIndex = 1,
        [switch]$Multiple
    )
    $picked = @(Select-FromListCore @PSBoundParameters)
    Write-Choice -Question $Title -Answer (($picked | ForEach-Object { $Options[$_ - 1] }) -join '; ')
    return $picked
}

function Select-FromListCore {
    # The prompt itself. Use Select-FromList, which also logs the answer.
    param(
        [string]$Title,
        [string[]]$Options,
        [int]$DefaultIndex = 1,
        [switch]$Multiple
    )
    if ($script:IsUnattended) {
        if ($Multiple) { return @(1..$Options.Count) }
        return @($DefaultIndex)
    }
    Write-Host ''
    Write-Host $Title -ForegroundColor Cyan
    for ($i = 0; $i -lt $Options.Count; $i++) {
        $mark = ''
        if ((-not $Multiple) -and (($i + 1) -eq $DefaultIndex)) { $mark = '   (default)' }
        Write-Host ('   [{0}] {1}{2}' -f ($i + 1), $Options[$i], $mark)
    }
    if ($Multiple) { Write-Host '   Type numbers separated by commas (for example 1,3), a range (2-4), or A for all. Press Enter for all.' -ForegroundColor DarkGray }
    else { Write-Host '   Type a number and press Enter. Press Enter alone to accept the default.' -ForegroundColor DarkGray }

    while ($true) {
        $answer = Read-Answer '   Your choice'
        if ($null -eq $answer -or $answer -eq '') {
            # Enter alone accepts the default. $null means no console (for example an RMM shell): use the default too.
            if ($Multiple) { return @(1..$Options.Count) }
            return @($DefaultIndex)
        }
        if ($Multiple -and $answer -match '^(a|all)$') { return @(1..$Options.Count) }

        $picked = New-Object System.Collections.ArrayList
        $valid = $true
        foreach ($token in ($answer -split '[,\s]+' | Where-Object { $_ -ne '' })) {
            if ($token -match '^\d+$') { [void]$picked.Add([int]$token) }
            elseif ($Multiple -and $token -match '^(\d+)-(\d+)$') {
                $a = [int]$Matches[1]; $b = [int]$Matches[2]
                if ($a -le $b) { foreach ($n in $a..$b) { [void]$picked.Add($n) } } else { $valid = $false }
            }
            else { $valid = $false }
        }
        if ($valid) {
            foreach ($n in $picked) { if ($n -lt 1 -or $n -gt $Options.Count) { $valid = $false } }
        }
        if ($valid -and $picked.Count -gt 0 -and ($Multiple -or $picked.Count -eq 1)) {
            return @($picked | Sort-Object -Unique)
        }
        Write-Host '   That choice is not valid. Please try again.' -ForegroundColor Yellow
    }
}

function Read-YesNo {
    # Asks a yes or no question. Returns $true or $false. The answer is written to the run log.
    param([string]$Question, [bool]$DefaultYes = $true)
    $r = Read-YesNoCore @PSBoundParameters
    Write-Choice -Question $Question -Answer $(if ($r) { 'Yes' } else { 'No' })
    return $r
}

function Read-YesNoCore {
    # The prompt itself. Use Read-YesNo, which also logs the answer.
    param([string]$Question, [bool]$DefaultYes = $true)
    if ($script:IsUnattended) { return $DefaultYes }
    $hint = if ($DefaultYes) { '[Y/n]' } else { '[y/N]' }
    while ($true) {
        $a = Read-Answer ('{0} {1}' -f $Question, $hint)
        if ($null -eq $a -or $a -eq '') { return $DefaultYes }
        $a = $a.ToLower()
        if ($a -in @('y', 'yes')) { return $true }
        if ($a -in @('n', 'no')) { return $false }
        Write-Host '   Please type Y or N.' -ForegroundColor Yellow
    }
}

function Read-Text {
    # Asks for a line of text. Returns the default in unattended mode. The answer is written to the run log.
    param([string]$Prompt, [string]$Default = '')
    $r = Read-TextCore @PSBoundParameters
    Write-Choice -Question $Prompt -Answer $(if ($r) { $r } else { '(blank)' })
    return $r
}

function Read-TextCore {
    # The prompt itself. Use Read-Text, which also logs the answer.
    param([string]$Prompt, [string]$Default = '')
    if ($script:IsUnattended) { return $Default }
    $a = Read-Answer $Prompt
    if ($null -eq $a -or $a -eq '') { return $Default }
    return $a
}

function Show-Banner {
    # Title and plain-language instructions shown before anything runs.
    Write-Host ''
    Write-Host '==============================================================================' -ForegroundColor Cyan
    Write-Host ('  OneDriveDiag - OneDrive Diagnostic Collector  v{0}' -f $script:ScriptVersion) -ForegroundColor White
    Write-Host '==============================================================================' -ForegroundColor Cyan
    Write-Host '  This tool collects information about OneDrive on this PC to help find sync faults.'
    Write-Host '  - It is READ-ONLY. It does not change, reset or repair anything.'
    Write-Host '  - It is safe to run while the user is working.'
    Write-Host '  - Keep this window open until you see "Collection complete".'
    Write-Host '  - Run it as the user who has the problem (not as SYSTEM).'
    Write-Host '  - A result folder (and optional zip) is created under the output folder.'
    Write-Host '  - Treat the result as confidential. It contains file and folder names.'
    Write-Host '------------------------------------------------------------------------------' -ForegroundColor DarkGray
}

# ----------------------------------------------------------------------------------------------
# SECTION 3. START-UP CHECKS AND RUN SETTINGS
# ----------------------------------------------------------------------------------------------

function Test-RunContext {
    # Confirms the script runs as a real user on Windows, and warns about a user mismatch.
    if ($env:OS -ne 'Windows_NT') {
        Write-Host 'This script supports Windows only.' -ForegroundColor Red
        exit 1
    }
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $script:CurrentUser = $id.Name
    $principal = New-Object Security.Principal.WindowsPrincipal($id)
    $script:IsElevated = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

    if ($id.IsSystem) {
        Write-Host ''
        Write-Host 'STOP: This script is running as SYSTEM.' -ForegroundColor Red
        Write-Host 'OneDrive settings belong to the signed-in user. Start a USER context shell and run it again.' -ForegroundColor Red
        exit 1
    }

    # Find who is signed in at the desktop. If it is a different person, the registry data would be wrong.
    $owners = @()
    try {
        foreach ($p in @(Get-CimInstance -ClassName Win32_Process -Filter "Name='explorer.exe'" -ErrorAction Stop)) {
            $o = Invoke-CimMethod -InputObject $p -MethodName GetOwner -ErrorAction Stop
            if ($o.User) { $owners += ($o.Domain + '\' + $o.User) }
        }
    }
    catch { }
    $script:ExplorerOwners = @($owners | Select-Object -Unique)
    $script:UserMismatch = $false
    if ($script:ExplorerOwners.Count -gt 0 -and ($script:ExplorerOwners -notcontains $id.Name)) {
        $script:UserMismatch = $true
    }
}

function New-OutputFolder {
    # Creates c:\temp\onedrivediag_<hostname>_<username>_<DATETIME>\ and the run log.
    $stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    $name = 'onedrivediag_{0}_{1}_{2}' -f $env:COMPUTERNAME, $env:USERNAME, $stamp
    $root = $OutputRoot
    try {
        if (-not (Test-Path -LiteralPath $root)) { New-Item -ItemType Directory -Path $root -Force -ErrorAction Stop | Out-Null }
        $script:OutDir = Join-Path $root $name
        New-Item -ItemType Directory -Path $script:OutDir -Force -ErrorAction Stop | Out-Null
    }
    catch {
        # The chosen location is not writable. Use the user temp folder instead.
        $root = $env:TEMP
        $script:OutDir = Join-Path $root $name
        New-Item -ItemType Directory -Path $script:OutDir -Force | Out-Null
        Write-Host ('  Could not write to {0}. Using {1} instead.' -f $OutputRoot, $root) -ForegroundColor Yellow
    }
    $script:OutputParent = $root
    $script:LogFile = Join-Path $script:OutDir '00_RunLog.txt'
    Write-Log ('Script version {0} started by {1} on {2}' -f $script:ScriptVersion, $script:CurrentUser, $env:COMPUTERNAME)
    # Write out the lines logged before this folder existed (start-up checks and early answers).
    if ($script:PendingLog.Count -gt 0) {
        try { Add-Content -LiteralPath $script:LogFile -Value @($script:PendingLog) -Encoding UTF8 -ErrorAction Stop } catch { }
        $script:PendingLog.Clear()
    }
}

function Get-RunSettings {
    # Fills in any setting the caller did not pass as a parameter, by asking from a list.
    $script:IsUnattended = ($Unattended.IsPresent -or (-not [Environment]::UserInteractive))

    # Collection level
    if ($script:BoundParams.ContainsKey('Level')) { $script:LevelName = $Level }
    else {
        $opts = @(
            'Quick     - settings, counters, events, network, top-level folder list (1 to 3 minutes)',
            'Standard  - Quick plus full file index and log signature scan (recommended)',
            'Deep      - Standard plus raw log copies (larger package)'
        )
        $pick = @(Select-FromList -Title 'How much should be collected?' -Options $opts -DefaultIndex 2)
        $script:LevelName = @('Quick', 'Standard', 'Deep')[$pick[0] - 1]
    }
    $script:LevelNum = switch ($script:LevelName) { 'Quick' { 1 } 'Standard' { 2 } 'Deep' { 3 } }

    # Zip choice
    if ($ZipOnly.IsPresent) { $script:DoZip = $true; $script:ZipKeepFolder = $false }
    elseif ($Zip.IsPresent) { $script:DoZip = $true; $script:ZipKeepFolder = $true }
    elseif (-not $script:IsUnattended) {
        $opts = @(
            'Keep the folder only (no zip)',
            'Keep the folder AND create a zip (easy to attach to a ticket)',
            'Create a zip only (the folder is removed after zipping)'
        )
        $pick = @(Select-FromList -Title 'How should the result be packaged?' -Options $opts -DefaultIndex 2)
        switch ($pick[0]) {
            1 { $script:DoZip = $false }
            2 { $script:DoZip = $true; $script:ZipKeepFolder = $true }
            3 { $script:DoZip = $true; $script:ZipKeepFolder = $false }
        }
    }

    $script:ScanFullIndex = $IncludeFullIndex.IsPresent
    if ($script:LevelNum -ge 3) { $script:IncludeRaw = $true } else { $script:IncludeRaw = $IncludeRawLogs.IsPresent }
}

# ----------------------------------------------------------------------------------------------
# SECTION 4. COLLECTION STEPS
# Each step is one function. A failure in one step never stops the others.
# ----------------------------------------------------------------------------------------------

function Step-Environment {
    # STEP: Windows, hardware, power, disks, security software, join state and sign-in token state.
    $o = New-Object System.Collections.ArrayList
    $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction SilentlyContinue
    $cs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction SilentlyContinue
    $cv = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction SilentlyContinue

    [void]$o.Add('=== IDENTITY ===')
    [void]$o.Add('Computer name        : ' + $env:COMPUTERNAME)
    [void]$o.Add('Running as           : ' + $script:CurrentUser)
    [void]$o.Add('Elevated (admin)     : ' + $script:IsElevated)
    [void]$o.Add('Desktop user(s)      : ' + ($script:ExplorerOwners -join ', '))
    [void]$o.Add('Session id           : ' + (Get-Process -Id $PID).SessionId)
    [void]$o.Add('Collected (local)    : ' + (Get-Date).ToString('yyyy-MM-dd HH:mm:ss zzz'))
    try { [void]$o.Add('Time zone           : ' + (Get-TimeZone).Id) } catch { }

    [void]$o.Add('')
    [void]$o.Add('=== WINDOWS ===')
    if ($os) {
        [void]$o.Add('Edition              : ' + $os.Caption)
        [void]$o.Add(('Version / build      : {0} build {1}.{2} ({3})' -f $cv.DisplayVersion, $cv.CurrentBuild, $cv.UBR, $os.OSArchitecture))
        [void]$o.Add('Last boot            : ' + $os.LastBootUpTime)
        $up = (Get-Date) - $os.LastBootUpTime
        [void]$o.Add(('Uptime               : {0} days {1} hours' -f $up.Days, $up.Hours))
        $script:Facts['Windows'] = '{0} {1} build {2}.{3}' -f $os.Caption, $cv.DisplayVersion, $cv.CurrentBuild, $cv.UBR
        $script:Facts['Uptime'] = '{0} days {1} hours' -f $up.Days, $up.Hours
    }
    $fs = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power' -ErrorAction SilentlyContinue
    if ($fs) { [void]$o.Add('Fast Startup enabled : ' + $fs.HiberbootEnabled) }
    $lp = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem' -ErrorAction SilentlyContinue
    if ($lp) { [void]$o.Add('Long paths enabled   : ' + $lp.LongPathsEnabled) }
    [void]$o.Add('PowerShell           : ' + $PSVersionTable.PSVersion + ' (' + $ExecutionContext.SessionState.LanguageMode + ')')

    [void]$o.Add('')
    [void]$o.Add('=== HARDWARE AND POWER ===')
    if ($cs) {
        [void]$o.Add(('Manufacturer / model : {0} {1}' -f $cs.Manufacturer, $cs.Model))
        [void]$o.Add('Memory               : ' + (Format-Bytes $cs.TotalPhysicalMemory))
        [void]$o.Add(('Domain / workgroup   : {0} (PartOfDomain={1})' -f $cs.Domain, $cs.PartOfDomain))
    }
    $bat = @(Get-CimInstance -ClassName Win32_Battery -ErrorAction SilentlyContinue)
    if ($bat.Count -gt 0) {
        foreach ($b in $bat) { [void]$o.Add(('Battery              : {0}% charge, status code {1}' -f $b.EstimatedChargeRemaining, $b.BatteryStatus)) }
    }
    else { [void]$o.Add('Battery              : none detected (desktop)') }
    try { [void]$o.Add('Active power plan    : ' + ((& powercfg.exe /getactivescheme) -join ' ')) } catch { }

    [void]$o.Add('')
    [void]$o.Add('=== FIXED DISKS ===')
    $sysDrive = $env:SystemDrive
    foreach ($d in @(Get-CimInstance -ClassName Win32_LogicalDisk -Filter 'DriveType=3' -ErrorAction SilentlyContinue)) {
        $pct = 0
        if ($d.Size -gt 0) { $pct = [math]::Round(100 * $d.FreeSpace / $d.Size, 1) }
        [void]$o.Add(('{0}  {1} total, {2} free ({3}%), {4}' -f $d.DeviceID, (Format-Bytes $d.Size), (Format-Bytes $d.FreeSpace), $pct, $d.FileSystem))
        if ($d.DeviceID -eq $sysDrive) {
            if ($d.FreeSpace -lt 2GB) {
                Add-Finding 'Environment' 'System drive free space' 'FAIL' ('Only {0} free on {1}.' -f (Format-Bytes $d.FreeSpace), $d.DeviceID) 'Free disk space first. OneDrive cannot download or hydrate files without space.'
            }
            elseif ($d.FreeSpace -lt 10GB -or $pct -lt 10) {
                Add-Finding 'Environment' 'System drive free space' 'WARN' ('{0} free ({1}%) on {2}.' -f (Format-Bytes $d.FreeSpace), $pct, $d.DeviceID) 'Low space can slow or block downloads. Consider freeing space.'
            }
            else {
                Add-Finding 'Environment' 'System drive free space' 'PASS' ('{0} free ({1}%) on {2}.' -f (Format-Bytes $d.FreeSpace), $pct, $d.DeviceID)
            }
        }
    }

    [void]$o.Add('')
    [void]$o.Add('=== SECURITY SOFTWARE (SecurityCenter2) ===')
    try {
        $av = @(Get-CimInstance -Namespace 'root\SecurityCenter2' -ClassName AntiVirusProduct -ErrorAction Stop)
        foreach ($a in $av) { [void]$o.Add(('Antivirus            : {0} (state {1})' -f $a.displayName, $a.productState)) }
        if ($av.Count -eq 0) { [void]$o.Add('No antivirus product reported.') }
    }
    catch { [void]$o.Add('Not available on this edition of Windows.') }

    # Controlled Folder Access (Defender ransomware protection) can silently block writes into Documents,
    # Desktop and Pictures. When those folders are moved into OneDrive this looks like a sync fault.
    [void]$o.Add('')
    [void]$o.Add('=== CONTROLLED FOLDER ACCESS (Microsoft Defender) ===')
    $cfaNames = @{ 0 = 'Off'; 1 = 'On (block)'; 2 = 'Audit only'; 3 = 'Block disk changes only'; 4 = 'Audit disk changes only' }
    $cfa = $null; $cfaSource = ''
    try {
        $mp = Get-MpPreference -ErrorAction Stop
        if ($null -ne $mp.EnableControlledFolderAccess) { $cfa = [int]$mp.EnableControlledFolderAccess; $cfaSource = 'Get-MpPreference' }
        if ($mp.ControlledFolderAccessAllowedApplications) { [void]$o.Add('Allowed apps         : ' + ($mp.ControlledFolderAccessAllowedApplications -join '; ')) }
    }
    catch { }
    if ($null -eq $cfa) {
        foreach ($k in @('HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Controlled Folder Access',
                'HKLM:\SOFTWARE\Microsoft\Windows Defender\Windows Defender Exploit Guard\Controlled Folder Access')) {
            $v = (Get-ItemProperty -Path $k -ErrorAction SilentlyContinue).EnableControlledFolderAccess
            if ($null -ne $v) { $cfa = [int]$v; $cfaSource = $k; break }
        }
    }
    if ($null -eq $cfa) { [void]$o.Add('State                : not readable (Defender may not be the active antivirus)') }
    else {
        [void]$o.Add(('State                : {0} ({1})  source {2}' -f $cfa, $cfaNames[$cfa], $cfaSource))
        $script:Facts['Controlled Folder Access'] = $cfaNames[$cfa]
    }
    # Block (1123) and audit (1124) events that name OneDrive or a file under a OneDrive folder.
    $cfaEvents = @()
    try {
        $cfaEvents = @(Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-Windows Defender/Operational'; Id = 1123, 1124; StartTime = (Get-Date).AddDays(-1 * $EventDays) } -MaxEvents 500 -ErrorAction Stop |
                Where-Object { $_.Message -match 'OneDrive' })
    }
    catch { }
    [void]$o.Add('Block/audit events naming OneDrive (last ' + $EventDays + ' days): ' + $cfaEvents.Count)
    foreach ($ev in ($cfaEvents | Select-Object -First 20)) {
        [void]$o.Add(('  {0}  id {1}  {2}' -f $ev.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss'), $ev.Id, (($ev.Message -replace '\s+', ' ').Trim() -replace '^(.{0,300}).*$', '$1')))
    }
    $blocks = @($cfaEvents | Where-Object { $_.Id -eq 1123 })
    if ($blocks.Count -gt 0) {
        Add-Finding 'Environment' 'Controlled Folder Access blocks' 'WARN' ('{0} Controlled Folder Access block event(s) mention OneDrive. Latest {1}.' -f $blocks.Count, $blocks[0].TimeCreated) 'Defender is blocking writes to protected folders. Ask security to allow the blocked app, or review the blocked paths in 01_Environment.txt.'
    }
    elseif ($cfa -eq 1 -or $cfa -eq 3) {
        Add-Finding 'Environment' 'Controlled Folder Access' 'INFO' ('Controlled Folder Access is {0}. No OneDrive blocks recorded.' -f $cfaNames[$cfa]) 'If files in Desktop or Documents will not save or sync, check Defender protection history.'
    }

    [void]$o.Add('')
    [void]$o.Add('=== OTHER SYNC OR BACKUP CLIENTS RUNNING ===')
    $others = @(Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.Name -match '^(dropbox|googledrivefs|box|boxsync|egnyte|nextcloud|syncthing|megasync|pcloud|synologydrive|citrixfiles|icloud)' })
    if ($others.Count -eq 0) { [void]$o.Add('None found.') }
    else {
        foreach ($p in $others) { [void]$o.Add(('{0} (pid {1})' -f $p.Name, $p.Id)) }
        Add-Finding 'Environment' 'Other sync clients' 'INFO' ('Running: ' + (($others | Select-Object -ExpandProperty Name -Unique) -join ', ')) 'Other sync tools can lock files or add their own icons in File Explorer.'
    }

    [void]$o.Add('')
    [void]$o.Add('=== EXECUTION POLICY ===')
    try { foreach ($l in (Get-ExecutionPolicy -List | Out-String -Stream)) { if ($l.Trim()) { [void]$o.Add($l) } } } catch { }

    Save-Text '01_Environment.txt' $o

    # Device join and sign-in token state. A missing Primary Refresh Token causes sign-in and sync authentication problems.
    try {
        $ds = (& dsregcmd.exe /status 2>&1 | Out-String)
        Save-Text '01_Environment_dsregcmd.txt' $ds
        $prt = [regex]::Match($ds, '(?im)^\s*AzureAdPrt\s*:\s*(\w+)')
        $aadj = [regex]::Match($ds, '(?im)^\s*AzureAdJoined\s*:\s*(\w+)')
        $dj = [regex]::Match($ds, '(?im)^\s*DomainJoined\s*:\s*(\w+)')
        $script:Facts['Join state'] = 'AzureAdJoined={0}, DomainJoined={1}, AzureAdPrt={2}' -f $aadj.Groups[1].Value, $dj.Groups[1].Value, $prt.Groups[1].Value
        if ($prt.Success -and $prt.Groups[1].Value -eq 'NO') {
            Add-Finding 'Environment' 'Primary Refresh Token' 'WARN' 'AzureAdPrt is NO for this user.' 'The user may face repeated sign-in prompts or sync authentication errors. Check the device registration and sign-in state.'
        }
        elseif ($prt.Success) {
            Add-Finding 'Environment' 'Primary Refresh Token' 'PASS' 'AzureAdPrt is YES.'
        }
    }
    catch { Write-Log ('dsregcmd failed: ' + $_.Exception.Message) 'WARN' }
}

function Step-Client {
    # STEP: Where OneDrive.exe is installed, which version, and whether it is running.
    $o = New-Object System.Collections.ArrayList
    $x86 = [Environment]::GetEnvironmentVariable('ProgramFiles(x86)')
    $candidates = @(
        @{ Path = (Join-Path $env:LOCALAPPDATA 'Microsoft\OneDrive\OneDrive.exe'); Type = 'Per-user install' },
        @{ Path = (Join-Path $env:ProgramFiles 'Microsoft OneDrive\OneDrive.exe'); Type = 'Per-machine install' }
    )
    if ($x86) { $candidates += @{ Path = (Join-Path $x86 'Microsoft OneDrive\OneDrive.exe'); Type = 'Per-machine install (32-bit)' } }

    [void]$o.Add('=== INSTALLED COPIES OF ONEDRIVE.EXE ===')
    $found = @()
    foreach ($c in $candidates) {
        if (Test-Path -LiteralPath $c.Path) {
            $vi = (Get-Item -LiteralPath $c.Path).VersionInfo
            [void]$o.Add(('{0}: {1}  version {2}' -f $c.Type, $c.Path, $vi.FileVersion))
            $found += [pscustomobject]@{ Type = $c.Type; Path = $c.Path; Version = $vi.FileVersion }
        }
    }
    if ($found.Count -eq 0) {
        [void]$o.Add('No OneDrive.exe found in the standard locations.')
        Add-Finding 'Client' 'OneDrive installed' 'FAIL' 'OneDrive.exe was not found in the standard install locations.' 'Install or repair OneDrive. Check whether the user has a non-standard install.'
    }
    else {
        $script:Facts['OneDrive version'] = $found[0].Version + ' (' + $found[0].Type + ')'
        if ($found.Count -gt 1) {
            Add-Finding 'Client' 'Multiple installs' 'INFO' ('{0} copies of OneDrive.exe found (per-user and per-machine).' -f $found.Count) 'Normal during a move from per-user to per-machine. Confirm which copy is running.'
        }
    }

    [void]$o.Add('')
    [void]$o.Add('=== RUNNING PROCESS (this user session) ===')
    $sid = (Get-Process -Id $PID).SessionId
    $procs = @(Get-Process -Name 'OneDrive' -ErrorAction SilentlyContinue | Where-Object { $_.SessionId -eq $sid })
    if ($procs.Count -eq 0) {
        [void]$o.Add('OneDrive is NOT running in this session.')
        $script:Facts['OneDrive running'] = 'No'
        Add-Finding 'Client' 'OneDrive process' 'FAIL' 'OneDrive.exe is not running in the user session.' 'Start OneDrive from the Start menu and confirm it stays running. Check for crash events in 07_Events_OneDrive_Application.csv.'
    }
    else {
        foreach ($p in $procs) {
            $path = ''
            try { $path = $p.Path } catch { }
            [void]$o.Add(('PID {0}  started {1}  CPU {2:N0}s  memory {3}  handles {4}  threads {5}' -f $p.Id, $p.StartTime, $p.CPU, (Format-Bytes $p.WorkingSet64), $p.HandleCount, $p.Threads.Count))
            [void]$o.Add('Path: ' + $path)
        }
        $script:Facts['OneDrive running'] = 'Yes (started ' + $procs[0].StartTime + ')'
        Add-Finding 'Client' 'OneDrive process' 'PASS' ('Running, started {0}.' -f $procs[0].StartTime)
        if ($procs[0].WorkingSet64 -gt 2GB) {
            Add-Finding 'Client' 'OneDrive memory' 'WARN' ('OneDrive is using {0} of memory.' -f (Format-Bytes $procs[0].WorkingSet64)) 'Very high memory use is common on libraries with many files. Note it for the escalation.'
        }
    }

    [void]$o.Add('')
    [void]$o.Add('=== STARTUP ENTRY ===')
    $run = Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' -ErrorAction SilentlyContinue
    if ($run -and $run.OneDrive) { [void]$o.Add('Run key: ' + $run.OneDrive) } else { [void]$o.Add('No OneDrive entry in the HKCU Run key.') }

    [void]$o.Add('')
    [void]$o.Add('=== UPDATE SCHEDULED TASKS ===')
    try {
        $tasks = @(Get-ScheduledTask -TaskName 'OneDrive*' -ErrorAction Stop)
        foreach ($t in $tasks) {
            $ti = Get-ScheduledTaskInfo -InputObject $t -ErrorAction SilentlyContinue
            [void]$o.Add(('{0}  state {1}  last run {2}  last result {3}' -f $t.TaskName, $t.State, $ti.LastRunTime, $ti.LastTaskResult))
        }
        if ($tasks.Count -eq 0) { [void]$o.Add('No OneDrive scheduled tasks visible.') }
    }
    catch { [void]$o.Add('Scheduled tasks could not be read: ' + $_.Exception.Message) }

    [void]$o.Add('')
    [void]$o.Add('=== HKCU\Software\Microsoft\OneDrive (top-level values) ===')
    $od = Get-ItemProperty 'HKCU:\Software\Microsoft\OneDrive' -ErrorAction SilentlyContinue
    if ($od) {
        foreach ($prop in $od.PSObject.Properties) {
            if ($prop.Name -notmatch '^PS(Path|ParentPath|ChildName|Drive|Provider)$') { [void]$o.Add(('{0} = {1}' -f $prop.Name, $prop.Value)) }
        }
    }
    Save-Text '02_OneDrive_Client.txt' $o
}

function Get-OneDriveFileLines {
    # Reads a OneDrive text file and returns its lines.
    # OneDrive writes most .ini files as UTF-16 WITHOUT a byte order mark, which Get-Content reads as
    # garbage on Windows PowerShell 5.1. So the encoding is detected from the bytes:
    #   FF FE (BOM) or a zero byte in position 2 or 4 -> UTF-16 LE. EF BB BF -> UTF-8. Anything else -> UTF-8.
    # The file is opened with shared read access because OneDrive may have it open.
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { return @() }
    $fs = $null
    try {
        $fs = New-Object System.IO.FileStream($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, ([System.IO.FileShare]::ReadWrite -bor [System.IO.FileShare]::Delete))
        if ($fs.Length -gt 50MB) { return @() }
        $buf = New-Object byte[] ([int]$fs.Length)
        $read = 0
        while ($read -lt $buf.Length) {
            $n = $fs.Read($buf, $read, $buf.Length - $read)
            if ($n -le 0) { break }
            $read += $n
        }
    }
    catch { return @() }
    finally { if ($fs) { $fs.Close() } }
    if ($buf.Length -eq 0) { return @() }

    $enc = [System.Text.Encoding]::UTF8
    $skip = 0
    if ($buf.Length -ge 2 -and $buf[0] -eq 0xFF -and $buf[1] -eq 0xFE) { $enc = [System.Text.Encoding]::Unicode; $skip = 2 }
    elseif ($buf.Length -ge 3 -and $buf[0] -eq 0xEF -and $buf[1] -eq 0xBB -and $buf[2] -eq 0xBF) { $skip = 3 }
    elseif (($buf.Length -ge 2 -and $buf[1] -eq 0) -or ($buf.Length -ge 4 -and $buf[3] -eq 0)) { $enc = [System.Text.Encoding]::Unicode }
    $text = $enc.GetString($buf, $skip, $buf.Length - $skip)
    return @([regex]::Split($text, '\r?\n'))
}

function Get-IniKeyValues {
    # Reads a simple "key = value" file into an ordered hashtable (any encoding OneDrive uses).
    param([string]$Path)
    $kv = [ordered]@{}
    foreach ($line in (Get-OneDriveFileLines -Path $Path)) {
        if ($line -match '^\s*([A-Za-z0-9_]+)\s*=\s*(.*?)\s*$') { $kv[$Matches[1]] = $Matches[2] }
    }
    return $kv
}

function Step-AccountsAndRoots {
    # STEP: Find every OneDrive account and every synced library. This gives the REAL local folders.
    # SharePoint libraries are frequently mounted outside the "OneDrive - <Company>" folder, so we cannot guess the path.
    $o = New-Object System.Collections.ArrayList
    $odBase = Join-Path $env:LOCALAPPDATA 'Microsoft\OneDrive'
    $accounts = New-Object System.Collections.ArrayList

    [void]$o.Add('=== ONEDRIVE ACCOUNTS (HKCU:\Software\Microsoft\OneDrive\Accounts) ===')
    $accBase = 'HKCU:\Software\Microsoft\OneDrive\Accounts'
    if (Test-Path $accBase) {
        foreach ($k in @(Get-ChildItem $accBase -ErrorAction SilentlyContinue)) {
            $p = Get-ItemProperty -LiteralPath $k.PSPath -ErrorAction SilentlyContinue
            if ($null -eq $p) { continue }
            [void]$o.Add('')
            [void]$o.Add('[' + $k.PSChildName + ']')
            foreach ($prop in $p.PSObject.Properties) {
                if ($prop.Name -notmatch '^PS(Path|ParentPath|ChildName|Drive|Provider)$') { [void]$o.Add(('  {0} = {1}' -f $prop.Name, $prop.Value)) }
            }
            if ($p.UserFolder -or $p.UserEmail) {
                [void]$accounts.Add([pscustomobject]@{
                        Key = $k.PSChildName; Email = $p.UserEmail; UserFolder = $p.UserFolder; DisplayName = $p.DisplayName
                        TenantId = [string]$p.ConfiguredTenantId
                        SettingsDir = (Join-Path $odBase ('settings\' + $k.PSChildName))
                        LogsDir = (Join-Path $odBase ('logs\' + $k.PSChildName))
                    })
            }
        }
    }
    $script:Accounts = @($accounts)
    if ($script:Accounts.Count -eq 0) {
        Add-Finding 'Accounts' 'OneDrive account signed in' 'FAIL' 'No OneDrive account with a user folder was found in the registry.' 'The user may not be signed in to OneDrive. Ask the user to sign in, then run this tool again.'
    }
    else {
        $script:Facts['Accounts'] = (($script:Accounts | ForEach-Object { '{0} ({1})' -f $_.Email, $_.Key }) -join '; ')
        Add-Finding 'Accounts' 'OneDrive account signed in' 'PASS' ('{0} account(s): {1}' -f $script:Accounts.Count, (($script:Accounts | ForEach-Object { $_.Email }) -join ', '))
    }

    # Read the library table in each account ini file. It maps scope ids to site, library and local folder.
    #   libraryScope  = one synced library (site title, library title, URL, local folder)
    #   libraryFolder = a folder shortcut ("Add shortcut to My files") or a single synced folder
    $scopeInfo = @{}
    $shortcuts = New-Object System.Collections.ArrayList
    foreach ($a in $script:Accounts) {
        if (-not (Test-Path -LiteralPath $a.SettingsDir)) { continue }
        foreach ($ini in @(Get-ChildItem -LiteralPath $a.SettingsDir -Filter '*.ini' -ErrorAction SilentlyContinue)) {
            foreach ($line in (Get-OneDriveFileLines -Path $ini.FullName)) {
                if ($line -notmatch '^library(Scope|Folder)\s*=') { continue }
                $mount = [regex]::Match($line, '"([A-Za-z]:\\[^"]*)"').Groups[1].Value
                $m = [regex]::Match($line, '^libraryScope\s*=\s*\d+\s+(\S+)\s+\d+\s+"([^"]*)"\s+"([^"]*)"\s+\d+\s+"([^"]*)"')
                if ($m.Success) {
                    $scopeInfo[$m.Groups[1].Value] = [pscustomobject]@{ Site = $m.Groups[2].Value; Library = $m.Groups[3].Value; WebUrl = $m.Groups[4].Value; Mount = $mount; Account = $a.Key }
                    continue
                }
                # libraryFolder = <n> <n> <scopeid> <time> "<local folder>" <n> "<folder name>" ...
                $f = [regex]::Match($line, '^libraryFolder\s*=\s*\d+\s+\d+\s+(\S+)\s+\d+\s+"([^"]*)"\s+\d+\s+"([^"]*)"')
                if ($f.Success -and $f.Groups[2].Value) {
                    [void]$shortcuts.Add([pscustomobject]@{ ScopeId = $f.Groups[1].Value; Mount = $f.Groups[2].Value.TrimEnd('\'); Name = $f.Groups[3].Value; Account = $a.Key })
                }
            }
        }
    }

    # Read every sync root Windows knows about.
    $roots = New-Object System.Collections.ArrayList
    $provBase = 'HKCU:\Software\SyncEngines\Providers\OneDrive'
    if (Test-Path $provBase) {
        foreach ($k in @(Get-ChildItem $provBase -ErrorAction SilentlyContinue)) {
            $p = Get-ItemProperty -LiteralPath $k.PSPath -ErrorAction SilentlyContinue
            if ($null -eq $p -or [string]::IsNullOrWhiteSpace($p.MountPoint)) { continue }
            $mp = ([string]$p.MountPoint).TrimEnd('\')
            $existing = $roots | Where-Object { $_.MountPoint -ieq $mp } | Select-Object -First 1
            if ($existing) {
                if (-not $existing.LibraryUrl -and $p.UrlNamespace) { $existing.LibraryUrl = [string]$p.UrlNamespace }
                if ($p.LibraryType -eq 'mysite') { $existing.LibraryType = 'mysite' }
                continue
            }
            $info = $scopeInfo[$k.PSChildName]
            [void]$roots.Add([pscustomobject]@{
                    ScopeId = $k.PSChildName; LibraryType = [string]$p.LibraryType; MountPoint = $mp
                    LibraryUrl = [string]$p.UrlNamespace; WebUrl = [string]$p.WebUrl
                    SiteTitle = $(if ($info) { $info.Site } else { '' }); LibraryTitle = $(if ($info) { $info.Library } else { '' })
                    Account = $(if ($info) { $info.Account } else { '' })
                    Title = ''; Type = ''; Exists = $false; Drive = ''; DriveType = ''; DriveSize = 0; ServerPrefixLen = -1; FreeBytes = 0
                })
        }
    }
    # Fall back to account user folders and OneDrive environment variables.
    $fallback = @()
    foreach ($a in $script:Accounts) { if ($a.UserFolder) { $fallback += $a.UserFolder } }
    foreach ($ev in @('OneDriveCommercial', 'OneDrive', 'OneDriveConsumer')) {
        $v = [Environment]::GetEnvironmentVariable($ev)
        if ($v) { $fallback += $v }
    }
    foreach ($f in $fallback) {
        $mp = ([string]$f).TrimEnd('\')
        if (-not ($roots | Where-Object { $_.MountPoint -ieq $mp })) {
            [void]$roots.Add([pscustomobject]@{
                    ScopeId = ''; LibraryType = 'account-folder'; MountPoint = $mp; LibraryUrl = ''; WebUrl = ''
                    SiteTitle = ''; LibraryTitle = ''; Account = ''; Title = ''; Type = ''; Exists = $false
                    Drive = ''; DriveType = ''; DriveSize = 0; ServerPrefixLen = -1; FreeBytes = 0
                })
        }
    }
    # Folder shortcuts. They usually sit inside the OneDrive folder, but are listed separately so they can be chosen on their own.
    foreach ($sc in $shortcuts) {
        $hit = $roots | Where-Object { $_.MountPoint -ieq $sc.Mount } | Select-Object -First 1
        if ($hit) { $hit.LibraryType = 'shortcut'; $hit.LibraryTitle = $sc.Name; continue }
        [void]$roots.Add([pscustomobject]@{
                ScopeId = $sc.ScopeId; LibraryType = 'shortcut'; MountPoint = $sc.Mount; LibraryUrl = ''; WebUrl = ''
                SiteTitle = ''; LibraryTitle = $sc.Name; Account = $sc.Account; Title = ''; Type = ''; Exists = $false
                Drive = ''; DriveType = ''; DriveSize = 0; ServerPrefixLen = -1; FreeBytes = 0
            })
    }

    # Work out friendly names, drive details and the server path length used by the SharePoint 400 character check.
    $driveCache = @{}
    foreach ($r in $roots) {
        switch ($r.LibraryType) {
            'mysite' { $r.Type = 'OneDrive (personal)'; $r.Title = 'OneDrive personal' }
            'personal' { $r.Type = 'OneDrive (personal)'; $r.Title = 'OneDrive personal' }
            'teamsite' {
                $r.Type = 'SharePoint library'
                if ($r.SiteTitle -or $r.LibraryTitle) { $r.Title = ('{0} - {1}' -f $r.SiteTitle, $r.LibraryTitle) } else { $r.Title = (Split-Path -Leaf $r.MountPoint) }
            }
            'shortcut' {
                $r.Type = 'Folder shortcut'
                if ($r.LibraryTitle) { $r.Title = $r.LibraryTitle } else { $r.Title = (Split-Path -Leaf $r.MountPoint) }
            }
            default { $r.Type = 'OneDrive folder'; $r.Title = (Split-Path -Leaf $r.MountPoint) }
        }
        $r.Exists = Test-Path -LiteralPath $r.MountPoint
        $r.Drive = [IO.Path]::GetPathRoot($r.MountPoint)
        $dl = $r.Drive.TrimEnd('\')
        if (-not $driveCache.ContainsKey($dl)) {
            $driveCache[$dl] = Get-CimInstance -ClassName Win32_LogicalDisk -Filter ("DeviceID='{0}'" -f $dl) -ErrorAction SilentlyContinue
        }
        $ld = $driveCache[$dl]
        if ($ld) { $r.DriveType = [string]$ld.DriveType; $r.FreeBytes = [long]$ld.FreeSpace; $r.DriveSize = [long]$ld.Size }
        if ($r.LibraryUrl) {
            try {
                $u = [Uri]$r.LibraryUrl
                $r.ServerPrefixLen = ([Uri]::UnescapeDataString($u.AbsolutePath)).TrimEnd('/').Length
            }
            catch { }
        }
    }
    $script:SyncRoots = @($roots)

    [void]$o.Add('')
    [void]$o.Add('=== SYNC ROOTS (local folders that OneDrive keeps in sync) ===')
    foreach ($r in $script:SyncRoots) {
        [void]$o.Add('')
        [void]$o.Add('Title        : ' + $r.Title)
        [void]$o.Add('Type         : ' + $r.Type + ' (' + $r.LibraryType + ')')
        [void]$o.Add('Local folder : ' + $r.MountPoint)
        [void]$o.Add('Exists       : ' + $r.Exists)
        [void]$o.Add('Library URL  : ' + $r.LibraryUrl)
        [void]$o.Add('Scope id     : ' + $r.ScopeId)
        if ($r.Exists) { Add-Finding 'Sync roots' ('Folder exists: ' + $r.Title) 'PASS' $r.MountPoint }
        else { Add-Finding 'Sync roots' ('Folder exists: ' + $r.Title) 'FAIL' ('Local folder is missing: ' + $r.MountPoint) 'OneDrive expects this folder. It may have been moved, renamed or deleted. Escalate before any reset.' }
        if ($r.DriveType -eq '4') { Add-Finding 'Sync roots' ('Network drive: ' + $r.Title) 'WARN' 'The sync folder is on a network drive.' 'OneDrive sync folders should be on a local fixed disk.' }
    }

    # Free space on every drive that holds a sync root. The system drive is already checked in the Environment step.
    $drivesSeen = @{}
    foreach ($r in $script:SyncRoots) {
        $dl = ([string]$r.Drive).TrimEnd('\')
        if (-not $dl -or $drivesSeen.ContainsKey($dl) -or $dl -ieq $env:SystemDrive -or $r.DriveSize -le 0) { continue }
        $drivesSeen[$dl] = $true
        $pct = [math]::Round(100 * $r.FreeBytes / $r.DriveSize, 1)
        $txt = '{0} free ({1}%) on {2}, which holds {3}.' -f (Format-Bytes $r.FreeBytes), $pct, $dl, $r.Title
        if ($r.FreeBytes -lt 2GB) { Add-Finding 'Sync roots' ('Free space ' + $dl) 'FAIL' $txt 'OneDrive cannot download or keep files on this drive. Free space first.' }
        elseif ($r.FreeBytes -lt 10GB -or $pct -lt 10) { Add-Finding 'Sync roots' ('Free space ' + $dl) 'WARN' $txt 'Low space can slow or block downloads to this drive.' }
        else { Add-Finding 'Sync roots' ('Free space ' + $dl) 'PASS' $txt }
    }
    if ($script:SyncRoots.Count -eq 0) {
        Add-Finding 'Sync roots' 'Sync roots found' 'FAIL' 'No sync root was found.' 'Check that OneDrive is signed in and set up.'
    }
    else {
        $script:Facts['Sync roots'] = ('{0} folder(s)' -f $script:SyncRoots.Count)
        Add-Finding 'Sync roots' 'Sync roots found' 'INFO' (('{0} sync root(s): ' -f $script:SyncRoots.Count) + (($script:SyncRoots | ForEach-Object { $_.Title }) -join '; ')) 'Each root has its own local folder. Check the right one when a user reports a problem.'
    }
    Save-Csv '03_SyncRoots.csv' ($script:SyncRoots | Select-Object -Property @('Title', 'Type', 'LibraryType', 'MountPoint', 'Exists', 'LibraryUrl', 'ScopeId', 'Account', 'Drive', 'DriveType'))

    # Known Folder Move: shows whether Desktop, Documents and Pictures are redirected into OneDrive.
    [void]$o.Add('')
    [void]$o.Add('=== KNOWN FOLDERS (User Shell Folders) ===')
    $usf = Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders' -ErrorAction SilentlyContinue
    if ($usf) {
        foreach ($n in @('Desktop', 'Personal', 'My Pictures', 'My Music', 'My Video', '{374DE290-123F-4565-9164-39C4925E467B}')) {
            $v = $usf.$n
            if ($v) { [void]$o.Add(('{0,-42} {1}' -f $n, $v)) }
        }
    }

    # Per-account settings: ini files carry flags that explain many sync faults.
    foreach ($a in $script:Accounts) {
        [void]$o.Add('')
        [void]$o.Add('=== SETTINGS FLAGS for account ' + $a.Key + ' ===')
        $g = Get-IniKeyValues (Join-Path $a.SettingsDir 'global.ini')
        foreach ($name in @('PlaceholdersTurnedOffByFilterError', 'FilterConnectionErrorDialogTriggered', 'SavedPlaceholdersEnabledState', 'PlaceholdersEnabledUserSettingTribit',
                'IsCleanShutdown', 'LastCleanShutdownTimestamp', 'PreviousDiagnosticsRunSyncProblemsCount', 'LocalMassDeleteDetectedTime',
                'ConsecutiveHealthySyncVerificationRuns', 'RestartsSinceDBValidation', 'TeamSitesDehydrationTriggered', 'LastKnownOfficeVersion')) {
            if ($g.Contains($name)) { [void]$o.Add(('{0} = {1}' -f $name, $g[$name])) }
        }
        if ($g['PlaceholdersTurnedOffByFilterError'] -eq 'true') {
            Add-Finding 'Accounts' 'Files On-Demand turned off by filter error' 'FAIL' ('Account {0}: PlaceholdersTurnedOffByFilterError is true.' -f $a.Key) 'The Windows Cloud Files driver failed to connect. Escalate. A restart or driver repair may be needed.'
        }
        if ($g['FilterConnectionErrorDialogTriggered'] -eq 'true') {
            Add-Finding 'Accounts' 'Filter connection error dialog' 'WARN' ('Account {0}: the filter connection error dialog was shown.' -f $a.Key) 'The Cloud Files driver had a connection problem at some point.'
        }
        if ($g['IsCleanShutdown'] -eq 'false') {
            Add-Finding 'Accounts' 'Clean shutdown' 'WARN' ('Account {0}: OneDrive did not shut down cleanly last time.' -f $a.Key) 'This matches a power loss or crash. Check the power events in 07_Events_System_PowerBoot.csv.'
        }
        if ($g['PreviousDiagnosticsRunSyncProblemsCount'] -and ([int]$g['PreviousDiagnosticsRunSyncProblemsCount'] -gt 0)) {
            Add-Finding 'Accounts' 'Previous diagnostics sync problems' 'WARN' ('Account {0}: the last built-in diagnostics run found {1} sync problem(s).' -f $a.Key, $g['PreviousDiagnosticsRunSyncProblemsCount']) 'Review 04_SyncDiagnostics_Parsed.txt.'
        }
        if ($g['LocalMassDeleteDetectedTime'] -and $g['LocalMassDeleteDetectedTime'] -ne '0') {
            Add-Finding 'Accounts' 'Mass delete detected' 'WARN' ('Account {0}: OneDrive recorded a local mass delete event (value {1}).' -f $a.Key, $g['LocalMassDeleteDetectedTime']) 'Confirm the user did not delete a large folder. Check the recycle bin and SharePoint recycle bin.'
        }
        # The account ini named after the account id (guid.ini) carries limits and permission state.
        foreach ($ini in @(Get-ChildItem -LiteralPath $a.SettingsDir -Filter '*-*-*-*-*.ini' -ErrorAction SilentlyContinue)) {
            $kv = Get-IniKeyValues $ini.FullName
            foreach ($name in @('uploadLimitKbPerSec', 'downloadLimitKbPerSec', 'uploadSpeedAutoLimited', 'edpManaged', 'pendingPermissionInheritanceChange', 'needsPlaceholderTransition', 'lastRefreshTime', 'bytesTransferred', 'requestsSent')) {
                if ($kv.Contains($name)) {
                    $val = $kv[$name]
                    if ($name -eq 'lastRefreshTime' -and $val -match '^\d+$') { $val = $val + '  (' + [DateTimeOffset]::FromUnixTimeSeconds([long]$val).LocalDateTime.ToString('yyyy-MM-dd HH:mm:ss') + ')' }
                    [void]$o.Add(('{0} = {1}   [{2}]' -f $name, $val, $ini.Name))
                }
            }
            if ($kv['pendingPermissionInheritanceChange'] -and $kv['pendingPermissionInheritanceChange'] -ne 'None') {
                Add-Finding 'Accounts' 'Pending permission change' 'WARN' ('Account {0}: pending permission inheritance change = {1}.' -f $a.Key, $kv['pendingPermissionInheritanceChange']) 'A permission change is waiting to apply. Check SharePoint permissions for the affected library.'
            }
            if ($kv['needsPlaceholderTransition'] -eq 'true') {
                Add-Finding 'Accounts' 'Placeholder transition needed' 'WARN' ('Account {0}: needsPlaceholderTransition is true.' -f $a.Key) 'OneDrive still needs to convert files to Files On-Demand placeholders.'
            }
            foreach ($lim in @('uploadLimitKbPerSec', 'downloadLimitKbPerSec')) {
                if ($kv[$lim] -and $kv[$lim] -match '^\d+$' -and [int]$kv[$lim] -gt 0) {
                    Add-Finding 'Accounts' ('Bandwidth limit ' + $lim) 'INFO' ('Account {0}: {1} = {2} KB/s.' -f $a.Key, $lim, $kv[$lim]) 'A manual or automatic bandwidth limit slows sync.'
                }
            }
        }
    }
    Save-Text '03_Accounts_and_SyncRoots.txt' $o
}

function Step-SyncDiagnostics {
    # STEP: Parse SyncDiagnostics.log. This file is written by OneDrive itself and holds the sync engine counters.
    $o = New-Object System.Collections.ArrayList

    # Counters that should be zero on a healthy client. Any value above zero is reported.
    $errorCounters = @('conflictsFailed', 'failedBytesDownloadedTotal', 'failedBytesUploadedTotal', 'numAbortedMissingServerChanges',
        'numAbortedReSyncNeeded', 'numAbortedUnexpectedHttpStatus', 'numAbortedWatcherEtagDifference', 'numDownloadErrorsReported',
        'numFileFailedDownloads', 'numFileFailedUploads', 'numFileInWarning', 'numHashMismatchErrorsReported', 'numRealizerErrorsReported',
        'numUploadErrorsReported', 'errorFromGetDiskSizeAPICall')
    $stallCounters = @('syncStallDetected', 'scanStateStallDetected')

    foreach ($a in $script:Accounts) {
        $file = Join-Path $a.LogsDir 'SyncDiagnostics.log'
        [void]$o.Add('=== ACCOUNT ' + $a.Key + ' (' + $a.Email + ') ===')
        if (-not (Test-Path -LiteralPath $file)) {
            [void]$o.Add('SyncDiagnostics.log not found at ' + $file)
            Add-Finding 'Sync counters' ('SyncDiagnostics.log (' + $a.Key + ')') 'INFO' 'File not found.' 'OneDrive may not have run long enough to create it.'
            continue
        }
        Copy-Item -LiteralPath $file -Destination (Join-Path $script:OutDir ('04_SyncDiagnostics_raw_' + (Get-SafeName $a.Key) + '.log')) -ErrorAction SilentlyContinue
        $kv = Get-IniKeyValues $file
        [void]$o.Add('File last written: ' + (Get-Item -LiteralPath $file).LastWriteTime)

        $flagged = @()
        foreach ($c in $errorCounters) {
            if ($kv.Contains($c) -and $kv[$c] -match '^-?\d+(\.\d+)?$' -and [double]$kv[$c] -gt 0) { $flagged += ('{0}={1}' -f $c, $kv[$c]) }
        }
        foreach ($c in $stallCounters) {
            if ($kv.Contains($c) -and $kv[$c] -match '^-?\d+$' -and [int]$kv[$c] -gt 0) {
                Add-Finding 'Sync counters' ($c + ' (' + $a.Key + ')') 'FAIL' ('{0} = {1}.' -f $c, $kv[$c]) 'The sync engine reports a stall. Escalate with this package.'
            }
        }
        if ($flagged.Count -gt 0) {
            Add-Finding 'Sync counters' ('Error counters (' + $a.Key + ')') 'WARN' ($flagged -join ', ') 'The sync engine reports errors. See the log signature file 12_ODL_Signatures.txt for the matching error text.'
        }
        else {
            Add-Finding 'Sync counters' ('Error counters (' + $a.Key + ')') 'PASS' 'All upload, download, hash, realizer and conflict error counters are zero.' ''
        }
        if ($kv['wasFileDBReset'] -eq '1') {
            Add-Finding 'Sync counters' ('Sync database reset (' + $a.Key + ')') 'WARN' 'wasFileDBReset = 1. OneDrive rebuilt its local database.' 'A rebuild causes a full re-scan and can take a long time on large libraries.'
        }
        if ($kv['numResyncs'] -and $kv['numResyncs'] -match '^\d+$' -and [int]$kv['numResyncs'] -gt 0) {
            Add-Finding 'Sync counters' ('Resyncs (' + $a.Key + ')') 'INFO' ('numResyncs = ' + $kv['numResyncs']) ''
        }
        foreach ($c in @('filesToDownload', 'driveChangesToSend', 'numLocalChanges', 'drivesWaitingForInitialSync')) {
            if ($kv.Contains($c) -and $kv[$c] -match '^\d+$' -and [int]$kv[$c] -gt 0) {
                Add-Finding 'Sync counters' ($c + ' (' + $a.Key + ')') 'INFO' ('{0} = {1} (work still in the queue).' -f $c, $kv[$c]) ''
            }
        }
        # Age of the data. Old data while OneDrive runs means the diagnostics are not being refreshed.
        if ($kv['timeUtc']) {
            try {
                $t = [datetime]::Parse($kv['timeUtc'], [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::RoundtripKind)
                $age = (Get-Date).ToUniversalTime() - $t.ToUniversalTime()
                [void]$o.Add(('Snapshot time (UTC): {0}  ({1:N1} hours old)' -f $kv['timeUtc'], $age.TotalHours))
                if ($age.TotalHours -gt 24) {
                    Add-Finding 'Sync counters' ('Snapshot age (' + $a.Key + ')') 'WARN' ('SyncDiagnostics is {0:N0} hours old.' -f $age.TotalHours) 'OneDrive may not be running or may be stuck. Check the client process result.'
                }
            }
            catch { }
        }
        if ($kv['files'] -match '^\d+$' -and $kv['folders'] -match '^\d+$') {
            $script:EstimatedItems += ([long]$kv['files'] + [long]$kv['folders'])
            $script:Facts['Items synced (' + $a.Key + ')'] = ('{0:N0} files, {1:N0} folders' -f [long]$kv['files'], [long]$kv['folders'])
            if (([long]$kv['files'] + [long]$kv['folders']) -gt 300000) {
                Add-Finding 'Sync counters' ('Very large sync set (' + $a.Key + ')') 'INFO' ('{0:N0} files and {1:N0} folders are synced.' -f [long]$kv['files'], [long]$kv['folders']) 'Microsoft recommends staying well below 300,000 items per account. Large sets slow scans and icon updates.'
            }
        }
        [void]$o.Add('')
        [void]$o.Add('--- All values ---')
        foreach ($key in $kv.Keys) {
            $mark = ''
            if ($flagged | Where-Object { $_ -like ($key + '=*') }) { $mark = '   <== ERROR COUNTER ABOVE ZERO' }
            [void]$o.Add(('{0,-52} {1}{2}' -f $key, $kv[$key], $mark))
        }
        [void]$o.Add('')
    }
    if ($script:Accounts.Count -eq 0) { [void]$o.Add('No accounts to read.') }
    Save-Text '04_SyncDiagnostics_Parsed.txt' $o
}

function Step-Registry {
    # STEP: Export the registry areas that control OneDrive, then read the policies in plain language.
    $o = New-Object System.Collections.ArrayList
    $keys = @(
        @{ Key = 'HKCU\Software\Microsoft\OneDrive'; File = 'HKCU_OneDrive.reg' },
        @{ Key = 'HKCU\Software\SyncEngines'; File = 'HKCU_SyncEngines.reg' },
        @{ Key = 'HKCU\Software\Policies\Microsoft\OneDrive'; File = 'HKCU_Policies_OneDrive.reg' },
        @{ Key = 'HKLM\SOFTWARE\Policies\Microsoft\OneDrive'; File = 'HKLM_Policies_OneDrive.reg' },
        @{ Key = 'HKLM\SOFTWARE\Microsoft\OneDrive'; File = 'HKLM_OneDrive.reg' },
        @{ Key = 'HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders'; File = 'HKCU_UserShellFolders.reg' },
        @{ Key = 'HKCU\Software\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy'; File = 'HKCU_StorageSense.reg' },
        @{ Key = 'HKLM\SYSTEM\CurrentControlSet\Services\CldFlt'; File = 'HKLM_CldFlt_Service.reg' },
        @{ Key = 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ShellIconOverlayIdentifiers'; File = 'HKLM_ShellIconOverlays.reg' }
    )
    foreach ($k in $keys) {
        $target = Join-Path $script:OutDir ('05_Registry\' + $k.File)
        $parent = Split-Path -Parent $target
        if (-not (Test-Path -LiteralPath $parent)) { New-Item -ItemType Directory -Path $parent -Force | Out-Null }
        try {
            $null = & reg.exe export $k.Key $target /y 2>&1
            if ($LASTEXITCODE -eq 0) { [void]$o.Add('Exported : ' + $k.Key) }
            else { [void]$o.Add('Not present or no access : ' + $k.Key) }
        }
        catch { [void]$o.Add('Failed : ' + $k.Key + ' - ' + $_.Exception.Message) }
    }
    Write-Status 'OK' ('Registry export finished ({0} keys checked).' -f $keys.Count)

    # Policies in plain language.
    [void]$o.Add('')
    [void]$o.Add('=== ONEDRIVE POLICIES (values set by IT) ===')
    $policyCount = 0
    foreach ($pk in @('HKLM:\SOFTWARE\Policies\Microsoft\OneDrive', 'HKCU:\Software\Policies\Microsoft\OneDrive')) {
        $p = Get-ItemProperty -Path $pk -ErrorAction SilentlyContinue
        if ($p) {
            [void]$o.Add('[' + $pk + ']')
            foreach ($prop in $p.PSObject.Properties) {
                if ($prop.Name -notmatch '^PS(Path|ParentPath|ChildName|Drive|Provider)$') { [void]$o.Add(('  {0} = {1}' -f $prop.Name, $prop.Value)); $policyCount++ }
            }
            if ($p.DisableFileSyncNGSC -eq 1) {
                Add-Finding 'Policy' 'OneDrive sync disabled by policy' 'FAIL' 'DisableFileSyncNGSC = 1 is set.' 'A policy blocks OneDrive sync. Review the policy source.'
            }
            if ($p.FilesOnDemandEnabled -eq 0) {
                Add-Finding 'Policy' 'Files On-Demand disabled by policy' 'INFO' 'FilesOnDemandEnabled = 0 is set.' 'All files are kept fully on disk. Check disk space for large libraries.'
            }
        }
    }
    if ($policyCount -eq 0) { [void]$o.Add('No OneDrive policy values found.') }
    $script:Facts['OneDrive policy values'] = $policyCount

    # Key policies in plain language. Machine (HKLM) policy wins over user (HKCU) policy.
    $pol = @{}
    foreach ($pk in @('HKCU:\Software\Policies\Microsoft\OneDrive', 'HKLM:\SOFTWARE\Policies\Microsoft\OneDrive')) {
        $p = Get-ItemProperty -Path $pk -ErrorAction SilentlyContinue
        if ($p) { foreach ($prop in $p.PSObject.Properties) { if ($prop.Name -notmatch '^PS(Path|ParentPath|ChildName|Drive|Provider)$') { $pol[$prop.Name] = $prop.Value } } }
    }
    $ringNames = @{ 0 = 'Deferred'; 4 = 'Insiders'; 5 = 'Production' }
    if ($pol.ContainsKey('GPOSetUpdateRing')) {
        $ring = [int]$pol['GPOSetUpdateRing']
        $script:Facts['Update ring (policy)'] = ('{0} ({1})' -f $ringNames[$ring], $ring)
    }
    else { $script:Facts['Update ring (policy)'] = 'Not set (Production by default)' }
    foreach ($name in @('KFMSilentOptIn', 'KFMBlockOptIn', 'KFMBlockOptOut', 'FilesOnDemandEnabled', 'SilentAccountConfig', 'DisablePersonalSync', 'DisableFileSyncNGSC')) {
        if ($pol.ContainsKey($name)) { $script:Facts['Policy ' + $name] = [string]$pol[$name] }
    }

    # Tenant allow and block lists. If the signed-in work account's tenant is not allowed, OneDrive refuses to sync it.
    $allow = @(); $block = @()
    foreach ($base in @('HKLM:\SOFTWARE\Policies\Microsoft\OneDrive', 'HKCU:\Software\Policies\Microsoft\OneDrive')) {
        foreach ($pair in @(@('AllowTenantList', 'allow'), @('BlockTenantList', 'block'))) {
            $lp = Get-ItemProperty -Path (Join-Path $base $pair[0]) -ErrorAction SilentlyContinue
            if ($lp) {
                foreach ($prop in $lp.PSObject.Properties) {
                    if ($prop.Name -notmatch '^PS(Path|ParentPath|ChildName|Drive|Provider)$') {
                        if ($pair[1] -eq 'allow') { $allow += [string]$prop.Value } else { $block += [string]$prop.Value }
                    }
                }
            }
        }
    }
    [void]$o.Add('')
    [void]$o.Add('=== TENANT RESTRICTIONS ===')
    [void]$o.Add('Allowed tenants : ' + $(if ($allow.Count) { $allow -join ', ' } else { '(no allow list)' }))
    [void]$o.Add('Blocked tenants : ' + $(if ($block.Count) { $block -join ', ' } else { '(no block list)' }))
    if ($allow.Count -gt 0) { $script:Facts['Tenant allow list'] = ('{0} tenant(s)' -f $allow.Count) }
    foreach ($a in @($script:Accounts | Where-Object { $_.TenantId })) {
        if ($allow.Count -gt 0 -and ($allow -notcontains $a.TenantId)) {
            Add-Finding 'Policy' ('Tenant not allowed (' + $a.Key + ')') 'FAIL' ('Tenant {0} is not in AllowTenantList.' -f $a.TenantId) 'Policy only allows other tenants, so this account cannot sync. Check the OneDrive policy with IT.'
        }
        elseif ($block -contains $a.TenantId) {
            Add-Finding 'Policy' ('Tenant blocked (' + $a.Key + ')') 'FAIL' ('Tenant {0} is in BlockTenantList.' -f $a.TenantId) 'Policy blocks this tenant, so this account cannot sync. Check the OneDrive policy with IT.'
        }
        elseif ($allow.Count -gt 0) {
            Add-Finding 'Policy' ('Tenant allowed (' + $a.Key + ')') 'PASS' 'The account tenant is in AllowTenantList.'
        }
    }

    [void]$o.Add('')
    [void]$o.Add('=== STORAGE SENSE (can turn files back into online-only) ===')
    $ss = Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy' -ErrorAction SilentlyContinue
    if ($ss) {
        foreach ($prop in $ss.PSObject.Properties) {
            if ($prop.Name -notmatch '^PS(Path|ParentPath|ChildName|Drive|Provider)$') { [void]$o.Add(('  {0} = {1}' -f $prop.Name, $prop.Value)) }
        }
    }
    else { [void]$o.Add('No Storage Sense policy values for this user.') }
    Save-Text '05_Registry_and_Policy_Summary.txt' $o
}

function Step-CloudFiles {
    # STEP: The Windows Cloud Files driver (CldFlt) and the shell overlay handlers that draw the sync icons.
    $o = New-Object System.Collections.ArrayList
    [void]$o.Add('=== CLOUD FILES DRIVER (CldFlt) ===')
    $svc = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\CldFlt' -ErrorAction SilentlyContinue
    $startNames = @{ 0 = 'Boot'; 1 = 'System'; 2 = 'Automatic'; 3 = 'Manual'; 4 = 'DISABLED' }
    if ($svc) {
        [void]$o.Add(('Start type : {0} ({1})' -f $svc.Start, $startNames[[int]$svc.Start]))
        [void]$o.Add('Image path : ' + $svc.ImagePath)
        if ($svc.Start -eq 4) {
            Add-Finding 'Cloud Files' 'CldFlt driver start type' 'FAIL' 'The Cloud Files driver is disabled.' 'Files On-Demand cannot work. Re-enable the driver. Escalate.'
        }
    }
    else { [void]$o.Add('CldFlt service key not found.') }

    $scOut = ''
    try { $scOut = (& sc.exe query cldflt 2>&1 | Out-String) } catch { }
    [void]$o.Add('')
    [void]$o.Add('sc query cldflt:')
    [void]$o.Add($scOut.Trim())
    $st = [regex]::Match($scOut, 'STATE\s*:\s*\d+\s+(\w+)')
    if ($st.Success -and $st.Groups[1].Value -eq 'RUNNING') {
        Add-Finding 'Cloud Files' 'CldFlt driver state' 'PASS' 'The Cloud Files driver is running.'
    }
    elseif ($st.Success) {
        Add-Finding 'Cloud Files' 'CldFlt driver state' 'FAIL' ('The Cloud Files driver state is ' + $st.Groups[1].Value + '.') 'Files On-Demand needs this driver. Restart the PC. If it persists, escalate.'
    }
    else {
        Add-Finding 'Cloud Files' 'CldFlt driver state' 'INFO' 'The driver state could not be read.' 'Not critical. See 06_CloudFiles_Platform.txt.'
    }

    [void]$o.Add('')
    [void]$o.Add('=== FILE SYSTEM FILTER DRIVERS (fltmc, needs admin) ===')
    if ($script:IsElevated) {
        try {
            $flt = (& fltmc.exe 2>&1 | Out-String)
            [void]$o.Add($flt.Trim())
            if ($flt -notmatch '(?i)CldFlt') {
                Add-Finding 'Cloud Files' 'CldFlt filter loaded' 'FAIL' 'CldFlt is not in the loaded filter list.' 'Files On-Demand cannot work. Escalate.'
            }
            $thirdParty = @([regex]::Split($flt, '\r?\n') | Where-Object { $_ -match '^\S+\s+\d+\s+[\d\.]+' -and $_ -notmatch '(?i)^(bindflt|MsSecFlt|UCPD|WdFilter|storqosflt|wcifs|CldFlt|bfs|FileCrypt|luafv|UnionFS|npsvctrig|Wof|FileInfo|applockerfltr?|PrjFlt|FsDepends|Dfs|DfsDriver|Ntfs|Msfs)\s' })
            if ($thirdParty.Count -gt 0) {
                $names = @($thirdParty | ForEach-Object { ($_ -split '\s+')[0] })
                [void]$o.Add('')
                [void]$o.Add('Possible third-party filter drivers: ' + ($names -join ', '))
                Add-Finding 'Cloud Files' 'Third-party filter drivers' 'INFO' ('Present: ' + ($names -join ', ')) 'Endpoint security and backup filters can slow or block cloud file operations.'
            }
        }
        catch { [void]$o.Add('fltmc failed: ' + $_.Exception.Message) }
    }
    else {
        [void]$o.Add('Skipped. This session is not elevated. Run PowerShell as administrator to include the filter list.')
        Write-Status 'SKIP' 'fltmc filter list skipped (not elevated).'
    }

    [void]$o.Add('')
    [void]$o.Add('=== SHELL ICON OVERLAY HANDLERS (these draw the sync icons in File Explorer) ===')
    $overlayNative = @()
    foreach ($base in @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ShellIconOverlayIdentifiers', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer\ShellIconOverlayIdentifiers')) {
        [void]$o.Add('[' + $base + ']')
        if (Test-Path $base) {
            foreach ($k in @(Get-ChildItem $base -ErrorAction SilentlyContinue | Sort-Object PSChildName)) {
                $guid = (Get-ItemProperty -LiteralPath $k.PSPath -ErrorAction SilentlyContinue).'(default)'
                [void]$o.Add(('  "{0}"  {1}' -f $k.PSChildName, $guid))
                if ($base -notmatch 'WOW6432Node') { $overlayNative += $k.PSChildName.Trim() }
            }
        }
    }
    $nonOd = @($overlayNative | Where-Object { $_ -notmatch '^(OneDrive|SkyDrivePro)' })
    [void]$o.Add('')
    [void]$o.Add(('Native overlay handlers : {0}  (Windows loads only the first 15, in alphabetical order)' -f $overlayNative.Count))
    if ($overlayNative.Count -gt 15) {
        Add-Finding 'Cloud Files' 'Overlay handler count' 'WARN' ('{0} overlay handlers are registered. Windows loads only 15.' -f $overlayNative.Count) 'Sync icons may be missing or wrong when other products take the slots. Review the list in 06_CloudFiles_Platform.txt.'
    }
    else {
        Add-Finding 'Cloud Files' 'Overlay handler count' 'PASS' ('{0} overlay handlers registered (limit is 15). Other than OneDrive: {1}.' -f $overlayNative.Count, $(if ($nonOd.Count -gt 0) { $nonOd -join ', ' } else { 'none' }))
    }
    Save-Text '06_CloudFiles_Platform.txt' $o
}

function Get-EventRows {
    # Reads events with a filter and returns tidy rows. Returns nothing (and no error) when there are no matching events.
    param([hashtable]$Filter, [int]$Max)
    try { $events = @(Get-WinEvent -FilterHashtable $Filter -MaxEvents $Max -ErrorAction Stop) }
    catch {
        if ($_.FullyQualifiedErrorId -notlike 'NoMatchingEventsFound*') { Write-Log ('Event query note: ' + $_.Exception.Message) 'INFO' }
        return @()
    }
    $rows = foreach ($e in $events) {
        $msg = ''
        if ($e.Message) { $msg = ($e.Message -replace '\s+', ' ').Trim(); if ($msg.Length -gt 400) { $msg = $msg.Substring(0, 400) } }
        [pscustomobject]@{
            TimeCreated = $e.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss'); Id = $e.Id; Level = $e.LevelDisplayName
            Provider = $e.ProviderName; Message = $msg
        }
    }
    return @($rows)
}

function Step-Events {
    # STEP: Event logs that explain OneDrive, Cloud Files, sign-in, disk and power problems.
    $since = (Get-Date).AddDays(-1 * $EventDays)
    $o = New-Object System.Collections.ArrayList
    [void]$o.Add(('Event window: last {0} day(s), from {1}' -f $EventDays, $since))

    # 1. OneDrive related Application log entries (crashes and errors).
    $app = @(Get-EventRows -Filter @{ LogName = 'Application'; Level = 1, 2, 3; StartTime = $since } -Max 3000 | Where-Object { $_.Provider -match 'OneDrive|FileSyncShell|FileCoAuth|CldFlt' -or $_.Message -match 'OneDrive' })
    Save-Csv '07_Events_OneDrive_Application.csv' ($app | Select-Object -First $MaxEventsPerLog)
    [void]$o.Add('OneDrive related Application errors/warnings: ' + $app.Count)
    $crash = @($app | Where-Object { $_.Id -in 1000, 1001, 1002 -and $_.Message -match 'OneDrive' })
    if ($crash.Count -gt 0) {
        Add-Finding 'Events' 'OneDrive crashes' 'WARN' ('{0} OneDrive crash or hang event(s) in the last {1} days. Latest {2}.' -f $crash.Count, $EventDays, $crash[0].TimeCreated) 'Repeated crashes interrupt sync. Note the faulting module in 07_Events_OneDrive_Application.csv.'
    }
    elseif ($app.Count -gt 0) {
        Add-Finding 'Events' 'OneDrive application events' 'INFO' ('{0} OneDrive related warning or error event(s).' -f $app.Count) 'Review 07_Events_OneDrive_Application.csv.'
    }
    else { Add-Finding 'Events' 'OneDrive application events' 'PASS' ('No OneDrive related errors in the last {0} days.' -f $EventDays) }

    # 2. Cloud Files filter operational log.
    $cf = @(Get-EventRows -Filter @{ LogName = 'Microsoft-Windows-CloudFiles-Filter/Operational'; StartTime = $since } -Max $MaxEventsPerLog)
    Save-Csv '07_Events_CloudFiles_Filter.csv' $cf
    [void]$o.Add('Cloud Files filter events: ' + $cf.Count)
    $cfBad = @($cf | Where-Object { $_.Level -in 'Error', 'Warning', 'Critical' })
    if ($cfBad.Count -gt 0) {
        Add-Finding 'Events' 'Cloud Files filter errors' 'WARN' ('{0} warning or error event(s) from the Cloud Files filter.' -f $cfBad.Count) 'The Windows driver reported problems with cloud files. Review 07_Events_CloudFiles_Filter.csv.'
    }
    else { Add-Finding 'Events' 'Cloud Files filter errors' 'PASS' 'No warnings or errors from the Cloud Files filter.' }

    # 3. Power and boot timeline. An unexpected shutdown can leave files in an unfinished state.
    $power = @(Get-EventRows -Filter @{ LogName = 'System'; Id = 41, 1074, 6005, 6006, 6008; StartTime = $since } -Max 500)
    Save-Csv '07_Events_System_PowerBoot.csv' ($power | Select-Object -First $MaxEventsPerLog)
    $unexpected = @($power | Where-Object { $_.Id -in 41, 6008 })
    [void]$o.Add('Unexpected shutdown events (41 / 6008): ' + $unexpected.Count)
    if ($unexpected.Count -gt 0) {
        Add-Finding 'Events' 'Unexpected shutdowns' 'WARN' ('{0} unexpected shutdown event(s) in the last {1} days. Latest {2}.' -f $unexpected.Count, $EventDays, $unexpected[0].TimeCreated) 'A power loss can leave open files and sync state unfinished. Compare the time with the start of the sync problem.'
    }
    else { Add-Finding 'Events' 'Unexpected shutdowns' 'PASS' ('No unexpected shutdowns in the last {0} days.' -f $EventDays) }

    # 4. Disk and file system errors.
    $disk = @(Get-EventRows -Filter @{ LogName = 'System'; ProviderName = 'Disk', 'Ntfs', 'volmgr', 'volsnap', 'stornvme', 'storahci', 'partmgr'; Level = 1, 2, 3; StartTime = $since } -Max $MaxEventsPerLog)
    Save-Csv '07_Events_System_DiskNtfs.csv' $disk
    [void]$o.Add('Disk / NTFS errors and warnings: ' + $disk.Count)
    if ($disk.Count -gt 0) {
        Add-Finding 'Events' 'Disk and NTFS events' 'WARN' ('{0} disk or NTFS warning/error event(s). Latest {1}.' -f $disk.Count, $disk[0].TimeCreated) 'File system errors can cause red cross icons and failed syncs. Consider a disk check.'
    }
    else { Add-Finding 'Events' 'Disk and NTFS events' 'PASS' 'No disk or NTFS errors.' }

    # 5. Sign-in (Azure AD / WAM) problems.
    $aad = @(Get-EventRows -Filter @{ LogName = 'Microsoft-Windows-AAD/Operational'; Level = 1, 2, 3; StartTime = $since } -Max $MaxEventsPerLog)
    Save-Csv '07_Events_AAD_SignIn.csv' $aad
    [void]$o.Add('Azure AD sign-in errors and warnings: ' + $aad.Count)
    # The AAD log is noisy on healthy PCs (hundreds of errors a week is normal), so it is reported as INFO only.
    # The Primary Refresh Token check in the Environment step is the reliable sign-in health signal.
    if ($aad.Count -gt 0) {
        $topIds = ($aad | Group-Object Id | Sort-Object Count -Descending | Select-Object -First 5 | ForEach-Object { 'id {0} x{1}' -f $_.Name, $_.Count }) -join ', '
        [void]$o.Add('  Most common: ' + $topIds)
        Add-Finding 'Events' 'Sign-in (AAD) events' 'INFO' ('{0} sign-in warning or error events ({1}).' -f $aad.Count, $topIds) 'Normal on most PCs. Only relevant if the user gets repeated sign-in prompts. Review 07_Events_AAD_SignIn.csv.'
    }

    Save-Text '07_Events_Summary.txt' $o
}

function Test-TcpEndpoint {
    # Resolves a name and tests a TCP connection with a time-out. Never throws.
    param([string]$HostName, [int]$Port = 443, [int]$TimeoutMs = 4000)
    $result = [pscustomobject]@{ Host = $HostName; Port = $Port; Dns = 'FAIL'; Address = ''; Tcp = 'FAIL'; Ms = -1; Note = '' }
    try {
        $addr = [System.Net.Dns]::GetHostAddresses($HostName) | Where-Object { $_.AddressFamily -eq 'InterNetwork' } | Select-Object -First 1
        if ($null -eq $addr) { $addr = [System.Net.Dns]::GetHostAddresses($HostName) | Select-Object -First 1 }
        $result.Dns = 'OK'; $result.Address = [string]$addr
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        $client = New-Object System.Net.Sockets.TcpClient
        $iar = $client.BeginConnect($addr, $Port, $null, $null)
        if ($iar.AsyncWaitHandle.WaitOne($TimeoutMs, $false) -and $client.Connected) {
            $client.EndConnect($iar); $result.Tcp = 'OK'; $result.Ms = [int]$sw.ElapsedMilliseconds
        }
        else { $result.Note = 'Connection timed out' }
        $client.Close()
    }
    catch { $result.Note = $_.Exception.Message }
    return $result
}

function Step-Network {
    # STEP: Can this PC reach Microsoft 365 and the tenant? Also proxy settings and clock accuracy.
    $o = New-Object System.Collections.ArrayList
    $hosts = New-Object System.Collections.ArrayList
    foreach ($h in @('login.microsoftonline.com', 'g.live.com', 'oneclient.sfx.ms', 'storage.live.com')) { [void]$hosts.Add($h) }
    foreach ($r in $script:SyncRoots) {
        foreach ($u in @($r.LibraryUrl, $r.WebUrl)) {
            if ($u) { try { $hn = ([Uri]$u).Host; if ($hn -and -not ($hosts -contains $hn)) { [void]$hosts.Add($hn) } } catch { } }
        }
    }
    $rows = New-Object System.Collections.ArrayList
    $i = 0
    foreach ($h in $hosts) {
        $i++
        Write-Progress -Id 2 -ParentId 1 -Activity 'Testing network endpoints' -Status $h -PercentComplete ([int](100 * $i / $hosts.Count))
        $res = Test-TcpEndpoint -HostName $h
        [void]$rows.Add($res)
        $critical = ($h -match 'login\.microsoftonline|sharepoint\.com')
        if ($res.Dns -ne 'OK') {
            Add-Finding 'Network' ('DNS ' + $h) $(if ($critical) { 'FAIL' } else { 'WARN' }) 'Name could not be resolved.' 'Check DNS, VPN and internet access.'
        }
        elseif ($res.Tcp -ne 'OK') {
            Add-Finding 'Network' ('TCP 443 ' + $h) $(if ($critical) { 'FAIL' } else { 'WARN' }) ('Connection failed: ' + $res.Note) 'Check firewall, proxy and internet access.'
        }
        else { Add-Finding 'Network' ('TCP 443 ' + $h) 'PASS' ('Connected in {0} ms.' -f $res.Ms) }
    }
    Write-Progress -Id 2 -Activity 'Testing network endpoints' -Completed
    Save-Csv '08_Network_Endpoints.csv' $rows

    [void]$o.Add('=== WinHTTP PROXY ===')
    try { [void]$o.Add(((& netsh.exe winhttp show proxy 2>&1) -join [Environment]::NewLine)) } catch { }
    [void]$o.Add('')
    [void]$o.Add('=== USER INTERNET SETTINGS ===')
    $is = Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -ErrorAction SilentlyContinue
    if ($is) {
        [void]$o.Add('ProxyEnable   : ' + $is.ProxyEnable)
        [void]$o.Add('ProxyServer   : ' + $is.ProxyServer)
        [void]$o.Add('AutoConfigURL : ' + $is.AutoConfigURL)
        if ($is.ProxyEnable -eq 1 -or $is.AutoConfigURL) {
            Add-Finding 'Network' 'Proxy in use' 'INFO' ('Proxy {0} {1}' -f $is.ProxyServer, $is.AutoConfigURL) 'A proxy can block or slow OneDrive. Note it for the escalation.'
        }
    }
    [void]$o.Add('')
    [void]$o.Add('=== ACTIVE NETWORK ADAPTERS ===')
    try {
        foreach ($n in @(Get-NetAdapter -ErrorAction Stop | Where-Object { $_.Status -eq 'Up' })) {
            [void]$o.Add(('{0}  {1}  {2}  {3}' -f $n.Name, $n.InterfaceDescription, $n.LinkSpeed, $n.MediaType))
        }
    }
    catch { [void]$o.Add('Adapter list not available.') }
    [void]$o.Add('')
    [void]$o.Add('=== TIME SYNC (w32tm) ===')
    try {
        $w = (& w32tm.exe /query /status 2>&1 | Out-String)
        [void]$o.Add($w.Trim())
        if ($w -match 'error|0x800') {
            Add-Finding 'Network' 'Time service' 'INFO' 'The Windows time service did not return a normal status.' 'A wrong clock can break sign-in. Check the clock and time source.'
        }
    }
    catch { [void]$o.Add('w32tm not available.') }
    Save-Text '08_Network_and_Proxy.txt' $o
}

function Step-Listings {
    # STEP: List (do not read) the OneDrive settings and log folders. File names, sizes and dates only.
    $odBase = Join-Path $env:LOCALAPPDATA 'Microsoft\OneDrive'
    $settings = New-Object System.Collections.ArrayList
    $logs = New-Object System.Collections.ArrayList
    foreach ($a in $script:Accounts) {
        foreach ($f in @(Get-ChildItem -LiteralPath $a.SettingsDir -File -ErrorAction SilentlyContinue)) {
            [void]$settings.Add([pscustomobject]@{ Account = $a.Key; Name = $f.Name; SizeBytes = $f.Length; SizeText = (Format-Bytes $f.Length); LastWrite = $f.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss') })
        }
        $db = Get-Item -LiteralPath (Join-Path $a.SettingsDir 'SyncEngineDatabase.db') -ErrorAction SilentlyContinue
        if ($db) {
            $script:Facts['Sync database size (' + $a.Key + ')'] = (Format-Bytes $db.Length)
            if ($db.Length -gt 1GB) {
                Add-Finding 'Settings' ('Large sync database (' + $a.Key + ')') 'INFO' ('SyncEngineDatabase.db is {0}.' -f (Format-Bytes $db.Length)) 'A large database means a very large sync set.'
            }
        }
        $total = 0; $count = 0; $newest = $null
        foreach ($f in @(Get-ChildItem -LiteralPath $a.LogsDir -Recurse -File -ErrorAction SilentlyContinue)) {
            $total += $f.Length; $count++
            if ($null -eq $newest -or $f.LastWriteTime -gt $newest) { $newest = $f.LastWriteTime }
            [void]$logs.Add([pscustomobject]@{ Account = $a.Key; Name = $f.FullName.Substring($odBase.Length + 1); SizeBytes = $f.Length; LastWrite = $f.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss') })
        }
        $script:Facts['Log folder (' + $a.Key + ')'] = ('{0} files, {1}, newest {2}' -f $count, (Format-Bytes $total), $newest)
    }
    Save-Csv '09_Settings_Folder_Listing.csv' $settings
    Save-Csv '09_Logs_Folder_Listing.csv' $logs
    Write-Status 'OK' ('Listed {0} settings files and {1} log files.' -f $settings.Count, $logs.Count)
}

# ----------------------------------------------------------------------------------------------
# SECTION 5. FILE SYSTEM INDEX
# One pass over a sync root builds all the evidence at once, so the folder tree is never walked twice.
# The pass records attributes, sizes and dates only. It does not open or hydrate any file.
# ----------------------------------------------------------------------------------------------

function Test-ReparseTag {
    # Reads the reparse tag of one item with fsutil. Cloud Files tags look like 0x9000?01A.
    # Returns $null when the tool is unavailable (for example when not elevated).
    param([string]$Path)
    try {
        $text = (& fsutil.exe reparsepoint query $Path 2>&1 | Out-String)
        $m = [regex]::Match($text, 'Reparse Tag Value\s*:\s*0x([0-9a-fA-F]+)')
        if ($m.Success) {
            $hex = $m.Groups[1].Value.ToLower().PadLeft(8, '0')
            return [pscustomobject]@{ Tag = ('0x' + $hex); IsCloud = ($hex -match '^9000[0-9a-f]01a$') }
        }
    }
    catch { }
    return $null
}

function Invoke-FolderIndex {
    # Walks one folder tree once. Mode Full = whole tree. Mode TopLevel = first level only.
    param(
        [pscustomobject]$Root,
        [string]$StartPath,
        [string]$Mode,
        [bool]$FullIndex,
        [string]$Label
    )

    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $StartPath = $StartPath.TrimEnd('\')
    $rootPath = ([string]$Root.MountPoint).TrimEnd('\')

    # The \\?\ prefix lets .NET read paths longer than 260 characters. Fall back to a plain path when it is not accepted.
    $prefix = '\\?\'
    try {
        $probe = New-Object System.IO.DirectoryInfo($prefix + $StartPath)
        $null = $probe.EnumerateFileSystemInfos().GetEnumerator().MoveNext()
    }
    catch { $prefix = '' }
    $prefixLen = $prefix.Length
    $rootLongLen = $prefixLen + $rootPath.Length
    $serverPrefix = [int]$Root.ServerPrefixLen   # -1 when the library URL is unknown

    # Attribute bit masks (Windows Cloud Files and standard attributes).
    $cloudMask = 0x1000 -bor 0x40000 -bor 0x80000 -bor 0x100000 -bor 0x400000
    $recallMask = 0x1000 -bor 0x40000 -bor 0x400000
    $largeFileBytes = 10GB
    $maxDepth = 80
    $reparseSampleMax = 20

    # Fast name test. Only names that match are examined further.
    $comp = [regex]::Escape($env:COMPUTERNAME)
    $nameRx = New-Object System.Text.RegularExpressions.Regex(('^\s|\s$|\.$|^~\$|\.tmp$|_vti_|^(con|prn|aux|nul|com[0-9]|lpt[0-9])(\.|$)|-' + $comp + '(-\d+)?(\.[^.]+)?$'), [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)

    # Output files. They are streamed, so memory use stays small even for very large libraries.
    $utf8 = New-Object System.Text.UTF8Encoding($true)
    $excPath = Join-Path $script:OutDir ('11_FileSystem_{0}_Exceptions.csv' -f $Label)
    $excWriter = New-Object System.IO.StreamWriter($excPath, $false, $utf8)
    $excWriter.WriteLine('Category,Path,Attributes,AttributesDecoded,Length,LastWriteUtc,LocalPathLength,ServerPathLength,Note')
    $idxWriter = $null
    $idxPath = $null
    if ($FullIndex) {
        $idxPath = Join-Path $script:OutDir ('11_FileSystem_{0}_FullIndex.csv' -f $Label)
        $idxWriter = New-Object System.IO.StreamWriter($idxPath, $false, $utf8)
        $idxWriter.WriteLine('Path,Type,Attributes,Length,LastWriteUtc')
    }

    # Counters
    [long]$items = 0; [long]$files = 0; [long]$dirs = 0; [long]$bytes = 0; [long]$hydratedBytes = 0
    [long]$onlineOnly = 0; [long]$locallyAvail = 0; [long]$alwaysKeep = 0; [long]$pinnedPending = 0
    [long]$localOnly = 0; [long]$systemHidden = 0; [long]$foldersPinned = 0; [long]$foldersUnpinned = 0
    [long]$zeroByte = 0; [long]$enumErrors = 0; [long]$dirsEnumerated = 0
    $truncated = $false
    $excCounts = @{}
    $attrHist = @{}
    $extHist = @{}
    $topAgg = @{}              # top-level folder name -> long[7] (files, dirs, bytes, onlineOnly, locallyAvail, alwaysKeep, localOnly)
    $topItems = New-Object System.Collections.ArrayList
    $topFiles = New-Object System.Collections.ArrayList
    [long]$minTop = 0
    $maxLocal = 0; $maxLocalPath = ''; $maxServer = 0; $maxServerPath = ''
    $reparseChecked = 0; $reparseCloud = 0; $reparseOther = 0; $reparseToolFailed = $false
    $tagCounts = @{}

    function Add-ScanException {
        # Counts a problem item and writes a row until the per-category limit is reached.
        param([string]$Category, [string]$FullPath, [int]$Attr, [long]$Len, [datetime]$Written, [int]$LocalLen, [int]$ServerLen, [string]$Note = '')
        $excCounts[$Category] = 1 + [long]$excCounts[$Category]
        if ($excCounts[$Category] -le $MaxExceptionsPerCategory) {
            $disp = $FullPath
            if ($prefixLen -gt 0 -and $disp.StartsWith($prefix)) { $disp = $disp.Substring($prefixLen) }
            $excWriter.WriteLine(('{0},"{1}",{2},"{3}",{4},{5},{6},{7},"{8}"' -f $Category, $disp.Replace('"', '""'), $Attr, (ConvertTo-AttributeText $Attr), $Len, $Written.ToString('yyyy-MM-dd HH:mm:ss'), $LocalLen, $ServerLen, $Note.Replace('"', '""')))
        }
    }

    $stackPath = New-Object 'System.Collections.Generic.Stack[string]'
    $stackDepth = New-Object 'System.Collections.Generic.Stack[int]'
    $stackTop = New-Object 'System.Collections.Generic.Stack[string]'
    $stackPath.Push($prefix + $StartPath); $stackDepth.Push(0); $stackTop.Push('(root)')

    Write-Status 'INFO' ('Indexing ({0}): {1}' -f $Mode, $StartPath)
    try {
        while ($stackPath.Count -gt 0 -and -not $truncated) {
            $cur = $stackPath.Pop(); $depth = $stackDepth.Pop(); $topName = $stackTop.Pop()
            $dirsEnumerated++
            try {
                $di = New-Object System.IO.DirectoryInfo($cur)
                foreach ($e in $di.EnumerateFileSystemInfos()) {
                    $items++
                    $attr = [int]$e.Attributes
                    $name = $e.Name
                    $full = $e.FullName
                    $isDir = (($attr -band 16) -ne 0)
                    $plen = $full.Length - $prefixLen
                    $attrHist[$attr] = 1 + [long]$attrHist[$attr]

                    if ($isDir) {
                        # ---------- FOLDER ----------
                        $dirs++
                        if ($depth -eq 0) { $tn = $name } else { $tn = $topName }
                        $agg = $topAgg[$tn]
                        if ($null -eq $agg) { $agg = New-Object 'long[]' 7; $topAgg[$tn] = $agg }
                        $agg[1]++
                        if (($attr -band 0x80000) -ne 0) { $foldersPinned++ }
                        if (($attr -band 0x100000) -ne 0) { $foldersUnpinned++ }
                        if (($attr -band 0x400) -eq 0) {
                            # A normal folder (no cloud reparse point). Hidden system folders are ignored.
                            if (($attr -band 6) -ne 6) { $agg[6]++; Add-ScanException 'FolderNotCloudManaged' $full $attr 0 $e.LastWriteTimeUtc $plen 0 }
                        }
                        elseif (($attr -band $cloudMask) -eq 0 -and $reparseChecked -lt $reparseSampleMax -and -not $reparseToolFailed) {
                            # A reparse folder with no cloud flag. Check its tag on a small sample to rule out junctions and symlinks.
                            $reparseChecked++
                            $tag = Test-ReparseTag -Path $full.Substring($prefixLen)
                            if ($null -eq $tag) { $reparseToolFailed = $true }
                            else {
                                $tagCounts[$tag.Tag] = 1 + [long]$tagCounts[$tag.Tag]
                                if ($tag.IsCloud) { $reparseCloud++ }
                                else { $reparseOther++; Add-ScanException 'NonCloudReparseFolder' $full $attr 0 $e.LastWriteTimeUtc $plen 0 ('Reparse tag ' + $tag.Tag) }
                            }
                        }
                        if ($depth -eq 0 -and $name -ieq 'forms') { Add-ScanException 'SharePointReservedName' $full $attr 0 $e.LastWriteTimeUtc $plen 0 'Forms at library root' }
                        if ($Mode -eq 'Full') {
                            if ($depth -lt $maxDepth) { $stackPath.Push($full); $stackDepth.Push($depth + 1); $stackTop.Push($tn) }
                            else { Add-ScanException 'MaxDepthReached' $full $attr 0 $e.LastWriteTimeUtc $plen 0 }
                        }
                        if ($depth -eq 0 -and $topItems.Count -lt 5000) {
                            [void]$topItems.Add([pscustomobject]@{ Name = $name; Type = 'Folder'; Attributes = $attr; AttributesDecoded = (ConvertTo-AttributeText $attr); Length = 0; LastWrite = $e.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss') })
                        }
                        if ($null -ne $idxWriter) { $idxWriter.WriteLine('"' + $full.Substring($prefixLen).Replace('"', '""') + '",Folder,' + $attr + ',0,' + $e.LastWriteTimeUtc.ToString('yyyy-MM-dd HH:mm:ss')) }
                    }
                    else {
                        # ---------- FILE ----------
                        $files++
                        $len = [long]$e.Length
                        $bytes += $len
                        if ($depth -eq 0) { $tn = '(files in root)' } else { $tn = $topName }
                        $agg = $topAgg[$tn]
                        if ($null -eq $agg) { $agg = New-Object 'long[]' 7; $topAgg[$tn] = $agg }
                        $agg[0]++; $agg[2] += $len

                        if (($attr -band 0x400) -eq 0) {
                            # No reparse point: OneDrive does not manage this file as a placeholder (new local file, or not tracked).
                            if (($attr -band 6) -ne 6) { $localOnly++; $agg[6]++; Add-ScanException 'FileNotCloudManaged' $full $attr $len $e.LastWriteTimeUtc $plen 0 }
                            else { $systemHidden++ }
                        }
                        elseif (($attr -band $recallMask) -ne 0) {
                            # Online-only placeholder (not stored on disk).
                            $onlineOnly++; $agg[3]++
                            if (($attr -band 0x80000) -ne 0) { $pinnedPending++ }
                        }
                        else {
                            # Placeholder with its content on disk.
                            $hydratedBytes += $len
                            if (($attr -band 0x80000) -ne 0) { $alwaysKeep++; $agg[5]++ } else { $locallyAvail++; $agg[4]++ }
                        }

                        $ext = $e.Extension.ToLowerInvariant()
                        $extHist[$ext] = 1 + [long]$extHist[$ext]
                        if ($len -eq 0) { $zeroByte++; Add-ScanException 'ZeroByteFile' $full $attr 0 $e.LastWriteTimeUtc $plen 0 }
                        if ($len -ge $largeFileBytes) { Add-ScanException 'VeryLargeFile' $full $attr $len $e.LastWriteTimeUtc $plen 0 ('{0:N1} GB' -f ($len / 1GB)) }
                        if ($len -gt $minTop -or $topFiles.Count -lt 15) {
                            [void]$topFiles.Add([pscustomobject]@{ Length = $len; Path = $full.Substring($prefixLen) })
                            if ($topFiles.Count -gt 15) {
                                $sorted = @($topFiles | Sort-Object Length -Descending | Select-Object -First 15)
                                $topFiles.Clear(); foreach ($s in $sorted) { [void]$topFiles.Add($s) }
                                $minTop = $sorted[$sorted.Count - 1].Length
                            }
                        }
                        if ($depth -eq 0 -and $topItems.Count -lt 5000) {
                            [void]$topItems.Add([pscustomobject]@{ Name = $name; Type = 'File'; Attributes = $attr; AttributesDecoded = (ConvertTo-AttributeText $attr); Length = $len; LastWrite = $e.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss') })
                        }
                        if ($null -ne $idxWriter) { $idxWriter.WriteLine('"' + $full.Substring($prefixLen).Replace('"', '""') + '",File,' + $attr + ',' + $len + ',' + $e.LastWriteTimeUtc.ToString('yyyy-MM-dd HH:mm:ss')) }
                    }

                    # ---------- CHECKS THAT APPLY TO FILES AND FOLDERS ----------
                    if ($plen -gt $maxLocal) { $maxLocal = $plen; $maxLocalPath = $full.Substring($prefixLen) }
                    if ($plen -ge $PathWarnLength) { Add-ScanException 'LocalPathLength' $full $attr 0 $e.LastWriteTimeUtc $plen 0 }
                    if ($serverPrefix -ge 0) {
                        $slen = $serverPrefix + $full.Length - $rootLongLen
                        if ($slen -gt $maxServer) { $maxServer = $slen; $maxServerPath = $full.Substring($prefixLen) }
                        if ($slen -ge 400) { Add-ScanException 'ServerPathOverLimit' $full $attr 0 $e.LastWriteTimeUtc $plen $slen }
                        elseif ($slen -ge $ServerPathWarnLength) { Add-ScanException 'ServerPathNearLimit' $full $attr 0 $e.LastWriteTimeUtc $plen $slen }
                    }
                    if ($nameRx.IsMatch($name)) {
                        $cat = 'ConflictCopy'
                        if ($name -match '^\s|\s$') { $cat = 'NameLeadingOrTrailingSpace' }
                        elseif ($name.EndsWith('.')) { $cat = 'NameTrailingPeriod' }
                        elseif ($name.StartsWith('~$')) { $cat = 'OfficeLockFile' }
                        elseif ($name -match '(?i)\.tmp$') { $cat = 'TempFile' }
                        elseif ($name -match '(?i)_vti_') { $cat = 'SharePointReservedName' }
                        elseif ($name -match '(?i)^(con|prn|aux|nul|com[0-9]|lpt[0-9])(\.|$)') { $cat = 'WindowsReservedName' }
                        Add-ScanException $cat $full $attr 0 $e.LastWriteTimeUtc $plen 0
                    }

                    # ---------- PROGRESS AND TIME LIMIT (checked every 2000 items) ----------
                    if (($items % 2000) -eq 0) {
                        $secs = [math]::Max(1, $sw.Elapsed.TotalSeconds)
                        $leaf = $cur
                        if ($leaf.Length -gt 70) { $leaf = '...' + $leaf.Substring($leaf.Length - 67) }
                        Write-Progress -Id 2 -ParentId 1 -Activity ('Indexing: ' + $Label) -Status ('{0:N0} items, {1:N0} per second, {2} folders waiting. {3}' -f $items, ($items / $secs), $stackPath.Count, $leaf)
                        if (($items % 50000) -eq 0) { Write-Status 'INFO' ('  ... {0:N0} items indexed ({1:N0} per second)' -f $items, ($items / $secs)) }
                        if ($sw.Elapsed.TotalMinutes -ge $ScanTimeLimitMinutes) { $truncated = $true; break }
                    }
                }
            }
            catch {
                # A folder could not be read (access denied, too long, removed during the scan).
                $enumErrors++
                Add-ScanException 'EnumerationError' $cur 0 0 ([datetime]::UtcNow) 0 0 $_.Exception.Message
            }
        }
    }
    finally {
        $excWriter.Flush(); $excWriter.Close()
        if ($null -ne $idxWriter) { $idxWriter.Flush(); $idxWriter.Close() }
        Write-Progress -Id 2 -Activity ('Indexing: ' + $Label) -Completed
    }
    $sw.Stop()

    # ---------- WRITE THE SUMMARY FILE ----------
    $secsTotal = [math]::Max(0.001, $sw.Elapsed.TotalSeconds)
    $s = New-Object System.Collections.ArrayList
    [void]$s.Add('FILE INDEX SUMMARY: ' + $Root.Title)
    [void]$s.Add('Sync root      : ' + $rootPath)
    [void]$s.Add('Scanned path   : ' + $StartPath)
    [void]$s.Add('Mode           : ' + $Mode)
    if ($truncated) { [void]$s.Add('Result         : PARTIAL. The scan stopped at the time limit of ' + $ScanTimeLimitMinutes + ' minutes.') } else { [void]$s.Add('Result         : Complete') }
    [void]$s.Add(('Duration       : {0:N1} seconds ({1:N0} items per second)' -f $secsTotal, ($items / $secsTotal)))
    [void]$s.Add(('Items          : {0:N0} ({1:N0} files, {2:N0} folders)' -f $items, $files, $dirs))
    [void]$s.Add('Logical size   : ' + (Format-Bytes $bytes) + ' (size of all files if fully downloaded)')
    [void]$s.Add('On disk (est.) : ' + (Format-Bytes $hydratedBytes))
    [void]$s.Add('')
    [void]$s.Add('FILE STATE')
    [void]$s.Add(('  Online-only placeholders         : {0:N0}' -f $onlineOnly))
    [void]$s.Add(('  Locally available (downloaded)   : {0:N0}' -f $locallyAvail))
    [void]$s.Add(('  Always keep on this device       : {0:N0}' -f $alwaysKeep))
    [void]$s.Add(('  Always keep but not yet downloaded: {0:N0}' -f $pinnedPending))
    [void]$s.Add(('  Not managed by OneDrive (no placeholder): {0:N0}' -f $localOnly))
    [void]$s.Add(('  System or hidden files           : {0:N0}' -f $systemHidden))
    [void]$s.Add(('  Zero byte files                  : {0:N0}' -f $zeroByte))
    [void]$s.Add(('FOLDERS: pinned {0:N0}, unpinned {1:N0}' -f $foldersPinned, $foldersUnpinned))
    [void]$s.Add(('Longest local path  : {0} characters  {1}' -f $maxLocal, $maxLocalPath))
    if ($serverPrefix -ge 0) { [void]$s.Add(('Longest server path : {0} characters (estimate)  {1}' -f $maxServer, $maxServerPath)) }
    [void]$s.Add('')
    [void]$s.Add(('REPARSE TAG SAMPLE (folders with no cloud flag): checked {0}, cloud {1}, other {2}{3}' -f $reparseChecked, $reparseCloud, $reparseOther, $(if ($reparseToolFailed) { ' (fsutil not available)' } else { '' })))
    foreach ($k in $tagCounts.Keys) { [void]$s.Add('  tag ' + $k + ' : ' + $tagCounts[$k]) }
    [void]$s.Add('')
    [void]$s.Add('PROBLEM CATEGORIES (total found; the exceptions CSV holds up to ' + $MaxExceptionsPerCategory + ' rows each)')
    if ($excCounts.Count -eq 0) { [void]$s.Add('  None') }
    foreach ($k in ($excCounts.Keys | Sort-Object)) { [void]$s.Add(('  {0,-30} {1:N0}' -f $k, $excCounts[$k])) }
    [void]$s.Add('')
    [void]$s.Add('ATTRIBUTE VALUES SEEN (top 15)')
    foreach ($kv in ($attrHist.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 15)) {
        [void]$s.Add(('  {0,10}  0x{1:X8}  {2,10:N0}  {3}' -f $kv.Key, [int]$kv.Key, $kv.Value, (ConvertTo-AttributeText ([int]$kv.Key))))
    }
    [void]$s.Add('')
    [void]$s.Add('TOP-LEVEL FOLDERS (largest by file count, top 40)')
    [void]$s.Add(('  {0,-44} {1,10} {2,10} {3,12} {4,10} {5,10}' -f 'Folder', 'Files', 'Folders', 'Size', 'OnlineOnly', 'LocalOnly'))
    foreach ($kv in ($topAgg.GetEnumerator() | Sort-Object { $_.Value[0] } -Descending | Select-Object -First 40)) {
        $nm = [string]$kv.Key; if ($nm.Length -gt 44) { $nm = $nm.Substring(0, 41) + '...' }
        [void]$s.Add(('  {0,-44} {1,10:N0} {2,10:N0} {3,12} {4,10:N0} {5,10:N0}' -f $nm, $kv.Value[0], $kv.Value[1], (Format-Bytes $kv.Value[2]), $kv.Value[3], $kv.Value[6]))
    }
    if ($Mode -eq 'TopLevel') { [void]$s.Add('  (Top level mode: folder contents were not read, so counts per folder are zero. See the TopLevel CSV for the folder list.)') }
    [void]$s.Add('')
    [void]$s.Add('FILE EXTENSIONS (top 15)')
    foreach ($kv in ($extHist.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 15)) {
        $x = $kv.Key; if ([string]::IsNullOrEmpty($x)) { $x = '(none)' }
        [void]$s.Add(('  {0,-14} {1,10:N0}' -f $x, $kv.Value))
    }
    [void]$s.Add('')
    [void]$s.Add('LARGEST FILES')
    foreach ($tf in ($topFiles | Sort-Object Length -Descending)) { [void]$s.Add(('  {0,12}  {1}' -f (Format-Bytes $tf.Length), $tf.Path)) }
    Save-Text ('11_FileSystem_{0}_Summary.txt' -f $Label) $s
    Save-Csv ('11_FileSystem_{0}_TopLevel.csv' -f $Label) $topItems

    return [pscustomobject]@{
        Title = $Root.Title; Label = $Label; RootPath = $rootPath; ScannedPath = $StartPath; Mode = $Mode
        Items = $items; Files = $files; Dirs = $dirs; Truncated = $truncated; Seconds = $secsTotal
        Exceptions = $excCounts; LocalOnly = $localOnly; EnumErrors = $enumErrors; OnlineOnly = $onlineOnly
        LocallyAvailable = $locallyAvail; MaxLocalPath = $maxLocal; MaxServerPath = $maxServer
        ReparseOther = $reparseOther; ReparseChecked = $reparseChecked; ExceptionFile = $excPath; IndexFile = $idxPath
    }
}

function Add-ScanFindings {
    # Turns the numbers from one index run into helpdesk findings.
    param([pscustomobject]$R)
    $t = $R.Title
    $ex = $R.Exceptions
    function Get-Count {
        param([string]$Name)
        if ($ex.ContainsKey($Name)) { return [long]$ex[$Name] }
        return [long]0
    }

    if ($R.Truncated) {
        Add-Finding 'File index' ('Scan complete: ' + $t) 'WARN' ('Stopped after {0:N0} items at the {1} minute limit. Results are partial.' -f $R.Items, $ScanTimeLimitMinutes) 'Run again with -FocusPath on one folder, or raise -ScanTimeLimitMinutes.'
    }
    else {
        Add-Finding 'File index' ('Scan complete: ' + $t) 'PASS' ('{0:N0} items ({1:N0} files, {2:N0} folders) in {3:N0} seconds. Mode {4}.' -f $R.Items, $R.Files, $R.Dirs, $R.Seconds, $R.Mode)
    }
    if ($R.EnumErrors -gt 0) {
        Add-Finding 'File index' ('Unreadable folders: ' + $t) 'WARN' ('{0:N0} folder(s) could not be read.' -f $R.EnumErrors) 'See the EnumerationError rows in the exceptions CSV. Common causes are access denied, path too long, or removal during the scan.'
    }
    $c = Get-Count 'ServerPathOverLimit'
    if ($c -gt 0) { Add-Finding 'File index' ('SharePoint path over 400: ' + $t) 'FAIL' ('{0:N0} item(s) have an estimated server path of 400 characters or more. Longest {1}.' -f $c, $R.MaxServerPath) 'SharePoint cannot hold paths over 400 characters. These items will fail to sync. Shorten folder or file names.' }
    $c = Get-Count 'ServerPathNearLimit'
    if ($c -gt 0) { Add-Finding 'File index' ('SharePoint path near limit: ' + $t) 'WARN' ('{0:N0} item(s) are within reach of the 400 character limit (from {1}).' -f $c, $ServerPathWarnLength) 'Long paths often fail when an extra sub folder or longer name is added.' }
    $c = Get-Count 'LocalPathLength'
    if ($c -gt 0) { Add-Finding 'File index' ('Local path length: ' + $t) 'WARN' ('{0:N0} item(s) have a local path of {1} characters or more. Longest {2}.' -f $c, $PathWarnLength, $R.MaxLocalPath) 'File Explorer and many apps fail on long paths. A shorter sync folder location or shorter names helps.' }
    $c = Get-Count 'FileNotCloudManaged'
    if ($c -gt 25) { Add-Finding 'File index' ('Files not managed by OneDrive: ' + $t) 'WARN' ('{0:N0} file(s) are normal local files with no OneDrive placeholder state.' -f $c) 'These may be new files waiting to sync, or files OneDrive is not tracking. Check them in the exceptions CSV.' }
    elseif ($c -gt 0) { Add-Finding 'File index' ('Files not managed by OneDrive: ' + $t) 'INFO' ('{0:N0} file(s) are normal local files with no placeholder state.' -f $c) 'Often new or recently saved files that are about to sync.' }
    $c = Get-Count 'FolderNotCloudManaged'
    if ($c -gt 0) { Add-Finding 'File index' ('Folders not managed by OneDrive: ' + $t) 'INFO' ('{0:N0} folder(s) are normal local folders.' -f $c) 'New local folders appear here until OneDrive picks them up.' }
    $c = Get-Count 'NonCloudReparseFolder'
    if ($c -gt 0) { Add-Finding 'File index' ('Junctions or links: ' + $t) 'WARN' ('{0:N0} sampled folder(s) are not cloud placeholders (junction or symbolic link).' -f $c) 'OneDrive does not follow links reliably. Review these in the exceptions CSV.' }
    foreach ($n in @('NameLeadingOrTrailingSpace', 'NameTrailingPeriod', 'WindowsReservedName', 'SharePointReservedName')) {
        $c = Get-Count $n
        if ($c -gt 0) { Add-Finding 'File index' ($n + ': ' + $t) 'WARN' ('{0:N0} item(s) have a name SharePoint does not accept ({1}).' -f $c, $n) 'Rename the items. They cannot sync under these names.' }
    }
    $c = Get-Count 'ConflictCopy'
    if ($c -gt 0) { Add-Finding 'File index' ('Conflict copies: ' + $t) 'INFO' ('{0:N0} file(s) look like OneDrive conflict copies (name ends with this PC name).' -f $c) 'The same file was changed in two places. The user should keep one version.' }
    $c = Get-Count 'OfficeLockFile'
    if ($c -gt 0) { Add-Finding 'File index' ('Office lock files: ' + $t) 'INFO' ('{0:N0} Office owner or lock file(s) (names start with ~$).' -f $c) 'Lock files mean a document is open or was not closed cleanly.' }
    $c = Get-Count 'VeryLargeFile'
    if ($c -gt 0) { Add-Finding 'File index' ('Very large files: ' + $t) 'INFO' ('{0:N0} file(s) are 10 GB or larger.' -f $c) 'Large files take a long time to upload or download.' }
    $c = Get-Count 'MaxDepthReached'
    if ($c -gt 0) { Add-Finding 'File index' ('Folder depth: ' + $t) 'WARN' ('{0:N0} folder(s) are deeper than 80 levels and were not read.' -f $c) 'This depth is unusual. Check for a folder loop.' }
}

function Step-FileSystem {
    # STEP: Decide what to index (asking when needed), then run the index.
    $existing = @($script:SyncRoots | Where-Object { $_.Exists })
    if ($existing.Count -eq 0) { Write-Status 'SKIP' 'No sync roots exist on disk, so there is nothing to index.'; return }

    # ---- 1. Which sync roots? ----
    $targets = New-Object System.Collections.ArrayList
    $wantAll = ($SyncRoot -and ($SyncRoot -contains 'All'))
    if ($script:LevelNum -eq 1) {
        foreach ($r in $existing) { [void]$targets.Add([pscustomobject]@{ Root = $r; StartPath = $r.MountPoint; Mode = 'TopLevel' }) }
    }
    else {
        $chosen = @()
        if ($SyncRoot -and -not $wantAll) {
            foreach ($s in $SyncRoot) {
                $sp = $s.TrimEnd('\')
                $match = $existing | Where-Object { $_.MountPoint -ieq $sp } | Select-Object -First 1
                if ($match) { $chosen += [pscustomobject]@{ Root = $match; StartPath = $match.MountPoint; Narrow = $false }; continue }
                if (Test-Path -LiteralPath $sp -PathType Container) {
                    # Any folder can be indexed. If it sits inside a known sync root, borrow that root for the server path maths.
                    $parent = $existing | Where-Object { $sp.StartsWith($_.MountPoint + '\', [StringComparison]::OrdinalIgnoreCase) } | Sort-Object { $_.MountPoint.Length } -Descending | Select-Object -First 1
                    if ($parent) { $rootObj = $parent }
                    else { $rootObj = [pscustomobject]@{ Title = (Split-Path -Leaf $sp); MountPoint = $sp; ServerPrefixLen = -1; Exists = $true } }
                    $chosen += [pscustomobject]@{ Root = $rootObj; StartPath = $sp; Narrow = $true }
                }
                else { Write-Status 'WARN' ('SyncRoot path not found and skipped: ' + $sp) }
            }
        }
        elseif ($existing.Count -gt 1 -and -not $wantAll) {
            $opts = @($existing | ForEach-Object { '{0}  [{1}]  {2}' -f $_.Title, $_.Type, $_.MountPoint })
            $pick = @(Select-FromList -Title 'Which synced folders should be indexed?' -Options $opts -Multiple)
            foreach ($i in $pick) { $chosen += [pscustomobject]@{ Root = $existing[$i - 1]; StartPath = $existing[$i - 1].MountPoint; Narrow = $false } }
        }
        else {
            foreach ($r in $existing) { $chosen += [pscustomobject]@{ Root = $r; StartPath = $r.MountPoint; Narrow = $false } }
        }

        # ---- 2. Focus folder given as a parameter ----
        if ($FocusPath) {
            $resolved = @()
            foreach ($c in $chosen) {
                $try = $FocusPath
                if (-not [IO.Path]::IsPathRooted($FocusPath)) { $try = Join-Path $c.StartPath $FocusPath }
                if (Test-Path -LiteralPath $try -PathType Container) { $resolved += [pscustomobject]@{ Root = $c.Root; StartPath = $try.TrimEnd('\'); Narrow = $true } }
            }
            if ($resolved.Count -eq 0) { Write-Status 'WARN' ('FocusPath not found under the chosen sync roots: ' + $FocusPath + '. Using top-level listing instead.') }
            $chosen = if ($resolved.Count -gt 0) { $resolved } else { $chosen }
            if ($resolved.Count -eq 0) { foreach ($c in $chosen) { $c.Narrow = $false } }
        }

        # ---- 3. Large dataset guard ----
        $anyBroad = @($chosen | Where-Object { -not $_.Narrow }).Count -gt 0
        $largeAction = $LargeDatasetAction
        $isLarge = ($script:EstimatedItems -gt $LargeDatasetThreshold)
        $focusPrompt = $null
        if ($isLarge -and $anyBroad) {
            if ($largeAction -eq 'Prompt') {
                if ($script:IsUnattended) { $largeAction = 'TopLevel'; Write-Status 'INFO' ('Large library ({0:N0} items). Unattended mode: top-level listing only. Use -FocusPath or -LargeDatasetAction Full to change this.' -f $script:EstimatedItems) }
                else {
                    Write-Host ''
                    Write-Host ('OneDrive reports about {0:N0} files and folders across all synced libraries on this PC.' -f $script:EstimatedItems) -ForegroundColor Yellow
                    Write-Host 'Reading every item can take a long time and puts load on OneDrive.' -ForegroundColor Yellow
                    $opts = @(
                        'Top-level folders only (fast, about 1 minute)',
                        'Index ONE folder that I choose (best when the problem area is known)',
                        ('Index everything (stops after {0} minutes per sync root)' -f $ScanTimeLimitMinutes),
                        'Skip the file index'
                    )
                    $pick = @(Select-FromList -Title 'What should be done with the large library?' -Options $opts -DefaultIndex 1)
                    switch ($pick[0]) {
                        1 { $largeAction = 'TopLevel' }
                        2 {
                            $largeAction = 'Focus'
                            $focusPrompt = Read-Text -Prompt 'Type the folder name (relative to the sync root) or a full path'
                        }
                        3 { $largeAction = 'Full' }
                        4 { $largeAction = 'Skip' }
                    }
                }
            }
        }
        else { $largeAction = 'Full' }

        foreach ($c in $chosen) {
            $mode = 'Full'; $start = $c.StartPath
            if ($isLarge -and -not $c.Narrow) {
                switch ($largeAction) {
                    'TopLevel' { $mode = 'TopLevel' }
                    'Skip' { $mode = 'Skip' }
                    'Focus' {
                        $try = $focusPrompt
                        if ($try -and -not [IO.Path]::IsPathRooted($try)) { $try = Join-Path $c.StartPath $try }
                        if ($try -and (Test-Path -LiteralPath $try -PathType Container)) { $start = $try.TrimEnd('\') }
                        else { $mode = 'TopLevel'; Write-Status 'WARN' ('Folder not found under ' + $c.Root.Title + '. Using a top-level listing.') }
                    }
                }
            }
            if ($mode -ne 'Skip') { [void]$targets.Add([pscustomobject]@{ Root = $c.Root; StartPath = $start; Mode = $mode }) }
            else { Write-Status 'SKIP' ('File index skipped for ' + $c.Root.Title) }
        }

        # ---- 4. Full index option (Deep) ----
        $fullPlanned = @($targets | Where-Object { $_.Mode -eq 'Full' }).Count -gt 0
        if ($fullPlanned -and $script:LevelNum -ge 3 -and -not $script:ScanFullIndex -and -not $script:IsUnattended) {
            $script:ScanFullIndex = Read-YesNo -Question 'Also write a CSV listing every file and folder? (large, about 100 MB per 400,000 items)' -DefaultYes $false
        }
    }

    # ---- 5. Run the index ----
    if ($targets.Count -eq 0) { Write-Status 'SKIP' 'No file index to run.'; return }
    $n = 0
    foreach ($t in $targets) {
        $n++
        $label = '{0}_{1}' -f $n, (Get-SafeName $t.Root.Title)
        if ($t.StartPath -ne $t.Root.MountPoint) { $label = $label + '_' + (Get-SafeName (Split-Path -Leaf $t.StartPath)) }
        $res = Invoke-FolderIndex -Root $t.Root -StartPath $t.StartPath -Mode $t.Mode -FullIndex $script:ScanFullIndex -Label $label
        [void]$script:ScanResults.Add($res)
        Add-ScanFindings -R $res
    }
}

# ----------------------------------------------------------------------------------------------
# SECTION 6. OneDrive LOG (ODL) SIGNATURES AND RAW LOG COPIES
# ODL files are binary, but the error text inside them is readable. We pull out short text snippets that
# match known error words, remove ids and numbers, and count how often each one appears.
# This avoids dumping megabytes of binary data to the screen.
# ----------------------------------------------------------------------------------------------

function Get-OdlFileSet {
    # Picks the newest ODL files from EVERY OneDrive log folder (each account, plus Common which holds the
    # launcher and updater logs), within the per-folder count and the total size limit.
    #   .odl / .aodl : current binary logs
    #   .odlgz       : older logs, gzip compressed (decompressed in memory when scanned)
    #   .odlsent     : already uploaded to Microsoft and stripped; almost no readable text, so skipped
    $logsBase = Join-Path $env:LOCALAPPDATA 'Microsoft\OneDrive\logs'
    if (-not (Test-Path -LiteralPath $logsBase)) { return @() }
    $folders = @(Get-Item -LiteralPath $logsBase) + @(Get-ChildItem -LiteralPath $logsBase -Directory -ErrorAction SilentlyContinue)
    $candidates = @()
    foreach ($d in $folders) {
        $candidates += @(Get-ChildItem -LiteralPath $d.FullName -File -ErrorAction SilentlyContinue |
                Where-Object { $_.Extension -in '.odl', '.aodl', '.odlgz' } |
                Sort-Object LastWriteTime -Descending | Select-Object -First $OdlMaxFiles)
    }
    $picked = @()
    $total = [long]0
    $cap = [long]$OdlMaxTotalMB * 1MB
    foreach ($f in @($candidates | Sort-Object LastWriteTime -Descending)) {
        if (($total + $f.Length) -gt $cap) { continue }
        $picked += $f
        $total += $f.Length
    }
    return $picked
}

function Read-OdlText {
    # Returns the text view of one ODL file (Latin-1, so every byte maps to one character).
    # .odlgz files are decompressed in memory first. Returns $null when the file cannot be read.
    param([System.IO.FileInfo]$File, [long]$MaxBytes)
    $fs = $null; $gz = $null; $ms = $null
    try {
        $fs = New-Object System.IO.FileStream($File.FullName, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, ([System.IO.FileShare]::ReadWrite -bor [System.IO.FileShare]::Delete))
        $ms = New-Object System.IO.MemoryStream
        $src = $fs
        if ($File.Extension -eq '.odlgz') {
            # An .odlgz file is a 256-byte ODL header followed by a gzip stream. Find the gzip signature (1F 8B 08)
            # in the first 4 KB and start decompressing there.
            $head = New-Object byte[] 4096
            $hn = $fs.Read($head, 0, $head.Length)
            $start = -1
            for ($i = 0; $i -lt ($hn - 2); $i++) {
                if ($head[$i] -eq 0x1F -and $head[$i + 1] -eq 0x8B -and $head[$i + 2] -eq 0x08) { $start = $i; break }
            }
            if ($start -lt 0) { throw 'No gzip data found in the file.' }
            $fs.Position = $start
            $gz = New-Object System.IO.Compression.GZipStream($fs, [System.IO.Compression.CompressionMode]::Decompress)
            $src = $gz
        }
        $chunk = New-Object byte[] 1048576
        while ($ms.Length -lt $MaxBytes) {
            $n = $src.Read($chunk, 0, $chunk.Length)
            if ($n -le 0) { break }
            $ms.Write($chunk, 0, $n)
        }
        return [System.Text.Encoding]::GetEncoding(28591).GetString($ms.GetBuffer(), 0, [int]$ms.Length)
    }
    catch {
        Write-Status 'WARN' ('Could not read ' + $File.Name + ': ' + $_.Exception.Message)
        return $null
    }
    finally {
        if ($gz) { $gz.Close() }
        if ($fs) { $fs.Close() }
        if ($ms) { $ms.Close() }
    }
}

function Step-OdlSignatures {
    # STEP: Scan the newest ODL files for error text and summarise it.
    $files = @(Get-OdlFileSet)
    $script:OdlFilesToCopy = $files
    if ($files.Count -eq 0) { Write-Status 'SKIP' 'No ODL log files found.'; return }

    # Words to look for. "Strong" words usually point to a real sync fault.
    $strong = @('FileSyncError', 'RecordFileSyncError', 'UpdatePHState', 'PostponedFailure', 'UnexpectedFailure', 'AccessDenied', 'ACCESS_DENIED',
        'Unauthorized', 'Forbidden', 'Throttl', 'QuotaExceeded', 'OverQuota', 'StorageFull', 'SiteLocked', 'ItemLocked', 'NameConflict', 'InvalidName', 'PathTooLong', 'DiskFull', 'NoSpace')
    $pattern = '(FileSyncError|RecordFileSyncError|UpdatePHState|PostponedFailure|UnexpectedFailure|Failure|AccessDenied|ACCESS_DENIED|Unauthorized|Forbidden|Throttl|QuotaExceeded|OverQuota|StorageFull|SiteLocked|ItemLocked|NameConflict|InvalidName|PathTooLong|DiskFull|NoSpace|0x8[0-9A-Fa-f]{7}|0xC[0-9A-Fa-f]{7})'
    $kwRx = New-Object System.Text.RegularExpressions.Regex($pattern)
    $leftRx = New-Object System.Text.RegularExpressions.Regex('[\x20-\x7E]*', [System.Text.RegularExpressions.RegexOptions]::RightToLeft)
    $rightRx = New-Object System.Text.RegularExpressions.Regex('^[\x20-\x7E]*')

    $kwCounts = @{}
    $sigCounts = @{}
    $sigFile = @{}
    $overflow = 0
    $readNames = @()
    $i = 0
    foreach ($f in $files) {
        $i++
        Write-Progress -Id 2 -ParentId 1 -Activity 'Scanning OneDrive logs' -Status ('{0} ({1})' -f $f.Name, (Format-Bytes $f.Length)) -PercentComplete ([int](100 * ($i - 1) / $files.Count))
        if ($f.Length -gt 120MB) { Write-Status 'SKIP' ('Too large to scan: ' + $f.Name); continue }
        # Read at most 120 MB of text per file (after decompression) to keep memory use bounded.
        $text = Read-OdlText -File $f -MaxBytes 120MB
        if ($null -eq $text) { continue }
        $readNames += ($f.Directory.Name + '\' + $f.Name)
        $lastEnd = 0
        $nMatch = 0
        foreach ($m in $kwRx.Matches($text)) {
            $nMatch++
            $kw = $m.Groups[1].Value
            if ($kw -match '^0x') { $kw = 'HexErrorCode' }
            $kwCounts[$kw] = 1 + [long]$kwCounts[$kw]
            # Build a readable snippet around the match (printable characters only). Capped at 60,000 per file.
            if ($nMatch -le 60000 -and $m.Index -ge $lastEnd) {
                $ls = [Math]::Max(0, $m.Index - 120)
                $left = $text.Substring($ls, $m.Index - $ls)
                $rl = [Math]::Min(160, $text.Length - $m.Index)
                $right = $text.Substring($m.Index, $rl)
                $rm = $rightRx.Match($right)
                $snippet = ($leftRx.Match($left).Value + $rm.Value).Trim()
                $lastEnd = $m.Index + $rm.Length
                $snippet = [regex]::Replace($snippet, '[0-9a-fA-F]{32}(\+\d+)?', '<id>')
                $snippet = [regex]::Replace($snippet, '[A-Za-z0-9_\-]{36,}', '<token>')
                if ($sigCounts.ContainsKey($snippet)) { $sigCounts[$snippet] = 1 + [long]$sigCounts[$snippet] }
                elseif ($sigCounts.Count -lt 4000) { $sigCounts[$snippet] = 1; $sigFile[$snippet] = $f.Name }
                else { $overflow++ }
            }
        }
        $text = $null
        [GC]::Collect()
    }
    Write-Progress -Id 2 -Activity 'Scanning OneDrive logs' -Completed
    $script:OdlFilesRead = $readNames

    $o = New-Object System.Collections.ArrayList
    [void]$o.Add('ONEDRIVE LOG SIGNATURE SCAN')
    [void]$o.Add('Files scanned (newest first): ' + ($readNames -join ', '))
    [void]$o.Add('Note: ODL files are binary. Text may be missing on some OneDrive versions. Counts show how often a word appears, not how many separate faults exist.')
    [void]$o.Add('')
    [void]$o.Add('KEYWORD COUNTS')
    if ($kwCounts.Count -eq 0) { [void]$o.Add('  No matches.') }
    foreach ($kv in ($kwCounts.GetEnumerator() | Sort-Object Value -Descending)) {
        $flag = ''
        if ($strong -contains $kv.Key) { $flag = '   <== review' }
        [void]$o.Add(('  {0,-22} {1,10:N0}{2}' -f $kv.Key, $kv.Value, $flag))
    }
    [void]$o.Add('')
    [void]$o.Add('TOP SIGNATURES (count, first file seen, text)')
    foreach ($kv in ($sigCounts.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 150)) {
        [void]$o.Add(('{0,8:N0}  [{1}]  {2}' -f $kv.Value, $sigFile[$kv.Key], $kv.Key))
    }
    if ($overflow -gt 0) { [void]$o.Add(('(More than 4000 different signatures. {0:N0} further snippets were not stored.)' -f $overflow)) }
    Save-Text '12_ODL_Signatures.txt' $o

    # Findings. FileSyncError and access words are the useful signals. Other words are shown for information.
    # Throttl is NOT in this list: it mostly matches code names such as ShouldThrottleRequestInternal on healthy PCs.
    $hot = @('FileSyncError', 'RecordFileSyncError', 'AccessDenied', 'ACCESS_DENIED', 'Unauthorized', 'Forbidden', 'QuotaExceeded', 'OverQuota', 'StorageFull', 'SiteLocked', 'ItemLocked', 'NameConflict', 'InvalidName', 'PathTooLong', 'DiskFull', 'NoSpace')
    $hotFound = @($kwCounts.GetEnumerator() | Where-Object { $hot -contains $_.Key } | Sort-Object Value -Descending)
    $soft = @($kwCounts.GetEnumerator() | Where-Object { ($strong -contains $_.Key) -and -not ($hot -contains $_.Key) } | Sort-Object Value -Descending)
    if ($hotFound.Count -gt 0) {
        $txt = ($hotFound | Select-Object -First 6 | ForEach-Object { '{0} x{1:N0}' -f $_.Key, $_.Value }) -join ', '
        Add-Finding 'Log signatures' 'Sync error words in OneDrive logs' 'WARN' $txt 'The OneDrive logs record sync errors. Open 12_ODL_Signatures.txt and read the top signatures. Send the package to L2.'
    }
    elseif ($soft.Count -gt 0) {
        $txt = ($soft | Select-Object -First 6 | ForEach-Object { '{0} x{1:N0}' -f $_.Key, $_.Value }) -join ', '
        Add-Finding 'Log signatures' 'Possible sync issues in OneDrive logs' 'INFO' $txt 'These words also appear in normal logs. Read 12_ODL_Signatures.txt if the user still reports a problem.'
    }
    else {
        Add-Finding 'Log signatures' 'Sync error words in OneDrive logs' 'PASS' ('No error words found in {0} log file(s).' -f $readNames.Count)
    }
}

function Copy-SharedFile {
    # Copies a file that OneDrive may have open (read share allowed).
    param([string]$Source, [string]$Destination)
    $in = $null; $out = $null
    try {
        $in = New-Object System.IO.FileStream($Source, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, ([System.IO.FileShare]::ReadWrite -bor [System.IO.FileShare]::Delete))
        $out = New-Object System.IO.FileStream($Destination, [System.IO.FileMode]::Create, [System.IO.FileAccess]::Write)
        $in.CopyTo($out)
        return $true
    }
    catch { Write-Log ('Copy failed for ' + $Source + ': ' + $_.Exception.Message) 'WARN'; return $false }
    finally { if ($in) { $in.Close() }; if ($out) { $out.Close() } }
}

function Step-RawLogs {
    # STEP (Deep or -IncludeRawLogs): copy settings files and the newest ODL logs into the package.
    $dest = Join-Path $script:OutDir '13_RawLogs'
    New-Item -ItemType Directory -Path $dest -Force | Out-Null
    $copied = 0
    foreach ($a in $script:Accounts) {
        $sdest = Join-Path $dest ((Get-SafeName $a.Key) + '_settings')
        New-Item -ItemType Directory -Path $sdest -Force | Out-Null
        foreach ($ini in @(Get-ChildItem -LiteralPath $a.SettingsDir -Filter '*.ini' -File -ErrorAction SilentlyContinue)) {
            if (Copy-SharedFile -Source $ini.FullName -Destination (Join-Path $sdest $ini.Name)) { $copied++ }
        }
    }
    $odl = @($script:OdlFilesToCopy)
    if ($odl.Count -eq 0) { $odl = @(Get-OdlFileSet) }
    $ldest = Join-Path $dest 'odl'
    New-Item -ItemType Directory -Path $ldest -Force | Out-Null
    foreach ($f in $odl) {
        # Prefix with the log folder name (Business1, Personal, Common) so files with the same name do not collide.
        if (Copy-SharedFile -Source $f.FullName -Destination (Join-Path $ldest ($f.Directory.Name + '_' + $f.Name))) { $copied++ }
    }
    Write-Status 'OK' ('Copied {0} raw log and settings file(s) to 13_RawLogs.' -f $copied)
}

# ----------------------------------------------------------------------------------------------
# SECTION 7. REPORT, MANIFEST AND ZIP
# ----------------------------------------------------------------------------------------------

function Step-Report {
    # STEP: Write the plain-language summary, the findings CSV and the manifest.
    $finish = Get-Date
    $dur = $finish - $script:StartTime
    $order = @{ 'FAIL' = 0; 'WARN' = 1; 'INFO' = 2; 'PASS' = 3 }
    $sorted = @($script:Findings | Sort-Object -Property @(@{ Expression = { $order[$_.Status] } }, @{ Expression = { $_.Area } }))
    $nFail = @($sorted | Where-Object { $_.Status -eq 'FAIL' }).Count
    $nWarn = @($sorted | Where-Object { $_.Status -eq 'WARN' }).Count
    $nInfo = @($sorted | Where-Object { $_.Status -eq 'INFO' }).Count
    $nPass = @($sorted | Where-Object { $_.Status -eq 'PASS' }).Count
    $script:CountFail = $nFail; $script:CountWarn = $nWarn

    Save-Csv '00_Findings.csv' ($sorted | Select-Object -Property @('Status', 'Area', 'Check', 'Detail', 'Advice'))

    $s = New-Object System.Collections.ArrayList
    [void]$s.Add('ONEDRIVE DIAGNOSTIC SUMMARY')
    [void]$s.Add('===========================')
    [void]$s.Add('Computer        : ' + $env:COMPUTERNAME)
    [void]$s.Add('User            : ' + $script:CurrentUser)
    [void]$s.Add('Collected       : ' + $script:StartTime.ToString('yyyy-MM-dd HH:mm:ss'))
    [void]$s.Add(('Duration        : {0:N0} seconds' -f $dur.TotalSeconds))
    [void]$s.Add('Collection level: ' + $script:LevelName)
    [void]$s.Add('Script version  : ' + $script:ScriptVersion)
    [void]$s.Add('')
    [void]$s.Add(('RESULT: {0} FAIL, {1} WARN, {2} INFO, {3} PASS' -f $nFail, $nWarn, $nInfo, $nPass))
    [void]$s.Add('')
    [void]$s.Add('KEY FACTS')
    foreach ($k in $script:Facts.Keys) { [void]$s.Add(('  {0,-34} {1}' -f $k, $script:Facts[$k])) }
    [void]$s.Add('')

    foreach ($status in @('FAIL', 'WARN')) {
        $group = @($sorted | Where-Object { $_.Status -eq $status })
        if ($group.Count -gt 0) {
            if ($status -eq 'FAIL') { [void]$s.Add('FAILED CHECKS (fix or escalate these first)') } else { [void]$s.Add('WARNINGS (review these)') }
            $n = 0
            foreach ($f in $group) {
                $n++
                [void]$s.Add(('  {0}. [{1}] {2}' -f $n, $f.Area, $f.Check))
                [void]$s.Add('     What was found : ' + $f.Detail)
                if ($f.Advice) { [void]$s.Add('     What to do     : ' + $f.Advice) }
            }
            [void]$s.Add('')
        }
    }
    $info = @($sorted | Where-Object { $_.Status -eq 'INFO' })
    if ($info.Count -gt 0) {
        [void]$s.Add('INFORMATION')
        foreach ($f in $info) { [void]$s.Add(('  - [{0}] {1}: {2}' -f $f.Area, $f.Check, $f.Detail)) }
        [void]$s.Add('')
    }
    $pass = @($sorted | Where-Object { $_.Status -eq 'PASS' })
    if ($pass.Count -gt 0) {
        [void]$s.Add('PASSED CHECKS')
        foreach ($f in $pass) { [void]$s.Add(('  - [{0}] {1}: {2}' -f $f.Area, $f.Check, $f.Detail)) }
        [void]$s.Add('')
    }

    if ($script:ScanResults.Count -gt 0) {
        [void]$s.Add('FILE INDEX RESULTS')
        foreach ($r in $script:ScanResults) {
            $partial = ''
            if ($r.Truncated) { $partial = ' (PARTIAL)' }
            [void]$s.Add(('  {0}: {1:N0} items, mode {2}{3}. Details: 11_FileSystem_{4}_Summary.txt' -f $r.Title, $r.Items, $r.Mode, $partial, $r.Label))
        }
        [void]$s.Add('')
    }

    [void]$s.Add('WHAT TO DO NEXT')
    if ($nFail -gt 0) { [void]$s.Add('  1. There are failed checks. Attach the zip to the ticket and name the failed checks in your notes.') }
    elseif ($nWarn -gt 0) { [void]$s.Add('  1. There are warnings. Review each one. If the user still has the problem, attach the zip to the ticket.') }
    else { [void]$s.Add('  1. The tool found no fault. Attach the zip to the ticket and ask the user for the exact symptom.') }
    [void]$s.Add('  2. Write down the exact folder or file path that shows the problem, the time, and take a screenshot with the Status column visible in File Explorer.')
    [void]$s.Add('  3. Do NOT reset, unlink or reinstall OneDrive on a large library until L2 has reviewed this package.')
    [void]$s.Add('  4. To focus on one folder of a very large library run again with: -SyncRoot "<library folder>" -FocusPath "<folder name>"')
    [void]$s.Add('')
    [void]$s.Add('PRIVACY')
    [void]$s.Add('  This package holds the user email, tenant and site names, and file and folder names. Handle it as confidential.')
    [void]$s.Add('')
    [void]$s.Add('STEP TIMINGS')
    foreach ($r in $script:StepResults) { [void]$s.Add(('  {0,-48} {1,-8} {2,7:N1} s' -f $r.Name, $r.Status, $r.Seconds)) }
    [void]$s.Add('')
    [void]$s.Add('FILES IN THIS PACKAGE')
    $root = $script:OutDir.TrimEnd('\') + '\'
    foreach ($f in @(Get-ChildItem -LiteralPath $script:OutDir -Recurse -File -ErrorAction SilentlyContinue | Sort-Object FullName)) {
        [void]$s.Add(('  {0,-70} {1,12}' -f $f.FullName.Substring($root.Length), (Format-Bytes $f.Length)))
    }
    Save-Text '00_Summary.txt' $s

    $manifest = [ordered]@{
        ScriptVersion = $script:ScriptVersion; Computer = $env:COMPUTERNAME; User = $script:CurrentUser
        Started = $script:StartTime.ToString('o'); Finished = $finish.ToString('o'); Level = $script:LevelName
        Elevated = $script:IsElevated; Unattended = $script:IsUnattended
        Parameters = [ordered]@{ OutputRoot = $OutputRoot; SyncRoot = ($SyncRoot -join ';'); FocusPath = $FocusPath; LargeDatasetAction = $LargeDatasetAction
            LargeDatasetThreshold = $LargeDatasetThreshold; ScanTimeLimitMinutes = $ScanTimeLimitMinutes; PathWarnLength = $PathWarnLength
            ServerPathWarnLength = $ServerPathWarnLength; EventDays = $EventDays; OdlMaxFiles = $OdlMaxFiles; OdlMaxTotalMB = $OdlMaxTotalMB
            FullIndex = $script:ScanFullIndex; RawLogs = $script:IncludeRaw }
        Counts = [ordered]@{ Fail = $nFail; Warn = $nWarn; Info = $nInfo; Pass = $nPass }
        Facts = $script:Facts
        Steps = @($script:StepResults)
        FileIndex = @($script:ScanResults | ForEach-Object { [ordered]@{ Title = $_.Title; Mode = $_.Mode; Items = $_.Items; Files = $_.Files; Dirs = $_.Dirs; Truncated = $_.Truncated; Seconds = $_.Seconds; Problems = $_.Exceptions } })
        Findings = @($sorted | Select-Object -Property @('Status', 'Area', 'Check', 'Detail', 'Advice'))
    }
    try { ($manifest | ConvertTo-Json -Depth 6) | Out-File -LiteralPath (Join-Path $script:OutDir '00_Manifest.json') -Encoding UTF8 }
    catch { Write-Log ('Manifest failed: ' + $_.Exception.Message) 'WARN' }
}

function Step-Zip {
    # STEP: Pack the folder into one .zip file next to it.
    $zipPath = $script:OutDir.TrimEnd('\') + '.zip'
    $zipStream = $null; $archive = $null
    try {
        Add-Type -AssemblyName System.IO.Compression
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        if (Test-Path -LiteralPath $zipPath) { Remove-Item -LiteralPath $zipPath -Force }
        # Entries are added one by one with forward-slash names. ZipFile.CreateFromDirectory on Windows PowerShell 5.1
        # writes backslash names, which some unzip tools (and non-Windows systems) cannot extract correctly.
        $baseName = Split-Path -Leaf $script:OutDir
        $rootLen = $script:OutDir.TrimEnd('\').Length + 1
        $zipStream = New-Object System.IO.FileStream($zipPath, [System.IO.FileMode]::CreateNew)
        $archive = New-Object System.IO.Compression.ZipArchive($zipStream, [System.IO.Compression.ZipArchiveMode]::Create)
        foreach ($f in @(Get-ChildItem -LiteralPath $script:OutDir -Recurse -File -ErrorAction SilentlyContinue)) {
            $entryName = $baseName + '/' + $f.FullName.Substring($rootLen).Replace('\', '/')
            [void][System.IO.Compression.ZipFileExtensions]::CreateEntryFromFile($archive, $f.FullName, $entryName, [System.IO.Compression.CompressionLevel]::Optimal)
        }
        $archive.Dispose(); $archive = $null
        $zipStream.Dispose(); $zipStream = $null
        $script:ZipPath = $zipPath
        Write-Status 'OK' ('Zip created: {0} ({1})' -f $zipPath, (Format-Bytes (Get-Item -LiteralPath $zipPath).Length))
        if (-not $script:ZipKeepFolder) {
            Remove-Item -LiteralPath $script:OutDir -Recurse -Force -ErrorAction SilentlyContinue
            Write-Status 'INFO' 'The unzipped folder was removed (zip only).'
        }
    }
    catch {
        if ($archive) { $archive.Dispose() }
        if ($zipStream) { $zipStream.Dispose() }
        Remove-Item -LiteralPath $zipPath -Force -ErrorAction SilentlyContinue
        Write-Status 'WARN' ('Zip failed: ' + $_.Exception.Message + '. The folder is still available.')
        $script:ZipPath = $null
    }
}

# ----------------------------------------------------------------------------------------------
# SECTION 8. STEP RUNNER AND MAIN PROGRAM
# ----------------------------------------------------------------------------------------------

function Invoke-Step {
    # Runs one step with a progress bar, timing and error capture. A failing step never stops the run.
    param([int]$Index, [int]$Total, [string]$Name, [scriptblock]$Action)
    Write-Progress -Id 1 -Activity 'OneDrive diagnostics' -Status ('Step {0} of {1}: {2}' -f $Index, $Total, $Name) -PercentComplete ([int](100 * ($Index - 1) / $Total))
    Write-Host ''
    Write-Host ('Step {0} of {1}: {2}' -f $Index, $Total, $Name) -ForegroundColor White
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $status = 'OK'
    $script:StepErrorCount = 0
    try {
        # Error records are sent to the run log instead of the screen. Normal output is passed through.
        & $Action 2>&1 | ForEach-Object {
            if ($_ -is [System.Management.Automation.ErrorRecord]) {
                $script:StepErrorCount++
                if ($script:StepErrorCount -le 5) { Write-Log ('   ' + $_.ToString()) 'INFO' }
            }
            else { $_ }
        }
    }
    catch {
        $status = 'ERROR'
        Write-Log ($_ | Out-String) 'ERROR'
        # Recorded as a finding so a broken step can never hide behind a clean "0 FAIL" result.
        Add-Finding 'Tool' ('Step stopped early: ' + $Name) 'WARN' $_.Exception.Message 'Part of the data for this step is missing. The run log (00_RunLog.txt) has the details. Send it to whoever maintains this tool.'
    }
    $sw.Stop()
    if ($script:StepErrorCount -gt 0) {
        Write-Log ('{0} non-terminating error(s) during step "{1}". The first few are listed above.' -f $script:StepErrorCount, $Name) 'INFO'
    }
    [void]$script:StepResults.Add([pscustomobject]@{ Name = $Name; Status = $status; Seconds = [math]::Round($sw.Elapsed.TotalSeconds, 1) })
    if ($status -eq 'OK') { Write-Status 'OK' ('Finished in {0:N1} seconds.' -f $sw.Elapsed.TotalSeconds) }
}

function Show-Plan {
    # Shows what will happen, then waits for Enter in interactive mode.
    Write-Host ''
    Write-Host 'PLAN' -ForegroundColor Cyan
    Write-Host ('  Computer / user   : {0} / {1}' -f $env:COMPUTERNAME, $script:CurrentUser)
    Write-Host ('  Collection level  : {0}' -f $script:LevelName)
    Write-Host ('  Output folder     : {0}' -f $script:OutDir)
    $zipText = 'No zip'
    if ($script:DoZip -and $script:ZipKeepFolder) { $zipText = 'Zip, keep folder' } elseif ($script:DoZip) { $zipText = 'Zip only (folder removed)' }
    Write-Host ('  Packaging         : {0}' -f $zipText)
    Write-Host ('  Elevated          : {0}' -f $script:IsElevated)
    if (-not $script:IsElevated) { Write-Host '  Note: not elevated. The fltmc filter list will be skipped. Everything else runs.' -ForegroundColor DarkGray }
    if ($script:IsUnattended) { Write-Host '  Mode              : unattended (no prompts)' }
    else {
        Write-Host ''
        [void](Read-Answer 'Press Enter to start, or press Ctrl+C to cancel')
    }
}

# ---- MAIN ----
$script:BoundParams = $PSBoundParameters
Show-Banner
Test-RunContext

if ($script:UserMismatch) {
    Write-Host ''
    Write-Host ('WARNING: This session runs as {0}, but the signed-in desktop user is {1}.' -f $script:CurrentUser, ($script:ExplorerOwners -join ', ')) -ForegroundColor Yellow
    Write-Host 'OneDrive data belongs to the desktop user. Results from this session may describe the wrong profile.' -ForegroundColor Yellow
    $script:IsUnattended = ($Unattended.IsPresent -or (-not [Environment]::UserInteractive))
    if (-not $script:IsUnattended) {
        if (-not (Read-YesNo -Question 'Continue anyway?' -DefaultYes $false)) { Write-Host 'Cancelled.'; exit 1 }
    }
    Add-Finding 'Environment' 'User context mismatch' 'WARN' ('Running as {0}; desktop user is {1}.' -f $script:CurrentUser, ($script:ExplorerOwners -join ', ')) 'Run the tool again in the context of the desktop user.'
}

Get-RunSettings
New-OutputFolder

# The ordered list of steps. Min is the lowest collection level (1 Quick, 2 Standard, 3 Deep) that runs the step.
$stepList = @(
    @{ Name = 'Environment, power and sign-in state'; Min = 1; Run = { Step-Environment } },
    @{ Name = 'OneDrive client and process'; Min = 1; Run = { Step-Client } },
    @{ Name = 'Accounts and sync roots'; Min = 1; Run = { Step-AccountsAndRoots } },
    @{ Name = 'Sync engine counters (SyncDiagnostics)'; Min = 1; Run = { Step-SyncDiagnostics } },
    @{ Name = 'Registry and policy export'; Min = 1; Run = { Step-Registry } },
    @{ Name = 'Cloud Files driver and overlay handlers'; Min = 1; Run = { Step-CloudFiles } },
    @{ Name = 'Event logs'; Min = 1; Run = { Step-Events } },
    @{ Name = 'Network and authentication'; Min = 1; Run = { Step-Network } },
    @{ Name = 'Settings and log folder listings'; Min = 1; Run = { Step-Listings } },
    @{ Name = 'File system index'; Min = 1; Run = { Step-FileSystem } },
    @{ Name = 'OneDrive log signatures'; Min = 2; Run = { Step-OdlSignatures } },
    @{ Name = 'Raw log copies'; Min = 9; Run = { Step-RawLogs } },
    @{ Name = 'Summary and manifest'; Min = 1; Run = { Step-Report } }
)
# Raw log copies run for Deep, or when -IncludeRawLogs is used.
foreach ($st in $stepList) { if ($st.Name -eq 'Raw log copies' -and $script:IncludeRaw) { $st.Min = 1 } }
$active = @($stepList | Where-Object { $_.Min -le $script:LevelNum })
if ($script:DoZip) { $active += @{ Name = 'Packaging (zip)'; Min = 1; Run = { Step-Zip } } }

Show-Plan
$total = $active.Count
$idx = 0
foreach ($st in $active) {
    $idx++
    Invoke-Step -Index $idx -Total $total -Name $st.Name -Action $st.Run
}
Write-Progress -Id 1 -Activity 'OneDrive diagnostics' -Completed

# ---- FINISH ----
Write-Host ''
Write-Host '==============================================================================' -ForegroundColor Cyan
Write-Host '  Collection complete' -ForegroundColor Green
Write-Host '==============================================================================' -ForegroundColor Cyan
$col = 'Green'
if ($script:CountWarn -gt 0) { $col = 'Yellow' }
if ($script:CountFail -gt 0) { $col = 'Red' }
Write-Host ('  Result : {0} FAIL, {1} WARN' -f $script:CountFail, $script:CountWarn) -ForegroundColor $col
$shown = @($script:Findings | Where-Object { $_.Status -eq 'FAIL' -or $_.Status -eq 'WARN' } | Sort-Object { if ($_.Status -eq 'FAIL') { 0 } else { 1 } } | Select-Object -First 8)
foreach ($f in $shown) { Write-Host ('    [{0}] {1}: {2}' -f $f.Status, $f.Check, $f.Detail) -ForegroundColor $(if ($f.Status -eq 'FAIL') { 'Red' } else { 'Yellow' }) }
if ($script:ZipKeepFolder -or -not $script:DoZip) { Write-Host ('  Folder : {0}' -f $script:OutDir) }
if ($script:ZipPath) { Write-Host ('  Zip    : {0}' -f $script:ZipPath) }
Write-Host '  Next   : open 00_Summary.txt first. Attach the zip (or folder) to the ticket.'
Write-Host '  Note   : the package contains file and folder names. Handle it as confidential.' -ForegroundColor DarkGray
if ($OpenOutput.IsPresent) {
    $openTarget = $script:OutputParent
    if (Test-Path -LiteralPath $script:OutDir) { $openTarget = $script:OutDir }
    try { Start-Process -FilePath 'explorer.exe' -ArgumentList ('"' + $openTarget + '"') } catch { }
}
