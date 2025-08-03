$logRoot       = "C:\inetpub\logs\LogFiles"    # Location of IIS logs
$ThrottleLimit = 12                              # Processor core count

# ---------- constants ----------
$requiredFields = @(
    'date','time','cs-method','cs-uri-stem','cs-uri-query',
    'cs(User-Agent)','cs(Referer)','c-ip'
)
$uriWildcardRegex	= '^/_layouts/(15|16)/[^/]+\.aspx$'
$referer		= '/_layouts/SignOut.aspx'

# IoC Set 1 ─ ToolPane abuse (POST)
$method1        = 'POST'
$uriQuery1      = 'DisplayMode=Edit&a=/ToolPane.aspx'

# IoC Set 2 ─ suspicious file names (GET)
$method2       = 'GET'
$uriFilePatterns = @(
    'spinstall\.aspx',
    'spinstall.*\.aspx',
    'xxx\.aspx',
    '3plx\.aspx',
    'debug_dev\.js',
    'info\.js',
    'spinstaller\.aspx',
    'machinekey\.aspx',
    'info.*\.js'
)
$uriRegex2 = '^/_layouts/(15|16)/(' + ($uriFilePatterns -join '|') + ')$'

# IoC Set 3 ─ any *.aspx under /_layouts/15|16/ with suspicious UA strings (POST)
$userAgentIndicators  = @('curl','powershell','python', 'java')

# IoC Set 4 ─ wildcard + big VIEWSTATE + naughty UA strings
$viewstateRegex = '^__VIEWSTATE=.*'

# IoC Set 5 ─ client IP in external Toolshell IoC list
$ipListUrl = 'https://raw.githubusercontent.com/zach115th/BlockLists/main/emerging-threats/2025/toolshell/toolshell_ips.txt'
try {
    $ipIoCList = (Invoke-WebRequest -UseBasicParsing -Uri $ipListUrl).Content -split "`n" |
                 ForEach-Object { $_.Trim() } |
                 Where-Object { $_ -and ($_ -notmatch '^\s*#') }
    Write-Host "`nDownloaded $($ipIoCList.Count) IP addresses from IoC list."
} catch {
    Write-Warning "Unable to download IP list: $_"
    $ipIoCList = @()
}

# ---------- gather log files ----------
$logFiles = Get-ChildItem -Path $logRoot -Recurse -Include *.log

# ---------- parallel scan ----------
$results = $logFiles | ForEach-Object -Parallel {

    $logFile    = $_
    $filePath   = $logFile.FullName
    $fieldIdx   = @{}
    $headerSeen = $false
    $hits       = @()

    foreach ($raw in [System.IO.File]::ReadLines($filePath)) {

        $line = $raw.Trim()

        if ($line.StartsWith('#Fields:')) {
            $headerSeen = $true
            $fieldIdx   = @{}
            $fields     = $line.Substring(8).Trim().Split(' ')
            for ($i = 0; $i -lt $fields.Count; $i++) { $fieldIdx[$fields[$i]] = $i }
            continue
        }

        if (-not $headerSeen -or $line.StartsWith('#') -or [string]::IsNullOrWhiteSpace($line)) { continue }
        if ($line.IndexOf('/_layouts') -lt 0) { continue }

        $cols        = $line.Split(' ')
        $dateVal     = $cols[$fieldIdx['date']]
        $timeVal     = $cols[$fieldIdx['time']]
        $methodVal   = $cols[$fieldIdx['cs-method']]
        $uaVal       = $cols[$fieldIdx['cs(User-Agent)']]
        $stemVal     = $cols[$fieldIdx['cs-uri-stem']]
        $queryVal    = $cols[$fieldIdx['cs-uri-query']]
        $refVal      = $cols[$fieldIdx['cs(Referer)']]
        $clientIpVal = $fieldIdx.ContainsKey('c-ip') ? $cols[$fieldIdx['c-ip']] : ''

        switch ($true) {

            # IoC 1 – ToolPane POST (regex match, not literal!)
            { $methodVal -eq $using:method1 -and
              $stemVal   -match $using:uriWildcardRegex -and
              $queryVal  -like "*$($using:uriQuery1)*" -and
              $refVal    -like "*$($using:referer)*" } {

                $hits += [pscustomobject]@{
                    IoCType   = 'ToolPane_POST'
                    File      = $filePath
                    Date      = $dateVal; Time = $timeVal; Method = $methodVal
                    ClientIP  = $clientIpVal
                    UserAgent = $uaVal;   UriStem = $stemVal;   UriQuery = $queryVal
                    Referer   = $refVal;  Line = $line
                }
            }

            # IoC 2 – Suspicious GET
            { $methodVal -eq $using:method2 -and
              $stemVal   -match $using:uriRegex2 -and
              $refVal    -like "*$($using:referer)*" } {

                $hits += [pscustomobject]@{
                    IoCType   = 'Suspicious_GET'
                    File      = $filePath
                    Date      = $dateVal; Time = $timeVal; Method = $methodVal
                    ClientIP  = $clientIpVal
                    UserAgent = $uaVal;   UriStem = $stemVal;   UriQuery = $queryVal
                    Referer   = $refVal;  Line = $line
                }
            }

            # IoC 4 – ViewState + SuspiciousUA
            { $stemVal -match $using:uriWildcardRegex -and
              $queryVal -match $using:viewstateRegex -and
              ($using:userAgentIndicators | Where-Object { $uaVal.ToLower() -like "*$($_.ToLower())*" }) } {

                $hits += [pscustomobject]@{
                    IoCType   = 'LayoutsAspx_ViewState_SuspiciousUA'
                    File      = $filePath
                    Date      = $dateVal; Time = $timeVal; Method = $methodVal
                    ClientIP  = $clientIpVal
                    UserAgent = $uaVal;   UriStem = $stemVal;   UriQuery = $queryVal
                    Referer   = $refVal;  Line = $line
                }
            }

            # IoC 3 – SuspiciousUA (no ViewState)
            { $methodVal -eq $using:method1 -and
              $stemVal   -match $using:uriWildcardRegex -and
              ($using:userAgentIndicators | Where-Object { $uaVal.ToLower() -like "*$($_.ToLower())*" }) -and
              -not ($queryVal -match $using:viewstateRegex) } {

                $hits += [pscustomobject]@{
                    IoCType   = 'LayoutsAspx_SuspiciousUA'
                    File      = $filePath
                    Date      = $dateVal; Time = $timeVal; Method = $methodVal
                    ClientIP  = $clientIpVal
                    UserAgent = $uaVal;   UriStem = $stemVal;   UriQuery = $queryVal
                    Referer   = $refVal;  Line = $line
                }
            }

            # IoC 5 – Malicious client IP
            { $clientIpVal -and ($using:ipIoCList -contains $clientIpVal) } {

                $hits += [pscustomobject]@{
                    IoCType   = 'Malicious_ClientIP'
                    File      = $filePath
                    Date      = $dateVal; Time = $timeVal; Method = $methodVal
                    ClientIP  = $clientIpVal
                    UserAgent = $uaVal;   UriStem = $stemVal;   UriQuery = $queryVal
                    Referer   = $refVal;  Line = $line
                }
            }
        }
    }

    $hits   # emit matches for this file
} -ThrottleLimit $ThrottleLimit

# ---------- output ----------
if ($results) {
    $results | Export-Csv -Path .\IIS_IoC_Matches.csv -NoTypeInformation
    Write-Host "`nMatches exported to IIS_IoC_Matches.csv`n"
} else {
    Write-Host 'No matches found.`n'
}
