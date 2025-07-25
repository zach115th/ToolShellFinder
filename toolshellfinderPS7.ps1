$logRoot = "C:\inetpub\logs\LogFiles"

# ---------- constants ----------
$requiredFields = @(
    'date','time','cs-method','cs-uri-stem',
    'cs-uri-query','cs(User-Agent)','cs(Referer)'
)

# IoC Set 1 ─ ToolPane abuse
$method1   = 'POST'
$uriStems1 = @('/_layouts/15/ToolPane.aspx','/_layouts/16/ToolPane.aspx')
$uriQuery1 = 'DisplayMode=Edit&a=/ToolPane.aspx'
$referer1  = '/_layouts/SignOut.aspx'

# IoC Set 2 ─ suspicious file names
$method2   = 'GET'
$referer2  = '/_layouts/SignOut.aspx'
$uriFilePatterns = @(
    'spinstall.aspx','spinstall0.aspx','spinstall1.aspx','spinstall2.aspx',
    'xxx.aspx','3plx.aspx','debug_dev.js','info.js','spinstaller.aspx'
)
$uriRegex2 = '^/_layouts/(15|16)/(' + ($uriFilePatterns -join '|').Replace('.','\.') + ')$'

# IoC Set 3 ─ any *.aspx under /_layouts/15|16/ with naughty UA strings
$method3          = 'GET'
$uriWildcardRegex = '^/_layouts/(15|16)/[^/]+\.aspx$'
$userAgentIndicators  = @('curl','powershell','python')

# IoC Set 4 ─ same wildcard + big VIEWSTATE + naughty UA strings
$userAgentIndicators4 = @('curl','powershell','python')
$viewstateRegex       = '^__VIEWSTATE=.*'

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

        $cols      = $line.Split(' ')
        $dateVal   = $cols[$fieldIdx['date']]
        $timeVal   = $cols[$fieldIdx['time']]
        $methodVal = $cols[$fieldIdx['cs-method']]
        $uaVal     = $cols[$fieldIdx['cs(User-Agent)']]
        $stemVal   = $cols[$fieldIdx['cs-uri-stem']]
        $queryVal  = $cols[$fieldIdx['cs-uri-query']]
        $refVal    = $cols[$fieldIdx['cs(Referer)']]

        switch ($true) {

            { $methodVal -eq $using:method1 -and
              $using:uriStems1 -contains $stemVal -and
              $queryVal -like "*$($using:uriQuery1)*" -and
              $refVal   -like "*$($using:referer1)*" } {

                $hits += [pscustomobject]@{
                    IoCType   = 'ToolPane_POST'
                    File      = $filePath
                    Date      = $dateVal; Time = $timeVal; Method = $methodVal
                    UserAgent = $uaVal;   UriStem = $stemVal;   UriQuery = $queryVal
                    Referer   = $refVal;  Line = $line
                }
            }

            { $methodVal -eq $using:method2 -and
              $stemVal -match $using:uriRegex2 -and
              $refVal  -like "*$($using:referer2)*" } {

                $hits += [pscustomobject]@{
                    IoCType   = 'Suspicious_GET'
                    File      = $filePath
                    Date      = $dateVal; Time = $timeVal; Method = $methodVal
                    UserAgent = $uaVal;   UriStem = $stemVal;   UriQuery = $queryVal
                    Referer   = $refVal;  Line = $line
                }
            }

            { $methodVal -eq $using:method3 -and
              $stemVal   -match $using:uriWildcardRegex -and
              ($using:userAgentIndicators | Where-Object { $uaVal -like "*$_*" }) } {

                $hits += [pscustomobject]@{
                    IoCType   = 'LayoutsAspx_SuspiciousUA'
                    File      = $filePath
                    Date      = $dateVal; Time = $timeVal; Method = $methodVal
                    UserAgent = $uaVal;   UriStem = $stemVal;   UriQuery = $queryVal
                    Referer   = $refVal;  Line = $line
                }
            }

            { $stemVal -match $using:uriWildcardRegex -and
              $queryVal -match $using:viewstateRegex -and
              ($using:userAgentIndicators4 | Where-Object { $uaVal -like "*$_*" }) } {

                $hits += [pscustomobject]@{
                    IoCType   = 'LayoutsAspx_ViewState_SuspiciousUA'
                    File      = $filePath
                    Date      = $dateVal; Time = $timeVal; Method = $methodVal
                    UserAgent = $uaVal;   UriStem = $stemVal;   UriQuery = $queryVal
                    Referer   = $refVal;  Line = $line
                }
            }
        }
    }

    $hits   # emit matches for this file
} -ThrottleLimit 12

# ---------- output ----------
if ($results) {
    #$results | Format-Table -AutoSize
    $results | Export-Csv -Path .\IIS_IoC_Matches.csv -NoTypeInformation
    Write-Host "`nMatches exported to IIS_IoC_Matches.csv`n"
} else {
    Write-Host 'No matches found.`n'
}
