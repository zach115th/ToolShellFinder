$logRoot = "C:\inetpub\logs\LogFiles"

# --- IoC Set 1 ---
$method1   = "POST"
$uriStems1 = @("/_layouts/15/ToolPane.aspx", "/_layouts/16/ToolPane.aspx")
$uriQuery1 = "DisplayMode=Edit&a=/ToolPane.aspx"
$referer1  = "/_layouts/SignOut.aspx"

# --- IoC Set 2 ---
$method2   = "GET"
$referer2  = "/_layouts/SignOut.aspx"
$uriFilePatterns = @(
    "spinstall.aspx", "spinstall0.aspx", "spinstall1.aspx", "spinstall2.aspx",
    "xxx.aspx", "3plx.aspx", "debug_dev.js", "info.js", "spinstaller.aspx"
)
$uriRegex2 = "^/_layouts/(15|16)/(" + ($uriFilePatterns -join '|').Replace('.', '\.') + ")$"

# --- IoC Set 3 ---
$method3   = "GET"
$uriStems3 = @("/_layouts/15/start.aspx", "/_layouts/16/start.aspx")
$userAgentIndicators = @("curl", "powershell", "python")

# --- IoC Set 4 ---
$uriStems4 = @("/_layouts/15/success.aspx", "/_layouts/16/success.aspx")
$userAgentIndicators4 = @("curl", "powershell", "python")
$viewstateRegex = "^__VIEWSTATE=.{40,}"  # base64 is usually quite long, so 40+ chars as threshold

$results = @()
$logFiles = Get-ChildItem -Path $logRoot -Recurse -Include *.log

foreach ($logFile in $logFiles) {
    Write-Host "Processing $($logFile.FullName)..."
    $headerFound = $false
    $fieldIndex = @{}

    Get-Content $logFile.FullName | ForEach-Object {
        $line = $_.Trim()
        if ($line.StartsWith("#Fields:")) {
            $headerFound = $true
            $fields = $line.Substring(8).Trim().Split(" ")
            $fieldIndex = @{}
            for ($i = 0; $i -lt $fields.Count; $i++) {
                $fieldIndex[$fields[$i]] = $i
            }
            return
        }
        elseif ($line.StartsWith("#") -or !$headerFound -or [string]::IsNullOrWhiteSpace($line)) {
            return
        }

        $cols = $line.Split(" ")

        $requiredFields = @("date", "time", "cs-method", "cs-uri-stem", "cs-uri-query", "cs(User-Agent)", "cs(Referer)")
        if (-not ($requiredFields | ForEach-Object { $fieldIndex.ContainsKey($_) } | Where-Object { -not $_ } | Measure-Object).Count -eq 0) {
            return
        }

        $dateVal      = $cols[$fieldIndex["date"]]
        $timeVal      = $cols[$fieldIndex["time"]]
        $methodVal    = $cols[$fieldIndex["cs-method"]]
        $uaVal        = $cols[$fieldIndex["cs(User-Agent)"]]
        $uriStemVal   = $cols[$fieldIndex["cs-uri-stem"]]
        $uriQueryVal  = $cols[$fieldIndex["cs-uri-query"]]
        $refererVal   = $cols[$fieldIndex["cs(Referer)"]]

        # --- IoC Set 1: ToolPane POST ---
        if (
            $methodVal -eq $method1 -and
            $uriStems1 -contains $uriStemVal -and
            $uriQueryVal -like "*$uriQuery1*" -and
            $refererVal -like "*$referer1*"
        ) {
            $match = [PSCustomObject]@{
                IoCType    = "ToolPane_POST"
                File       = $logFile.FullName
                Date       = $dateVal
                Time       = $timeVal
                Method     = $methodVal
                UserAgent  = $uaVal
                UriStem    = $uriStemVal
                UriQuery   = $uriQueryVal
                Referer    = $refererVal
                Line       = $line
            }
            $results += $match
        }
        # --- IoC Set 2: spinstall, etc. GETs ---
        elseif (
            $methodVal -eq $method2 -and
            $uriStemVal -match $uriRegex2 -and
            $refererVal -like "*$referer2*"
        ) {
            $match = [PSCustomObject]@{
                IoCType    = "Suspicious_GET"
                File       = $logFile.FullName
                Date       = $dateVal
                Time       = $timeVal
                Method     = $methodVal
                UserAgent  = $uaVal
                UriStem    = $uriStemVal
                UriQuery   = $uriQueryVal
                Referer    = $refererVal
                Line       = $line
            }
            $results += $match
        }
        # --- IoC Set 3: GET start.aspx with suspicious UA ---
        elseif (
            $methodVal -eq $method3 -and
            $uriStems3 -contains $uriStemVal -and
            ($userAgentIndicators | Where-Object { $uaVal.ToLower() -like "*$($_.ToLower())*" })
        ) {
            $match = [PSCustomObject]@{
                IoCType    = "StartAspx_SuspiciousUA"
                File       = $logFile.FullName
                Date       = $dateVal
                Time       = $timeVal
                Method     = $methodVal
                UserAgent  = $uaVal
                UriStem    = $uriStemVal
                UriQuery   = $uriQueryVal
                Referer    = $refererVal
                Line       = $line
            }
            $results += $match
        }
        # --- IoC Set 4: success.aspx with suspicious UA and long __VIEWSTATE ---
        elseif (
            $uriStems4 -contains $uriStemVal -and
            $uriQueryVal -match $viewstateRegex -and
            ($userAgentIndicators4 | Where-Object { $uaVal.ToLower() -like "*$($_.ToLower())*" })
        ) {
            $match = [PSCustomObject]@{
                IoCType    = "SuccessAspx_ViewState_SuspiciousUA"
                File       = $logFile.FullName
                Date       = $dateVal
                Time       = $timeVal
                Method     = $methodVal
                UserAgent  = $uaVal
                UriStem    = $uriStemVal
                UriQuery   = $uriQueryVal
                Referer    = $refererVal
                Line       = $line
            }
            $results += $match
        }
    }
}

if ($results.Count -gt 0) {
    $results | Format-Table -AutoSize
    $results | Export-Csv -Path ".\IIS_IoC_Matches.csv" -NoTypeInformation
    Write-Host "`nMatches found and exported to IIS_IoC_Matches.csv"
} else {
    Write-Host "No matches found."
}
