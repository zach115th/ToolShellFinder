$logRoot       = "C:\inetpub\logs\LogFiles"      # Location of IIS logs
$ThrottleLimit = 12                              # Processor core count

# ---------- constants ----------
$requiredFields = @(
    'date','time',
    'cs-method',
    'cs-uri-stem',
    'cs-uri-query',
    'cs(User-Agent)',
    'cs(Referer)',
    'c-ip'
)

# ---------- iocs ----------
$method        		= @('POST', 'GET')
$uriStemRegex		= '^/_layouts/(15|16)/ToolPane\.aspx$'
$uriQuery      		= 'DisplayMode=Edit&a=/ToolPane.aspx'
$referer		= @("/_layouts/SignOut.aspx", " ")
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
$uriRegex = '^/_layouts/(15|16)/(' + ($uriFilePatterns -join '|') + ')$'

# IoC Set 5 ─ client IP in external Toolshell IoC list
$ipListUrl = 'https://raw.githubusercontent.com/zach115th/BlockLists/main/emerging-threats/2025/toolshell/toolshell_ips.txt'
try {
    $ipIoCList = (Invoke-WebRequest -UseBasicParsing -Uri $ipListUrl).Content -split "`n" |
                 ForEach-Object { $_.Trim() } |
                 Where-Object { $_ -and ($_ -notmatch '^\s*#') }
    Write-Host "`nDownloaded $($ipIoCList.Count) IP addresses from IoC list." -ForegroundColor Green
} catch {
    Write-Warning "Unable to download IP list: $_" -ForegroundColor Red
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

            # CVE-2025-53771
            { $methodVal -in $using:method -and
              $stemVal   -match $using:uriStemRegex -and
              $queryVal  -like "*$($using:uriQuery)*" -and
              $refVal    -in $using:referer } {
	      $iocType = if ($methodVal -eq 'POST') {
				'CVE-2025-53771_POST'
    			} else {
        			'CVE-2025-53771_GET'
    			}

                $hits += [pscustomobject]@{
                    IoCType   = $iocType
                    File      = $filePath
                    Date      = $dateVal
		    Time      = $timeVal
		    Method    = $methodVal
                    ClientIP  = $clientIpVal
                    UserAgent = $uaVal
		    UriStem   = $stemVal
		    UriQuery  = $queryVal
                    Referer   = $refVal
		    Line      = $line
                }
            }

	    # CVE-2025-53770
	    { $methodVal -in $using:method -and
    	      $stemVal   -match $using:uriRegex -and
              $refVal -in $using:referer} {
	      		$iocType = if ($methodVal -eq 'POST') {
        			'CVE-2025-53770_POST'
    			} else {
        			'CVE-2025-53770_GET'
    			}

    		$hits += [pscustomobject]@{
        	IoCType   = $iocType
        	File      = $filePath
        	Date      = $dateVal
        	Time      = $timeVal
        	Method    = $methodVal
        	ClientIP  = $clientIpVal
        	UserAgent = $uaVal
        	UriStem   = $stemVal
        	UriQuery  = $queryVal
        	Referer   = $refVal
        	Line      = $line
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
    Write-Host "`nMatches exported to IIS_IoC_Matches.csv`n" -ForegroundColor Red
} else {
    Write-Host "`nNo matches found.`n" -ForegroundColor Green
}
