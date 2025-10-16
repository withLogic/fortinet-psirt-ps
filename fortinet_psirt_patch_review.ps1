<#
.SYNOPSIS
    FortiNetPatchReview - Get a list of the vulnerabilities from FortiGuard Lab's PSIRT RSS feed

.DESCRIPTION
    This script retrieves the list of vulnerabiltiies from FortiGuard Lab's PSIRT RSS feed.
    It returns the date the vulnerability was published, the CVE ID, CVSS3 score, and the title of the vulnerability

    Inspired by the MSRC-PatchReview project:
    https://github.com/f-bader/MSRC-PatchReview

.PARAMETER BaseScore
    Base CVSS score threshold for highlighting high-severity vulnerabilities. Default is 8.0
    Vulnerabilities with a CVSS score equal to or greater than this value will be highlighted in the output.

.PARAMETER Output
    Output format: "human-readable" (default), "json", or "psobject".
    - "human-readable": Outputs a formatted text report to the console.
    - "json": Outputs the data in JSON format.
    - "psobject": Outputs the data as PowerShell objects for further processing.

.PARAMETER ProductFilter
    Comma-seperated value of products to filter the vulnerabilities results by. This can include specific version information, like FortiOS 7.4, or overall product categories like FortiOS. 
    The values are not case sensitive and you can mix specific product versions and overall products, i.e "FortiOS 7.4, fortimail"

.PARAMETER ExcludeProducts
    Bypass the parsing of the product table. Can make the script execute quicker. Useful if getting impacted product detail is not needed. 

.EXAMPLE
    .\fortinet_psirt_patch_review.ps1 -BaseScore 6

.NOTES
    Permission is hereby granted, free of charge, to any person obtaining a copy
    of this software and associated documentation files (the "Software"), to deal
    in the Software without restriction, including without limitation the rights
    to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
    copies of the Software, and to permit persons to whom the Software is
    furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all
    copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
    SOFTWARE.
#>

[CmdletBinding()]
param(
    [float]$baseScore = 8.0,

    [ValidateSet("human-readable", "json", "psobject")]
    [string]$Output = "human-readable",

    [string]$ProductFilter,

    [switch]$ExcludeProducts
)

$FeedUrl = "https://filestore.fortinet.com/fortiguard/rss/ir.xml"

$storedProgressPreference = $ProgressPreference
$ProgressPreference = 'SilentlyContinue'

try {
    [xml]$rss = Invoke-WebRequest -Uri $FeedUrl -UseBasicParsing | Select-Object -ExpandProperty Content 
} catch {
    Write-Host "Failed to fetch RSS feed: $_"
    exit
} finally {
    $ProgressPreference = $storedProgressPreference
}

# Detect feed type
if ($rss.rss -ne $null) {
    $items = $rss.rss.channel.item
    $feedType = "RSS"
} elseif ($rss.feed -ne $null) {
    $items = $rss.feed.entry
    $feedType = "Atom"
} else {
    Write-Host "Unknown feed format."
    exit
}

$filters = @()
if ($ProductFilter) {
    $ExcludeProducts = $false
    $filters = $ProductFilter -split ',' | ForEach-Object { $_.Trim().ToLower() } | Where-Object { $_ -ne "" }
}

$seenCVEs = @{}
$results = @()

foreach ($item in $items) {
    if ($feedType -eq "RSS") {
        $pubDate = Get-Date $item.pubDate
        $title = $item.title
        $link = $item.link
    } else {
        $pubDate = Get-Date $item.updated
        $title = $item.title.'#text'
        $link = $item.link.href
    }

    $storedProgressPreference = $ProgressPreference
    $ProgressPreference = 'SilentlyContinue'

    try {
        $page = Invoke-WebRequest -Uri $link
        $html = $page.Content

        $severity = if ($html -match '(?is)<td>\s*Severity\s*</td>\s*<td[^>]*>(.*?)</td>') {
            ($matches[1] -replace '<[^>]+>', '').Trim()
        } else { "N/A" }

        $cvss = if ($html -match '(?is)<td>\s*CVSSv3\s*Score\s*</td>\s*<td[^>]*>.*?>([\d\.]+)</a>') {
            ($matches[1] -replace '[^\d\.]', '').Trim()
        } else { "N/A" }

        $cveids = @()
        if ($html -match '(?is)<td>\s*CVE\s*ID\s*</td>\s*<td[^>]*>(.*?)</td>') {
            $inner = $matches[1]
            $cveids = [regex]::Matches($inner, 'CVE-\d{4}-\d{4,7}', 'IgnoreCase') | ForEach-Object { $_.Value }
        }
        if (-not $cveids -or $cveids.Count -eq 0) { $cveids = @("N/A") }

        $impact = if ($html -match '(?is)<td>\s*Impact\s*</td>\s*<td[^>]*>(.*?)</td>') {
            ($matches[1] -replace '<[^>]+>', '').Trim()
        } else { "N/A" }

        # Extract table of affected versions
        $affectedProducts = @()

        if(-not $ExcludeProducts) {

            if ($html -match '(?is)<table[^>]*>(.*?)</table>') {
                $tableHtml = $matches[1]

                # Find each <tr> row within the table
                $rows = [regex]::Matches($tableHtml, '(?is)<tr>(.*?)</tr>')

                foreach ($row in $rows) {
                    # Find all <td> cells in the row
                    $cells = [regex]::Matches($row.Groups[1].Value, '(?is)<td[^>]*>(.*?)</td>') | ForEach-Object { 
                        ($_ -replace '<[^>]+>', '').Trim()
                    }

                    # If there are 3 columns and the first looks like a product/version
                    if ($cells.Count -ge 1 -and $cells[0] -match '\S') {
                        $affectedProducts += $cells[0]
                    }
                }
            }
        }

        if ($affectedProducts.Count -eq 0) { 
            $affectedProducts = @("N/A") 
        }


        foreach ($cve in $cveids) {
            if (-not $seenCVEs.ContainsKey($cve)) {
                $seenCVEs[$cve] = $true

                $numericCVSS = 0
                if ($cvss -ne "N/A") {
                    $clean = $cvss.Trim() -replace '[^\d\.]', ''
                    if ([double]::TryParse($clean, [ref]$null)) {
                        $numericCVSS = [double]$clean
                    }
                }

                $results += [PSCustomObject]@{
                    CVE       = $cve
                    CVSS      = $numericCVSS
                    Severity  = $severity
                    Impact    = $impact
                    Title     = $title
                    URL       = $link
                    PDate     = $pubDate.ToString("MM/dd/yyyy")
                    Products  = ($affectedProducts -join ", ")
                }
            }
        }

    } catch {
        Write-Warning "Failed to load details page: $_"
    } finally {
        $ProgressPreference = $storedProgressPreference
    }
}

if ($filters.Count -gt 0) {
    $results = $results | Where-Object {
        $productList = ($_.Products -split ',') | ForEach-Object { $_.Trim().ToLower() }
        foreach ($filter in $filters) {
            if ($productList -match ("^" + [regex]::Escape($filter))) {
                return $true
            }
        }
        return $false
    }
}


if ($Output -eq "psobject") {
    $results
    exit 0
}

if ($Output -eq "json") {
    $results | ConvertTo-Json -Depth 3
    exit 0
}

Write-Host "[+] FortiNet Security Updates Stats"-ForegroundColor Green 
Write-Host "[+] https://github.com/withlogic/fortinet-psirt-ps"-ForegroundColor Green 
Write-Host "[+] Checking $feedType feed for entries" -ForegroundColor Green -NoNewline

$total = $results.Count
Write-Host "`n[+] Found a total of $total vulnerabilities" -ForegroundColor Green

$impactGroups = $results | Group-Object -Property Impact | Sort-Object -Property Count -Descending

foreach ($group in $impactGroups) {
    $impactName = if ([string]::IsNullOrWhiteSpace($group.Name)) { "Unspecified Impact" } else { $group.Name }
    Write-Host ("  [-] {0} {1}" -f $group.Count, $impactName) -ForegroundColor Cyan
}

$highSeverity = @($results | Where-Object { $_.CVSS -ge $baseScore } | Sort-Object -Property CVSS -Descending)
$otherVulns   = $results | Where-Object { $_.CVSS -lt $baseScore -or $_.CVSS -eq 0.0 } | Sort-Object -Property CVSS -Descending

if (($highSeverity | Measure-Object).Count -gt 0) {
    Write-Host "[+] Highest Rated Vulnerabilities - CVE >= $($baseScore)" -ForegroundColor Green
    foreach ($item in $highSeverity) {
        $cvssFormatted = if ($item.CVSS -eq 0) { "N/A" } else { "{0:N1}" -f $item.CVSS }
        Write-Host "  [-] $($item.PDate) - $($item.CVE) - $cvssFormatted - $($item.Title) - $($item.URL)" -ForegroundColor Red
    }
}

if ($otherVulns.Count -gt 0) {
    Write-Host "[+] Remaining Vulnerabilities" -ForegroundColor Green
    foreach ($item in $otherVulns) {
        $cvssFormatted = if ($item.CVSS -eq 0) { "N/A" } else { "{0:N1}" -f $item.CVSS }
        Write-Host "  [-] $($item.PDate) - $($item.CVE) - $cvssFormatted - $($item.Title) - $($item.URL)" -ForegroundColor Yellow
    }
}