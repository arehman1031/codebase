# ================================================
# CVE Lookup Tool using NVD API 2.0
# PowerShell Version
# ================================================

function Get-CVEDetails {
    param(
        [Parameter(Mandatory=$true)]
        [string]$CVEID
    )

    $url = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=$CVEID"

    Write-Host "`nFetching CVE details from NVD API..." -ForegroundColor Cyan

    try {
        $response = Invoke-RestMethod -Uri $url `
                                     -Method Get `
                                     -UserAgent "PowerShell-CVE-Lookup/1.0" `
                                     -TimeoutSec 15

        $vuln = $response.vulnerabilities[0].cve

        if (-not $vuln) {
            Write-Host "Error: No data found for CVE ID: $CVEID" -ForegroundColor Red
            return
        }

        $description = $vuln.descriptions[0].value

        Write-Host "`n===== CVE DETAILS =====" -ForegroundColor Green
        Write-Host "CVE ID       : $CVEID"
        Write-Host "Description  : $description"

        # CVSS v3.1 Metrics
        $cvss = $vuln.metrics.cvssMetricV31[0].cvssData

        if ($cvss) {
            Write-Host "`nCVSS Score   : $($cvss.baseScore)" -ForegroundColor Yellow
            Write-Host "Severity     : $($cvss.baseSeverity)" -ForegroundColor Yellow
            Write-Host "Vector       : $($cvss.vectorString)" -ForegroundColor Yellow
        }
        else {
            Write-Host "`nCVSS data not available (or only older versions present)" -ForegroundColor DarkYellow
        }

    }
    catch {
        Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
        
        if ($_.Exception.Response) {
            Write-Host "Status Code: $($_.Exception.Response.StatusCode)" -ForegroundColor Red
        }
    }
}

# ===================== Main Execution =====================

Clear-Host
Write-Host "=== NVD CVE Lookup Tool (PowerShell) ===" -ForegroundColor Cyan

$cveId = Read-Host -Prompt "Enter CVE ID (e.g., CVE-2021-44228)"

if ([string]::IsNullOrWhiteSpace($cveId)) {
    Write-Host "Error: CVE ID cannot be empty." -ForegroundColor Red
    exit 1
}

Get-CVEDetails -CVEID $cveId

Write-Host "`nPress any key to exit..." -ForegroundColor Gray
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")