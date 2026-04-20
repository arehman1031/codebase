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

        $cveData = $response.vulnerabilities[0].cve

        if (-not $cveData) {
            Write-Host "Error: No data found for CVE ID: $CVEID" -ForegroundColor Red
            return
        }

        $description = $cveData.descriptions[0].value

        Write-Host "`n===== CVE DETAILS =====" -ForegroundColor Green
        Write-Host "CVE ID       : $CVEID"
        Write-Host "Description  : $description"

        # CVSS v3.1 Metrics
        $cvss = $cveData.metrics.cvssMetricV31[0].cvssData

        if ($cvss) {
            Write-Host "`nCVSS Score   : $($cvss.baseScore)" -ForegroundColor Yellow
            Write-Host "Severity     : $($cvss.baseSeverity)" -ForegroundColor Yellow
            Write-Host "Vector       : $($cvss.vectorString)" -ForegroundColor Yellow
        }
        else {
            Write-Host "`nCVSS data not available (or only older versions present)" -ForegroundColor DarkYellow
        }

        # CWE
        $cwe = $cveData.weaknesses | ForEach-Object { $_.description | Where-Object lang -eq 'en' | Select-Object -ExpandProperty value }
        if ($cwe) { Write-Host "CWE         : $($cwe -join ', ')" }

        # CISA KEV Check (simple local download or cached; for production use GitHub raw)
        $kevUrl = "https://raw.githubusercontent.com/cisagov/known-exploited-vulnerabilities/master/known_exploited_vulnerabilities.json"
        try {
            $kevData = Invoke-RestMethod -Uri $kevUrl -Method Get
            $isKEV = $kevData.vulnerabilities | Where-Object cveID -eq $CVE
            if ($isKEV) {
                Write-Host "`n This CVE is in CISA Known Exploited Vulnerabilities (KEV)!" -ForegroundColor Red
                Write-Host "Due Date    : $($isKEV.dueDate)"
                Write-Host "Notes       : $($isKEV.notes)"
            }
        }
        catch {
            Write-Warning "Could not check CISA KEV catalog."
        }

        # Heuristic ATT&CK Mapping Suggestions
        Write-Host "`n Suggested MITRE ATT&CK Techniques (Heuristic)" -ForegroundColor Magenta

        $description = ($cveData.descriptions | Where-Object lang -eq 'en' | Select-Object -ExpandProperty value).ToLower()

        $techniques = @()

        if ($description -match 'remote code execution|rce|arbitrary code|command injection') {
            $techniques += [PSCustomObject]@{ID="T1190"; Name="Exploit Public-Facing Application"; Tactic="Initial Access"}
            $techniques += [PSCustomObject]@{ID="T1059"; Name="Command and Scripting Interpreter"; Tactic="Execution"}
        }

        if ($description -match 'privilege escalation|escalat|local privilege') {
            $techniques += [PSCustomObject]@{ID="T1068"; Name="Exploitation for Privilege Escalation"; Tactic="Privilege Escalation"}
        }

        if ($description -match 'sql injection|injection') {
            $techniques += [PSCustomObject]@{ID="T1190"; Name="Exploit Public-Facing Application"; Tactic="Initial Access"}
        }

        if ($description -match 'buffer overflow|use after free|memory corruption') {
            $techniques += [PSCustomObject]@{ID="T1203"; Name="Exploitation for Client Execution"; Tactic="Execution"}
        }

        if ($description -match 'cross-site scripting|xss') {
            $techniques += [PSCustomObject]@{ID="T1189"; Name="Drive-by Compromise"; Tactic="Initial Access"}
        }

        # Default fallback
        if ($techniques.Count -eq 0) {
            $techniques += [PSCustomObject]@{ID="T1190"; Name="Exploit Public-Facing Application (common for many vulns)"; Tactic="Initial Access"}
        }

        $techniques | Format-Table -AutoSize @{Label="Technique ID"; Expression={$_.ID}}, 
                                        @{Label="Technique Name"; Expression={$_.Name}}, 
                                        @{Label="Tactic"; Expression={$_.Tactic}}

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

























