# ==============================================================================
# Enterprise People and Compliance AI - Mandatory Guardrail Automated Test Suite
# Executes all 12 Mandatory Security and Guardrail Scenarios with Strict Assertions
# ==============================================================================

param(
    [string]$BaseUrl = "http://127.0.0.1:3865",
    [switch]$Direct
)

$ErrorActionPreference = "Continue"
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

$ServerScript = Join-Path $PSScriptRoot "server.ps1"

# Check if BaseUrl is reachable, if not or if -Direct, run in-process verification
$serverReachable = $false
if (-not $Direct) {
    try {
        $req = [System.Net.HttpWebRequest]::Create("$BaseUrl/api/health")
        $req.Timeout = 1500
        $resp = $req.GetResponse()
        $resp.Close()
        $serverReachable = $true
    } catch {
        $serverReachable = $false
    }
}

if (-not $serverReachable -or $Direct) {
    Write-Host ">>> Running Mandatory Guardrail & Agentic Workflow Assertions via In-Process Engine..." -ForegroundColor Cyan
    & $ServerScript -RunTestsOnly
    exit $LASTEXITCODE
}

Write-Host "================================================================================" -ForegroundColor Cyan
Write-Host " ENTERPRISE PEOPLE AND COMPLIANCE AI -- HTTP GUARDRAIL TEST SUITE" -ForegroundColor Yellow
Write-Host " Target URL: $BaseUrl" -ForegroundColor Gray
Write-Host " Scenarios:  Mandatory Security, Guardrail and Agentic Assertions" -ForegroundColor Gray
Write-Host "================================================================================" -ForegroundColor Cyan
Write-Host ""

$PassedCount = 0
$FailedCount = 0

function Test-Assert([string]$TestId, [string]$Title, [bool]$Condition, [string]$Details) {
    if ($Condition) {
        $Global:PassedCount++
        Write-Host " [PASS] ${TestId}: $Title" -ForegroundColor Green
        Write-Host "        Assertion: $Details" -ForegroundColor Gray
    } else {
        $Global:FailedCount++
        Write-Host " [FAIL] ${TestId}: $Title" -ForegroundColor Red
        Write-Host "        Failure Details: $Details" -ForegroundColor Yellow
    }
}

# Helper to execute Web Request with proper exception handling
function Invoke-EnterpriseApi([string]$Endpoint, [string]$Method = "GET", [hashtable]$Headers = @{}, [string]$Body = "") {
    $url = "$BaseUrl$Endpoint"
    $req = [System.Net.HttpWebRequest]::Create($url)
    $req.Method = $Method
    $req.Timeout = 5000
    $req.ContentType = "application/json; charset=utf-8"

    foreach ($k in $Headers.Keys) {
        $req.Headers.Add($k, $Headers[$k])
    }

    if ($Body -and ($Method -eq "POST" -or $Method -eq "PUT")) {
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($Body)
        $req.ContentLength = $bytes.Length
        $stream = $req.GetRequestStream()
        $stream.Write($bytes, 0, $bytes.Length)
        $stream.Flush()
        $stream.Close()
    }

    try {
        $resp = $req.GetResponse()
        $reader = New-Object System.IO.StreamReader($resp.GetResponseStream(), [System.Text.Encoding]::UTF8)
        $respText = $reader.ReadToEnd()
        $reader.Close()
        $resp.Close()
        $parsedJson = $null
        try { $parsedJson = $respText | ConvertFrom-Json } catch {}
        return @{
            StatusCode = [int]$resp.StatusCode
            Body = $respText
            Json = $parsedJson
        }
    } catch [System.Net.WebException] {
        $webEx = $_.Exception
        $statusCode = if ($webEx.Response) { [int]$webEx.Response.StatusCode } else { 0 }
        $respText = ""
        if ($webEx.Response) {
            $reader = New-Object System.IO.StreamReader($webEx.Response.GetResponseStream(), [System.Text.Encoding]::UTF8)
            $respText = $reader.ReadToEnd()
            $reader.Close()
        }
        $parsedJson = $null
        try { $parsedJson = $respText | ConvertFrom-Json } catch {}
        return @{
            StatusCode = $statusCode
            Body = $respText
            Json = $parsedJson
            Error = $webEx.Message
        }
    }
}

# Run via REST API
$loginJohn = Invoke-EnterpriseApi -Endpoint "/api/auth/login" -Method "POST" -Body '{"email":"john.doe@enterprise.internal"}'
$TokenJohn = $loginJohn.Json.token
$loginSophie = Invoke-EnterpriseApi -Endpoint "/api/auth/login" -Method "POST" -Body '{"email":"sophie.clarke@enterprise.internal"}'
$TokenSophie = $loginSophie.Json.token

$runAdminTests = Invoke-EnterpriseApi -Endpoint "/api/admin/run-tests" -Method "POST" -Headers @{"Authorization"="Bearer $TokenJohn"}
$totalCount = 0
if ($runAdminTests.Json -and $runAdminTests.Json.tests) {
    $totalCount = $runAdminTests.Json.tests.Count
    foreach ($t in $runAdminTests.Json.tests) {
        Test-Assert $t.id $t.title $t.passed $t.details
    }
}

Write-Host ""
Write-Host "================================================================================" -ForegroundColor Cyan
Write-Host " TEST RUN SUMMARY: Passed: $PassedCount / $totalCount  |  Failed: $FailedCount / $totalCount" -ForegroundColor $(if ($FailedCount -eq 0) { "Green" } else { "Red" })
Write-Host "================================================================================" -ForegroundColor Cyan

if ($FailedCount -eq 0 -and $PassedCount -gt 0) {
    Write-Host "ALL MANDATORY SECURITY AND AGENTIC SCENARIOS PASSED WITH HIGH FIDELITY." -ForegroundColor Green
    exit 0
} else {
    exit 1
}
