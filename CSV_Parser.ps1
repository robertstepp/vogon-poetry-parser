<#
.SYNOPSIS
    Input CSV files exported from Nessus Scanner and parses it into a usable listing of files with vulnerabilities.
    Exports the results to a CSV file.

.DESCRIPTION
    This script imports a Nessus CSV export, normalizes hostnames from DNS/NetBIOS formats,
    extracts all file paths (Windows and Linux) from Plugin Output, and exports results
    in the format: Plugin, Severity, Hostname, Path

.PARAMETER InputFilePath
    Path to the input Nessus CSV file

.PARAMETER OutputFilePath
    Path for the output CSV file

.EXAMPLE
    .\CSV_Parser.ps1 -InputFilePath "C:\nessus_export.csv" -OutputFilePath "C:\parsed_results.csv"
#>

param (
    [Parameter(Mandatory = $true)]
    [string]$InputFilePath,

    [Parameter(Mandatory = $true)]
    [string]$OutputFilePath
)

function ConvertFrom-DNSName {
    param (
        [string]$dnsName
    )
    # Take DNS name (myHost.myDomain.com) and convert to just hostname in lowercase (myhost)
    if ([string]::IsNullOrWhiteSpace($dnsName)) {
        return $null
    }
    $hostname = ($dnsName -split '\.')[0].ToLower()
    return $hostname
}

function ConvertFrom-NetbiosName {
    param (
        [string]$netbiosName
    )
    # Take NetBIOS name (myDomain\myHost) and convert to just hostname in lowercase (myhost)
    if ([string]::IsNullOrWhiteSpace($netbiosName)) {
        return $null
    }
    if ($netbiosName -match '\\') {
        $hostname = ($netbiosName -split '\\')[-1].ToLower()
    } else {
        $hostname = $netbiosName.ToLower()
    }
    return $hostname
}

function Get-NormalizedHostname {
    param (
        [string]$dnsName,
        [string]$netbiosName
    )
    # Try DNS name first, fall back to NetBIOS
    $hostname = ConvertFrom-DNSName -dnsName $dnsName
    if ([string]::IsNullOrWhiteSpace($hostname)) {
        $hostname = ConvertFrom-NetbiosName -netbiosName $netbiosName
    }
    return $hostname
}

function Get-PathsFromOutput {
    param (
        [string]$pluginOutput
    )

    $paths = @()

    if ([string]::IsNullOrWhiteSpace($pluginOutput)) {
        return $paths
    }

    # Pattern for paths following "path:" prefix - captures until end of line
    $pathPrefixPattern = '(?im)^\s*path\s*:\s*(.+?)$'

    $prefixMatches = [regex]::Matches($pluginOutput, $pathPrefixPattern)
    foreach ($match in $prefixMatches) {
        $extractedPath = $match.Groups[1].Value.Trim()
        if (-not [string]::IsNullOrWhiteSpace($extractedPath)) {
            $paths += $extractedPath
        }
    }

    # If no "path:" prefixed paths found, try standalone path patterns
    if ($paths.Count -eq 0) {
        # Windows paths: C:\path\to\file (handles spaces)
        $windowsPattern = '(?m)[A-Za-z]:\\[^\r\n"''<>|*?]+'

        # Linux absolute paths: /path/to/file
        $linuxPattern = '(?m)(?<![A-Za-z0-9])/(?:[a-zA-Z0-9._\-]+/)*[a-zA-Z0-9._\-]+'

        $winMatches = [regex]::Matches($pluginOutput, $windowsPattern)
        foreach ($match in $winMatches) {
            $extractedPath = $match.Value.TrimEnd(' ', '\', '.')
            if (-not [string]::IsNullOrWhiteSpace($extractedPath)) {
                $paths += $extractedPath
            }
        }

        $linuxMatches = [regex]::Matches($pluginOutput, $linuxPattern)
        foreach ($match in $linuxMatches) {
            $extractedPath = $match.Value
            if ($extractedPath -notmatch '^/(n|r|t)$' -and $extractedPath.Length -gt 2) {
                $paths += $extractedPath
            }
        }
    }

    # Remove duplicates while preserving order
    $uniquePaths = $paths | Select-Object -Unique

    return $uniquePaths
}

function Import-NessusCSV {
    param (
        [string]$inputFilePath,
        [string]$outputFilePath
    )

    if (-not (Test-Path $inputFilePath)) {
        Write-Error "Input file not found: $inputFilePath"
        return
    }

    Write-Host "Importing CSV file: $inputFilePath"
    $nessusData = Import-Csv -Path $inputFilePath

    $parsedResults = @()
    $rowCount = 0

    foreach ($row in $nessusData) {
        $rowCount++

        $hostname = Get-NormalizedHostname -dnsName $row.'DNS Name' -netbiosName $row.'Netbios Name'
        $paths = Get-PathsFromOutput -pluginOutput $row.'Plugin Output'
        $plugin = $row.'Plugin'
        $severity = $row.'Severity'

        if ($paths.Count -gt 0) {
            foreach ($path in $paths) {
                $result = [PSCustomObject]@{
                    Plugin   = $plugin
                    Severity = $severity
                    Hostname = $hostname
                    Path     = $path
                }
                $parsedResults += $result
            }
        } else {
            # Still output row even if no paths found
            $result = [PSCustomObject]@{
                Plugin   = $plugin
                Severity = $severity
                Hostname = $hostname
                Path     = ""
            }
            $parsedResults += $result
        }
    }

    Write-Host "Processed $rowCount rows from input file"
    Write-Host "Generated $($parsedResults.Count) output records"

    $parsedResults | Export-Csv -Path $outputFilePath -NoTypeInformation
    Write-Host "Results exported to: $outputFilePath"

    return $parsedResults
}

# Main execution
Import-NessusCSV -inputFilePath $InputFilePath -outputFilePath $OutputFilePath