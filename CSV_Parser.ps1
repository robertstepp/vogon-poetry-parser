<#
.SYNOPSIS
    Input CSV files exported from Nessus Scanner and parses it into a usable listing of files with vulnerabilities.
    Exports the results to a CSV file.

.DESCRIPTION
    This script imports a Nessus CSV export, normalizes hostnames from DNS/NetBIOS formats,
    extracts all file paths (Windows and Linux) from Plugin Output, and exports results
    in the format: Plugin, Severity, Hostname, Path

.PARAMETER InputFilePath
    Path to the input Nessus CSV file. If not provided, a file picker dialog will open.

.PARAMETER OutputFilePath
    Path for the output CSV file. If not provided, defaults to input filename with "-parsed.csv" suffix.

.EXAMPLE
    .\CSV_Parser.ps1 -InputFilePath "C:\nessus_export.csv" -OutputFilePath "C:\parsed_results.csv"

.EXAMPLE
    .\CSV_Parser.ps1 -InputFilePath "C:\nessus_export.csv"
    # Outputs to C:\nessus_export-parsed.csv

.EXAMPLE
    .\CSV_Parser.ps1
    # Opens file picker, outputs to same directory with -parsed.csv suffix
#>

param (
    [Parameter(Mandatory = $false)]
    [string]$InputFilePath,

    [Parameter(Mandatory = $false)]
    [string]$OutputFilePath,

    [Parameter(Mandatory = $false)]
    [ValidateSet("SilentlyContinue", "Continue")]
    [string]$DebugPreference
)

# Start the transcript for debugging purposes
if ($DebugPreference -eq "Continue")
{
    $logFile = Join-Path -Path ($PSScriptRoot) -ChildPath "CSV_Parser_debug.log"
    Start-Transcript -Path $logFile -Append
}

function Show-FilePickerDialog {

    Add-Type -AssemblyName System.Windows.Forms

    $filePicker = New-Object System.Windows.Forms.OpenFileDialog
    $filePicker.Title = "Select Nessus CSV Export"
    $filePicker.Filter = "CSV Files (*.csv)|*.csv"
    $filePicker.FilterIndex = 1

    # Start in the same directory as the script
    $scriptDirectory = $PSScriptRoot
    if ([string]::IsNullOrWhiteSpace($scriptDirectory)) {
        # Fallback if PSScriptRoot is empty (e.g., running in ISE or interactively)
        $scriptDirectory = Split-Path -Parent $MyInvocation.MyCommand.Definition
    }
    if ([string]::IsNullOrWhiteSpace($scriptDirectory)) {
        # Final fallback to current working directory
        $scriptDirectory = Get-Location
    }

    $filePicker.InitialDirectory = $scriptDirectory

    $result = $filePicker.ShowDialog()

    if ($result -eq [System.Windows.Forms.DialogResult]::OK) {
        return $filePicker.FileName
    } else {
        return $null
    }
}

function Get-DefaultOutputPath {
    <#
    .SYNOPSIS
        Generates default output path by appending -parsed.csv to input filename.
    #>
    param (
        [string]$inputPath
    )

    $directory = [System.IO.Path]::GetDirectoryName($inputPath)
    $filenameWithoutExt = [System.IO.Path]::GetFileNameWithoutExtension($inputPath)
    $outputFilename = "$filenameWithoutExt-parsed.csv"

    if ([string]::IsNullOrWhiteSpace($directory)) {
        return $outputFilename
    }

    return [System.IO.Path]::Combine($directory, $outputFilename)
}

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
    # Handles variable whitespace: "path:", "path :", "path    :", etc.
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
        $linuxPattern = '(?m)(?<![A-Za-z0-9])/(?:[A-Za-z0-9._\-]+/)*[A-Za-z0-9._\-]+'

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
        Write-Debug "Input file not found: $inputFilePath"
        return
    }

    Write-Debug "Importing CSV file: $inputFilePath"
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

    Write-Debug "Processed $rowCount rows from input file"
    Write-Debug "Generated $($parsedResults.Count) output records"

    $parsedResults | Export-Csv -Path $outputFilePath -NoTypeInformation
    Write-Debug "Results exported to: $outputFilePath"

    return $parsedResults
}

# Main execution

# Handle InputFilePath - show file picker if not provided
if ([string]::IsNullOrWhiteSpace($InputFilePath)) {
    Write-Debug "No input file specified. Opening file picker..."
    $InputFilePath = Show-FilePickerDialog

    if ([string]::IsNullOrWhiteSpace($InputFilePath)) {
        Write-Debug "No file selected. Exiting."
        exit 1
    }
}

# Handle OutputFilePath - generate default if not provided
if ([string]::IsNullOrWhiteSpace($OutputFilePath)) {
    $OutputFilePath = Get-DefaultOutputPath -inputPath $InputFilePath
    Write-Debug "No output file specified. Using default: $OutputFilePath"
}

Import-NessusCSV -inputFilePath $InputFilePath -outputFilePath $OutputFilePath

# Open the output file with the default application
Write-Debug "Opening output file..."
Invoke-Item -Path $OutputFilePath

if ($DebugPreference -eq "Continue") {
    # Stop the transcript
    Stop-Transcript
}