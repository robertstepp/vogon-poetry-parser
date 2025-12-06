# vogon-poetry-parser

> "For a moment, nothing happened. Then, after a second or so, nothing continued to happen."
> — Unlike this parser, which actually does something useful.

A PowerShell script that transforms chaotic Nessus CSV exports into clean, organized vulnerability path data. Like a Babel Fish for your security scans.

## What It Does

This script takes Nessus scanner CSV exports and:

- **Normalizes hostnames** - Converts both DNS names (`webserver01.corp.contoso.com`) and NetBIOS names (`CORP\WEBSERVER01`) to a consistent lowercase format (`webserver01`)
- **Extracts all file paths** - Finds Windows paths (`C:\Program Files\app.exe`) and Linux paths (`/usr/lib/libssl.so`) from plugin output
- **Handles messy formatting** - Works with `path:`, `path :`, and `path    :` variations
- **Outputs clean CSV** - Produces a simple `Plugin, Severity, Hostname, Path` format
- **Auto-opens results** - Opens the parsed CSV in your default application when complete

## Requirements

- PowerShell 5.1 or later (Windows PowerShell or PowerShell Core)
- Windows (for file picker dialog functionality)

## Usage

### Full Manual Control
```powershell
.\CSV_Parser.ps1 -InputFilePath "C:\nessus_export.csv" -OutputFilePath "C:\parsed_results.csv"
```

### Auto-Generate Output Path
```powershell
.\CSV_Parser.ps1 -InputFilePath "C:\Scans\nessus_export.csv"
# Creates: C:\Scans\nessus_export-parsed.csv
```

### File Picker Mode (No Parameters)
```powershell
.\CSV_Parser.ps1
# Opens file picker dialog starting in script directory
# Creates: <selected_directory>\<filename>-parsed.csv
```

### Debug Mode
```powershell
.\CSV_Parser.ps1 -DebugPreference Continue
# Creates CSV_Parser_debug.log in the script directory
```

## Parameters

| Parameter | Required | Description |
|-----------|----------|-------------|
| `InputFilePath` | No | Path to input Nessus CSV. Opens file picker if not provided. |
| `OutputFilePath` | No | Path for output CSV. Defaults to `<input>-parsed.csv` in same directory. |
| `DebugPreference` | No | Set to `Continue` to enable debug logging. |

### Input Format

The script expects a Nessus CSV export with at least these columns:

| Column | Description |
|--------|-------------|
| Plugin | Nessus plugin ID |
| Severity | Vulnerability severity level |
| Plugin Output | Raw output containing file paths |
| DNS Name | FQDN of the scanned host |
| Netbios Name | NetBIOS name of the scanned host |

### Output Format

| Column | Description |
|--------|-------------|
| Plugin | Nessus plugin ID |
| Severity | Vulnerability severity level |
| Hostname | Normalized hostname (lowercase, no domain) |
| Path | Individual file path extracted from plugin output |

Each path gets its own row, so one input row with 3 paths becomes 3 output rows.

## 🛠 Features

| Feature | Description |
|---------|-------------|
|  File Picker | GUI dialog opens in script directory when no input specified |
|  Smart Output Naming | Auto-generates output path with `-parsed.csv` suffix |
|  Same Directory Output | Saves output alongside input file by default |
|  Auto-Open Results | Opens parsed CSV in default application (Excel, etc.) |
|  Debug Logging | Optional transcript logging for troubleshooting |

##  Path Detection

The script handles:

-  Windows paths with spaces (`C:\Program Files (x86)\App\file.exe`)
-  Linux absolute paths (`/etc/shadow`)
-  Multiple drive letters (`C:\`, `D:\`, `E:\`)
-  Paths prefixed with `path:` (with variable whitespace)
-  Multiple paths per plugin output
-  Rows with no paths (outputs empty path field)

##  License

MIT License - Do what you want with it. If it saves you time, that's all the thanks needed.

## 🐬 So Long, and Thanks for All the Paths

*"Time is an illusion. Lunchtime doubly so."*
*— But vulnerability remediation deadlines are very real.*

---

**Don't Panic** - Your paths are in good hands. 🌍