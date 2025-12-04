# vogon-poetry-parser 🐬

> "For a moment, nothing happened. Then, after a second or so, nothing continued to happen." 
> — Unlike this parser, which actually does something useful.

A PowerShell script that transforms chaotic Nessus CSV exports into clean, organized vulnerability path data. Like a Babel Fish for your security scans.

## 🌌 What It Does

This script takes Nessus scanner CSV exports and:

- **Normalizes hostnames** - Converts both DNS names (`webserver01.corp.contoso.com`) and NetBIOS names (`CORP\WEBSERVER01`) to a consistent lowercase format (`webserver01`)
- **Extracts all file paths** - Finds Windows paths (`C:\Program Files\app.exe`) and Linux paths (`/usr/lib/libssl.so`) from plugin output
- **Handles messy formatting** - Works with `path:`, `path :`, and `path    :` variations
- **Outputs clean CSV** - Produces a simple `Plugin, Severity, Hostname, Path` format

## 📋 Requirements

- PowerShell 5.1 or later (Windows PowerShell or PowerShell Core)

## 🚀 Usage
```powershell
.\CSV_Parser.ps1 -InputFilePath "C:\nessus_export.csv" -OutputFilePath "C:\parsed_results.csv"
```

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

## 🔧 Example

**Input:**
```csv
Plugin,Severity,Plugin Output,DNS Name,Netbios Name
10001,Critical,"Vulnerable software detected
path: C:\Program Files\Java\bin\java.exe
path: /usr/lib/jvm/java/bin/java",webserver01.corp.contoso.com,CORP\WEBSERVER01
```

**Output:**
```csv
Plugin,Severity,Hostname,Path
10001,Critical,webserver01,C:\Program Files\Java\bin\java.exe
10001,Critical,webserver01,/usr/lib/jvm/java/bin/java
```

## 🐛 Path Detection

The script handles:

- ✅ Windows paths with spaces (`C:\Program Files (x86)\App\file.exe`)
- ✅ Linux absolute paths (`/etc/shadow`)
- ✅ Multiple drive letters (`C:\`, `D:\`, `E:\`)
- ✅ Paths prefixed with `path:` (with variable whitespace)
- ✅ Multiple paths per plugin output
- ✅ Rows with no paths (outputs empty path field)

## 🤝 Contributing

Found a bug? Have a path format that isn't detected? PRs welcome!

1. Fork it
2. Create your feature branch (`git checkout -b feature/infinite-improbability-paths`)
3. Commit your changes (`git commit -am 'Add some paths'`)
4. Push to the branch (`git push origin feature/infinite-improbability-paths`)
5. Open a Pull Request

Do what you want with it. If it saves you time, that's all the thanks needed.

## 🐬 So Long, and Thanks for All the Paths

*"Time is an illusion. Lunchtime doubly so."*  
*— But vulnerability remediation deadlines are very real.*

---

**Don't Panic** - Your paths are in good hands. 🌍
