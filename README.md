## 🚀 DomainLite

`DomainLite` is a powerful PowerShell script designed to **automate the removal of bloatware** and unnecessary Windows components from machines **joined to an Active Directory (AD) domain**. It supports targeting:

- 🖥️ Specific computers
- 🗂️ Organizational Units (OUs)
- 🌐 All domain-joined computers

---

## 📦 Features

✨ **Highlights:**

- 🧽 Debloats Windows by removing unwanted built-in apps  
- 📁 Supports custom app list via editable `Apps.txt`  
- 🧾 Imports `.reg` files to apply registry tweaks  
- 📋 Generates logs with timestamps for full traceability  
- 🧪 Supports `-WhatIf` mode for safe testing  
- 💪 Designed for AD environments and remote execution  

---

## 🧰 Requirements

Before running the script, ensure the following prerequisites:

- ✅ PowerShell 5.1 or later  
- ✅ Active Directory module  
- ✅ Administrator privileges  
- ✅ Domain-joined Windows machine(s)  

---

## 📝 Editable Files

📄 **Apps.txt**  
This file contains a list of app names to remove.  
You can **edit this file** to customize the apps that get uninstalled. One app name per line.

📂 **Scripts/**  
This folder should contain your `.reg` files. They are imported automatically on each target machine to apply registry tweaks.

---

## 📋 Parameters

| Parameter             | Description                                                                 |
|----------------------|-----------------------------------------------------------------------------|
| `-ComputerName`       | Target a specific computer                                                 |
| `-OU`                 | Target all computers in a specific OU                                      |
| `-AllDomainComputers` | Target **all** domain-joined machines                                      |
| `-WhatIf`             | Show what would happen without making any changes                         |
| `-Force`              | Reserved for future use                                                    |
| `-AppsFile`           | Path to the file listing apps to remove (default: `Apps.txt`)              |
| `-RegFilesDirectory`  | Path to folder containing `.reg` files (default: `.\Scripts`)              |

---

## 🔧 Usage Examples

### 1. Target a specific computer:
```powershell
.\AD-DebloatWindows.ps1 -ComputerName "Workstation01"
