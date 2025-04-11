# AD-WinDebloat 🚀  
**Automated Windows Debloating & Optimization for Active Directory**  

A PowerShell script to remove bloatware, disable telemetry, and optimize Windows 10/11 across Active Directory domains. Designed for sysadmins managing enterprise environments.

---

## 🔥 Features  
- **Bloatware Removal**  
  Uninstalls 50+ preinstalled apps (Candy Crush, Xbox, OneDrive, etc.) for all users.  
- **Privacy Hardening**  
  Disables Cortana, telemetry, ads, and Windows Spotlight.  
- **AD Scalability**  
  Target single machines, OUs, or all domain-joined computers.  
- **Safety First**  
  `-WhatIf` support and transcript logging for audits.  

---

## 🛠️ Usage  

### **Basic Commands**  
```powershell
# Debloat a single computer  
.\AD-DebloatWindows.ps1 -ComputerName "PC01"  

# Debloat all computers in an OU  
.\AD-DebloatWindows.ps1 -OU "OU=Workstations,DC=domain,DC=com"  

# Dry-run (preview changes)  
.\AD-DebloatWindows.ps1 -AllDomainComputers -WhatIf  
```

### **Parameters**  
| Parameter           | Description                          |  
|---------------------|--------------------------------------|  
| `-ComputerName`     | Target a single machine.            |  
| `-OU`               | Target all computers in an OU.      |  
| `-AllDomainComputers` | Debloat every domain-joined PC.   |  
| `-Force`            | Aggressive cleanup (e.g., OneDrive).|  
| `-WhatIf`           | Preview changes without execution.  |  

---

## 📋 Requirements  
- **PowerShell 5.1+** (Windows 10/11, Server 2016+)  
- **Active Directory Module** (`RSAT-AD-PowerShell`)  
- **Admin Rights** on target machines  

---

## 📜 Logging  
Script generates logs at:  
`C:\Windows\Temp\Debloat_<TIMESTAMP>.log`  

---

## ⚠️ Disclaimer  
Use at your own risk. Test in a non-production environment first.  
**Not recommended for:**  
- Systems requiring Microsoft Store apps  
- Environments with strict compliance policies (e.g., DISA STIG)  

---

## 📥 Installation  
```powershell
# Clone the repository  
git clone https://github.com/your-repo/AD-WinDebloat.git  
cd AD-WinDebloat  
```
