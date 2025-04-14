<#
.SYNOPSIS
    Windows Debloating Script for Active Directory Environments
.DESCRIPTION
    This script automates the removal of bloatware and unnecessary Windows components from machines in Active Directory.
    It can target specific computers, OUs, or all domain-joined machines.
.NOTES
    File Name      : AD-DebloatWindows.ps1
    Prerequisites  : PowerShell 5.1 or later, Active Directory module, Administrator privileges
    Version        : 1.1
#>

#Requires -Module ActiveDirectory
#Requires -RunAsAdministrator

param (
    [string]$ComputerName,
    [string]$OU,
    [switch]$AllDomainComputers,
    [switch]$WhatIf,
    [switch]$Force,
    [string]$AppsFile = "Apps.txt",  # Path to the file containing app names to remove
    [string]$RegFilesDirectory = Join-Path -Path $PSScriptRoot -ChildPath "Scripts"  # Directory containing the .reg files
)

# Function to log output messages with timestamps
function Log-Message {
    param (
        [string]$Message,
        [string]$LogLevel = "INFO"
    )
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    Write-Host "$timestamp [$LogLevel] - $Message"
}

# Function to import .reg files
function Import-RegFiles {
    param (
        [string]$Directory
    )

    $regFiles = Get-ChildItem -Path $Directory -Filter *.reg

    if ($regFiles.Count -eq 0) {
        Log-Message "No .reg files found in $Directory" "ERROR"
        return
    }

    foreach ($regFile in $regFiles) {
        try {
            Log-Message "Importing registry file: $($regFile.FullName)" "INFO"
            reg import $regFile.FullName
            Log-Message "Successfully imported registry file: $($regFile.FullName)" "INFO"
        }
        catch {
            Log-Message "Failed to import registry file $($regFile.FullName): $_" "ERROR"
        }
    }
}

# Function to safely remove registry keys if they exist
function Set-RegistryKey {
    param (
        [string]$KeyPath,
        [string]$KeyName,
        [int]$Value
    )

    if (-not (Test-Path $KeyPath)) {
        New-Item -Path $KeyPath -Force | Out-Null
        Log-Message "Created registry key: $KeyPath" "INFO"
    }
    Set-ItemProperty -Path $KeyPath -Name $KeyName -Value $Value -Type DWord -Force
    Log-Message "Set registry key $KeyPath\$KeyName to $Value" "INFO"
}

# Function to debloat a local computer
function Invoke-DebloatLocal {
    param (
        [string]$ComputerName,
        [string]$AppsFile
    )

    try {
        # Create a session to the remote computer
        $session = New-PSSession -ComputerName $ComputerName -ErrorAction Stop
        Log-Message "Started session to $ComputerName" "INFO"

        # Execute debloating commands on the remote computer
        Invoke-Command -Session $session -ScriptBlock {
            param($AppsFile, $RegFilesDirectory)

            # Logging setup
            $logPath = "$env:SystemRoot\Temp\Debloat_$(Get-Date -Format 'yyyyMMdd-HHmmss').log"
            Start-Transcript -Path $logPath -Append
            Log-Message "Starting debloat process on $env:COMPUTERNAME" "INFO"

            # Import .reg files to disable respective bloat
            Import-RegFiles -Directory $RegFilesDirectory

            # Read the list of apps from the Apps.txt file
            $bloatware = Get-Content -Path $AppsFile

            # Remove bloatware apps for all users
            Log-Message "Removing bloatware apps..." "INFO"
            Get-AppxPackage -AllUsers | Where-Object { $bloatware -contains $_.Name } | Remove-AppxPackage -ErrorAction SilentlyContinue
            Get-AppxProvisionedPackage -Online | Where-Object { $bloatware -contains $_.DisplayName } | Remove-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue

            # Continue with additional debloating steps here...
            # (You can keep your existing debloating actions here if necessary)
            
            Log-Message "Debloat process completed on $env:COMPUTERNAME" "INFO"
            Stop-Transcript
        } -ArgumentList $AppsFile, $RegFilesDirectory -ErrorAction Stop

        Log-Message "Successfully debloated $ComputerName" "INFO"
    }
    catch {
        Log-Message "Failed to debloat $ComputerName : $_" "ERROR"
    }
    finally {
        if ($session) { Remove-PSSession -Session $session }
    }
}

# Main script execution
if (-not ($ComputerName -or $OU -or $AllDomainComputers)) {
    Log-Message "Please specify a computer name, OU, or use -AllDomainComputers" "ERROR"
    exit 1
}

if ($ComputerName) {
    # Target a single computer
    if ($WhatIf) {
        Log-Message "[WhatIf] Would debloat computer: $ComputerName" "INFO"
    }
    else {
        Invoke-DebloatLocal -ComputerName $ComputerName -AppsFile $AppsFile
    }
}
elseif ($OU) {
    # Target all computers in a specific OU
    $computers = Get-ADComputer -Filter * -SearchBase $OU -Properties Name | Select-Object -ExpandProperty Name
    
    if ($WhatIf) {
        Log-Message "[WhatIf] Would debloat computers in OU $OU:" "INFO"
        $computers | ForEach-Object { Log-Message "  - $_" "INFO" }
    }
    else {
        foreach ($computer in $computers) {
            Invoke-DebloatLocal -ComputerName $computer -AppsFile $AppsFile
        }
    }
}
elseif ($AllDomainComputers) {
    # Target all domain-joined computers
    $computers = Get-ADComputer -Filter * -Properties Name | Select-Object -ExpandProperty Name
    
    if ($WhatIf) {
        Log-Message "[WhatIf] Would debloat all domain computers:" "INFO"
        $computers | Select-Object -First 10 | ForEach-Object { Log-Message "  - $_" "INFO" }
        if ($computers.Count -gt 10) { Log-Message "  ... and $($computers.Count - 10) more" "INFO" }
    }
    else {
        foreach ($computer in $computers) {
            Invoke-DebloatLocal -ComputerName $computer -AppsFile $AppsFile
        }
    }

    Log-Message "Script completed! Please check above for any errors." "INFO"
}
