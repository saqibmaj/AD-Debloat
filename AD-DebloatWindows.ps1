<#
.SYNOPSIS
    Windows Debloating Script for Active Directory Environments
.DESCRIPTION
    This script automates the removal of bloatware and unnecessary Windows components from machines in Active Directory.
    It can target specific computers, OUs, or all domain-joined machines.
.NOTES
    File Name      : AD-DebloatWindows.ps1
    Prerequisites  : PowerShell 5.1 or later, Active Directory module, Administrator privileges
    Version        : 1.0
#>

#Requires -Module ActiveDirectory
#Requires -RunAsAdministrator

param (
    [string]$ComputerName,
    [string]$OU,
    [switch]$AllDomainComputers,
    [switch]$WhatIf,
    [switch]$Force
)

function Invoke-DebloatLocal {
    param (
        [string]$ComputerName
    )

    try {
        # Create a session to the remote computer
        $session = New-PSSession -ComputerName $ComputerName -ErrorAction Stop

        # Execute debloating commands on the remote computer
        Invoke-Command -Session $session -ScriptBlock {
            # Logging setup
            $logPath = "$env:SystemRoot\Temp\Debloat_$(Get-Date -Format 'yyyyMMdd-HHmmss').log"
            Start-Transcript -Path $logPath -Append

            Write-Output "Starting debloat process on $env:COMPUTERNAME at $(Get-Date)"

            # Common bloatware packages to remove (adjust as needed)
            $bloatware = @(
                "*3DPrint*",
                "*Bing*",
                "*BubbleWitch*",
                "*CandyCrush*",
                "*Disney*",
                "*Dolby*",
                "*FarmVille*",
                "*Flipboard*",
                "*King*",
                "*MarchofEmpires*",
                "*Minecraft*",
                "*Netflix*",
                "*OfficeHub*",
                "*OneNote*",
                "*Pandora*",
                "*People*",
                "*Photos*",
                "*Plex*",
                "*Skype*",
                "*Solitaire*",
                "*Spotify*",
                "*Twitter*",
                "*WindowsAlarms*",
                "*WindowsCamera*",
                "*WindowsCommunicationsApps*",
                "*WindowsFeedbackHub*",
                "*WindowsMaps*",
                "*WindowsPhone*",
                "*WindowsSoundRecorder*",
                "*Xbox*",
                "*Zune*",
                "Microsoft.Microsoft3DViewer",
                "Microsoft.MicrosoftOfficeHub",
                "Microsoft.MicrosoftSolitaireCollection",
                "Microsoft.MicrosoftStickyNotes",
                "Microsoft.MixedReality.Portal",
                "Microsoft.Office.OneNote",
                "Microsoft.OneConnect",
                "Microsoft.People",
                "Microsoft.Print3D",
                "Microsoft.SkypeApp",
                "Microsoft.Wallet",
                "Microsoft.Windows.Photos",
                "Microsoft.WindowsAlarms",
                "Microsoft.WindowsCalculator",
                "Microsoft.WindowsCamera",
                "microsoft.windowscommunicationsapps",
                "Microsoft.WindowsFeedbackHub",
                "Microsoft.WindowsMaps",
                "Microsoft.WindowsSoundRecorder",
                "Microsoft.Xbox.TCUI",
                "Microsoft.XboxApp",
                "Microsoft.XboxGameOverlay",
                "Microsoft.XboxGamingOverlay",
                "Microsoft.XboxIdentityProvider",
                "Microsoft.XboxSpeechToTextOverlay",
                "Microsoft.YourPhone",
                "Microsoft.ZuneMusic",
                "Microsoft.ZuneVideo"
            )

            # Remove bloatware apps for all users
            Write-Output "Removing bloatware apps..."
            Get-AppxPackage -AllUsers | Where-Object { $bloatware -contains $_.Name } | Remove-AppxPackage -ErrorAction SilentlyContinue
            Get-AppxProvisionedPackage -Online | Where-Object { $bloatware -contains $_.DisplayName } | Remove-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue

            # Disable telemetry and data collection
            Write-Output "Disabling telemetry and data collection..."
            $telemetryKeys = @(
                "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection",
                "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection",
                "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection"
            )

            foreach ($key in $telemetryKeys) {
                if (-not (Test-Path $key)) { New-Item -Path $key -Force | Out-Null }
                Set-ItemProperty -Path $key -Name "AllowTelemetry" -Value 0 -Type DWord -Force
            }

            # Disable Cortana
            Write-Output "Disabling Cortana..."
            $cortanaKeys = @(
                "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"
            )

            foreach ($key in $cortanaKeys) {
                if (-not (Test-Path $key)) { New-Item -Path $key -Force | Out-Null }
                Set-ItemProperty -Path $key -Name "AllowCortana" -Value 0 -Type DWord -Force
                Set-ItemProperty -Path $key -Name "DisableWebSearch" -Value 1 -Type DWord -Force
                Set-ItemProperty -Path $key -Name "ConnectedSearchUseWeb" -Value 0 -Type DWord -Force
            }

            # Disable Windows tips and tricks
            Write-Output "Disabling Windows tips..."
            Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338388Enabled" -Value 0 -Type DWord -Force
            Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SystemPaneSuggestionsEnabled" -Value 0 -Type DWord -Force

            # Disable automatic updates for Store apps
            Write-Output "Disabling automatic Store updates..."
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore" -Name "AutoDownload" -Value 2 -Type DWord -Force

            # Disable Xbox features
            Write-Output "Disabling Xbox features..."
            $xboxKeys = @(
                "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR",
                "HKLM:\SYSTEM\CurrentControlSet\Services\xbgm"
            )

            foreach ($key in $xboxKeys) {
                if (-not (Test-Path $key)) { New-Item -Path $key -Force | Out-Null }
            }

            Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR" -Name "AllowGameDVR" -Value 0 -Type DWord -Force
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\xbgm" -Name "Start" -Value 4 -Type DWord -Force

            # Disable OneDrive
            Write-Output "Disabling OneDrive..."
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" -Name "DisableFileSyncNGSC" -Value 1 -Type DWord -Force

            # Optional: Remove OneDrive completely
            if ($using:Force) {
                $onedrivePath = "$env:SystemRoot\SysWOW64\OneDriveSetup.exe"
                if (Test-Path $onedrivePath) {
                    Start-Process $onedrivePath -ArgumentList "/uninstall" -NoNewWindow -Wait
                }
            }

            # Clean up Start Menu tiles
            Write-Output "Cleaning up Start Menu..."
            Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CloudStore\Store\Cache\DefaultAccount\*" -Recurse -Force -ErrorAction SilentlyContinue

            # Disable Windows Spotlight
            Write-Output "Disabling Windows Spotlight..."
            Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "RotatingLockScreenEnabled" -Value 0 -Type DWord -Force
            Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "RotatingLockScreenOverlayEnabled" -Value 0 -Type DWord -Force
            Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338387Enabled" -Value 0 -Type DWord -Force

            # Disable automatic installation of suggested apps
            Write-Output "Disabling suggested apps..."
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsConsumerFeatures" -Value 1 -Type DWord -Force

            # Optional: Disable Windows Defender (not recommended for security)
            if ($using:Force) {
                Write-Output "Disabling Windows Defender..."
                Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "DisableAntiSpyware" -Value 1 -Type DWord -Force
            }

            Write-Output "Debloat process completed on $env:COMPUTERNAME at $(Get-Date)"
            Stop-Transcript
        } -ErrorAction Stop

        Write-Host "Successfully debloated $ComputerName" -ForegroundColor Green
    }
    catch {
        Write-Host "Failed to debloat $ComputerName : $_" -ForegroundColor Red
    }
    finally {
        if ($session) { Remove-PSSession -Session $session }
    }
}

# Main script execution
if (-not ($ComputerName -or $OU -or $AllDomainComputers)) {
    Write-Host "Please specify a computer name, OU, or use -AllDomainComputers" -ForegroundColor Yellow
    exit 1
}

if ($ComputerName) {
    # Target a single computer
    if ($WhatIf) {
        Write-Host "[WhatIf] Would debloat computer: $ComputerName" -ForegroundColor Cyan
    }
    else {
        Invoke-DebloatLocal -ComputerName $ComputerName
    }
}
elseif ($OU) {
    # Target all computers in a specific OU
    $computers = Get-ADComputer -Filter * -SearchBase $OU -Properties Name | Select-Object -ExpandProperty Name
    
    if ($WhatIf) {
        Write-Host "[WhatIf] Would debloat computers in OU $OU :" -ForegroundColor Cyan
        $computers | ForEach-Object { Write-Host "  - $_" }
    }
    else {
        foreach ($computer in $computers) {
            Invoke-DebloatLocal -ComputerName $computer
        }
    }
}
elseif ($AllDomainComputers) {
    # Target all domain-joined computers
    $computers = Get-ADComputer -Filter * -Properties Name | Select-Object -ExpandProperty Name
    
    if ($WhatIf) {
        Write-Host "[WhatIf] Would debloat all domain computers:" -ForegroundColor Cyan
        $computers | Select-Object -First 10 | ForEach-Object { Write-Host "  - $_" }
        if ($computers.Count -gt 10) { Write-Host "  ... and $($computers.Count - 10) more" }
    }
    else {
        foreach ($computer in $computers) {
            Invoke-DebloatLocal -ComputerName $computer
        }
    }
}
