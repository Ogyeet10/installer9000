# launcher.ps1
# Check if running as administrator, if not relaunch as admin
if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Start-Process powershell.exe -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
    exit
}

# Download and execute the remote script
$scriptUrl = 'https://github.com/Ogyeet10/installer9000/raw/refs/heads/main/sw-win.ps1'
$scriptContent = (New-Object Net.WebClient).DownloadString($scriptUrl)
Invoke-Expression $scriptContent
