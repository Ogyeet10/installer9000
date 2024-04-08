# launcher.ps1
if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Start-Process powershell.exe -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
    exit
}

$scriptUrl = 'https://raw.githubusercontent.com/Ogyeet10/installer9000/main/conf.ps1'
$scriptContent = (New-Object Net.WebClient).DownloadString($scriptUrl)
Invoke-Expression $scriptContent
