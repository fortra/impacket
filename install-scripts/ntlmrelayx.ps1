# Install ntlmrelayx

$startingDirectory = Get-Location
$tempPath = $env:TEMP

$pythonInstaller = Join-Path -Path $TempPath -ChildPath "python-3.13.0.exe"

$repositoryArchive = Join-Path -Path $TempPath -ChildPath "impacket-exe.zip"
$repositoryFolder = Join-Path -Path $TempPath -ChildPath "impacket-exe-master"

$applicationFolder = "C:\Program Files\ntlmrelayx"

# Download and install Python
Write-Host "Installing Python"
Invoke-WebRequest -Uri "https://www.python.org/ftp/python/3.13.0/python-3.13.0.exe" -OutFile $pythonInstaller
Start-Process $pythonInstaller -ArgumentList "/quiet PrependPath=1" -Wait
Remove-Item $pythonInstaller

# Download and unzip repository
Write-Host "Downloading repository"
Invoke-WebRequest -Uri "https://github.com/p0rtL6/impacket-exe/archive/refs/heads/master.zip" -OutFile $repositoryArchive
Expand-Archive -Path $repositoryArchive -DestinationPath $tempPath -Force
Remove-Item $repositoryArchive

# Begin build process
Write-Host "Beginning build process"
Set-Location -Path $repositoryFolder

# Create and activate virtual environment
py -m venv .venv
.venv\Scripts\activate.ps1

# Setup
pip install -r requirements.txt
py setup.py install

# Build
pyinstaller --onefile examples\ntlmrelayx.py

# Prepare destination folder
Write-Host "Copying executable to Program Files"
New-Item -ItemType Directory -Path $applicationFolder -Force

# Copy built executable into program files
$application = Join-Path -Path $repositoryFolder -ChildPath "dist\ntlmrelayx.exe"
Copy-Item -Path $application -Destination $applicationFolder -Force

# Clean up
Write-Host "Cleaning up repository folder"
deactivate
Set-Location -Path $startingDirectory
Remove-Item -Recurse -Force $repositoryFolder

# Get the current PATH environment variable
Write-Host "Updating PATH"
$currentPath = [System.Environment]::GetEnvironmentVariable("Path", [System.EnvironmentVariableTarget]::Machine)

# Check if the path already exists in PATH
if ($currentPath -notlike "*$applicationFolder*") {
    # Append the new path to the existing PATH variable
    $newPath = $currentPath + ";" + $applicationFolder
    
    # Set the new PATH variable
    [System.Environment]::SetEnvironmentVariable("Path", $newPath, [System.EnvironmentVariableTarget]::Machine)
    
    Write-Host "Successfully added $applicationFolder to PATH."
} else {
    Write-Host "$applicationFolder is already in PATH."
}