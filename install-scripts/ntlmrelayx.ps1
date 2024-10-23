# Install ntlmrelayx

$startingDirectory = Get-Location
$tempPath = $env:TEMP

$pythonInstaller = Join-Path -Path $TempPath -ChildPath "python-3.13.0.exe"

$repositoryArchive = Join-Path -Path $TempPath -ChildPath "impacket-exe.zip"
$repositoryFolder = Join-Path -Path $TempPath -ChildPath "impacket-exe-master"

$applicationFolder = "C:\Program Files\ntlmrelayx"

$machinePythonKey = "HKLM:\Software\Python\PythonCore"
$userPythonKey = "HKCU:\Software\Python\PythonCore"

$foundPython = $false

# Check Local Machine Registry
if (Test-Path $machinePythonKey) {
    Get-ChildItem $machinePythonKey | ForEach-Object {
        $versionInfo = Get-ItemProperty $_.PSPath
        if ($_.PSChildName -eq "3.13") {
            $foundPython = $true
            Write-Host "Python $($_.PSChildName) found in Local Machine: $($versionInfo.InstallPath)"
        }
    }
}

# Check Current User Registry
if (Test-Path $userPythonKey) {
    Get-ChildItem $userPythonKey | ForEach-Object {
        $versionInfo = Get-ItemProperty $_.PSPath
        if ($_.PSChildName -eq "3.13") {
            $foundPython = $true
            Write-Host "Python $($_.PSChildName) found in Current User: $($versionInfo.InstallPath)"
        }
    }
}

# Download and install Python
if (-not $foundPython) {
    Write-Host "Python 3.13 is not installed, installing now"
    Invoke-WebRequest -Uri "https://www.python.org/ftp/python/3.13.0/python-3.13.0-amd64.exe" -OutFile $pythonInstaller
    Start-Process $pythonInstaller -ArgumentList "/quiet PrependPath=1 Include_launcher=0" -Wait

    # Refresh PATH
    $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User") 
}

# Download and unzip repository
Write-Host "Downloading repository"
Invoke-WebRequest -Uri "https://github.com/p0rtL6/impacket-exe/archive/refs/heads/master.zip" -OutFile $repositoryArchive
Expand-Archive -Path $repositoryArchive -DestinationPath $tempPath -Force
Remove-Item $repositoryArchive

# Begin build process
Write-Host "Beginning build process"
Set-Location -Path $repositoryFolder

# Create and activate virtual environment
python -m venv .venv
.venv\Scripts\activate.ps1

# Setup
pip install -r requirements.txt
python setup.py install

# Build
pyinstaller --onefile examples\ntlmrelayx.py

# Prepare destination folder
Write-Host "Copying executable to Program Files"
New-Item -ItemType Directory -Path $applicationFolder -Force

# Copy built executable into program files
$application = Join-Path -Path $repositoryFolder -ChildPath "dist\ntlmrelayx.exe"
Copy-Item -Path $application -Destination $applicationFolder -Force

# Clean up
Write-Host "Cleaning up"
deactivate
Set-Location -Path $startingDirectory
Remove-Item -Recurse -Force $repositoryFolder

if (-not $foundPython) {
    Start-Process $pythonInstaller -ArgumentList "/uninstall /quiet PrependPath=1" -Wait
}

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

Write-Host "Done!"
