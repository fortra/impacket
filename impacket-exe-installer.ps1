# Impacket-exe Installer

## CMD ARG CONFIG ##

$PythonVersion = '3.13.0'
$StartingDirectory = Get-Location

$AvailableScripts = New-Object System.Collections.Generic.HashSet[string]
$AvailableScripts.Add('ntlmrelayx') | Out-Null
$AvailableScripts.Add('secretsdump') | Out-Null

$SelectedScripts = New-Object System.Collections.Generic.HashSet[string]

$Options = New-object System.Collections.Hashtable
$Options['OutputDir'] = @{
    Name = 'Output Directory'
    Desc = 'Set the output directory for the built executable'
    Keywords = @('-o', '--output-dir')
    Value = $StartingDirectory
    Type = 'Path'
}

$Flags = New-object System.Collections.Hashtable
$Flags['OverridePython'] = @{
    Name = 'Override Installed Python'
    Desc = "Install Python $PythonVersion even if an existing python version is installed"
    Keywords = @('-P', '--override-python')
    Value = $False
}
$Flags['LeavePython'] = @{
    Name = 'Leave Installed Python'
    Desc = 'If installed, do not uninstall Python $PythonVersion from the system'
    Keywords = @('-L', '--leave-python')
    Value = $False
}
$Flags['InstallSystemWide'] = @{
    Name = 'Install Scripts System-Wide'
    Desc = 'Install scripts to C:\Program Files\ and add them to the PATH (Ignores Output Directory)'
    Keywords = @('-I', '--install-systemwide')
    Value = $False
}


function GetKeyByKeyword {
    param (
        [hashtable]$HashTable,
        [string]$Keyword
    )
        
    foreach ($Key in $HashTable.Keys) {
        $Item = $HashTable[$Key]
        if ($Item.Keywords -contains $Keyword) {
            return $Key
        }
    }
    return $Null
}

$HelpMenuPadding = 25

function Show-HelpMenu {
    Write-Host '=== Impacket-exe Installer ==='
    Write-Host 'Downloads, builds, and installs scripts from the Impacket-exe repository'
    Write-Host ''
    Write-Host 'Usage: impacket-exe-installer.ps1 [FLAGS] [OPTIONS] [<scripts>]'
    Write-Host ''
    Write-Host 'Positional Arguments:'
    Write-Host "  $('<scripts>'.PadRight($HelpMenuPadding)) A space seperated list of scripts you want to install"
    Write-Host ''
    Write-Host 'Flags:'
    foreach ($Flag in $Flags.Values) {
        $FormattedKeywords = $Flag['Keywords'] -join '  '
        Write-Host "  $($FormattedKeywords.PadRight($HelpMenuPadding)) $($Flag['Desc']) (default: $($Flag['Value']))"
    }
    Write-Host ''
    Write-Host 'Options:'
    Write-Host "  $('-h  --help'.PadRight($HelpMenuPadding)) Display this menu"
    foreach ($Option in $Options.Values) {
        $FormattedKeywords = $Option['Keywords'] -join '  '
        Write-Host "  $($FormattedKeywords.PadRight($HelpMenuPadding)) $($Option['Desc']) (default: $($Option['Value']))"
    }
    Write-Host ''
}

## PARSING CMD ARGS ##

if ($Args.Count -eq 0) {
    Show-HelpMenu
    exit 0
}

for ($I = 0; $I -lt $Args.Count; $I++) {
    if ($Args[$I] -eq '-h' -or $Args[$I] -eq '--help') {
        Show-HelpMenu
        exit 0
    }
    elseif ($Args[$I].startsWith('-')) {
        $ArgParts = $Args[$I] -split '='
        $Keyword = $ArgParts[0]
        $Value = $Null

        $FlagsKey = GetKeyByKeyword -HashTable $Flags -Keyword $Keyword
        $OptionsKey = GetKeyByKeyword -HashTable $Options -Keyword $Keyword

        if ($ArgParts.Count -eq 2) {
            $Value = $ArgParts[1]
        }
        elseif ($ArgParts.Count -gt 1) {
            Write-Host "Error in $($Options[$OptionsKey]['Name']): Multiple equals signs`n"
            Show-HelpMenu
            throw
        }

        if ($FlagsKey){
            $Flags[$FlagsKey]['Value'] = $True
        }
        elseif ($OptionsKey) {
            if (-not $Value) {
                $I++
                $Value = $Args[$I]
            }
            if (-not $Value) {
                Write-Host "Error in $($Options[$OptionsKey]['Name']): No value recieved`n"
                Show-HelpMenu
                throw
            }
            if ($Options[$OptionsKey]['type'] -eq 'Path' -and -not (Test-Path $Value)) {
                Write-Host "Error in $($Options[$OptionsKey]['Name']): Path does not exist`n"
                Show-HelpMenu
                throw
            }
            $Options[$OptionsKey]['Value'] = $Value
        }
        else {
            Write-Host "Error: Unrecognized argument`n"
            Show-HelpMenu
            throw
        }
    }
    elseif ($AvailableScripts.Contains($Args[$I])) {
        $SelectedScripts.Add($Args[$I]) | Out-Null
    }
    else {
        $AvailableScriptsList = $AvailableScripts -join "`n    "
        Write-Host "Error: Invalid installer selected, available options are:`n    $AvailableScriptsList`n"
        Show-HelpMenu
        throw
    }
}

if ($SelectedScripts.Count -eq 0) {
    Write-Host "Error: Must select at least one script to install`n"
    Show-HelpMenu
    throw
}

## BEGIN INSTALLING ##

$TempPath = $Env:TEMP

$PythonInstaller = Join-Path -Path $TempPath -ChildPath "python-$PythonVersion.exe"

$RepositoryArchive = Join-Path -Path $TempPath -ChildPath "impacket-exe.zip"
$RepositoryFolder = Join-Path -Path $TempPath -ChildPath "impacket-exe-master"

$MachinePythonKey = "HKLM:\Software\Python\PythonCore"
$UserPythonKey = "HKCU:\Software\Python\PythonCore"
$FoundPython = $False

$PythonVersionParts = $PythonVersion.Split(".")
$TruncatedPythonVersion = "$($PythonVersionParts[0]).$($PythonVersionParts[1])"

# Check Local Machine Registry
if (Test-Path $MachinePythonKey) {
    Get-ChildItem $MachinePythonKey | ForEach-Object {
        if ($_.PSChildName -eq $TruncatedPythonVersion) {
            $FoundPython = $True
            Write-Host "Python $($_.PSChildName) found in Local Machine"
        }
    }
}

# Check Current User Registry
if (Test-Path $UserPythonKey) {
    Get-ChildItem $UserPythonKey | ForEach-Object {
        if ($_.PSChildName -eq $TruncatedPythonVersion) {
            $FoundPython = $True
            Write-Host "Python $($_.PSChildName) found in Current User"
        }
    }
}

# Download and install Python
if (-not $FoundPython -or $Flags['OverridePython']['Value']) {
    Write-Host "Python $PythonVersion is not installed, installing now..."
    Invoke-WebRequest -Uri "https://www.python.org/ftp/python/$PythonVersion/python-$PythonVersion-amd64.exe" -OutFile $PythonInstaller
    Start-Process $PythonInstaller -ArgumentList "/quiet PrependPath=1 Include_launcher=0" -Wait

    # Refresh PATH
    $Env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User") 
}

# Download and unzip repository
Write-Host 'Downloading repository...'
Invoke-WebRequest -Uri "https://github.com/p0rtL6/impacket-exe/archive/refs/heads/master.zip" -OutFile $RepositoryArchive
Expand-Archive -Path $RepositoryArchive -DestinationPath $TempPath -Force
Remove-Item $RepositoryArchive

# Begin build process
Write-Host 'Beginning build process...'
Set-Location -Path $RepositoryFolder

# Create and activate virtual environment
python -m venv .venv
.venv\Scripts\activate.ps1

# Setup
pip install -r requirements.txt
python setup.py install

foreach ($Script in $SelectedScripts) {
    Write-Host "Building $Script..."

    # Build
    pyinstaller --onefile "examples\$Script.py"

    $BuiltScriptPath = Join-Path -Path $RepositoryFolder -ChildPath "dist\$Script.exe"

    if ($Flags['InstallSystemWide']['Value']) {
        # Prepare destination folder
        Write-Host "Copying executable to Program Files..."
        New-Item -ItemType Directory -Path 'C:\Program Files\Impacket-exe' -Force

        # Copy built executable into program files
        Copy-Item -Path $BuiltScriptPath -Destination 'C:\Program Files\Impacket-exe' -Force
    }
    else {
        Copy-Item -Path $BuiltScriptPath -Destination $Options['OutputDir']['Value'] -Force
    }
}

if ($Flags['InstallSystemWide']['Value']) {
    # Get the current PATH environment variable
    Write-Host "Updating PATH..."
    $CurrentPath = [System.Environment]::GetEnvironmentVariable('Path', [System.EnvironmentVariableTarget]::Machine)

    # Check if the path already exists in PATH
    if ($CurrentPath -notlike "*C:\Program Files\Impacket-exe*") {
    # Append the new path to the existing PATH variable
    $NewPath = $CurrentPath + ';' + 'C:\Program Files\Impacket-exe'
    
    # Set the new PATH variable
    [System.Environment]::SetEnvironmentVariable('Path', $NewPath, [System.EnvironmentVariableTarget]::Machine)
    
    Write-Host 'Successfully added C:\Program Files\Impacket-exe to PATH.'
    } else {
        Write-Host 'C:\Program Files\Impacket-exe is already in PATH.'
    }
}

# Clean up
Write-Host 'Cleaning up...'
deactivate
Set-Location -Path $StartingDirectory
Remove-Item -Recurse -Force $RepositoryFolder

if (-not $Flags['LeavePython']['Value'] -and (-not $FoundPython -or $Flags['OverridePython']['Value'])) {
    Write-Host 'Uninstalling Python...'
    Start-Process $PythonInstaller -ArgumentList "/uninstall /quiet PrependPath=1" -Wait
}

Write-Host 'Done!'
