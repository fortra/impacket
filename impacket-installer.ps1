$scriptTitle = 'Impacket Installer'
$scriptFileName = 'impacket-installer.ps1'
$scriptDesc = 'Builds Impacket to windows compatible binaries'
$version = '1.0.0'

$commands = @{
    'install'    = @{
        Description = 'Install Impacket'
        Order       = 0
        Arguments   = @{
            'tools'       = @{
                Description = 'A list of tools to install'
                Order       = 0
                Required    = $true
                Type        = 'TOOL'
                CustomType  = @{
                    ReturnType = [string]
                    Parser     = {
                        param (
                            [System.Object]$Value
                        )

                        # Validate that the tools are in the list of available tools

                        $value = $value.ToLower()

                        if ($availableTools -contains $value) {
                            return $value
                        }
                        else {
                            return $null
                        }
                    }
                }
                List        = $true
            }
            'output-dir'  = @{
                Description = 'The output directory for the binaries'
                Order       = 1
                Required    = $false
                Type        = 'PATH'
                Default     = Get-Location
            }
            'source'      = @{
                Description = 'The source to download from (USER/REPO/BRANCh uses Github)'
                Order       = 2
                Required    = $false
                Default     = New-Object System.Uri('https://github.com/p0rtL6/impacket/archive/refs/heads/windows.zip')
                Type        = 'USER/REPO/BRANCH or URL or DIRECTORY'
                CustomType  = @{
                    ReturnType = [Uri]
                    Parser     = {
                        param (
                            [System.Object]$Value
                        )

                        # This is all just fancy parsing for the different input types, it should guarantee that we have a valid download url

                        $parsedUri = $null
                        $isURL = [Uri]::TryCreate($value, [UriKind]::RelativeOrAbsolute, [ref]$parsedUri)

                        if (-not $isURL) {
                            $parts = $value -split '/'
                            if ($parts.Length -eq 3) {
                                $stringUri = "https://github.com/$($parts[0])/$($parts[1])/archive/refs/heads/$($parts[2]).zip"
                                [Uri]::TryCreate($stringUri, [UriKind]::RelativeOrAbsolute, [ref]$parsedUri) | Out-Null
                            }
                        }
                        else {
                            if (-not $parsedUri.IsAbsoluteUri) {
                                if (Test-Path $parsedUri) {
                                    try {
                                        $resolvedPath = (Resolve-Path -Path $value).Path
                                        if (Test-Path -Path $resolvedPath -PathType Container) {
                                            $fileUri = "file://$resolvedPath"
                                            [Uri]::TryCreate($fileUri, [UriKind]::RelativeOrAbsolute, [ref]$parsedUri) | Out-Null
                                        }
                                        else {
                                            $parsedUri = $null
                                        }
                                    }
                                    catch {
                                        $parsedUri = $null
                                    }
                                }
                                else {
                                    $parsedUri = $null
                                }
                            }
                        }

                        return $parsedUri
                    }
                }
            }
            'temp-dir'    = @{
                Description = 'The temporary directory that is used for downloading and building'
                Order       = 3
                Required    = $false
                Type        = 'PATH'
                Default     = $env:temp
            }
            'extract-dir' = @{
                Description = 'The directory in which binaries will extract to during runtime'
                Order       = 4
                Required    = $false
                Type        = 'PATH'
            }
        }
        Flags       = @{
            'system-wide' = @{
                Description = 'Install system-wide and add to PATH'
                Order       = 0
            }
        }
    }
    'list-tools' = @{
        Description = 'Show the list of available tools to install'
        Order       = 1
    }
}

# A big list of all the examples in the Impacket repo, if something gets added, this needs to be updated
$availableTools = @(
    'DumpNTLMInfo'
    'Get-GPPPassword'
    'GetADComputers'
    'GetADUsers'
    'GetLAPSPassword'
    'GetNPUsers'
    'GetUserSPNs'
    'addcomputer'
    'atexec'
    'changepasswd'
    'dacledit'
    'dcomexec'
    'describeTicket'
    'dpapi'
    'esentutl'
    'exchanger'
    'findDelegation'
    'getArch'
    'getPac'
    'getST'
    'getTGT'
    'goldenPac'
    'karmaSMB'
    'keylistattack'
    'kintercept'
    'lookupsid'
    'machine_role'
    'mimikatz'
    'mqtt_check'
    'mssqlclient'
    'mssqlinstance'
    'net'
    'netview'
    'ntfs-read'
    'ntlmrelayx'
    'owneredit'
    'ping'
    'ping6'
    'psexec'
    'raiseChild'
    'rbcd'
    'rdp_check'
    'reg'
    'registry-read'
    'rpcdump'
    'rpcmap'
    'sambaPipe'
    'samrdump'
    'secretsdump'
    'services'
    'smbclient'
    'smbexec'
    'smbserver'
    'sniff'
    'sniffer'
    'split'
    'ticketConverter'
    'ticketer'
    'tstool'
    'wmiexec'
    'wmipersist'
    'wmiquery'
    'all'
)

# Extra code that needs to run conditionally for certain tools
$modules = @{
    'ntlmrelayx' = @{
        'install' = {
            param (
                [Hashtable]$Arguments,
                [Hashtable]$Flags
            )

            # No extra things need to happen here, just more Arguments
            # For some reason there is a bug with tkinter being included (?????)

            return @('--exclude-module', 'tkinter', '--collect-all', 'impacket.examples.ntlmrelayx')
        }
        'cleanup' = {
            param (
                [Hashtable]$Arguments,
                [Hashtable]$Flags
            )
        }
    }   
    'npcap'      = @{
        'install' = {
            param (
                [Hashtable]$Arguments,
                [Hashtable]$Flags
            )

            $tempDir = $arguments['temp-dir']
            $npcapInstaller = Join-Path -Path $tempDir -ChildPath 'npcap.exe'

            # Check if the module has already been run
            if (-not $flags['modulesRan'].Contains('npcap')) {

                # We need to make sure build tools are installed for pcapy-ng
                $buildToolsUrl = 'https://aka.ms/vs/17/release/vs_BuildTools.exe'
    
                # Npcap also needs to be bundled with the binaries
                $npcapVersion = '1.80'
                $npcapSDKVersion = '1.13'
    
                $npcapUrl = "https://npcap.com/dist/npcap-$npcapVersion.exe"
                $npcapSDKUrl = "https://npcap.com/dist/npcap-sdk-$npcapSDKVersion.zip"
    
                $buildToolsInstaller = Join-Path -Path $tempDir -ChildPath 'buildtools.exe'
                Invoke-WebRequest -Uri $buildToolsUrl -OutFile $buildToolsInstaller
    
                # Skip installation if already on the system
                if (Test-Path 'C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools') {
                    $flags['installedBuildTools'] = $false
                }
                else {
                    Write-Host 'Installing VC Build Tools...'
                    Start-Process $buildToolsInstaller -ArgumentList '--quiet', '--wait', '--add', 'Microsoft.VisualStudio.Workload.VCTools;includeRecommended' -Wait
    
                    $flags['installedBuildTools'] = $true
                    $arguments['buildToolsInstaller'] = $buildToolsInstaller
                }
                
                Invoke-WebRequest -Uri $npcapUrl -OutFile $npcapInstaller
            
                # Skip installation if already on the system
                if (Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Services\npcap') {
                    $flags['installedNpcap'] = $false
                }
                else {
                    Write-Host 'Installing Npcap...'
                    Start-Process $npcapInstaller -Wait
    
                    $flags['installedNpcap'] = $true
                }
            
                # The SDK also needs to be installed for pcapy-ng
    
                $npcapSDKArchive = Join-Path -Path $tempDir -ChildPath 'npcapSDK.zip'
                $npcapSDKFolder = Join-Path -Path $tempDir -ChildPath 'npcapSDK'
            
                Invoke-WebRequest -Uri $npcapSDKUrl -OutFile $npcapSDKArchive
                Expand-Archive -Path $npcapSDKArchive -DestinationPath $npcapSDKFolder -Force
                Remove-Item $npcapSDKArchive
            
                # Add required folders to the environment so that pcapy-ng builds correctly
    
                $env:INCLUDE = "$npcapSDKFolder\Include"
                $env:LIB = "$npcapSDKFolder\Lib\x64"
            }

            return @('--add-binary', "$npcapInstaller;.")
        }
        'cleanup' = {
            param (
                [Hashtable]$Arguments,
                [Hashtable]$Flags
            )

            if (-not $flags['modulesCleaned'].Contains('npcap')) {
                # Check if we installed Npcap during previous step
                if ($flags['installedNpcap']) {
                    Start-Process 'C:\Program Files\Npcap\Uninstall.exe' -Wait

                    # Set the flag to false so that on subsequent runs it does not try to uninstall again
                    $flags['installedNpcap'] = $false
                }
            
                # Check if we installed VC Build Tools during previous step
                if ($flags['installedBuildTools']) {
                    Write-Host 'Uninstalling VC Build Tools...'
                    Start-Process $arguments['buildToolsInstaller'] -ArgumentList '--quiet', '--wait', '--remove', 'Microsoft.VisualStudio.Workload.VCTools' -Wait
                
                    # Set the flag to false so that on subsequent runs it does not try to uninstall again
                    $flags['installedBuildTools'] = $false
                }
            }
        }
    }
}

# Define what tools require what modules and packages
$toolExtras = @{
    'ntlmrelayx' = @{
        Modules  = @('ntlmrelayx')
        Packages = @('pydivert')
    }
    'sniff'      = @{
        Modules  = @('npcap')
        Packages = @('pcapy-ng')
    }
    'split'      = @{
        Modules  = @('npcap')
        Packages = @('pcapy-ng')
    }
}

function install {
    param (
        [Hashtable]$Arguments,
        [Hashtable]$Flags
    )

    try {

        # With the way lists are parsed, this has to be done at runtime
        if ($arguments['tools'] -contains 'all') {
            $arguments['tools'] = $availableTools
        }

        # Create a folder in the specified temp dir, this will be used as the place where everything is downloaded and built in
        $tempDir = Join-Path -Path $arguments['temp-dir'] -ChildPath ($scriptTitle -replace ' ', '-').ToLower()
        $arguments['temp-dir'] = $tempDir

        # Remove any existing temp dir from a possible previous run
        if (Test-Path -Path $tempDir) {
            Remove-Item -Path $tempDir -Recurse -Force
        }
    
        New-Item -Path $tempDir -ItemType 'Directory' -Force | Out-Null

        # Save for later to return back to the start
        $startingDirectory = Get-Location

        $targetDirectory

        # Check if the source is a local directory, else download from the source url
        if ($arguments['source'].IsFile) {
            $targetDirectory = $arguments['source'].AbsolutePath
            $virtualEnvironmentPath = Join-Path -Path $targetDirectory -ChildPath '.venv'
            if (Test-Path -Path $virtualEnvironmentPath) {
                Remove-Item -Path $virtualEnvironmentPath -Recurse -Force
            }
        }
        else {
            Write-Host 'Downloading source...'
            $sourceArchivePath = Join-Path -Path $tempDir -ChildPath 'source.zip'
            $sourceFolderPath = Join-Path -Path $tempDir -ChildPath 'source'

            Invoke-WebRequest -Uri $arguments['source'].AbsoluteUri -OutFile $sourceArchivePath
            Expand-Archive -Path $sourceArchivePath -DestinationPath $sourceFolderPath

            # Git repo archives tend to be put inside subfolders so this should provide a better way to find the right folder without knowing things like the branch name
            # There may be a more ideal file to search for, but this shoudl work for now
            $foldersWithPythonFile = Get-ChildItem -Path $sourceFolderPath -Recurse -File -Filter "setup.py" | Select-Object DirectoryName
            $targetDirectory = $foldersWithPythonFile.DirectoryName
        }

        Set-Location -Path $targetDirectory

        $pythonBinary = Get-Python -TempDir $tempDir

        # Create and activate a Python virtual environment
        & $pythonBinary -m venv .venv
        .\.venv\Scripts\Activate.ps1

        # Install the requiements and Pyinstaller
        pip install -r requirements.txt
        pip install pyinstaller

        # Build the library
        python setup.py install

        # Create a base list of arguments for Pyinstaller
        $installerArgs = New-Object System.Collections.ArrayList
        $installerArgs.Add('--onefile') | Out-Null

        # This changes where the binaries extract their data to during runtime
        if ($arguments.ContainsKey('extract-dir')) {
            $installerArgs.Add('--runtime-tmpdir') | Out-Null
            $installerArgs.Add($arguments['extract-dir']) | Out-Null
        }

        # Start a list of modules that have been run so we can skip ones that have already been run
        $flags['modulesRan'] = New-Object System.Collections.Generic.HashSet[string]

        foreach ($tool in $arguments['tools']) {
            # Create a copy of the base args to be modified for each tool
            $toolInstallerArgs = [System.Collections.ArrayList]$installerArgs.Clone()

            # Check if there are extra things we need to do for this tool
            if ($toolExtras.ContainsKey($tool)) {
                foreach ($module in $toolExtras[$tool]['Modules']) {
                    # Modules return a list of arguments to be added to Pyinstaller, so we run the module, and append the arguments
                    Write-Host "Running module $module"
                    $moduleArguments = & $modules[$module]['install'] -Arguments $arguments -Flags $flags
                    $toolInstallerArgs.AddRange($moduleArguments)

                    ($flags['modulesRan']).Add($module) | Out-Null
                }

                # Install extra packages
                foreach ($package in $toolExtras[$tool]['Packages']) {
                    pip install $package
                }
            }

            # Build the binary
            pyinstaller $toolInstallerArgs "examples\$tool.py"

            $binaryPath = Join-Path -Path $targetDirectory -ChildPath "dist\$tool.exe"

            # If the system-wide flag was set, copy the binary to Program Files and add it to the PATH if not already added
            if ($flags['system-wide']) {
                Write-Host 'Copying binary to Program Files...'
                New-Item -ItemType Directory -Path 'C:\Program Files\Impacket' -Force
                Copy-Item -Path $binaryPath -Destination 'C:\Program Files\Impacket'
    
                $currentPath = [System.Environment]::GetEnvironmentVariable('Path', [System.EnvironmentVariableTarget]::Machine)
    
                if ($currentPath -notlike "*C:\Program Files\Impacket*") {
                    $newPath = $currentPath + ';' + 'C:\Program Files\Impacket'
    
                    Write-Host "Adding $tool to PATH..."
                    [System.Environment]::SetEnvironmentVariable('Path', $newPath, [System.EnvironmentVariableTarget]::Machine)
                }
                else {
                    Write-Host 'Impacket is already in PATH.'
                }
            }
            else {
                # Otherwise just copy it to the output directory
                Copy-Item -Path $binaryPath -Destination $arguments['output-dir']
            }
        }
    }
    finally {
        # Should run even if the installation failed
        Write-Host 'Cleaning up...'

        # Start list of already cleaned up modules, same as above
        $flags['modulesCleaned'] = New-Object System.Collections.Generic.HashSet[string]

        # Runs any module cleanup for tools
        foreach ($tool in $arguments['tools']) {
            if ($toolExtras.ContainsKey($tool)) {
                $toolModules = $toolExtras[$tool]['Modules']
                
                foreach ($module in $toolModules) {
                    Write-Host "Cleaning up module $module..."
                    & $modules[$module]['cleanup'] -Arguments $arguments -Flags $flags
                    
                    ($flags['modulesCleaned']).Add($module) | Out-Null
                }
            }
        }

        # Deactivate the Python virtual environment and reset our working directory
        deactivate
        Set-Location -Path $startingDirectory

        # Remove our Python install
        Remove-Python -TempDir $tempDir
        
        # Remove the temp dir if it still exists
        if (Test-Path -Path $tempDir) {
            Remove-Item -Path $tempDir -Recurse -Force
        }
    }
}

function list-tools {
    param (
        [Hashtable]$Arguments,
        [Hashtable]$Flags
    )

    Write-Host 'Available tools:'

    foreach ($tool in $availableTools) {
        Write-Host "$tool"
    }

    Write-Host ''
}

function Get-Python {
    param (
        [string]$TempDir
    )

    $pythonVersion = '3.13.2'
    $pythonUrl = "https://www.python.org/ftp/python/$pythonVersion/python-$pythonVersion-amd64.exe"

    # Check if Python is already installed, and if the version matches
    $pythonOutput = python --version
    if ($pythonOutput -eq "python $pythonVersion") {
        return (Get-Command python).Source
    }

    # Python needs to be downloaded, do that, and then return the path to the binary since we are not adding it to the PATH
    Write-Host 'Downloading Python...'

    $ProgressPreference = 'SilentlyContinue'
    $pythonDirectory = Join-Path -Path $TempDir -ChildPath 'python'

    if (Test-Path -Path $pythonDirectory) {
        Remove-Item $pythonDirectory -Recurse -Force
    }
    
    New-Item -Path $pythonDirectory -ItemType 'Directory' | Out-Null
    $pythonInstallerPath = Join-Path -Path $pythonDirectory -ChildPath 'python-installer.exe'

    Invoke-WebRequest -Uri $pythonUrl -Outfile $pythonInstallerPath
    Start-Process $pythonInstallerPath -ArgumentList '/quiet', "TargetDir=$($pythonDirectory -replace ' ', '` ')", 'Shortcuts=0', 'Include_doc=0', 'Include_launcher=0' -Wait -Verb RunAs

    $pythonBinary = Join-Path -Path $pythonDirectory -ChildPath 'python.exe'
    return $pythonBinary
}

function Remove-Python {
    param (
        [string]$TempDir
    )

    $pythonDirectory = Join-Path -Path $TempDir -ChildPath 'python'
    $pythonInstallerPath = Join-Path -Path $pythonDirectory -ChildPath 'python-installer.exe'

    # Check if the Python installer is still around, if so, uninstall, this should only happen if we did not find an existing install
    if (Test-Path $pythonInstallerPath) {
        Start-Process $pythonInstallerPath -ArgumentList '/quiet', 'uninstall' -Wait -Verb RunAs
    }
}

# !!! Everything below this point does not need to be changed !!!

function Get-FlatArguments {
    param (
        [string]$CommandName
    )

    $flatArguments = @{}

    if ($commands[$commandName].ContainsKey('Arguments')) {
        foreach ($argument in $commands[$commandName]['Arguments'].GetEnumerator()) {
            if ($argument.Value.ContainsKey('Group') -and $argument.Value['Group']) {
                $group = $argument.Value
                if ($group.ContainsKey('Arguments')) {
                    foreach ($groupArgument in $group['Arguments'].GetEnumerator()) {
                        $flatArguments[$groupArgument.Key] = $groupArgument.Value
                    }
                }
            }
            else {
                $flatArguments[$argument.Key] = $argument.Value
            }
        }
    }

    return $flatArguments
}

function Show-Argument {
    param (
        [System.Collections.DictionaryEntry]$Argument,
        [int]$Padding
    )

    $argumentOutputString = "      --$("$($argument.Key) <$($argument.Value['Type'])>".PadRight($padding)) $($argument.Value['Description'])"
    if ($argument.Value.ContainsKey('Default')) {
        if ($argument.Value['Default'] -is [System.Management.Automation.ScriptBlock]) {
            if ($argument.Value.ContainsKey('DefaultDescription')) {
                $argumentOutputString = $argumentOutputString + " (default: $($argument.Value['DefaultDescription']))"
            }
            else {
                $argumentOutputString = $argumentOutputString + " (default: <not specified>)"
            }
        }
        else {
            $argumentOutputString = $argumentOutputString + " (default: $($argument.Value['Default']))"
        }
    }

    Write-Host $argumentOutputString
}

function Show-HelpMenu {
    param (
        [Parameter(Mandatory = $False)]
        [string]$SelectedCommand
    )

    Write-Host "=== $scriptTitle ==="
    Write-Host $scriptDesc
    Write-Host "Version: $version"
    Write-Host ''
    Write-Host "Usage: $scriptFileName [COMMAND] [ARGUMENTS] [FLAGS]"
    Write-Host ''

    $helpMenuCommandPadding = 0
    $helpMenuArgsAndFlagsPadding = 0
    
    foreach ($commandName in $commands.Keys) {
        if ($commandName.Length -gt $helpMenuCommandPadding) {
            $helpMenuCommandPadding = $commandName.Length
        }

        $flatArguments = Get-FlatArguments -CommandName $commandName
    
        foreach ($argument in $flatArguments.GetEnumerator()) {
            $fullArgument = $argument.Key
            if ($argument.Value.ContainsKey('Type')) {
                $fullArgument = "$fullArgument <$($argument.Value['Type'])>"
            }

            if ($fullArgument.Length -gt $helpMenuArgsAndFlagsPadding) {
                $helpMenuArgsAndFlagsPadding = $fullArgument.Length
            }
        }
    
        foreach ($flagName in $commands[$commandName]['Flags'].Keys) {
            if ($flagName.Length -gt $helpMenuArgsAndFlagsPadding) {
                $helpMenuArgsAndFlagsPadding = $flagName.Length
            }
        }
    }
    
    $helpMenuCommandPadding += 2
    $helpMenuArgsAndFlagsPadding += 2

    if (-not $selectedCommand) {
        Write-Host '[COMMANDS]'
    }

    $sortedCommands = $commands.GetEnumerator() | Sort-Object { $_.Value['Order'] }
    foreach ($command in $sortedCommands) {

        if ($selectedCommand -and ($selectedCommand -ne ($command.Key))) {
            continue
        }

        Write-Host "  $($command.Key.PadRight($helpMenuCommandPadding)) $($command.Value['Description'])"
        Write-Host ''

        if ($command.Value.ContainsKey('Arguments')) {
            Write-Host '  [ARGUMENTS]'

            $arguments = $command.Value['Arguments']
            $sortedArguments = $arguments.GetEnumerator() | Sort-Object { $_.Value['Order'] }

            $lastItemWasGroup = $false

            foreach ($argument in $sortedArguments) {
                if ($argument.Value.ContainsKey('Group') -and $argument.Value['Group']) {
                    $lastItemWasGroup = $true
                    Write-Host ''

                    $group = $argument.Value

                    if ($group.ContainsKey('Arguments')) {
                        $groupTitleString = "    {$($argument.Key)}"
                        if ($group.ContainsKey('Required') -and $group['Required']) {
                            $groupTitleString += ' (Required)'
                        }
                        if ($group.ContainsKey('Exclusive') -and $group['Exclusive']) {
                            $groupTitleString += ' (Exclusive)'
                        }
                        Write-Host $groupTitleString

                        $groupArguments = $group['Arguments'].GetEnumerator() | Sort-Object { $_.Value['Order'] }
                        foreach ($groupArgument in $groupArguments) {
                            Show-Argument -Argument $groupArgument -Padding $helpMenuArgsAndFlagsPadding
                        }
                    }
                }
                else {
                    if ($lastItemWasGroup) {
                        Write-Host ''
                    }
                    Show-Argument -Argument $argument -Padding $helpMenuArgsAndFlagsPadding + 2
                }
            }
            Write-Host ''
        }

        if ($command.Value.ContainsKey('Flags')) {
            Write-Host '  [FLAGS]'
            $flags = $command.Value['Flags'].GetEnumerator() | Sort-Object { $_.Value['Order'] }
            foreach ($flagName in $flags.Key) {
                $flagValue = $command.Value['Flags'][$flagName]
                Write-Host "    -$($flagName.PadRight($helpMenuArgsAndFlagsPadding + 1)) $($flagValue['Description'])"
            }
            Write-Host ''
        }
    }
    Write-Host ''
}

if ($Args.Count -eq 0 -or $Args[0] -eq '-h' -or $Args[0] -eq '--help') {
    Show-HelpMenu
    exit 0
}

if (-not $commands.ContainsKey($Args[0])) {
    throw 'Invalid command selected (Use -h or --help for help)'
}

$selectedCommand = $null
$flattenedCommandArguments = $null
$selectedArguments = @{}
$selectedFlags = @{}

for ($i = 0; $i -lt $Args.Count; $i++) {
    if ($i -eq 0) {
        $selectedCommand = $Args[0]
        $flattenedCommandArguments = Get-FlatArguments -CommandName $Args[0]
    }
    elseif ($Args -contains '-h' -or $Args -contains '--help') {
        if ($selectedCommand) {
            Show-HelpMenu -SelectedCommand $selectedCommand
        }
        else {
            Show-HelpMenu
        }
        exit 0
    }
    elseif ($Args[$i].StartsWith('--')) {
        $arg = $Args[$i].Substring(2)
        $argParts = $arg -split '='
        $keyword = $argParts[0]
        $value = $null

        if (-not $flattenedCommandArguments.ContainsKey($keyword)) {
            throw 'Invalid argument (Use -h or --help for help)'
        }

        if ($argParts.Count -eq 2) {
            $value = $argParts[1]
        }
        elseif ($argParts.Count -gt 2 -or $argParts -lt 1) {
            throw 'Malformed argument (Use -h or --help for help)'
        }

        if (-not $value) {
            $i++
            $value = $Args[$i]
        }

        if (-not $value) {
            throw "No value provided for argument `"$keyword`" (Use -h or --help for help)"
        }

        $argumentTypeString = $flattenedCommandArguments[$keyword]['Type']

        $targetType = [System.Object]
        $parser = { param([System.Object]$Value) return $value }

        if ($flattenedCommandArguments[$keyword].ContainsKey('CustomType')) {
            if ($flattenedCommandArguments[$keyword].ContainsKey('ReturnType')) {
                $targetType = $flattenedCommandArguments[$keyword]['CustomType']['ReturnType']
            }

            $parser = $flattenedCommandArguments[$keyword]['CustomType']['Parser']
        }
        else {
            switch ($argumentTypeString) {
                'STRING' {
                    $targetType = [string]
                    $parser = { param([System.Object]$Value) return $value -as [string] }
                }
                'NUMBER' {
                    $targetType = [int32]
                    $parser = { param([System.Object]$Value) return $value -as [int32] }
                }
                'BOOLEAN' {
                    $targetType = [bool]
                    $parser = { param([System.Object]$Value) return $value -as [bool] }
                }
                'PATH' {
                    $targetType = [string]
                    $parser = {
                        param(
                            [System.Object]$Value
                        )

                        if ((-not ($value -match '\\')) -and (-not ($value -match '/'))) {
                            $value = Join-Path -Path (Get-Location) -ChildPath $value
                        }
            
                        $parentDir = Split-Path -Path $value -Parent
            
                        if ((-not $parentDir) -or ($parentDir -and (Test-Path -Path $parentDir))) {
                            return (Resolve-Path -Path $value).Path -as [string]
                        }
                    }
                }
            }
        }

        $targetArrayType = $targetType.MakeArrayType()
        $shouldBeList = $flattenedCommandArguments[$keyword].ContainsKey('List') -and $flattenedCommandArguments[$keyword]['List']

        $parsedValue = $null

        if ($value -is [System.Object[]]) {
            if (-not $shouldBeList) {
                throw "Argument value for `"$keyword`" cannot be a list (Use -h or --help for help)"
            }

            for ($j = 0; $j -lt $value.Length; $j++) {
                $parsedListItem = & $parser -Value $value[$j]
                if ($null -ne $parsedListItem) {
                    $value[$j] = $parsedListItem
                }
                else {
                    throw "Argument value `"$($value[$j])`" is not a valid $($argumentTypeString.ToLower()) (Use -h or --help for help)"
                }
            }

            $parsedValue = $value -as $targetArrayType
        }
        else {
            if ($shouldBeList) {
                $parsedItem = & $parser -Value $value
                if ($null -ne $parsedItem) {
                    $parsedValue = @($parsedItem) -as $targetArrayType
                }
                else {
                    throw "Argument value `"$value`" is not a valid $($argumentTypeString.ToLower()) (Use -h or --help for help)"
                }
            }
            else {
                $parsedValue = & $parser -Value $value
            }
        }
        
        if ($null -eq $parsedValue) {
            if ($shouldBeList) {
                throw "Argument value `"$value`" for `"$keyword`" is not a valid $($argumentTypeString.ToLower()) list (Use -h or --help for help)"
            }
            else {
                throw "Argument value `"$value`" for `"$keyword`" is not a valid $($argumentTypeString.ToLower()) (Use -h or --help for help)"
            }
        }
        
        $selectedArguments[$keyword] = $parsedValue
    }
    elseif ($Args[$i].StartsWith('-')) {
        $flag = $Args[$i].Substring(1)
        if (-not $commands[$selectedCommand]['Flags'].ContainsKey($flag)) {
            throw 'Invalid flag (Use -h or --help for help)'
        }

        $selectedFlags[$flag] = $True
    }
    else {
        throw 'Invalid input (Use -h or --help for help)'
    }
}

foreach ($flagName in $commands[$selectedCommand]['Flags'].Keys) {
    if (-not $selectedFlags.ContainsKey($flagName)) {
        $selectedFlags[$flagName] = $False
    }
}

$defaultArguments = @{}
foreach ($argument in $flattenedCommandArguments.GetEnumerator()) {
    if ($argument.Value.ContainsKey('Default')) {
        if ($argument.Value['Default'] -is [System.Management.Automation.ScriptBlock]) {
            $defaultArguments[$argument.Key] = & $argument.Value['Default'] -Arguments $selectedArguments -Flags $selectedFlags
        }
        else {
            $defaultArguments[$argument.Key] = $argument.Value['Default']
        }
    }
}

foreach ($defaultArgument in $defaultArguments.GetEnumerator()) {
    if (-not $selectedArguments.ContainsKey($defaultArgument.Key)) {
        $selectedArguments[$defaultArgument.Key] = $defaultArgument.Value
    }
}

foreach ($argument in $flattenedCommandArguments.GetEnumerator()) {
    if ($argument.Value.ContainsKey('Group') -and $argument.Value['Group']) {
        $group = $argument.Value

        if ($group.ContainsKey('Required')) {
            if ($group['Required'] -is [bool]) {
                $required = $false
                if ($group.ContainsKey('Required') -and $group['Required']) {
                    $required = $true 
                }
        
                $exclusive = $false
                if ($group.ContainsKey('Exclusive') -and $group['Exclusive']) {
                    $exclusive = $true 
                }
        
                if ($group.ContainsKey('Arguments')) {
                    $numberOfArgumentsSelected = 0
                    foreach ($groupArgument in $group['Arguments'].GetEnumerator()) {
                        $selectedArguments
                        if ($selectedArguments.ContainsKey($groupArgument.Key)) {
                            $numberOfArgumentsSelected++
                        }
                    }
        
                    if (($numberOfArgumentsSelected -eq 0) -and $required) {
                        throw "Missing required argument for required group `"$($argument.Key)`" (Use -h or --help for help)"
                    }
        
                    if (($numberOfArgumentsSelected -gt 1) -and $exclusive) {
                        throw "Multiple arguments specified for exclusive group `"$($argument.Key)`" (Use -h or --help for help)"
                    }
                }
            }
            elseif ($group['Required'] -is [System.Management.Automation.ScriptBlock]) {
                if (-not (& $group['Required'] -Arguments $selectedArguments -Flags $selectedFlags)) {
                    if ($group.ContainsKey('RequiredDescription')) {
                        throw "Group `"$($argument.Key)`" did not meet the requirements: $($group['RequiredDescription'])"
                    }
                    else {
                        throw "Group `"$($argument.Key)`" did not meet the requirements, no description was provided."
                    }
                }
            }
        }
    }
    else {
        if ($argument.Value.ContainsKey('Required')) {
            if ($argument.Value['Required'] -is [bool] -and $argument.Value['Required'] -and (-not $selectedArguments.ContainsKey($argument.Key))) {
                throw "Missing required argument `"$($argument.Key)`" (Use -h or --help for help)"
            }

            if ($argument.Value['Required'] -is [System.Management.Automation.ScriptBlock]) {
                if (-not (& $argument.Value['Required'] -Arguments $selectedArguments -Flags $selectedFlags)) {
                    if ($argument.Value.ContainsKey('RequiredDescription')) {
                        throw "Argument `"$($argument.Key)`" did not meet the requirements: $($argument.Value['RequiredDescription'])"
                    }
                    else {
                        throw "Argument `"$($argument.Key)`" did not meet the requirements, no description was provided."
                    }
                }
            }
        }
    }
}

& (Get-Command $selectedCommand) -Arguments $selectedArguments -Flags $selectedFlags