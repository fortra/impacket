function Main {
    $TempPath = $Env:TEMP

    $InstalledNpcap = $false

    Write-Host 'Downloading Npcap...'
    $NpcapInstaller = Join-Path -Path $TempPath -ChildPath "npcap.exe"
    Invoke-WebRequest -Uri 'https://npcap.com/dist/npcap-1.80.exe' -OutFile $NpcapInstaller

    # Check if Npcap is already installed
    if (Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Services\npcap') {
        Write-Host 'Found existing Npcap installation. Skipping install...'
    }
    else {
        Start-Process $NpcapInstaller -Wait
        $InstalledNpcap = $true
    }

    $NpcapSDKArchive = Join-Path -Path $TempPath -ChildPath "npcapSDK.zip"
    $NpcapSDKFolder = Join-Path -Path $TempPath -ChildPath "npcapSDK"

    Invoke-WebRequest -Uri 'https://npcap.com/dist/npcap-sdk-1.13.zip' -OutFile $NpcapSDKArchive
    Expand-Archive -Path $NpcapSDKArchive -DestinationPath $NpcapSDKFolder -Force
    Remove-Item $NpcapSDKArchive

    $env:INCLUDE = "$NpcapSDKArchive\Include"
    $env:LIB = "$NpcapSDKArchive\Lib\x64"

    $env:InstalledNPcap = $InstalledNpcap

    return @('--add-binary', "$NpcapInstaller;.")
}

function Cleanup {
    if ($env:InstalledNPcap -eq "True") {
        Start-Process 'C:\Program Files\Npcap\Uninstall.exe' -Wait
    }
}