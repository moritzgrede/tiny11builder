<#
.SYNOPSIS
Script to build a trimmed-down Windows 11 image.

.DESCRIPTION
Script to build a trimmed-down Windows 11 image. See REAMDE.md for further details!

.INPUTS
None. You cannot pipe objects to Start-Tiny11Builder.ps1.

.OUTPUTS
None. Start-Tiny11Builder.ps1 does not generate any output.

.EXAMPLE
PS> .\Start-Tiny11Builder.ps1 -IsoPath '.\Win10_21H1_EnglishInternational_x64.iso'

.LINK
https://github.com/moritzgrede/tiny11builder

.NOTES
Author: Moritz Grede
See Changelog.md for changelog history.
#>


#Requires -RunAsAdministrator

param (
    # Path to ISO containing Windows 11 image
    [Parameter( Mandatory = $true )]
    [ValidateScript( { Test-Path -LiteralPath $_ } )]
    [String]
    $IsoPath
)

<#
    FUNCTIONS
#>
function Start-DismAction {
    param (
        [Parameter( Mandatory = $true, ValueFromRemainingArguments = $true )]
        [Alias( 'Args' )]
        [String]
        $Arguments,

        [Switch]
        $NoImage,

        [Switch]
        $Break
    )
    begin {
        $Output = New-TemporaryFile
    }
    process {
        if ( $NoImage ) {
            $Process = Start-Process -FilePath 'Dism.exe' -ArgumentList $Arguments -WindowStyle Hidden -RedirectStandardOutput $Output.FullName -PassThru -Wait
        } else {
            $Process = Start-Process -FilePath 'Dism.exe' -ArgumentList "/Image:$( $WorkingDirectory.scratch.FullName ) $( $Arguments )" -WindowStyle Hidden -RedirectStandardOutput $Output.FullName -PassThru -Wait
        }
        if ( $Process.ExitCode -ne 0 ) {
            Write-Host -ForegroundColor Red 'ERROR'
            if ( $Break ) {
                Start-Cleanup
                Throw "Dism.exe exited with error code $( $LASTEXITCODE ):`r`n$( $IndiciesRaw )"
            }
            Write-Error ( Get-Content -LiteralPath $Output.FullName -Raw )
        } else {
            Write-Host -ForegroundColor Green 'SUCCESS'
        }
        $Process.ExitCode
    }
}

function Start-Cleanup {
    # Remove working directory
    Remove-Item -LiteralPath $WorkingDirectory.tiny11Path -Recurse -Force -ErrorAction SilentlyContinue
    # Remove scratch directory
    Remove-Item -LiteralPath $WorkingDirectory.scratchPath -Recurse -Force -ErrorAction SilentlyContinue
}

<#
    VARIABLES
#>
$ProvisionedAppxPackagesToRemove = @(
    'Clipchamp.Clipchamp',
    'Microsoft.BingNews',
    'Microsoft.BingWeather',
    'Microsoft.GamingApp',
    'Microsoft.GetHelp',
    'Microsoft.Getstarted',
    'Microsoft.MicrosoftOfficeHub',
    'Microsoft.MicrosoftSolitaireCollection',
    'Microsoft.People',
    'Microsoft.PowerAutomateDesktop',
    'Microsoft.Todos',
    'Microsoft.WindowsAlarms',
    'microsoft.windowscommunicationsapps',
    'Microsoft.WindowsFeedbackHub',
    'Microsoft.WindowsMaps',
    'Microsoft.WindowsSoundRecorder',
    'Microsoft.Xbox',
    'Microsoft.XboxGamingOverlay',
    'Microsoft.XboxGameOverlay',
    'Microsoft.XboxSpeechToTextOverlay',
    'Microsoft.YourPhone',
    'Microsoft.ZuneMusic',
    'Microsoft.ZuneVideo',
    'MicrosoftCorporationII.MicrosoftFamily',
    'MicrosoftCorporationII.QuickAssist',
    'MicrosoftTeams',
    'Microsoft.549981C3F5F10'
)
$PackagesToRemove = @(
    'Microsoft-Windows-InternetExplorer-Optional-Package',
    'Microsoft-Windows-Kernel-LA57-FoD-Package',
    # 'Microsoft-Windows-LanguageFeatures-Handwriting',
    # 'Microsoft-Windows-LanguageFeatures-OCR',
    # 'Microsoft-Windows-LanguageFeatures-Speech',
    # 'Microsoft-Windows-LanguageFeatures-TextToSpeech',
    'Microsoft-Windows-MediaPlayer-Package',
    'Microsoft-Windows-TabletPCMath-Package',
    'Microsoft-Windows-Wallpaper-Content-Extended-FoD-Package'
)
$WorkingDirectory = @{
    'tiny11Path' = Join-Path -Path $env:TEMP -ChildPath 'tiny11'
    'scratchPath' = Join-Path -Path $env:TEMP -ChildPath 'tiny11.scratchdir'
}

<#
    SCRIPT
#>
# Prepare working directory
if ( Test-Path -LiteralPath $WorkingDirectory.tiny11Path ) {
    $Choices = @(
        New-Object -TypeName System.Management.Automation.Host.ChoiceDescription -ArgumentList '&Yes',
        New-Object -TypeName System.Management.Automation.Host.ChoiceDescription -ArgumentList '&No'
    )
    if ( 0 -ne $Host.UI.PromptForChoice( 'Overwrite directory?', "Working directory `"$( $WorkingDirectory.tiny11Path )`" already exists, continue anyway?`r`nData may be lost!", $Choices, 1 ) ) {
        Write-Host -ForegroundColor Red 'ERROR'
        Throw "Working directory `"$( $WorkingDirectory.tiny11Path )`" already exists"
    }
    try {
        Remove-Item -LiteralPath $WorkingDirectory.tiny11Path -Recurse -Force -ErrorAction Stop
    } catch {
        Write-Host -ForegroundColor Red 'ERROR'
        Throw $_
    }
}
$WorkingDirectory.tiny11 = New-Item -ItemType Directory -Path $WorkingDirectory.tiny11Path -Force
# Prepare scratch directory
if ( Test-Path -LiteralPath $WorkingDirectory.scratchPath ) {
    $Choices = @(
        New-Object -TypeName System.Management.Automation.Host.ChoiceDescription -ArgumentList '&Yes',
        New-Object -TypeName System.Management.Automation.Host.ChoiceDescription -ArgumentList '&No'
    )
    if ( 0 -ne $Host.UI.PromptForChoice( 'Overwrite directory?', "Scratch directory `"$( $WorkingDirectory.scratchPath )`" already exists, continue anyway?`r`nData may be lost!", $Choices, 1 ) ) {
        Write-Host -ForegroundColor Red 'ERROR'
        Throw "Scratch directory `"$( $WorkingDirectory.scratchPath )`" already exists"
    }
    try {
        Remove-Item -LiteralPath $WorkingDirectory.scratchPath -Recurse -Force -ErrorAction Stop
    } catch {
        Write-Host -ForegroundColor Red 'ERROR'
        Throw $_
    }
}
$WorkingDirectory.scratch = New-Item -ItemType Directory -Path $WorkingDirectory.scratchDirectory -Force

# Welcome message
Write-Host 'Welcome to the'
Write-Host '   __  _            ________          _ __    __         '
Write-Host '  / /_(_)___  __  _<  <  / /_  __  __(_) /___/ /__  ____ '
Write-Host ' / __/ / __ \/ / / / // / __ \/ / / / / / __  / _ \/ ___/'
Write-Host '/ /_/ / / / / /_/ / // / /_/ / /_/ / / / /_/ /  __/ /    '
Write-Host '\__/_/_/ /_/\__, /_//_/_.___/\__,_/_/_/\__,_/\___/_/     '
Write-Host '           /____/                                        '

# Mount & check the iso
Write-Host -NoNewline 'Mounting ISO...'
$IsoRaw = Mount-DiskImage -ImagePath $IsoPath -StorageType ISO -Access ReadOnly -PassThru
$Iso = Get-Volume -DiskImage $IsoRaw
'boot.wim', 'install.wim' | ForEach-Object {
    if ( -not ( Test-Path -LiteralPath ( Join-Path -Path $Iso.Path -ChildPath "sources\$( $_ )" ) ) ) {
        Write-Host -ForegroundColor Red 'ERROR'
        Throw [System.IO.FileNotFoundException]::new( "Cannot find Windows OS $( $_ ) in ISO" )
    }
}
Write-Host -ForegroundColor Green 'SUCCESS'

# Create temporary directory and copy image
Write-Host -NoNewline 'Copying Windows image...'
Start-Process -FilePath 'xcopy.exe' -ArgumentList "/E /I /H /R /Y /J $( $Iso.DriveLetter ): `"$( $WorkingDirectory.tiny11.FullName )`"" -WindowStyle Hidden -Wait
if ( 0 -ne $LASTEXITCODE ) {
    Write-Host -ForegroundColor Red 'ERROR'
    Start-Cleanup
    Throw "xcopy.exe exited with error code $( $LASTEXITCODE )"
}
Write-Host -ForegroundColor Green 'SUCCESS'

# Get image information
Write-Host ''
Write-Host 'Getting image index information:'
$IndiciesRaw = Dism.exe /Get-WimInfo /wimfile:$( Join-Path -Path $Iso.Path -ChildPath 'sources\install.wim' )
if ( 0 -ne $LASTEXITCODE ) {
    Write-Host -ForegroundColor Red 'ERROR'
    Start-Cleanup
    Throw "Dism.exe exited with error code $( $LASTEXITCODE ):`r`n$( $IndiciesRaw )"
}
$Indicies = @{}
for ( $I = 0; $I -lt $IndiciesRaw.Count; $I++ ) {
    if ( $IndiciesRaw[$I] -like 'Index*' ) {
        $Index = [int] ( $IndiciesRaw[$I] -split ':' )[1].Trim()
        $Indicies[$Index] = @{
            'Name' = ( $IndiciesRaw[$I + 1] -split ':' )[1].Trim()
            'Description' = ( $IndiciesRaw[$I + 2] -split ':' )[1].Trim()
            'Size' = ( $IndiciesRaw[$I + 3] -split ':' )[1].Trim()
        }
        $I += 3
    }
}
foreach ( $Key in $Indicies.Keys ) {
    "$( $Key ): $( $Indicies[$Key].Name )"
}
do {
    Write-Host ''
    $ImageIndex = Read-Host -Prompt 'Please enter the image index'
    if ( [int] $ImageIndex -in $Indicies.Keys ) {
        break
    }
    Write-Error "Given index $( $ImageIndex ) not found in image"
} while ( $true )

# Unmount iso
Write-Host -NoNewline 'Unmounting ISO...'
try {
    $IsoRaw = $IsoRaw | Dismount-DiskImage -ErrorAction Stop
} catch {
    Write-Host -ForegroundColor Red 'ERROR'
    Start-Cleanup
    Throw $_
}
Write-Host -ForegroundColor Green 'SUCCESS'

# Mount Windows image
Write-Host 'Mounting Windows image. This may take a while...'
Dism.exe /mount-image /imagefile:"$( Join-Path -Path $WorkingDirectory.tiny11.FullName -ChildPath 'sources\install.wim' )" /index:"$( $ImageIndex )" /mountdir:"$( $WorkingDirectory.scratch.FullName )"
if ( $LASTEXITCODE -ne 0 -and $LASTEXITCODE -ne -1052638937 ) {
    Write-Host -ForegroundColor Red 'ERROR'
    Start-Cleanup
    Throw "Dism.exe exited with error code $( $LASTEXITCODE ). Mounting of Windows image failed."
}

# Get provisioned applications
Write-Host ''
Write-Host 'Performing removal of applications...'
$ProvisionedAppXPackagesRaw = Dism.exe /Image:"$( $WorkingDirectory.scratch.FullName )" /Get-ProvisionedAppXPackages
if ( 0 -ne $LASTEXITCODE ) {
    Write-Host -ForegroundColor Red 'ERROR'
    Start-Cleanup
    Throw "Dism.exe exited with error code $( $LASTEXITCODE ):`r`n$( $ProvisionedAppXPackagesRaw )"
}
$ProvisionedAppXPackages = @()
for ( $I = 0; $I -lt $ProvisionedAppXPackagesRaw.Count; $I++) {
    if ( $ProvisionedAppXPackagesRaw[$I] -like 'DisplayName*' ) {
        $ProvisionedAppXPackages += @{
            'DisplayName' = ( $ProvisionedAppXPackagesRaw[$I] -split ':' )[1].Trim()
            'Version' = ( $ProvisionedAppXPackagesRaw[$I + 1] -split ':' )[1].Trim()
            'PackageName' = ( $ProvisionedAppXPackagesRaw[$I + 4] -split ':' )[1].Trim()
        }
    $I += 5
    }
}

# Remove applications
$ProvisionedAppxPackagesToRemove | ForEach-Object {
    $Package = $_
    $ProvisionedAppXPackages | Where-Object -Property 'DisplayName' -EQ -Value $Package | ForEach-Object {
        Write-Host -NoNewline "Removing $( $_.PackageName ) "
        Start-DismAction "/Remove-ProvisionedAppxPackage /PackageName:$( $_.PackageName )" | Out-Null
    }
}
Write-Host 'Removing of system apps complete!'

# Get packages
Write-Host ''
Write-Host 'Performing removal of system packages...'
$PackagesRaw = Dism.exe /Image:"$( $WorkingDirectory.scratch.FullName )" /Get-Packages
if ( 0 -ne $LASTEXITCODE ) {
    Write-Host -ForegroundColor Red 'ERROR'
    Start-Cleanup
    Throw "Dism.exe exited with error code $( $LASTEXITCODE ):`r`n$( $PackagesRaw )"
}
$Packages = @()
for ( $I = 0; $I -lt $PackagesRaw.Count; $I++) {
    if ( $PackagesRaw[$I] -like 'Package Identity*' ) {
        $Packages += ( $PackagesRaw[$I] -split ':' )[1].Trim()
        $I += 3
    }
}

# Remove packages
$PackagesToRemove | ForEach-Object {
    $Package = $_
    $Packages | Where-Object { $_ -like "$( $Package )*" } | ForEach-Object {
        Write-Host -NoNewline "Removing $( $_ ) "
        Start-DismAction "/Remove-Package /PackageName:$( $_ )" | Out-Null
    }
}
# ToDo: Ask to remove Edge
'Edge', 'EdgeUpdate' | ForEach-Object {
    try {
        Write-Host -NoNewline "Removing Microsoft $( $_ )..."
        Remove-Item -LiteralPath ( Join-Path -Path $WorkingDirectory.scratch.FullName -ChildPath "Program Files (x86)\$( $_ )" ) -Recurse -Force -ErrorAction Stop
    } catch {
        Write-Host -ForegroundColor Red 'ERROR'
        Write-Error $_
        break
    }
}
Write-Host -ForegroundColor Green 'SUCCESS'
# ToDo: Ask to remove OneDrive
Write-Host -NoNewline 'Removing OneDrive...'
$OneDrivePath = Join-Path -Path $WorkingDirectory.scratch.FullName -ChildPath 'Windows\System32\OneDriveSetup.exe'
takeown.exe /f $OneDrivePath | Out-Null
icacls.exe $OneDrivePath /grant Administrators:F /T /C | Out-Null
try {
    Remove-Item -LiteralPath $OneDrivePath -Force -ErrorAction Stop
} catch {
    Write-Host -ForegroundColor Red 'ERROR'
    Write-Error $_
}
Write-Host -ForegroundColor Green 'SUCCESS'
Write-Host 'Removing of system packages complete!'

# Load registry
Write-Host ''
Write-Host -NoNewline 'Loading registry...'
# ToDo: Error handling
reg.exe LOAD HKLM\zCOMPONENTS "$( Join-Path -Path $WorkingDirectory.scratch.FullName -ChildPath 'Windows\System32\config\COMPONENTS' )" | Out-Null
reg.exe LOAD HKLM\zDEFAULT "$( Join-Path -Path $WorkingDirectory.scratch.FullName -ChildPath 'Windows\System32\config\default' )" | Out-Null
reg.exe LOAD HKLM\zNTUSER "$( Join-Path -Path $WorkingDirectory.scratch.FullName -ChildPath 'Users\Default\ntuser.dat' )" | Out-Null
reg.exe LOAD HKLM\zSOFTWARE "$( Join-Path -Path $WorkingDirectory.scratch.FullName -ChildPath 'Windows\System32\config\SOFTWARE' )" | Out-Null
reg.exe LOAD HKLM\zSYSTEM "$( Join-Path -Path $WorkingDirectory.scratch.FullName -ChildPath 'Windows\System32\config\SYSTEM' )" | Out-Null
Write-Host -ForegroundColor Green 'SUCCESS'

# Bypass system requirements
Write-Host -NoNewline 'Bypassing the images system requirements...'
reg.exe ADD 'HKLM\zDEFAULT\Control Panel\UnsupportedHardwareNotificationCache' /v 'SV1' /t REG_DWORD /d '0' /f | Out-Null
reg.exe ADD 'HKLM\zDEFAULT\Control Panel\UnsupportedHardwareNotificationCache' /v 'SV2' /t REG_DWORD /d '0' /f | Out-Null
reg.exe ADD 'HKLM\zNTUSER\Control Panel\UnsupportedHardwareNotificationCache' /v 'SV1' /t REG_DWORD /d '0' /f | Out-Null
reg.exe ADD 'HKLM\zNTUSER\Control Panel\UnsupportedHardwareNotificationCache' /v 'SV2' /t REG_DWORD /d '0' /f | Out-Null
reg.exe ADD 'HKLM\zSYSTEM\Setup\LabConfig' /v 'BypassCPUCheck' /t REG_DWORD /d '1' /f | Out-Null
reg.exe ADD 'HKLM\zSYSTEM\Setup\LabConfig' /v 'BypassRAMCheck' /t REG_DWORD /d '1' /f | Out-Null
reg.exe ADD 'HKLM\zSYSTEM\Setup\LabConfig' /v 'BypassSecureBootCheck' /t REG_DWORD /d '1' /f | Out-Null
reg.exe ADD 'HKLM\zSYSTEM\Setup\LabConfig' /v 'BypassStorageCheck' /t REG_DWORD /d '1' /f | Out-Null
reg.exe ADD 'HKLM\zSYSTEM\Setup\LabConfig' /v 'BypassTPMCheck' /t REG_DWORD /d '1' /f | Out-Null
reg.exe ADD 'HKLM\zSYSTEM\Setup\MoSetup' /v 'AllowUpgradesWithUnsupportedTPMOrCPU' /t REG_DWORD /d '1' /f | Out-Null
Write-Host -ForegroundColor Green 'SUCCESS'

# Disable Microsoft Teams
Write-Host -NoNewline 'Disabling Microsoft Teams...'
# ToDo: Acces denied to reg path
reg.exe ADD 'HKLM\zSOFTWARE\Microsoft\Windows\CurrentVersion\Communications' /v 'ConfigureChatAutoInstall' /t REG_DWORD /d '0' /f | Out-Null
Write-Host -ForegroundColor Green 'SUCCESS'

# Disable sponsored apps
Write-Host -NoNewline 'Disable sponsored apps...'
reg.exe ADD 'HKLM\zNTUSER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' /v 'OemPreInstalledAppsEnabled' /t REG_DWORD /d '0' /f | Out-Null
reg.exe ADD 'HKLM\zNTUSER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' /v 'PreInstalledAppsEnabled' /t REG_DWORD /d '0' /f | Out-Null
reg.exe ADD 'HKLM\zNTUSER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' /v 'SilentInstalledAppsEnabled' /t REG_DWORD /d '0' /f | Out-Null
reg.exe ADD 'HKLM\zSOFTWARE\Policies\Microsoft\Windows\CloudContent' /v 'DisableWindowsConsumerFeatures' /t REG_DWORD /d '1' /f | Out-Null
reg.exe ADD 'HKLM\zSOFTWARE\Microsoft\PolicyManager\current\device\Start' /v 'ConfigureStartPins' /t REG_SZ /d '{\"pinnedList\": [{}]}' /f | Out-Null
Write-Host -ForegroundColor Green 'SUCCESS'

# Enable local accounts on OOBE
Write-Host -NoNewline 'Enabling Local Accounts on OOBE...'
reg.exe ADD 'HKLM\zSOFTWARE\Microsoft\Windows\CurrentVersion\OOBE' /v 'BypassNRO' /t REG_DWORD /d '1' /f | Out-Null
Copy-Item -Path ( Join-Path -Path $PSScriptRoot -ChildPath 'autounattend.xml' ) -Destination ( Join-Path -Path $WorkingDirectory.scratch.FullName -ChildPath 'Windows\System32\Sysprep\autounattend.xml' ) -Force
Write-Host -ForegroundColor Green 'SUCCESS'

# Disable reserved storage
Write-Host -NoNewline 'Disabling reserved storage...'
reg.exe ADD 'HKLM\zSOFTWARE\Microsoft\Windows\CurrentVersion\ReserveManager' /v 'ShippedWithReserves' /t REG_DWORD /d '0' /f | Out-Null
Write-Host -ForegroundColor Green 'SUCCESS'

# Disable chat icon
Write-Host -NoNewline 'Disabling chat icon'
reg.exe ADD 'HKLM\zSOFTWARE\Policies\Microsoft\Windows\Windows Chat' /v 'ChatIcon' /t REG_DWORD /d '3' /f | Out-Null
reg.exe ADD 'HKLM\zNTUSER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced' /v 'TaskbarMn' /t REG_DWORD /d '0' /f | Out-Null
Write-Host -ForegroundColor Green 'SUCCESS'

# Unload registry
Write-Host -NoNewline 'Completed changes in registry. Unmounting registry...'
reg.exe UNLOAD HKLM\zCOMPONENTS | Out-Null
reg.exe UNLOAD HKLM\zDEFAULT | Out-Null
reg.exe UNLOAD HKLM\zNTUSER | Out-Null
reg.exe UNLOAD HKLM\zSOFTWARE | Out-Null
reg.exe UNLOAD HKLM\zSYSTEM | Out-Null
Write-Host -ForegroundColor Green 'SUCCESS'

# Cleanup
Write-Host -NoNewline 'Cleaning up image...'
Start-DismAction '/Cleanup-Image /StartComponentCleanup /ResetBase' -Break | Out-Null
Write-Host 'Unmounting Windows image...'
$ExitCode = Start-DismAction -NoImage "/unmount-image /mountdir:$( $WorkingDirectory.scratch.FullName ) /commit"
if ( 0 -ne $ExitCode ) {
    Write-Host -ForegroundColor Red 'ERROR'
    Start-DismAction -NoImage "/unmount-image /mountdir:$( $WorkingDirectory.scratch.FullName ) /discard" | Out-Null
    Start-Cleanup
    Throw "Dism.exe exited with error code $( $ExitCode ). Comitting image failed."
}
Write-Host -NoNewline 'Exporting Windows image...'
$ExitCode = Start-DismAction -NoImage "/Export-Image /SourceImageFile:$( Join-Path -Path $WorkingDirectory.tiny11.FullName -ChildPath 'sources\install.wim' ) /SourceIndex:$ImageIndex /DestinationImageFile:$( Join-Path -Path $WorkingDirectory.tiny11.FullName -ChildPath 'sources\install2.wim' ) /compress:max"
if ( 0 -ne $ExitCode ) {
    Write-Host -ForegroundColor Red 'ERROR'
    Start-Cleanup
    Throw "Dism.exe exited with error code $( $ExitCode )"
}
Remove-Item -LiteralPath ( Join-Path -Path $WorkingDirectory.tiny11.FullName -ChildPath 'sources\install.wim' ) -Force
Rename-Item -LiteralPath ( Join-Path -Path $WorkingDirectory.tiny11.FullName -ChildPath 'sources\install2.wim' ) -NewName 'install.wim' -Force
Write-Host 'Windows image completed. Continuing with boot.wim.'

# Boot image modifications
Write-Host ''
Write-Host -NoNewline 'Mounting boot image...'
Dism.exe /mount-image /imagefile:"$( Join-Path -Path $WorkingDirectory.FullName -ChildPath 'sources\boot.wim' )" /index:2 /mountdir:"$( $WorkingDirectory.scratch.FullName )"
if ( $LASTEXITCODE -ne 0 -and $LASTEXITCODE -ne -1052638937 ) {
    Write-Host -ForegroundColor Red 'ERROR'
    Start-Cleanup
    Throw "Dism.exe exited with error code $( $LASTEXITCODE )"
}
Write-Host -NoNewline 'Loading registry...'
# ToDo: Error handling
reg.exe LOAD HKLM\zCOMPONENTS "$( Join-Path -Path $WorkingDirectory.scratch.FullName -ChildPath 'Windows\System32\config\COMPONENTS' )" | Out-Null
reg.exe LOAD HKLM\zDEFAULT "$( Join-Path -Path $WorkingDirectory.scratch.FullName -ChildPath 'Windows\System32\config\default' )" | Out-Null
reg.exe LOAD HKLM\zNTUSER "$( Join-Path -Path $WorkingDirectory.scratch.FullName -ChildPath 'Users\Default\ntuser.dat' )" | Out-Null
reg.exe LOAD HKLM\zSOFTWARE "$( Join-Path -Path $WorkingDirectory.scratch.FullName -ChildPath 'Windows\System32\config\SOFTWARE' )" | Out-Null
reg.exe LOAD HKLM\zSYSTEM "$( Join-Path -Path $WorkingDirectory.scratch.FullName -ChildPath 'Windows\System32\config\SYSTEM' )" | Out-Null
Write-Host -ForegroundColor Green 'SUCCESS'
Write-Host -NoNewline 'Bypassing the images system requirements...'
reg.exe ADD 'HKLM\zDEFAULT\Control Panel\UnsupportedHardwareNotificationCache' /v 'SV1' /t REG_DWORD /d '0' /f | Out-Null
reg.exe ADD 'HKLM\zDEFAULT\Control Panel\UnsupportedHardwareNotificationCache' /v 'SV2' /t REG_DWORD /d '0' /f | Out-Null
reg.exe ADD 'HKLM\zNTUSER\Control Panel\UnsupportedHardwareNotificationCache' /v 'SV1' /t REG_DWORD /d '0' /f | Out-Null
reg.exe ADD 'HKLM\zNTUSER\Control Panel\UnsupportedHardwareNotificationCache' /v 'SV2' /t REG_DWORD /d '0' /f | Out-Null
reg.exe ADD 'HKLM\zSYSTEM\Setup\LabConfig' /v 'BypassCPUCheck' /t REG_DWORD /d '1' /f | Out-Null
reg.exe ADD 'HKLM\zSYSTEM\Setup\LabConfig' /v 'BypassRAMCheck' /t REG_DWORD /d '1' /f | Out-Null
reg.exe ADD 'HKLM\zSYSTEM\Setup\LabConfig' /v 'BypassSecureBootCheck' /t REG_DWORD /d '1' /f | Out-Null
reg.exe ADD 'HKLM\zSYSTEM\Setup\LabConfig' /v 'BypassStorageCheck' /t REG_DWORD /d '1' /f | Out-Null
reg.exe ADD 'HKLM\zSYSTEM\Setup\LabConfig' /v 'BypassTPMCheck' /t REG_DWORD /d '1' /f | Out-Null
reg.exe ADD 'HKLM\zSYSTEM\Setup\MoSetup' /v 'AllowUpgradesWithUnsupportedTPMOrCPU' /t REG_DWORD /d '1' /f | Out-Null
Write-Host -ForegroundColor Green 'SUCCESS'
Write-Host -NoNewline 'Completed changes in registry. Unmounting registry...'
reg.exe UNLOAD HKLM\zCOMPONENTS | Out-Null
reg.exe UNLOAD HKLM\zDEFAULT | Out-Null
reg.exe UNLOAD HKLM\zNTUSER | Out-Null
reg.exe UNLOAD HKLM\zSOFTWARE | Out-Null
reg.exe UNLOAD HKLM\zSYSTEM | Out-Null
Write-Host -ForegroundColor Green 'SUCCESS'
Write-Host -NoNewline 'Unmounting boot image...'
$ExitCode = Start-DismAction -NoImage "/unmount-image /mountdir:$( $WorkingDirectory.scratch.FullName ) /commit"
if ( 0 -ne $ExitCode ) {
    Write-Host -ForegroundColor Red 'ERROR'
    Start-DismAction -NoImage "/unmount-image /mountdir:$( $WorkingDirectory.scratch.FullName ) /discard" | Out-Null
    Start-Cleanup
    Throw "Dism.exe exited with error code $( $ExitCode ). Comitting image failed."
}
Write-Host 'Boot image completed.'

# Finish up
Write-Host ''
Write-Host 'The tiny11 image is now completed. Proceeding with the making of the ISO...'
Write-Host -NoNewline 'Copying unattended file for bypassing Microsoft account on OOBE...'
try {
    Copy-Item -Path ( Join-Path -Path $PSScriptRoot -ChildPath 'autounattend.xml' ) -Destination ( Join-Path -Path $WorkingDirectory.tiny11.FullName -ChildPath 'autounattend.xml' ) -Force -ErrorAction Stop
} catch {
    Write-Host -ForegroundColor Red 'ERROR'
    Start-Cleanup
    Throw $_
}
Write-Host -ForegroundColor Green 'SUCCESS'
Write-Host 'Creating ISO image...'
Start-Process -FilePath ( Join-Path -Path $PSScriptRoot -ChildPath 'oscdimg.exe' ) -ArgumentList "-m -o -u2 -udfver102 -bootdata:2#p0,e,b$( Join-Path -Path $WorkingDirectory.tiny11.FullName -ChildPath 'boot\etfsboot.com' )#pEF,e,b$( Join-Path -Path $WorkingDirectory.tiny11.FullName -ChildPath '\efi\microsoft\boot\efisys.bin' ) $( $WorkingDirectory.tiny11.FullName ) $( Join-Path -Path $PSScriptRoot -ChildPath 'tiny11.iso' )" -NoNewWindow -Wait
if ( 0 -ne $LASTEXITCODE ) {
    Write-Host -ForegroundColor Red 'ERROR'
    Start-Cleanup
    Throw "oscdimg.exe exited with error code $( $LASTEXITCODE )"
}
Write-Host -NoNewline 'Performing cleanup...'
Start-Cleanup
Write-Host -ForegroundColor Green 'SUCCESS'

Write-Host ''
Write-Host 'Creation completed! Check above messages and then press any key to exit the script...'
