#Requires -RunAsAdministrator
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


param (
    [CmdletBinding( DefaultParameterSetName = 'Interactive' )]
    # Path to ISO containing Windows 11 image
    [Parameter( ParameterSetName = 'Interactive', Mandatory = $true )]
    [Parameter( ParameterSetName = 'NonInteractive', Mandatory = $true )]
    [ValidateScript( { -not [string]::IsNullOrEmpty( $_ ) -and ( Test-Path -LiteralPath $_ ) } )]
    [string]
    $IsoPath,
    
    # Index or image name
    [Parameter( ParameterSetName = 'NonInteractive', Mandatory = $true )]
    [System.Object]
    $ImageIndex,
    
    # Name of create image file
    [Parameter( ParameterSetName = 'Interactive' )]
    [Parameter( ParameterSetName = 'NonInteractive')]
    [ValidateScript( { Test-Path -IsValid -LiteralPath $_ } )]
    [string]
    $ImagePath = '.\tiny11.iso',

    # All actions have to specified on the command line, no user interaction need
    [Parameter( ParameterSetName = 'NonInteractive', Mandatory = $true )]
    [switch]
    $NonInteractive,
    
    # Provisioned AppxPackages to remove
    [Parameter( ParameterSetName = 'NonInteractive')]
    [string[]]
    $ProvisionedAppxPackagesToRemove,
    
    # Packages to remove
    [Parameter( ParameterSetName = 'NonInteractive')]
    [string[]]
    $PackagesToRemove,
    
    # Wether to remove system requirements
    [Parameter( ParameterSetName = 'NonInteractive')]
    [switch]
    $RemoveSystemRequirements,
    
    # Wether to remove sponsored apps
    [Parameter( ParameterSetName = 'NonInteractive')]
    [switch]
    $RemoveSponsoredApps,
    
    # Wether to remove Edge
    [Parameter( ParameterSetName = 'NonInteractive')]
    [switch]
    $RemoveEdge,
    
    # Wether to remove OneDrive
    [Parameter( ParameterSetName = 'NonInteractive')]
    [switch]
    $RemoveOneDrive,
    
    # Wether to remove Microsoft Teams
    # [Parameter( ParameterSetName = 'NonInteractive')]
    # [switch]
    # $RemoveTeams,
    
    # Wether to remove chat icon in taskbar
    [Parameter( ParameterSetName = 'NonInteractive')]
    [switch]
    $RemoveChatIcon,
    
    # Wether to allow local account sign-up in OOBE
    [Parameter( ParameterSetName = 'NonInteractive')]
    [switch]
    $EnableLocalAccounts,
    
    # Wether to disable reserved space
    [Parameter( ParameterSetName = 'NonInteractive')]
    [switch]
    $DisableReservedStorage,
    
    # Hash value of ISO image
    [Parameter( ParameterSetName = 'NonInteractive')]
    [string]
    $CheckIsoHash = '',
    
    # Does not confirm file overrides with user
    [switch]
    $Force
)

<#
    VARIABLES
#>
$WorkingDirectory = @{
    'tiny11Path' = Join-Path -Path $env:TEMP -ChildPath 'tiny11'
    'scratchPath' = Join-Path -Path $env:TEMP -ChildPath 'tiny11.image'
}
$ScriptProgress = @{
    'WorkingDirectory'          = $false
    'ScratchDirectory'          = $false
    'IsoMount'                  = $false
    'IsoCopy'                   = $false
    'IsoIndex'                  = $false
    'IsoDismount'               = $false
    'DismInstallMount'          = $false
    'AppxPackageRemoval'        = $false
    'PackageRemoval'            = $false
    'EdgeRemoval'               = $false
    'OneDriveRemoval'           = $false
    'InstallRegistryMount'      = $false
    'SystemRequirementsInstall' = $false
    'Teams'                     = $false
    'SponsoredApps'             = $false
    'LocalAccounts'             = $false
    'ReservedStorage'           = $false
    'Chat'                      = $false
    'InstallRegistryDismount'   = $false
    'DismInstallDismount'       = $false
    'DismBootMount'             = $false
    'BootRegistryMount'         = $false
    'SystemRequirementsBoot'    = $false
    'BootRegistryDismount'      = $false
    'DismBootDismount'          = $false
    'IsoCreation'               = $false
}
$Choices = @(
    New-Object -TypeName 'System.Management.Automation.Host.ChoiceDescription' -ArgumentList '&Yes'
    New-Object -TypeName 'System.Management.Automation.Host.ChoiceDescription' -ArgumentList '&No'
)

<#
    SCRIPT
#>
# If set, check file hash of ISO
if ( -not [string]::IsNullOrEmpty( $CheckIsoHash ) ) {
    Write-Host -NoNewline 'Checking file hash...'
    if ( ( Get-FileHash -LiteralPath $IsoPath ).Hash -ne $CheckIsoHash ) {
        Write-Host -ForegroundColor Red 'ERROR'
        Throw 'File hash does not match!'
    }
    Write-Host -ForegroundColor Green 'SUCCESS'
}

# Prepare working directory
if ( Test-Path -LiteralPath $WorkingDirectory.tiny11Path ) {
    if ( -not $Force.IsPresent -or $NonInteractive.IsPresent -or 0 -ne $Host.UI.PromptForChoice( 'Overwrite directory?', "Working directory `"$( $WorkingDirectory.tiny11Path )`" already exists, continue anyway?`r`nData may be lost!", $Choices, 1 ) ) {
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
$ScriptProgress.WorkingDirectory = $true
# Prepare scratch directory
if ( Test-Path -LiteralPath $WorkingDirectory.scratchPath ) {
    if ( -not $Force.IsPresent -or $NonInteractive.IsPresent -or 0 -ne $Host.UI.PromptForChoice( 'Overwrite directory?', "Scratch directory `"$( $WorkingDirectory.scratchPath )`" already exists, continue anyway?`r`nData may be lost!", $Choices, 1 ) ) {
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
$WorkingDirectory.scratch = New-Item -ItemType Directory -Path $WorkingDirectory.scratchPath -Force
$ScriptProgress.ScratchDirectory = $true

# Welcome message
Write-Host ''
Write-Host 'Welcome to the'
Write-Host '   __  _            ________          _ __    __         '
Write-Host '  / /_(_)___  __  _<  <  / /_  __  __(_) /___/ /__  ____ '
Write-Host ' / __/ / __ \/ / / / // / __ \/ / / / / / __  / _ \/ ___/'
Write-Host '/ /_/ / / / / /_/ / // / /_/ / /_/ / / / /_/ /  __/ /    '
Write-Host '\__/_/_/ /_/\__, /_//_/_.___/\__,_/_/_/\__,_/\___/_/     '
Write-Host '           /____/                                        '

try {
    # Mount & check the iso
    Write-Host -NoNewline 'Mounting ISO...'
    try {
        $IsoRaw = Mount-DiskImage -ImagePath ( Resolve-Path -LiteralPath $IsoPath ).Path -StorageType ISO -Access ReadOnly -PassThru -ErrorAction Stop
    } catch {
        Throw $_
    }
    $ScriptProgress.IsoMount = $true
    $Iso = Get-Volume -DiskImage $IsoRaw
    'boot.wim', 'install.wim' | ForEach-Object {
        if ( -not ( Test-Path -LiteralPath ( Join-Path -Path $Iso.Path -ChildPath "sources\$( $_ )" ) ) ) {
            Throw [System.IO.FileNotFoundException]::new( "Cannot find Windows OS $( $_ ) in ISO" )
        }
    }
    Write-Host -ForegroundColor Green 'SUCCESS'

    # Create temporary directory and copy image
    Write-Host -NoNewline 'Copying Windows image...'
    $Output = New-TemporaryFile
    $Xcopy = Start-Process -FilePath 'xcopy.exe' -ArgumentList "/E /I /H /R /Y /J `"$( $Iso.DriveLetter ):`" `"$( $WorkingDirectory.tiny11.FullName )`"" -WindowStyle Hidden -RedirectStandardOutput $Output.FullName -Wait -PassThru
    if ( 0 -ne $Xcopy.ExitCode ) {
        Throw "xcopy.exe exited with error code $( $LASTEXITCODE )`r`n$( Get-Content -LiteralPath $Output.FullName -Raw )"
    }
    $ScriptProgress.IsoCopy = $true
    Write-Host -ForegroundColor Green 'SUCCESS'

    # Get image information
    Write-Host ''
    Write-Host 'Getting image index information...'
    $Skus = Get-WindowsImage -ImagePath ( Join-Path -Path $Iso.Path -ChildPath 'sources\install.wim' ) -ErrorAction Stop
    Write-Host -ForegroundColor Green 'SUCCESS'
    Write-Host ''
    foreach ( $Sku in $Skus ) {
        "$( $Sku.ImageIndex ): $( $Sku.ImageName )"
    }
    if ( -not $NonInteractive.IsPresent ) {
        # Ask user for index
        do {
            Write-Host ''
            $ImageIndex = Read-Host -Prompt 'Please enter the image index'
            $SelectedSku = $Skus | Where-Object -Property 'ImageIndex' -EQ -Value $ImageIndex
            if ( $SelectedSku -and $SelectedSku.Count -eq 1 ) {
                break
            }
            Write-Error "Given index $( $ImageIndex ) not found in image"
        } while ( $true )
    } else {
        # User has specified index in advance
        $SelectedSku = $Skus | Where-Object -Property 'ImageIndex' -EQ -Value $ImageIndex
        if ( -not $SelectedSku ) {
            Throw "Given index $( $ImageIndex ) not found in image"
        }
    }
    $ScriptProgress.IsoIndex = $true
    Write-Host "Selected image `"$( $SelectedSku.ImageName )`" (Index $( $SelectedSku.ImageIndex ))"

    # Unmount iso
    Write-Host -NoNewline 'Dismounting ISO...'
    try {
        $IsoRaw = $IsoRaw | Dismount-DiskImage -ErrorAction Stop
    } catch {
        Write-Host -ForegroundColor Red 'ERROR'
        Throw $_
    }
    $ScriptProgress.IsoDismount = $true
    Write-Host -ForegroundColor Green 'SUCCESS'
    
    # Mount Windows image
    Write-Host 'Mounting Windows image...'
    Mount-WindowsImage -ImagePath ( Join-Path -Path $WorkingDirectory.tiny11.FullName -ChildPath 'sources\install.wim' ) -Index $SelectedSku.ImageIndex -Path ( $WorkingDirectory.scratch.FullName ) -CheckIntegrity -Optimize -ErrorAction Stop | Out-Null
    $ScriptProgress.DismInstallMount = $true
    Write-Host -ForegroundColor Green 'SUCCESS'

    # Get provisioned applications
    Write-Host ''
    Write-Host 'Performing removal of applications...'
    $ProvisionedAppXPackages = Get-AppxProvisionedPackage -Path $WorkingDirectory.scratch.FullName -ErrorAction Stop

    # Remove applications
    if ( -not $NonInteractive.IsPresent ) {
        # Ask user to specify applications
        foreach ( $Package in $ProvisionedAppXPackages ) {
            if ( 0 -eq $Host.UI.PromptForChoice( "Remove $( $Package.DisplayName )?", "PackageName:`t$( $Package.PackageName )`r`nDisplayName:`t$( $Package.DisplayName )`r`nVersion:`t$( $Package.Version )", $Choices, 1 ) ) {
                Write-Host -NoNewline "Removing $( $Package.PackageName ) "
                try {
                    Remove-AppxProvisionedPackage -PackageName $Package.PackageName -Path $TemporaryMount -ErrorAction Stop | Out-Null
                    Write-Host -ForegroundColor Green 'SUCCESS'
                } catch {
                    Write-Host -ForegroundColor Red $_.ErrorDetails.Message
                }
            }
        }
    } else {
        # Remove specified applications
        foreach ( $Package in $ProvisionedAppxPackagesToRemove ) {
            $ProvisionedAppXPackages | Where-Object -Property 'DisplayName' -Like -Value "$( $Package )*" | ForEach-Object {
                Write-Host -NoNewline "Removing $( $_.PackageName ) "
                try {
                    Remove-AppxProvisionedPackage -PackageName $_.PackageName -Path $TemporaryMount -ErrorAction Stop | Out-Null
                    Write-Host -ForegroundColor Green 'SUCCESS'
                } catch {
                    Write-Host -ForegroundColor Red $_.ErrorDetails.Message
                }
            }
        }
    }
    $ScriptProgress.AppxPackageRemoval = $true
    Write-Host 'Removing of system apps complete!'

    # Get packages
    Write-Host ''
    Write-Host 'Performing removal of system packages...'
    $Packages = Get-WindowsPackage -Path $WorkingDirectory.scratch.FullName -ErrorAction Stop

    # Remove packages
    if ( -not $NonInteractive.IsPresent ) {
        # Ask user to specify applications
        foreach ( $Package in $Packages ) {
            $PackageInfo = $Package.PackageName -split '~'
            if ( 0 -eq $Host.UI.PromptForChoice( "Remove $( $PackageInfo[0] )?", "PackageName:`t$( $Package.PackageName )`r`nVersion:`t$( $PackageInfo[4] )", $Choices, 1 ) ) {
                Write-Host -NoNewline "Removing $( $Package.PackageName ) "
                try {
                    Remove-WindowsPackage -Path $WorkingDirectory.scratch.FullName -PackageName $Package.PackageName -ErrorAction Stop | Out-Null
                    Write-Host -ForegroundColor Green 'SUCCESS'
                } catch {
                    Write-Host -ForegroundColor Red 'ERROR'
                }
            }
        }
    } else {
        foreach ( $Package in $PackagesToRemove ) {
            $Packages | Where-Object -Property 'PackageName' -Like -Value "$( $Package )*" | ForEach-Object {
                Write-Host -NoNewline "Removing $( $_ ) "
                try {
                    Remove-WindowsPackage -Path $WorkingDirectory.scratch.FullName -PackageName $_.PackageName -ErrorAction Stop | Out-Null
                    Write-Host -ForegroundColor Green 'SUCCESS'
                } catch {
                    Write-Host -ForegroundColor Red $_.ErrorDetails.Message
                }
            }
        }
    }
    $ScriptProgress.PackageRemoval = $true

    if ( ( -not $NonInteractive.IsPresent -and 0 -eq $Host.UI.PromptForChoice( 'Remove Microsoft Edge?', 'Removes Microsoft Edge', $Choices, 1 ) ) -or $RemoveEdge ) {
        foreach ( $EdgePath in ( Join-Path -Path $WorkingDirectory.scratch.FullName -ChildPath 'Program Files (x86)\Microsoft\Edge*' -Resolve ) ) {
            try {
                $EdgePath = Get-Item -LiteralPath $EdgePath -Force
                Write-Host -NoNewline "Removing Microsoft $( $EdgePath.BaseName )..."
                $EdgePath | Remove-Item -Recurse -Force -ErrorAction Stop
                $ScriptProgress.EdgeRemoval = $true
                Write-Host -ForegroundColor Green 'SUCCESS'
            } catch {
                $ScriptProgress.EdgeRemoval = $false
                Write-Host -ForegroundColor Red 'ERROR'
                Write-Error $_
                break
            }
        }
    }

    if ( ( -not $NonInteractive.IsPresent -and 0 -eq $Host.UI.PromptForChoice( 'Remove Microsoft OneDrive?', 'Removes Microsoft OneDrive', $Choices, 1 ) ) -or $RemoveOneDrive ) {
        Write-Host -NoNewline 'Removing OneDrive...'
        $OneDrivePath = Join-Path -Path $WorkingDirectory.scratch.FullName -ChildPath 'Windows\System32\OneDriveSetup.exe'
        $Owner = New-Object -TypeName System.Security.Principal.SecurityIdentifier -ArgumentList 'S-1-5-32-544'
        $Acl = Get-Acl -LiteralPath $OneDrivePath
        $Acl.SetOwner( $Owner )
        $Acl = $Acl | Set-Acl -LiteralPath $OneDrivePath -Passthru
        $Acl.AddAccessRule( ( New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule -ArgumentList $Owner, 'FullControl', 'None', 'InheritOnly', 'Allow' ) )
        $Acl | Set-Acl -LiteralPath $OneDrivePath
        try {
            Remove-Item -LiteralPath $OneDrivePath -Force -ErrorAction Stop
        } catch {
            Write-Host -ForegroundColor Red 'ERROR'
            Write-Error $_
        }
        $ScriptProgress.OneDriveRemoval = $true
        Write-Host -ForegroundColor Green 'SUCCESS'
    }

    Write-Host 'Removal of system packages complete!'

    # Load registry
    if ( -not $NonInteractive.IsPresent -or ( $NonInteractive.IsPresent -and ( $RemoveSystemRequirements -or $RemoveTeams -or $RemoveSponsoredApps -or $EnableLocalAccounts -or $DisableReservedStorage -or $RemoveChatIcon ) ) ) {
        Write-Host ''
        Write-Host -NoNewline 'Loading registry...'
        reg.exe LOAD HKLM\zCOMPONENTS "$( Join-Path -Path $WorkingDirectory.scratch.FullName -ChildPath 'Windows\System32\config\COMPONENTS' )" | Out-Null
        reg.exe LOAD HKLM\zDEFAULT "$( Join-Path -Path $WorkingDirectory.scratch.FullName -ChildPath 'Windows\System32\config\default' )" | Out-Null
        reg.exe LOAD HKLM\zNTUSER "$( Join-Path -Path $WorkingDirectory.scratch.FullName -ChildPath 'Users\Default\ntuser.dat' )" | Out-Null
        reg.exe LOAD HKLM\zSOFTWARE "$( Join-Path -Path $WorkingDirectory.scratch.FullName -ChildPath 'Windows\System32\config\SOFTWARE' )" | Out-Null
        reg.exe LOAD HKLM\zSYSTEM "$( Join-Path -Path $WorkingDirectory.scratch.FullName -ChildPath 'Windows\System32\config\SYSTEM' )" | Out-Null
        $ScriptProgress.InstallRegistryMount = $true
        Write-Host -ForegroundColor Green 'SUCCESS'

        if ( ( -not $NonInteractive.IsPresent -and 0 -eq $Host.UI.PromptForChoice( 'Remove system requirements?', 'Removes system requirements', $Choices, 1 ) ) -or $RemoveSystemRequirements ) {
            # Bypass system requirements
            $RemoveSystemRequirements = $true
            Write-Host -NoNewline 'Bypassing the images system requirements...'
            # ToDo: Switch to PowerShell built-in methods (New-Item)
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
            $ScriptProgress.SystemRequirementsInstall = $true
            Write-Host -ForegroundColor Green 'SUCCESS'
        }

        <#
        if ( ( -not $NonInteractive.IsPresent -and 0 -eq $Host.UI.PromptForChoice( 'Remove Microsoft Teams?', 'Removes Microsoft Teams', $Choices, 1 ) ) -or $RemoveTeams ) {
            # Disable Microsoft Teams
            Write-Host -NoNewline 'Disabling Microsoft Teams...'
            # ToDo: Switch to PowerShell built-in methods (New-Item)
            $Owner = New-Object -TypeName System.Security.Principal.SecurityIdentifier -ArgumentList 'S-1-5-32-544'
            $Acl = Get-Acl -Path 'HKLM:\zSOFTWARE\Microsoft\Windows\CurrentVersion\Communications'
            $Acl.SetOwner( $Owner )
            $Acl = $Acl | Set-Acl -LiteralPath 'HKLM:\zSOFTWARE\Microsoft\Windows\CurrentVersion\Communications' -Passthru
            $Acl.AddAccessRule( ( New-Object -TypeName System.Security.AccessControl.RegistryAccessRule -ArgumentList $Owner, 'FullControl', 'ContainerInherit,ObjectInherit', 'InheritOnly', 'Allow' ) )
            $Acl | Set-Acl -Path 'HKLM:\zSOFTWARE\Microsoft\Windows\CurrentVersion\Communications'
            reg.exe ADD 'HKLM\zSOFTWARE\Microsoft\Windows\CurrentVersion\Communications' /v 'ConfigureChatAutoInstall' /t REG_DWORD /d '0' /f | Out-Null
            $ScriptProgress.Teams = $true
            Write-Host -ForegroundColor Green 'SUCCESS'
        }
        #>

        if ( ( -not $NonInteractive.IsPresent -and 0 -eq $Host.UI.PromptForChoice( 'Remove sponsored apps?', 'Removes sponsored / preinstalled apps', $Choices, 1 ) ) -or $RemoveSponsoredApps ) {
            # Disable sponsored apps
            Write-Host -NoNewline 'Disable sponsored apps...'
            # ToDo: Switch to PowerShell built-in methods (New-Item)
            reg.exe ADD 'HKLM\zNTUSER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' /v 'OemPreInstalledAppsEnabled' /t REG_DWORD /d '0' /f | Out-Null
            reg.exe ADD 'HKLM\zNTUSER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' /v 'PreInstalledAppsEnabled' /t REG_DWORD /d '0' /f | Out-Null
            reg.exe ADD 'HKLM\zNTUSER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' /v 'SilentInstalledAppsEnabled' /t REG_DWORD /d '0' /f | Out-Null
            reg.exe ADD 'HKLM\zSOFTWARE\Policies\Microsoft\Windows\CloudContent' /v 'DisableWindowsConsumerFeatures' /t REG_DWORD /d '1' /f | Out-Null
            reg.exe ADD 'HKLM\zSOFTWARE\Microsoft\PolicyManager\current\device\Start' /v 'ConfigureStartPins' /t REG_SZ /d '{\"pinnedList\": [{}]}' /f | Out-Null
            $ScriptProgress.SponsoredApps = $true
            Write-Host -ForegroundColor Green 'SUCCESS'
        }

        if ( ( -not $NonInteractive.IsPresent -and 0 -eq $Host.UI.PromptForChoice( 'Enable local accounts?', 'Enables local accounts for sign-in', $Choices, 1 ) ) -or $EnableLocalAccounts ) {
            # Enable local accounts on OOBE
            Write-Host -NoNewline 'Enabling Local Accounts on OOBE...'
            # ToDo: Switch to PowerShell built-in methods (New-Item)
            reg.exe ADD 'HKLM\zSOFTWARE\Microsoft\Windows\CurrentVersion\OOBE' /v 'BypassNRO' /t REG_DWORD /d '1' /f | Out-Null
            Copy-Item -Path ( Join-Path -Path $PSScriptRoot -ChildPath 'autounattend.xml' ) -Destination ( Join-Path -Path $WorkingDirectory.scratch.FullName -ChildPath 'Windows\System32\Sysprep\autounattend.xml' ) -Force
            $ScriptProgress.LocalAccounts = $true
            Write-Host -ForegroundColor Green 'SUCCESS'
        }

        if ( ( -not $NonInteractive.IsPresent -and 0 -eq $Host.UI.PromptForChoice( 'Disable reserved storage?', 'Disables reserved storage', $Choices, 1 ) ) -or $DisableReservedStorage ) {
            # Disable reserved storage
            Write-Host -NoNewline 'Disabling reserved storage...'
            # ToDo: Switch to PowerShell built-in methods (New-Item)
            reg.exe ADD 'HKLM\zSOFTWARE\Microsoft\Windows\CurrentVersion\ReserveManager' /v 'ShippedWithReserves' /t REG_DWORD /d '0' /f | Out-Null
            $ScriptProgress.ReservedStorage = $true
            Write-Host -ForegroundColor Green 'SUCCESS'
        }

        if ( ( -not $NonInteractive.IsPresent -and 0 -eq $Host.UI.PromptForChoice( 'Remove chat icon?', 'Removes chat icon from taskbar', $Choices, 1 ) ) -or $RemoveChatIcon ) {
            # Disable chat icon
            Write-Host -NoNewline 'Disabling chat icon...'
            # ToDo: Switch to PowerShell built-in methods (New-Item)
            reg.exe ADD 'HKLM\zSOFTWARE\Policies\Microsoft\Windows\Windows Chat' /v 'ChatIcon' /t REG_DWORD /d '3' /f | Out-Null
            reg.exe ADD 'HKLM\zNTUSER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced' /v 'TaskbarMn' /t REG_DWORD /d '0' /f | Out-Null
            $ScriptProgress.Chat = $true
            Write-Host -ForegroundColor Green 'SUCCESS'
        }

        # Unload registry
        Write-Host -NoNewline 'Completed changes in registry. Unmounting registry...'
        reg.exe UNLOAD HKLM\zCOMPONENTS | Out-Null
        reg.exe UNLOAD HKLM\zDEFAULT | Out-Null
        reg.exe UNLOAD HKLM\zNTUSER | Out-Null
        reg.exe UNLOAD HKLM\zSOFTWARE | Out-Null
        reg.exe UNLOAD HKLM\zSYSTEM | Out-Null
        $ScriptProgress.InstallRegistryDismount = $true
        Write-Host -ForegroundColor Green 'SUCCESS'
    }

    # Cleanup
    Write-Host -NoNewline 'Cleaning up image...'
    Repair-WindowsImage -Path $WorkingDirectory.scratch.FullName -StartComponentCleanup -ResetBase -ErrorAction Stop | Out-Null
    Write-Host -ForegroundColor Green 'SUCCESS'
    Write-Host -NoNewline 'Unmounting Windows image...'
    Dismount-WindowsImage -Path $WorkingDirectory.scratch.FullName -Save -CheckIntegrity -ErrorAction Stop | Out-Null
    $ScriptProgress.DismInstallDismount = $true
    Write-Host -ForegroundColor Green 'SUCCESS'
    Write-Host -NoNewline 'Exporting Windows image...'
    Export-WindowsImage -SourceImagePath ( Join-Path -Path $WorkingDirectory.tiny11.FullName -ChildPath 'sources\install.wim' ) -SourceIndex $SelectedSku.ImageIndex -DestinationImagePath ( Join-Path -Path $WorkingDirectory.tiny11.FullName -ChildPath 'sources\install2.wim' ) -CompressionType 'maximum' -ErrorAction Stop | Out-Null
    Write-Host -ForegroundColor Green 'SUCCESS'
    Remove-Item -LiteralPath ( Join-Path -Path $WorkingDirectory.tiny11.FullName -ChildPath 'sources\install.wim' ) -Force
    Rename-Item -LiteralPath ( Join-Path -Path $WorkingDirectory.tiny11.FullName -ChildPath 'sources\install2.wim' ) -NewName 'install.wim' -Force
    Write-Host 'Windows image completed. Continuing with boot.wim.'

    # Boot image modifications
    if ( $RemoveSystemRequirements ) {
        Write-Host ''
        Write-Host -NoNewline 'Mounting boot image. This may take a while...'
        Mount-WindowsImage -ImagePath ( Join-Path -Path $WorkingDirectory.tiny11.FullName -ChildPath 'sources\boot.wim' ) -Index 2 -Path ( $WorkingDirectory.scratch.FullName ) -CheckIntegrity -Optimize -ErrorAction Stop | Out-Null
        $ScriptProgress.DismBootMount = $true
        Write-Host -ForegroundColor Green 'SUCCESS'
        Write-Host -NoNewline 'Loading registry...'
        reg.exe LOAD HKLM\zCOMPONENTS "$( Join-Path -Path $WorkingDirectory.scratch.FullName -ChildPath 'Windows\System32\config\COMPONENTS' )" | Out-Null
        reg.exe LOAD HKLM\zDEFAULT "$( Join-Path -Path $WorkingDirectory.scratch.FullName -ChildPath 'Windows\System32\config\default' )" | Out-Null
        reg.exe LOAD HKLM\zNTUSER "$( Join-Path -Path $WorkingDirectory.scratch.FullName -ChildPath 'Users\Default\ntuser.dat' )" | Out-Null
        reg.exe LOAD HKLM\zSOFTWARE "$( Join-Path -Path $WorkingDirectory.scratch.FullName -ChildPath 'Windows\System32\config\SOFTWARE' )" | Out-Null
        reg.exe LOAD HKLM\zSYSTEM "$( Join-Path -Path $WorkingDirectory.scratch.FullName -ChildPath 'Windows\System32\config\SYSTEM' )" | Out-Null
        $ScriptProgress.BootRegistryMount = $true
        Write-Host -ForegroundColor Green 'SUCCESS'

        Write-Host -NoNewline 'Bypassing the images system requirements...'
        # ToDo: Switch to PowerShell built-in methods (New-Item)
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
        $ScriptProgress.SystemRequirementsBoot = $true
        Write-Host -ForegroundColor Green 'SUCCESS'
        Write-Host -NoNewline 'Completed changes in registry. Unmounting registry...'
        reg.exe UNLOAD HKLM\zCOMPONENTS | Out-Null
        reg.exe UNLOAD HKLM\zDEFAULT | Out-Null
        reg.exe UNLOAD HKLM\zNTUSER | Out-Null
        reg.exe UNLOAD HKLM\zSOFTWARE | Out-Null
        reg.exe UNLOAD HKLM\zSYSTEM | Out-Null
        $ScriptProgress.BootRegistryDismount = $true
        Write-Host -ForegroundColor Green 'SUCCESS'
        Write-Host -NoNewline 'Unmounting boot image...'
        Dismount-WindowsImage -Path $WorkingDirectory.scratch.FullName -Save -CheckIntegrity -ErrorAction Stop | Out-Null
        $ScriptProgress.DismBootDismount = $true
        Write-Host -ForegroundColor Green 'SUCCESS'
        Write-Host 'Boot image completed.'
    }

    # Finish up
    Write-Host ''
    Write-Host 'The tiny11 image is now completed. Proceeding with the making of the ISO.'
    Write-Host -NoNewline 'Copying unattend file for bypassing Microsoft account on OOBE...'
    Copy-Item -Path ( Join-Path -Path $PSScriptRoot -ChildPath 'autounattend.xml' ) -Destination ( Join-Path -Path $WorkingDirectory.tiny11.FullName -ChildPath 'autounattend.xml' ) -Force -ErrorAction Stop
    Write-Host -ForegroundColor Green 'SUCCESS'
    Write-Host 'Creating ISO image...'
    if ( -not $Force.IsPresent -and ( Test-Path -LiteralPath $ImagePath ) ) {
        if ( $NonInteractive.IsPresent -or 0 -ne $Host.UI.PromptForChoice( 'Overwrite image?', "ISO `"$( $ImagePath )`" already exists, override?`r`nData may be lost!", $Choices, 0 ) ) {
            Throw "ISO `"$( $ImagePath )`" already exists"
        }
    }
    Start-Process -FilePath ( Join-Path -Path $PSScriptRoot -ChildPath 'oscdimg.exe' ) -ArgumentList "-m -o -u2 -udfver102 -bootdata:2#p0,e,b$( Join-Path -Path $WorkingDirectory.tiny11.FullName -ChildPath 'boot\etfsboot.com' )#pEF,e,b$( Join-Path -Path $WorkingDirectory.tiny11.FullName -ChildPath '\efi\microsoft\boot\efisys.bin' ) $( $WorkingDirectory.tiny11.FullName ) $( $ImagePath )" -NoNewWindow -Wait
    if ( 0 -ne $LASTEXITCODE ) {
        Throw "oscdimg.exe exited with error code $( $LASTEXITCODE )"
    }
    $ScriptProgress.IsoCreation = $true
} catch {
    Write-Host -ForegroundColor Red 'ERROR'
    Throw $_
} finally {
    if ( $ScriptProgress.IsoCreation ) {
        Write-Host -NoNewline 'Performing cleanup...'
    }
    if ( $ScriptProgress.DismBootMount -and -not $ScriptProgress.DismBootDismount ) {
        if ( $ScriptProgress.BootRegistryMount -and -not $ScriptProgress.BootRegistryDismount ) {
            [System.GC]::Collect()
            [System.GC]::WaitForPendingFinalizers()
            reg.exe UNLOAD HKLM\zCOMPONENTS | Out-Null
            reg.exe UNLOAD HKLM\zDEFAULT | Out-Null
            reg.exe UNLOAD HKLM\zNTUSER | Out-Null
            reg.exe UNLOAD HKLM\zSOFTWARE | Out-Null
            reg.exe UNLOAD HKLM\zSYSTEM | Out-Null
        }
        Dismount-WindowsImage -Path $WorkingDirectory.scratch.FullName -Discard
    }
    if ( $ScriptProgress.DismInstallMount -and -not $ScriptProgress.DismInstallDismount ) {
        if ( $ScriptProgress.InstallRegistryMount -and -not $ScriptProgress.InstallRegistryDismount ) {
            [System.GC]::Collect()
            [System.GC]::WaitForPendingFinalizers()
            reg.exe UNLOAD HKLM\zCOMPONENTS | Out-Null
            reg.exe UNLOAD HKLM\zDEFAULT | Out-Null
            reg.exe UNLOAD HKLM\zNTUSER | Out-Null
            reg.exe UNLOAD HKLM\zSOFTWARE | Out-Null
            reg.exe UNLOAD HKLM\zSYSTEM | Out-Null
        }
        Dismount-WindowsImage -Path $WorkingDirectory.scratch.FullName -Discard
    }
if ( $ScriptProgress.IsoMount -and -not $ScriptProgress.IsoDismount ) {
        $IsoRaw = $IsoRaw | Dismount-DiskImage
    }
    if ( $ScriptProgress.ScratchDirectory ) {
        Remove-Item -LiteralPath $WorkingDirectory.scratchPath -Recurse -Force -ErrorAction SilentlyContinue
    }
    if ( $ScriptProgress.WorkingDirectory ) {
        Remove-Item -LiteralPath $WorkingDirectory.tiny11Path -Recurse -Force -ErrorAction SilentlyContinue
    }
    if ( $ScriptProgress.IsoCreation ) {
        Write-Host -ForegroundColor Green 'SUCCESS'
    }
}
