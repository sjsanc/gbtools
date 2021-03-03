. C:\Users\a-sscheepers\Documents\PowerShell\Modules\GBTools\GBToolsRepo.ps1

$VERSION = 1.1

function Invoke-Installer {
    param(
        [string] $machine,
        [string] $software
    )

    $localPath = "\\$machine\c$\temp\scriptinstaller.exe"
    $fullname = $repo[$software].name

    if (Test-Path $localPath) {
        Remove-Item $localPath
    }

    Copy-Item -Path $repo[$software].installer -Destination $localPath

    if (($software -eq "autohotkey") -or ($software -eq "notepad++") -or ($software -eq "filezilla")) {
        Invoke-Command -ComputerName $machine -ScriptBlock {
            cmd /c "C:\temp\scriptinstaller.exe /S" 
        } 
    }
    elseif (($software -eq "webex-ptools")) {
        Invoke-Command -ComputerName $machine -ScriptBlock {
            cmd /c "C:\temp\scriptinstaller.exe /quiet" 
        } 
    }
    else {
        Invoke-Command -ComputerName $machine -ScriptBlock {
            cmd /c "C:\temp\scriptinstaller.exe /verysilent" 
        } 
    }

    Start-Sleep 3

    if (Test-Path("\\" + $machine + $repo[$software].output)) {
        Remove-Item -Force $localPath
        Write-Host "[y] $fullname installed!" -ForegroundColor Green
    }
    else {
        Remove-Item -Force $localPath
        Write-Host "[x] $fullname was NOT installed..." -ForegroundColor Red
    }
}


function Install-GBSoftware {
        <#
        .SYNOPSIS
        Installs a specific package on a target remote machine. 

        .EXAMPLE
        PS> Install-GBSoftware -Machines GBUK-IT-0014 -Software mpc,apowersoft
    #>
    param(
        [Parameter(Mandatory = $true, ParameterSetName = "Software")]
        [Parameter(Mandatory = $true, ParameterSetName = "Batch")]
        [String[]] $Machines,
        [Parameter(Mandatory = $true, ParameterSetName = "Software")]
        [String[]] $Software,
        [Parameter(Mandatory = $true, ParameterSetName = "Batch")]
        [ValidateScript( {
                if ($batchlist.ContainsKey($_)) {
                    $True 
                }
                else {
                    # Show-GBSoftware -List batches
                    Throw "Incorrect batch name."
                }
            })]
        [string] $Batch
    )

    foreach ($machine in $Machines) {
        if (Test-Path("\\$machine\c$\")) {
            Write-Host ">> Attempting installation for $machine <<" -BackgroundColor White -ForegroundColor Black
            if ($Batch) {
                $Software = $batchlist[$Batch]
            }
            foreach ($item in $Software) {
                if ($repo.ContainsKey($item)) {
                    if (Test-Path("\\" + $machine + $repo[$item].output)) {
                        $name = $repo[$item].name
                        Write-Host "[~] $name is already installed on $machine"
                    }
                    else {
                        Invoke-Installer $machine $item
                    }
                }
                else {
                    Write-Host "[><] Error: unable to find installer for '$item'" -ForegroundColor Red
                }
            }
            Write-Host "<< Installation for $machine finished >>" -BackgroundColor White -ForegroundColor Black
        }
    }
}

function Remove-GBSoftware {
    param(
        [Parameter(Mandatory = $true)]
        [string] $Machine,
        [Parameter(Mandatory = $true)]
        [string] $Software
    )
    foreach ($item in $Software) {

        $script = {
            $p = Get-Process -Name "msiexec*"
            Stop-Process -InputObject $p
            $guid = "{90A58F28-D2E3-4AF5-AFE0-6AA7C04959A0}"
            cmd /c "msiexec.exe /x $guid /q"
        }

        if ($item -eq "autohotkey") {
            Write-Host "Cannot uninstall Autohotkey due to bad design."
        }
        else {
            Invoke-Command -ComputerName $Machine -ScriptBlock $script
        }
    }
    # WIP
}

function Test-GBSoftware {
    param(
        [Parameter(Mandatory = $true, ParameterSetName = "Software")]
        [Parameter(Mandatory = $true, ParameterSetName = "Batch")]
        [String[]] $Machines,
        [Parameter(Mandatory = $true, ParameterSetName = "Software")]
        [String[]] $Software,
        [Parameter(Mandatory = $true, ParameterSetName = "Batch")]
        [string] $Batch
    )

    foreach ($machine in $Machines) {
        if (Test-Path("\\$machine\c$\")) {
            if ($Batch) {
                $Software = $batchlist[$Batch]
                Write-Host "Testing with batch 'Strata'" -BackgroundColor White -ForegroundColor Black
            }
            foreach ($item in $Software) {
                $fullname = $repo[$item].name
                if (Test-Path("\\" + $machine + $repo[$item].output)) {
                    $i = $Software.indexOf($item) + 1
                    Write-Host "[$i] $fullname is installed on [$machine]" -ForegroundColor Green
                }
                else {
                    Write-Host "[-] $fullname is NOT installed on [$machine]"
                }   
            }
        }
        else {
            Write-Host "Error: could not find machine $machine. It could be offline, or the name malformed."
        }
    }
}
function Get-InstalledSoftware {
    <#
    .SYNOPSIS
        Retrieves a list of all software installed
    .EXAMPLE
        Get-InstalledSoftware
        
        This example retrieves all software installed on the local computer
    .PARAMETER Name
        The software title you'd like to limit the query to.
    #>
    [OutputType([System.Management.Automation.PSObject])]
    [CmdletBinding()]
    param (
        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]$Name
    )
 
    $UninstallKeys = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall", "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
    $null = New-PSDrive -Name HKU -PSProvider Registry -Root Registry::HKEY_USERS
    $UninstallKeys += Get-ChildItem HKU: -ErrorAction SilentlyContinue | Where-Object { $_.Name -match 'S-\d-\d+-(\d+-){1,14}\d+$' } | ForEach-Object { "HKU:\$($_.PSChildName)\Software\Microsoft\Windows\CurrentVersion\Uninstall" }
    if (-not $UninstallKeys) {
        Write-Verbose -Message 'No software registry keys found'
    }
    else {
        foreach ($UninstallKey in $UninstallKeys) {
            if ($PSBoundParameters.ContainsKey('Name')) {
                $WhereBlock = { ($_.PSChildName -match '^{[A-Z0-9]{8}-([A-Z0-9]{4}-){3}[A-Z0-9]{12}}$') -and ($_.GetValue('DisplayName') -like "$Name*") }
            }
            else {
                $WhereBlock = { ($_.PSChildName -match '^{[A-Z0-9]{8}-([A-Z0-9]{4}-){3}[A-Z0-9]{12}}$') -and ($_.GetValue('DisplayName')) }
            }
            $gciParams = @{
                Path        = $UninstallKey
                ErrorAction = 'SilentlyContinue'
            }
            $selectProperties = @(
                @{n = 'GUID'; e = { $_.PSChildName } }, 
                @{n = 'Name'; e = { $_.GetValue('DisplayName') } }
            )
            Get-ChildItem @gciParams | Where $WhereBlock | Select-Object -Property $selectProperties
        }
    }
}

# STILL WIP
function Convert-CCTV {
    param(
        [ValidateScript( {
                if (-Not ($_ | Test-Path)) {
                    Throw "File or folder does not exist."
                }
                if (-Not ($_ | Test-Path -PathType Container) ) {
                    Throw "Must specify a valid directory."
                }
                return $true
            })]
        [System.IO.FileInfo]$Directory = "C:\Users\sscheepers\Desktop\test\cctv",
        [string]$InputFileType,
        [string]$OutputFileType
    )

    $files = Get-ChildItem -Path $Directory -ErrorAction Continue -Filter *.$InputFileType
    foreach ($file in $files) {
            
        $i = $files.indexOf($file) + 1
        Write-Host $file
        Start-Process "C:\scripts\ffmpeg.exe" -ArgumentList "-i `"$file`" $i-converted.$OutputFileType" -Wait -NoNewWindow
    }
}

function Set-GBFolderAccess {
    param(
        [string]$Directory,
        [string[]]$Names,
        [string]$PermissionType,
        [switch]$Deny = $false,
        [switch]$Remove = $false
    )
    $Directory = $Directory.Replace("F:\", "\\emea\emeadata\GBE_PROD\UserData\MainSharedArea\")
    if ((Test-Path $Directory) -eq $false) {
        Throw "Could not find $Directory"
        return
    }

    Write-Host "Current Permissions for this folder:" -ForegroundColor Black -BackgroundColor White

    $acl = Get-Acl $Directory
    $acl | Format-Table -Wrap

    $Allow = "Allow"
    if ($Deny) {
        $Allow = "Deny"
    }

    foreach ($Name in $Names) {
        $AccessRuleArgs = "EMEA\$Name", "$PermissionType", "$Allow"
        $AccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule -ArgumentList $AccessRuleArgs
    
        if ($Remove) {
            $acl.RemoveAccessRule($AccessRule)
        }
        else {
            try {
                $acl.SetAccessRule($AccessRule)    
            }
            catch {
                Throw "Error: couldn't verify this username: $Name"
            }
        }

        try {
            Set-Acl -Path $Directory -AclObject $acl
        } 
        catch {
            Throw "Could not set permissions."
        }

    }

    Write-Host "Altered Permissions for this folder:" -ForegroundColor Black -BackgroundColor White
    Get-Acl $Directory | Format-Table -Wrap
}

function Duplicate-GBUser {
    param (
        [string[]]$NewUsers,
        [string]$OriginalUser
    )

    if($null -eq (Get-ADUser -Identity $OriginalUser)) {
        Throw "Error: couldn't find $OriginalUser"
    } else {
        $origin = Get-ADUser -Identity $OriginalUser -Properties memberof
        foreach ($user in $NewUsers) {
            $dest = Get-ADUser -Identity $user
            if(!$dest) {
                Write-Host "Warning: couldn't find $user"
            } else {
                $origin | Select-Object -ExpandProperty memberof | Add-ADGroupMember -Members $user
                Set-ADUser -Identity $user -HomeDrive H
                Set-ADUser -Identity $user -HomeDirectory "\\emea\emeadata\GBE_PROD\UserData\Home\$user"
            }
        }
    }   
}

function GBTools-PushUpdate {
    if($env:USERNAME -ne "a-sscheepers") {
        Write-Host "Only Steven can update GBTools, silly!"
    } else {
        try {
            Copy-Item C:\Users\a-sscheepers\Documents\PowerShell\Modules\GBTools \\GBEUKFILESERVER\Software$\Tools\GBTools\GBTools -Recurse -force
            Write-Host "GBTools update pushed to remote repo"
        } catch {
            Write-Error "Could not push to remote repo"
        }        
    }
}

function GBTools-Development {
    Invoke-Command -ScriptBlock {
        cmd /c "C:\Users\sscheepers\AppData\Local\Programs\Microsoft VS Code\Code.exe" "C:\Users\a-sscheepers\Documents\PowerShell\Modules\GBTools"
    }
}

Export-ModuleMember -Function Install-GBSoftware Test-GBSoftware Get-InstalledSoftware Set-GBFolderAccess 

