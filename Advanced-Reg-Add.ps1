$scriptBlock = {
    # Run as Admin
    if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Start-Process PowerShell.exe -Verb RunAs "-NoProfile -NoLogo -ExecutionPolicy Bypass -Command `"cd '$pwd'; & '$PSCommandPath';`"";
        exit;
    }

    $host.ui.RawUI.WindowTitle = 'RunAsTI - lean and mean snippet by AveYo, 2018-2023'
    <#
    [FEATURES]
    - innovative HKCU load, no need for reg load / unload ping-pong; programs get the user profile
    - sets ownership privileges, high priority, and explorer support; get System if TI unavailable
    - accepts special characters in paths for which default run as administrator fails
    - can copy-paste snippet directly in powershell console then use it manually
    [USAGE]
    - First copy-paste RunAsTI snippet before .ps1 script content
    - Then call it anywhere after to launch programs with arguments as TI
        RunAsTI regedit
        RunAsTI powershell '-noprofile -nologo -noexit -c [environment]::Commandline'
        RunAsTI cmd '/k "whoami /all & color e0"'
        RunAsTI "C:\System Volume Information"
    - Or just relaunch the script once if not already running as TI:
        if (((whoami /user)-split' ')[-1]-ne'S-1-5-18') {
        RunAsTI powershell "-f $($MyInvocation.MyCommand.Path) $($args[0]) $($args[1..99])"; return
        }
    2022.01.28: workaround for 11 release (22000) hindering explorer as TI
    #>

    #########################################################
    # copy-paste RunAsTI snippet before .ps1 script content #
    #########################################################

    function RunAsTI ($cmd,$arg) { $id='RunAsTI'; $key="Registry::HKU\$(((whoami /user)-split' ')[-1])\Volatile Environment"; $code=@'
    $I=[int32]; $M=$I.module.gettype("System.Runtime.Interop`Services.Mar`shal"); $P=$I.module.gettype("System.Int`Ptr"); $S=[string]
    $D=@(); $T=@(); $DM=[AppDomain]::CurrentDomain."DefineDynami`cAssembly"(1,1)."DefineDynami`cModule"(1); $Z=[uintptr]::size
    0..5|% {$D += $DM."Defin`eType"("AveYo_$_",1179913,[ValueType])}; $D += [uintptr]; 4..6|% {$D += $D[$_]."MakeByR`efType"()}
    $F='kernel','advapi','advapi', ($S,$S,$I,$I,$I,$I,$I,$S,$D[7],$D[8]), ([uintptr],$S,$I,$I,$D[9]),([uintptr],$S,$I,$I,[byte[]],$I)
    0..2|% {$9=$D[0]."DefinePInvok`eMethod"(('CreateProcess','RegOpenKeyEx','RegSetValueEx')[$_],$F[$_]+'32',8214,1,$S,$F[$_+3],1,4)}
    $DF=($P,$I,$P),($I,$I,$I,$I,$P,$D[1]),($I,$S,$S,$S,$I,$I,$I,$I,$I,$I,$I,$I,[int16],[int16],$P,$P,$P,$P),($D[3],$P),($P,$P,$I,$I)
    1..5|% {$k=$_; $n=1; $DF[$_-1]|% {$9=$D[$k]."Defin`eField"('f' + $n++, $_, 6)}}; 0..5|% {$T += $D[$_]."Creat`eType"()}
    0..5|% {nv "A$_" ([Activator]::CreateInstance($T[$_])) -fo}; function F ($1,$2) {$T[0]."G`etMethod"($1).invoke(0,$2)}
    $TI=(whoami /groups)-like'*1-16-16384*'; $As=0; if(!$cmd) {$cmd='control';$arg='admintools'}; if ($cmd-eq'This PC'){$cmd='file:'}
    if (!$TI) {'TrustedInstaller','lsass','winlogon'|% {if (!$As) {$9=sc.exe start $_; $As=@(get-process -name $_ -ea 0|% {$_})[0]}}
    function M ($1,$2,$3) {$M."G`etMethod"($1,[type[]]$2).invoke(0,$3)}; $H=@(); $Z,(4*$Z+16)|% {$H += M "AllocHG`lobal" $I $_}
    M "WriteInt`Ptr" ($P,$P) ($H[0],$As.Handle); $A1.f1=131072; $A1.f2=$Z; $A1.f3=$H[0]; $A2.f1=1; $A2.f2=1; $A2.f3=1; $A2.f4=1
    $A2.f6=$A1; $A3.f1=10*$Z+32; $A4.f1=$A3; $A4.f2=$H[1]; M "StructureTo`Ptr" ($D[2],$P,[boolean]) (($A2 -as $D[2]),$A4.f2,$false)
    $Run=@($null, "powershell -win 1 -nop -c iex `$env:R; # $id", 0, 0, 0, 0x0E080600, 0, $null, ($A4 -as $T[4]), ($A5 -as $T[5]))
    F 'CreateProcess' $Run; return}; $env:R=''; rp $key $id -force; $priv=[diagnostics.process]."GetM`ember"('SetPrivilege',42)[0]
    'SeSecurityPrivilege','SeTakeOwnershipPrivilege','SeBackupPrivilege','SeRestorePrivilege' |% {$priv.Invoke($null, @("$_",2))}
    $HKU=[uintptr][uint32]2147483651; $NT='S-1-5-18'; $reg=($HKU,$NT,8,2,($HKU -as $D[9])); F 'RegOpenKeyEx' $reg; $LNK=$reg[4]
    function L ($1,$2,$3) {sp 'HKLM:\Software\Classes\AppID\{CDCBCFCA-3CDC-436f-A4E2-0E02075250C2}' 'RunAs' $3 -force -ea 0
    $b=[Text.Encoding]::Unicode.GetBytes("\Registry\User\$1"); F 'RegSetValueEx' @($2,'SymbolicLinkValue',0,6,[byte[]]$b,$b.Length)}
    function Q {[int](gwmi win32_process -filter 'name="explorer.exe"'|?{$_.getownersid().sid-eq$NT}|select -last 1).ProcessId}
    $11bug=($((gwmi Win32_OperatingSystem).BuildNumber)-eq'22000')-AND(($cmd-eq'file:')-OR(test-path -lit $cmd -PathType Container))
    if ($11bug) {'System.Windows.Forms','Microsoft.VisualBasic' |% {[Reflection.Assembly]::LoadWithPartialName("'$_")}}
    if ($11bug) {$path='^(l)'+$($cmd -replace '([\+\^\%\~\(\)\[\]])','{$1}')+'{ENTER}'; $cmd='control.exe'; $arg='admintools'}
    L ($key-split'\\')[1] $LNK ''; $R=[diagnostics.process]::start($cmd,$arg); if ($R) {$R.PriorityClass='High'; $R.WaitForExit()}
    if ($11bug) {$w=0; do {if($w-gt40){break}; sleep -mi 250;$w++} until (Q); [Microsoft.VisualBasic.Interaction]::AppActivate($(Q))}
    if ($11bug) {[Windows.Forms.SendKeys]::SendWait($path)}; do {sleep 7} while(Q); L '.Default' $LNK 'Interactive User'
'@; $V='';'cmd','arg','id','key'|ForEach-Object{$V+="`n`$$_='$($(Get-Variable $_ -val)-replace"'","''")';"}; Set-ItemProperty $key $id $($V,$code) -type 7 -force -ea 0
    Start-Process powershell.exe -args "-win 1 -nop -c `n$V `$env:R=(gi `$key -ea 0).getvalue(`$id)-join''; iex `$env:R" -verb runas -Wait
    } # lean & mean snippet by AveYo, 2022.01.28

    #######################
    # .ps1 script content #
    #######################

    # Define Registry providers
    # Get-PSDrive -PSProvider Registry | Select-Object Name, Provider, Root
    New-PSDrive -PSProvider Registry -Root HKEY_CLASSES_ROOT -Name HKCR | Out-Null
    New-PSDrive -PSProvider Registry -Root HKEY_CURRENT_CONFIG -Name HKCC | Out-Null
    New-PSDrive -PSProvider Registry -Root HKEY_USERS -Name HKU | Out-Null

    function Test-RegistryName {
        param (
            [parameter(Mandatory=$true)][ValidateNotNullOrEmpty()]$Path,
            [parameter(Mandatory=$true)][ValidateNotNullOrEmpty()]$Name
        )

        try {
            $property = Get-ItemProperty -Path $Path -ErrorAction Stop
            if ($null -ne $property.PSObject.Properties[$Name]) {
                return $true
            } else {
                return $false
            }
        } catch {
            Write-Host "Error: Func Test-RegistryName"
        }
        return $false
    }

    if (((whoami /user)-split' ')[-1]-ne'S-1-5-18') {
    # Code to execute if not running as Local System
    # Run script as Local System User
    RunAsTI powershell "-f `"$($MyInvocation.MyCommand.Path)`" -NoProfile -NoLogo -WindowStyle Hidden -ExecutionPolicy Bypass"; return
    }

    function RegAdd {
        param(
            [Parameter(Mandatory = $true)]
            [string]$key,

            [Parameter(Mandatory = $false)]
            [string]$name,

            [Parameter(Mandatory = $false)]
            [string]$value,

            [Parameter(Mandatory = $false)]
            [ValidateSet("String", "ExpandString", "Binary", "DWord", "MultiString", "Qword")]
            [string]$type,

            [Parameter(Mandatory = $true)]
            [bool]$delete
        )

        if (((whoami /user)-split' ')[-1]-eq'S-1-5-18') {
            # Code to execute if running as Local System

            # System User
            Write-Host "User: $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)"
            Write-Host "SID: $([System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value)`n"

            $regKeyPsSyntax = "Registry::$key"

            if ($delete -and $name -eq '') {
                if (Test-Path $regKeyPsSyntax) {
                    try {
                        Write-Host "Removing - $key"
                        Remove-Item -Path $regKeyPsSyntax -Force -ErrorAction Stop
                        Write-Host "[SUCCEEDED] Removing $key"
                        return
                    } catch {
                        Write-Host "Error: Removing - $key"
                        return
                    }
                } else {
                    Write-Host "The registry key $key you want to delete does not exist."
                    return
                }
            } elseif ($delete -and $name -ne '') {
                if (Test-RegistryName -Path $regKeyPsSyntax -Name $name) {
                    try {
                        if ($name.ToLower() -eq "(Default)".ToLower()) {
                            Write-Host "Clearing - $name from $key"
                            Clear-ItemProperty -Path $regKeyPsSyntax -Name $name -Force -ErrorAction Stop
                            Write-Host "[SUCCEEDED] Clearing $name from $key"
                            return
                        } else {
                            Write-Host "Removing - $name from $key"
                            Remove-ItemProperty -Path $regKeyPsSyntax -Name $name -Force -ErrorAction Stop
                            Write-Host "[SUCCEEDED] Removing $name from $key"
                            return
                        }
                    } catch {
                        Write-Host "Error: Removing - $name from $key"
                        return
                    }
                } else {
                    Write-Host "The registry value $name from key $key you want to delete does not exist."
                    return
                }
            }

            # Check if the registry key exists and create if it doesn't
            if (-not(Test-Path $regKeyPsSyntax)) {
                try {
                    Write-Host "Creating the registry key - $key."
                    New-Item -Path $regKeyPsSyntax -Force -ErrorAction Stop | Out-Null
                    Write-Host "[SUCCEEDED] Creating the registry key $key"
                } catch {
                    Write-Host "Error: Creating registry key failed - $key"
                    Write-Host "[FAILED] Creating the registry key $key"
                    return
                }
            }

            if (Test-Path $regKeyPsSyntax) {
                if ($name -ne '' -and (Test-RegistryName -Path $regKeyPsSyntax -Name $name)) {
                    if ($name.ToLower() -eq "(Default)".ToLower()) {
                        try {
                            $propertyValue = (Get-ItemProperty -Path $regKeyPsSyntax -ErrorAction Stop).$name
                        } catch {
                            Write-Host "Error: failed to get propertyValue with name $name from key $key"
                        }
                    } else {
                        try {
                            $propertyValue = (Get-ItemProperty -Path $regKeyPsSyntax -Name $name -ErrorAction Stop).$name
                        } catch {
                            Write-Host "Error: failed to get propertyValue with name $name from key $key"
                        }
                    }

                    try {
                        $item = (Get-Item -Path $regKeyPsSyntax -ErrorAction Stop)
                        if ($name.ToLower() -eq "(Default)".ToLower()) {
                            try {
                                $propertyType = $item.GetValueKind('') 
                            } catch {
                                $propertyType = "String"
                            }
                        } else {
                            $propertyType = $item.GetValueKind($name)
                        }
                    } catch {
                        Write-Host "Error: failed to get item from $key"
                    }

                    if ($propertyValue.ToString().ToLower() -eq $value.ToString().ToLower()) {
                        if ($propertyType.ToString().ToLower() -eq $type.ToLower()) {
                            Write-Host "The registry key $key with name $name value $value and type $type already exists"
                            return
                        }
                    }
                }

                if ($name -ne '' -and $value -ne '' -and $type -ne '') {
                    $convertedType = [Microsoft.Win32.RegistryValueKind]::$type
                    if ($propertyValue -and $propertyType) {
                        Write-Host "Backup the registry name $name value $value and type $type"
                    } else {
                        Write-Host "Backup the registry name $name value $value and type $type"
                    }
                    try {
                        Write-Host "Adding $name to $key as $type with value $value."
                        Set-ItemProperty -Path $regKeyPsSyntax -Name $name -Value $value -Type $convertedType -Force -ErrorAction Stop
                        Write-Host "[SUCCEEDED] Adding $name to $key as $type with value $value"
                    } catch {
                        #$errorRecord = $_
                        Write-Host "Error: failed to add $name to $key as $type with value $value"
                        #Write-Host "Error Message: $($errorRecord.Exception.Message)"
                        #Write-Host "Error Category: $($errorRecord.CategoryInfo.Category)"
                        #Write-Host "Error ID: $($errorRecord.FullyQualifiedErrorId)"
                    }
                }
            }
        }
    }
}

# Run as Admin
if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Start-Process PowerShell.exe -Verb RunAs "-NoProfile -NoLogo -ExecutionPolicy Bypass -Command `"cd '$pwd'; & '$PSCommandPath';`"";
    exit;
}

$host.ui.RawUI.WindowTitle = 'RunAsTI - lean and mean snippet by AveYo, 2018-2023'
<#
  [FEATURES]
  - innovative HKCU load, no need for reg load / unload ping-pong; programs get the user profile
  - sets ownership privileges, high priority, and explorer support; get System if TI unavailable
  - accepts special characters in paths for which default run as administrator fails
  - can copy-paste snippet directly in powershell console then use it manually
  [USAGE]
  - First copy-paste RunAsTI snippet before .ps1 script content
  - Then call it anywhere after to launch programs with arguments as TI
    RunAsTI regedit
    RunAsTI powershell '-noprofile -nologo -noexit -c [environment]::Commandline'
    RunAsTI cmd '/k "whoami /all & color e0"'
    RunAsTI "C:\System Volume Information"
  - Or just relaunch the script once if not already running as TI:
    if (((whoami /user)-split' ')[-1]-ne'S-1-5-18') {
      RunAsTI powershell "-f $($MyInvocation.MyCommand.Path) $($args[0]) $($args[1..99])"; return
    }
  2022.01.28: workaround for 11 release (22000) hindering explorer as TI
#>

#########################################################
# copy-paste RunAsTI snippet before .ps1 script content #
#########################################################

function RunAsTI ($cmd,$arg) { $id='RunAsTI'; $key="Registry::HKU\$(((whoami /user)-split' ')[-1])\Volatile Environment"; $code=@'
 $I=[int32]; $M=$I.module.gettype("System.Runtime.Interop`Services.Mar`shal"); $P=$I.module.gettype("System.Int`Ptr"); $S=[string]
 $D=@(); $T=@(); $DM=[AppDomain]::CurrentDomain."DefineDynami`cAssembly"(1,1)."DefineDynami`cModule"(1); $Z=[uintptr]::size
 0..5|% {$D += $DM."Defin`eType"("AveYo_$_",1179913,[ValueType])}; $D += [uintptr]; 4..6|% {$D += $D[$_]."MakeByR`efType"()}
 $F='kernel','advapi','advapi', ($S,$S,$I,$I,$I,$I,$I,$S,$D[7],$D[8]), ([uintptr],$S,$I,$I,$D[9]),([uintptr],$S,$I,$I,[byte[]],$I)
 0..2|% {$9=$D[0]."DefinePInvok`eMethod"(('CreateProcess','RegOpenKeyEx','RegSetValueEx')[$_],$F[$_]+'32',8214,1,$S,$F[$_+3],1,4)}
 $DF=($P,$I,$P),($I,$I,$I,$I,$P,$D[1]),($I,$S,$S,$S,$I,$I,$I,$I,$I,$I,$I,$I,[int16],[int16],$P,$P,$P,$P),($D[3],$P),($P,$P,$I,$I)
 1..5|% {$k=$_; $n=1; $DF[$_-1]|% {$9=$D[$k]."Defin`eField"('f' + $n++, $_, 6)}}; 0..5|% {$T += $D[$_]."Creat`eType"()}
 0..5|% {nv "A$_" ([Activator]::CreateInstance($T[$_])) -fo}; function F ($1,$2) {$T[0]."G`etMethod"($1).invoke(0,$2)}
 $TI=(whoami /groups)-like'*1-16-16384*'; $As=0; if(!$cmd) {$cmd='control';$arg='admintools'}; if ($cmd-eq'This PC'){$cmd='file:'}
 if (!$TI) {'TrustedInstaller','lsass','winlogon'|% {if (!$As) {$9=sc.exe start $_; $As=@(get-process -name $_ -ea 0|% {$_})[0]}}
 function M ($1,$2,$3) {$M."G`etMethod"($1,[type[]]$2).invoke(0,$3)}; $H=@(); $Z,(4*$Z+16)|% {$H += M "AllocHG`lobal" $I $_}
 M "WriteInt`Ptr" ($P,$P) ($H[0],$As.Handle); $A1.f1=131072; $A1.f2=$Z; $A1.f3=$H[0]; $A2.f1=1; $A2.f2=1; $A2.f3=1; $A2.f4=1
 $A2.f6=$A1; $A3.f1=10*$Z+32; $A4.f1=$A3; $A4.f2=$H[1]; M "StructureTo`Ptr" ($D[2],$P,[boolean]) (($A2 -as $D[2]),$A4.f2,$false)
 $Run=@($null, "powershell -win 1 -nop -c iex `$env:R; # $id", 0, 0, 0, 0x0E080600, 0, $null, ($A4 -as $T[4]), ($A5 -as $T[5]))
 F 'CreateProcess' $Run; return}; $env:R=''; rp $key $id -force; $priv=[diagnostics.process]."GetM`ember"('SetPrivilege',42)[0]
 'SeSecurityPrivilege','SeTakeOwnershipPrivilege','SeBackupPrivilege','SeRestorePrivilege' |% {$priv.Invoke($null, @("$_",2))}
 $HKU=[uintptr][uint32]2147483651; $NT='S-1-5-18'; $reg=($HKU,$NT,8,2,($HKU -as $D[9])); F 'RegOpenKeyEx' $reg; $LNK=$reg[4]
 function L ($1,$2,$3) {sp 'HKLM:\Software\Classes\AppID\{CDCBCFCA-3CDC-436f-A4E2-0E02075250C2}' 'RunAs' $3 -force -ea 0
  $b=[Text.Encoding]::Unicode.GetBytes("\Registry\User\$1"); F 'RegSetValueEx' @($2,'SymbolicLinkValue',0,6,[byte[]]$b,$b.Length)}
 function Q {[int](gwmi win32_process -filter 'name="explorer.exe"'|?{$_.getownersid().sid-eq$NT}|select -last 1).ProcessId}
 $11bug=($((gwmi Win32_OperatingSystem).BuildNumber)-eq'22000')-AND(($cmd-eq'file:')-OR(test-path -lit $cmd -PathType Container))
 if ($11bug) {'System.Windows.Forms','Microsoft.VisualBasic' |% {[Reflection.Assembly]::LoadWithPartialName("'$_")}}
 if ($11bug) {$path='^(l)'+$($cmd -replace '([\+\^\%\~\(\)\[\]])','{$1}')+'{ENTER}'; $cmd='control.exe'; $arg='admintools'}
 L ($key-split'\\')[1] $LNK ''; $R=[diagnostics.process]::start($cmd,$arg); if ($R) {$R.PriorityClass='High'; $R.WaitForExit()}
 if ($11bug) {$w=0; do {if($w-gt40){break}; sleep -mi 250;$w++} until (Q); [Microsoft.VisualBasic.Interaction]::AppActivate($(Q))}
 if ($11bug) {[Windows.Forms.SendKeys]::SendWait($path)}; do {sleep 7} while(Q); L '.Default' $LNK 'Interactive User'
'@; $V='';'cmd','arg','id','key'|ForEach-Object{$V+="`n`$$_='$($(Get-Variable $_ -val)-replace"'","''")';"}; Set-ItemProperty $key $id $($V,$code) -type 7 -force -ea 0
 Start-Process powershell.exe -args "-win 1 -nop -c `n$V `$env:R=(gi `$key -ea 0).getvalue(`$id)-join''; iex `$env:R" -verb runas -Wait
} # lean & mean snippet by AveYo, 2022.01.28

#######################
# .ps1 script content #
#######################

# Define Registry providers
# Get-PSDrive -PSProvider Registry | Select-Object Name, Provider, Root
New-PSDrive -PSProvider Registry -Root HKEY_CLASSES_ROOT -Name HKCR | Out-Null
New-PSDrive -PSProvider Registry -Root HKEY_CURRENT_CONFIG -Name HKCC | Out-Null
New-PSDrive -PSProvider Registry -Root HKEY_USERS -Name HKU | Out-Null

function Replace-RegistryPath {
    param (
        [Parameter(Mandatory = $true)]
        [string]$registryPath
    )

    # Define a hashtable for root key replacements
    $rootKeyMap = @{
        "HKEY_CURRENT_USER"    = "HKCU"
        "HKEY_LOCAL_MACHINE"   = "HKLM"
        "HKEY_CLASSES_ROOT"    = "HKCR"
        "HKEY_CURRENT_CONFIG"  = "HKCC"
        "HKEY_USERS"           = "HKU"
    }

    # Replace long form names with abbreviated forms
    foreach ($key in $rootKeyMap.Keys) {
        if ($registryPath -like "$key\*") {
            $registryPath = $registryPath -replace [regex]::Escape($key), $rootKeyMap[$key]
            break
        }
    }

    # Replace backslashes with hyphens
    $registryPath = $registryPath -replace '\\', '-'
    $registryPath = $registryPath.Split([IO.Path]::GetInvalidFileNameChars()) -join '_'


    return $registryPath
}

function Test-RegistryName {
    param (
        [parameter(Mandatory=$true)][ValidateNotNullOrEmpty()]$Path,
        [parameter(Mandatory=$true)][ValidateNotNullOrEmpty()]$Name
    )

    try {
        $property = Get-ItemProperty -Path $Path -ErrorAction Stop
        if ($null -ne $property.PSObject.Properties[$Name]) {
            return $true
        } else {
            return $false
        }
    } catch {
          Write-Host "Error: Func Test-RegistryName"
    }
    return $false
}

function RandomString {
    # Use [System.IO.Path]::GetRandomFileName() to generate a random name
    $randomName = [System.IO.Path]::GetRandomFileName()

    # Truncate to the first 5 characters
    $folderName = $randomName.Substring(0, 5)

    return $folderName
}

function Write-Log {
    param (
        [string]$LogPath,
        [string]$Message
    )
    #$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    #$logEntry = "$timestamp - $Message"
    Add-Content -Path $LogPath -Value $Message
}

if (((whoami /user)-split' ')[-1]-ne'S-1-5-18') {
  # Code to execute if not running as Local System
  # Run script as Local System User
  RunAsTI powershell "-f `"$($MyInvocation.MyCommand.Path)`" -NoProfile -NoLogo -WindowStyle Hidden -ExecutionPolicy Bypass"; return
}

function RegAdd {
    param(
        [Parameter(Mandatory = $true)]
        [string]$key,

        [Parameter(Mandatory = $false)]
        [string]$name,

        [Parameter(Mandatory = $false)]
        [string]$value,

        [Parameter(Mandatory = $false)]
        [ValidateSet("String", "ExpandString", "Binary", "DWord", "MultiString", "Qword")]
        [string]$type,

        [Parameter(Mandatory = $true)]
        [bool]$delete
    )

    if (((whoami /user)-split' ')[-1]-eq'S-1-5-18') {
        # Code to execute if running as Local System

        # System User
        Write-Host "User: $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)"
        Write-Host "SID: $([System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value)`n"

        $regKeyPsSyntax = "Registry::$key"

        $dateTime = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"

        $logFolderBase = Join-Path -Path $PSScriptRoot -ChildPath "Logs"

        $logFolderDate = Join-Path -Path $logFolderBase -ChildPath $dateTime

        $logFile = Join-Path -Path $logFolderDate -ChildPath "Log.log"

        $backupFolderBase = Join-Path -Path $PSScriptRoot -ChildPath "Backups"

        $backupFolderDate = Join-Path -Path $backupFolderBase -ChildPath $dateTime

        # $backupFile = Join-Path -Path $backupFolderDate -ChildPath "Backup.ps1"
        $backupFileConvert = Replace-RegistryPath -registryPath $key
        if ($name -ne '') {
            $convertedBackupFile = $backupFileConvert + "_" + $name + ".ps1"
        } else {
            $randomString = RandomString
            $convertedBackupFile = $backupFileConvert + "_" + $randomString + ".ps1"
        }
        $backupFile = Join-Path -Path $backupFolderDate -ChildPath $convertedBackupFile

        if (-not(Test-Path -Path $logFolderDate)) {
            New-Item -ItemType Directory -Path $logFolderDate -Force | Out-Null
        }

        if (-not(Test-Path -Path $backupFolderDate)) {
            New-Item -ItemType Directory -Path $backupFolderDate -Force | Out-Null
        }

        if ($delete -and $name -eq '') {
            if (Test-Path $regKeyPsSyntax) {
                try {
                    Write-Host "Deleting - $key"
                    Remove-Item -Path $regKeyPsSyntax -Force -ErrorAction Stop
                    Write-Log -LogPath $logFile -Message "[SUCCEEDED] Deleted - $key"
                    return
                } catch {
                    Write-Host "ERROR: Deleting - $key"
                    Write-Log -LogPath $logFile -Message "[FAILED] Deleting - $key"
                    return
                }
            } else {
                Write-Host "The registry KEY $key that you want to delete does not exist"
                Write-Log -LogPath $logFile -Message "[INFO] The registry KEY $key that you want to delete does not exist"
                return
            }
        } elseif ($delete -and $name -ne '') {
            if (Test-RegistryName -Path $regKeyPsSyntax -Name $name) {
                try {
                    if ($name.ToLower() -eq "(Default)".ToLower()) {
                        try {
                            $propertyValue = (Get-ItemProperty -Path $regKeyPsSyntax -ErrorAction Stop).$name
                            $strValue = $propertyValue.ToString()
                        } catch {
                            Write-Host "ERROR: Failed to get propertyValue with NAME $name from KEY $key"
                        }
                        try {
                            $item = (Get-Item -Path $regKeyPsSyntax -ErrorAction Stop)
                                try {
                                    $propertyType = $item.GetValueKind('')
                                    $strType = $propertyType.ToString()
                                } catch {
                                    $propertyType = "String"
                                }
                        } catch {
                            Write-Host "ERROR: Failed to get the item from KEY $key"
                        }
                        if ($propertyValue -and $propertyType) {
                            Write-Host "Backup the registry NAME $name VALUE $strValue and TYPE $strType"
                            Write-Log -LogPath $backupFile -Message "$($scriptBlock.ToString())`n`nRegAdd -key `"$key`" -name `"$name`" -value `"$strValue`" -type `"$strType`" -delete `$false`n`npause`nexit"
                        }
                        $propertyValue = $null
                        $strValue = $null
                        $item = $null
                        $propertyType = $null
                        $strType = $null
                        Write-Host "Clearing - $name from $key"
                        Clear-ItemProperty -Path $regKeyPsSyntax -Name $name -Force -ErrorAction Stop
                        Write-Log -LogPath $logFile -Message "[SUCCEEDED] Cleared - $name from $key"
                        return
                    } else {
                        try {
                            $propertyValue = (Get-ItemProperty -Path $regKeyPsSyntax -Name $name -ErrorAction Stop).$name
                            $strValue = $propertyValue.ToString()
                        } catch {
                            Write-Host "ERROR: Failed to get propertyValue with NAME $name from KEY $key"
                        }
                        try {
                            $item = (Get-Item -Path $regKeyPsSyntax -ErrorAction Stop)
                            $propertyType = $item.GetValueKind($name)
                            $strType = $propertyType.ToString()
                        } catch {
                            Write-Host "ERROR: Failed to get item from KEY $key"
                        }
                        if ($null -ne $propertyValue -and $null -ne $propertyType) {
                            Write-Host "Backup the registry NAME $name VALUE $strValue and TYPE $strType"
                            Write-Log -LogPath $backupFile -Message "$($scriptBlock.ToString())`n`nRegAdd -key `"$key`" -name `"$name`" -value `"$strValue`" -type `"$strType`" -delete `$false`n`npause`nexit"
                        }
                        $propertyValue = $null
                        $strValue = $null
                        $item = $null
                        $propertyType = $null
                        $strType = $null
                        Write-Host "Deleting - $name from $key"
                        Remove-ItemProperty -Path $regKeyPsSyntax -Name $name -Force -ErrorAction Stop
                        Write-Log -LogPath $logFile -Message "[SUCCEEDED] Deleted - $name from $key"
                        return
                    }
                } catch {
                    Write-Host "ERROR: Deleting - NAME $name from KEY $key"
                    Write-Log -LogPath $logFile -Message "[FAILED] Deleting - $name from $key"
                    return
                }
            } else {
                Write-Host "The registry value NAME $name of key KEY $key that you want to delete does not exist."
                Write-Log -LogPath $logFile -Message "[INFO] The registry value $name of key $key that you want to delete does not exist"
                return
            }
        }

        # Check if the registry key exists and create if it doesn't
        if (-not(Test-Path $regKeyPsSyntax)) {
            try {
                Write-Host "Creating the registry KEY - $key."
                New-Item -Path $regKeyPsSyntax -Force -ErrorAction Stop | Out-Null
                Write-Log -LogPath $logFile -Message "[SUCCEEDED] Created - the registry key $key"
            } catch {
                Write-Host "ERROR: Creating - registry key failed - $key"
                Write-Log -LogPath $logFile -Message "[FAILED] Creating - the registry key $key"
                return
            }
        }

        if (Test-Path $regKeyPsSyntax) {
            if ($name -ne '' -and (Test-RegistryName -Path $regKeyPsSyntax -Name $name)) {
                if ($name.ToLower() -eq "(Default)".ToLower()) {
                    try {
                        $propertyValue = (Get-ItemProperty -Path $regKeyPsSyntax -ErrorAction Stop).$name
                    } catch {
                        Write-Host "ERROR: Failed to get the propertyValue with NAME $name from KEY $key"
                    }
                } else {
                    try {
                        $propertyValue = (Get-ItemProperty -Path $regKeyPsSyntax -Name $name -ErrorAction Stop).$name
                    } catch {
                        Write-Host "ERROR: Failed to get the propertyValue with NAME $name from KEY $key"
                    }
                }

                try {
                    $item = (Get-Item -Path $regKeyPsSyntax -ErrorAction Stop)
                    if ($name.ToLower() -eq "(Default)".ToLower()) {
                        try {
                            $propertyType = $item.GetValueKind('') 
                        } catch {
                            $propertyType = "String"
                        }
                    } else {
                        $propertyType = $item.GetValueKind($name)
                    }
                } catch {
                    Write-Host "ERROR: Failed to get the item from KEY $key"
                }

                if ($propertyValue.ToString().ToLower() -eq $value.ToString().ToLower()) {
                    if ($propertyType.ToString().ToLower() -eq $type.ToLower()) {
                        Write-Host "The registry KEY $key with NAME $name VALUE $value and TYPE $type already exists"
                        Write-Log -LogPath $logFile -Message "[INFO] The registry KEY $key with NAME $name VALUE $value and TYPE $type already exists"
                        return
                    }
                }
                
                $strValue = $propertyValue.ToString()
                $strType = $propertyType.ToString()
            }

            if ($name -ne '' -and $value -ne '' -and $type -ne '') {
                $convertedType = [Microsoft.Win32.RegistryValueKind]::$type
                if ($propertyValue -and $propertyType) {
                    Write-Host "Backup the registry NAME $name VALUE $strValue and TYPE $strType"
                    Write-Log -LogPath $backupFile -Message "$($scriptBlock.ToString())`n`nRegAdd -key `"$key`" -name `"$name`" -value `"$strValue`" -type `"$strType`" -delete `$false`n`npause`nexit"
                } else {
                    Write-Host "Backup the registry NAME $name"
                    Write-Log -LogPath $backupFile -Message "$($scriptBlock.ToString())`n`nRegAdd -key `"$key`" -name `"$name`" -delete `$true`n`npause`nexit"
                }
                try {
                    Write-Host "Adding $name to $key as $type with value $value."
                    Set-ItemProperty -Path $regKeyPsSyntax -Name $name -Value $value -Type $convertedType -Force -ErrorAction Stop
                    Write-Log -LogPath $logFile -Message "[SUCCEEDED] Added - $name to $key as $type with value $value"
                } catch {
                    #$errorRecord = $_
                    Write-Host "ERROR: Failed to add $name to $key as $type with value $value"
                    Write-Log -LogPath $logFile -Message "[FAILED] Adding - $name to $key as $type with value $value"
                    #Write-Host "Error Message: $($errorRecord.Exception.Message)"
                    #Write-Host "Error Category: $($errorRecord.CategoryInfo.Category)"
                    #Write-Host "Error ID: $($errorRecord.FullyQualifiedErrorId)"
                }
            }
        }
    }
}

#EXAMPLES

# Deleting Registry Key
#RegAdd -key "HKEY_LOCAL_MACHINE\SOFTWARE\myTestKey" -delete $true

# Deleting Registry Name
#RegAdd -key "HKEY_LOCAL_MACHINE\SOFTWARE\myTestKey" -name "myTestName" -delete $true

# Reg Add
#RegAdd -key "HKEY_LOCAL_MACHINE\SOFTWARE\myTestKey" -name "myTestName" -value "myTestString" -type "String" -delete $false

# Reg Add (Default) Name
#RegAdd -key "HKEY_LOCAL_MACHINE\SOFTWARE\myTestKey" -name "(Default)" -value "myTestStringDefaultName" -type "String" -delete $false

# Reg Add Multistring with newline
# RegAdd -key "HKEY_LOCAL_MACHINE\SOFTWARE\myTestKey" -name "myTestName" -value "myTestString`r`nmyTestStringNewLine" -type "MultiString" -delete $false

# Administrator can not access and modify this windows default key - but the script can :D
#RegAdd -key "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\NetworkSetup2" -name "myTestName" -value "myTestString" -type "String" -delete $false

# Administrator can access but not modify this windows default key - but the script can :D
#RegAdd -key "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes" -name "myTestName" -value "myTestString" -type "String" -delete $false

pause
exit
