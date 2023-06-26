<#
.SYNOPSIS
This script is designed to keep systems at peak performance, while minimising the impact on helpdesk.
Automatically test and resolve issues where possible. 
Flag potential future issues to helpdesk before the user generates a ticket.

.DESCRIPTION
This script is designed to run without user interaction. 
Schedule the script to run at regular intervals to ensure the system is running at peak performance.

.NOTES
Author: Christopher McDonald
Version: 0.1.3
Date: 26/06/2023

#>

# PS7
if (!(Get-PoshInstallation)) {
Install-Posh
} 

# Global
$errorCache = @()
if ($env:COMPUTERNAME) {
    $global:computerName = $env:COMPUTERNAME
}
elseif ($HOSTNAME) {
    $global:computerName = $HOSTNAME
}
$global:date = Get-Date
if ($env:USERNAME) {
    $global:user = $env:USERNAME
}
elseif ($USER) {
    $global:user = $USER
}
$global:domain = "domain.net"
$global:wifiInt = Get-NetAdapter | Where-Object { $_.Name -match 'WiFi' }
$global:ethInt = Get-NetAdapter | Where-Object { $_.Name -match 'Ethernet' }
$global:NetAdapter = Get-NetIPConfiguration -Detailed | Select-Object InterfaceAlias, @{Name="DHCP";Expression={$_.NetIPv4Interface.DHCP}}
$global:SerialNumber = Get-CimInstance Win32_BIOS | Select-Object -ExpandProperty SerialNumber
$global:DNS = Get-DnsClientServerAddress -AddressFamily IPv4 | Select-Object ServerAddresses
$global:DNS1 = '9.9.9.11' 
$global:DNS2 = '142.112.112.11'
$global:uptime = Get-Uptime
$global:drivers = Get-WindowsDriver -Online -All | Select-Object 'Driver', 'Date', 'Version'
$global:LastPoint = Get-ComputerRestorePoint -LastStatus   
$global:pro = Get-CimInstance -ClassName Win32_Processor | Select-Object -ExpandProperty Name
$global:mem = Get-CimInstance -ClassName Win32_OperatingSystem | Select-Object -ExpandProperty FreePhysicalMemory | ForEach-Object { $_ / 1MB }
$global:description = Get-CimInstance -ClassName Win32_OperatingSystem | Select-Object Description
$global:tag = Get-CimInstance -Class Win32_SystemEnclosure | Select-Object -ExpandProperty SMBIOSAssetTag
$global:DiskSpace = Get-CimInstance -Class Win32_logicalDisk | Where-Object {$_.DeviceID -eq 'C:'} | Select-Object Size, FreeSpace
$global:FreeSpace = $DiskSpace.FreeSpace / $DiskSpace.Size * 100
$global:temp = Get-CimInstance -Namespace root\wmi -Class MSAcpi_ThermalZoneTemperature -ComputerName $computerName | Select-Object -ExpandProperty CurrentTemperature
$global:lock = Get-BitLockerVolume -MountPoint "C:" |  Select-Object volumetype, protectionstatus -Verbose
$global:AV = Get-MpComputerStatus | Select-Object 'AMServiceEnabled', 'AntispywareEnabled', 'AntivirusEnabled'
$global:acls = Get-Acl -Path C:\ | Select-Object 'AccessToString'
$global:secboot = Confirm-SecureBootUefi
$global:DefaultGateway = (Get-NetRoute | Where-Object {$_.DestinationPrefix -eq '0.0.0.0/0' -and $_.NextHop -ne '::'}).NextHop
$global:Ping = Test-Connection $DefaultGateway -Count 1
$global:battery = Get-CimInstance -ClassName CIM_Battery | Select-Object 'Status'
$global:GetIP = (Get-NetIPConfiguration) | Select-Object IPv4DefaultGateway
$global:NextHop = ($GetIP.IPv4DefaultGateway)
$global:socket = (new-object System.Net.Sockets.TcpClient($NextHop.NextHop, $port))
$global:LogDate = (get-date) - (New-TimeSpan -Day 1)
$global:powerEventIDs = @(12, 41)
$global:logs = get-winevent | Where-Object {$_.LevelDisplayName -eq $LogDate, 'Critical, Warning', $powerEventIDs} | Select-Object -ExpandProperty Message
$global:GetPorts = get-nettcpconnection | Select-Object LocalPort
$global:Ports = ($GetPorts.LocalPort)
$global:emailAddress = "helpdesk.net"
$global:deliveryProblems = Get-DeliveryProblems -EmailAddress $emailAddress


# Functions
function Cache-Error {
    param (
        [Parameter(Mandatory=$true, Position=0)]
        [System.Management.Automation.ErrorRecord]$ErrorRecord
    )

    # Add the error to the cache
    $errorCache += $ErrorRecord
}


#function Verb-Noun {
#    [CmdletBinding()]
#    Param (
#        [Parameter(Mandatory=$true, Position=)]
#        [string]$PascalCase
#    )
#
#    Process {
#        try {
#            #Write code
#        } catch {
#                 Cache-Error -ErrorRecord $_
#        }
#    }
#}


function Create-RestorePoint {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$true, Position=1)]
        [string]$createRestorePoint
    )

    Process {
        try {
            Checkpoint-Computer -Description $date -RestorePointType MODIFY_SETTINGS
        } catch {
                 Cache-Error -ErrorRecord $_
        }
    }
}


function Get-PowerLogs {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$true)]
        [string]$getPowerLogs
    )

    Process {
        try {
            $powerEvents = Get-WinEvent -ComputerName $computerName -LogName 'System' -MaxEvents 100 |
            Where-Object { $_.ProviderName -eq 'Microsoft-Windows-Kernel-Power' }
            $surgeEvents = $powerEvents |
            Where-Object { $_.Id -eq 41 -or $_.Id -eq 109 }
        } catch {
                 Cache-Error -ErrorRecord $_
        }
    }
}


function Get-PoshInstallation {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$true)]
        [string]$getPoshInstallation
    )

    Process {
        try {
            $psVersionTable = $PSVersionTable.PSVersion
            $majorVersion = $psVersionTable.Major
            if ($majorVersion -eq 7) {
                return $true
                     } else {
                     return $false
}
        } catch {
                 Cache-Error -ErrorRecord $_
        }


function Install-Posh {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$true)]
        [string]$installPosh
    )

    Process {
        try {
            $url = "https://aka.ms/powershell7-windows"
            $installerPath = "$env:TEMP\PowerShell7.msi"

            # Download PowerShell 7 installer
            Invoke-WebRequest -Uri $url -OutFile $installerPath

            # Quiet Install PowerShell 7
            Start-Process -Wait -FilePath msiexec -ArgumentList "/i $installerPath /quiet"

            # Clean up installer file
            Remove-Item $installerPath -Force
        } catch {
                 Cache-Error -ErrorRecord $_
        }
    }
}


function Create-SnapShot {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$true)]
        [string]$createSnapShot
    )

    Process {
        try {
            $shadowCopy = (Get-WmiObject -List Win32_ShadowCopy).Create("C:\", "ClientAccessible")
        } catch {
                 Cache-Error -ErrorRecord $_
        }
    }
}


function Get-FanStatus {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$true)]
        [string]$getFanStats
    )

    Process {
        try {
            $fanInstances = Get-WmiObject -Class Win32_Fan -ComputerName $computerName
            foreach ($fan in $fanInstances) {
            $fanStatus = $fan.Status
            $fanName = $fan.Name
     }
        } catch {
                 Cache-Error -ErrorRecord $_
        }
    }
}


function Run-PowerCfg {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$true)]
        [string]$runPowerCfg
    )

    Process {
        try {
            powercfg /SETDCVALUEINDEX SCHEME_CURRENT 19cbb8fa-5279-450e-9fac-8a3d5fedd0c1 12bbebe6-58d6-4636-95bb-3217ef867c1a 0 | powercfg /SETACVALUEINDEX SCHEME_CURRENT 19cbb8fa-5279-450e-9fac-8a3d5fedd0c1 12bbebe6-58d6-4636-95bb-3217ef867c1a 0 | powercfg /change monitor-timeout-ac 0 | powercfg /change monitor-timeout-dc 0 | powercfg /change disk-timeout-ac 0 | powercfg /change disk-timeout-dc 0 | powercfg /change standby-timeout-ac 0 | powercfg /change standby-timeout-dc 0
        } catch {
                 Cache-Error -ErrorRecord $_
        }
    }
}


function Run-SFC {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$true)]
        [string]$runSFC
    )

    Process {
        try {
            sfc /scannow
        } catch {
                 Cache-Error -ErrorRecord $_
        }
    }
}


function Run-DISM {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$true)]
        [string]$runDISM
    )

    Process {
        try {
            Repair-WindowsImage -Online -RestoreHealth
        } catch {
                 Cache-Error -ErrorRecord $_
        }
    }
}


function Run-Chkdsk {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$true)]
        [string]$runChkdsk
    )

    Process {
        try {
            Repair-Volume -DriveLetter C -Scan -OfflineScanAndFix
        } catch {
                 Cache-Error -ErrorRecord $_
        }
    }
}


function Fix-HardwareFailure {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$true)]
        [string]$fixHardwareFailure
    )

    Process {
        try {
            $hardwareFailures = Get-CimInstance -ClassName CIM_LogicalDevice -Filter 'Status="Error"'
            foreach ($failure in $hardwareFailures) {
            $service = Get-Service | Where-Object {$_.Name -eq $failure.DeviceID} 
            if ($service) {
            Restart-Service -Name $service.Name}
     } 
        } catch {
                 Cache-Error -ErrorRecord $_
        }
    }
}


function Fix-Compatibility {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$true)]
        [string]$fixCompatibility
    )

    Process {
        try {
            $compatibilityIssues = Get-WindowsCompatibility -ScanPath "C:\Path\To\Software"
            foreach ($issue in $compatibilityIssues) {
             Resolve-WindowsCompatibility -Path $issue.Path -Issue $issue.Issue}
        } catch {
                 Cache-Error -ErrorRecord $_
        }
    }
}


function Fix-PnP {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$true)]
        [string]$fixPnP
    )

    Process {
        try {
            $devices = Get-PnpDevice | Where-Object {$_.Class -eq "Human Interface Device" -or $_.Class -eq "Keyboard" -or $_.Class -eq "Mouse"}
            $deviceId = $devices.InstanceId
            foreach ($device in $devices) {
            Disable-PnpDevice -InstanceId $deviceId -Confirm:$false
            Wait 5
            Enable-PnpDevice -InstanceId $deviceId -Confirm:$false}
        } catch {
                 Cache-Error -ErrorRecord $_
        }
    }
}

function Set-ActiveHours {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$true)]
        [string]$setActiveHours
    )

    Process {
        try {
            $start = '9' # Set start time for Active Hours
            $finish = '9' # Set finish time for Active Hours
            $HoursStart = Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings -Name ActiveHoursStart
            $HoursEnd = Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings -Name ActiveHoursEnd
            New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings -Name ActiveHoursStart -Value $start -PassThru | New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings -Name ActiveHoursEnd -Value $finish -PassThru
        } catch {
                 Cache-Error -ErrorRecord $_
        }
    }
}


function Optimise-System {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$true)]
        [string]$optimiseSystem
    )

    Process {
        try {
            Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management' -Name 'ClearPageFileAtShutdown' -Value 0 | Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management' -Name 'DisablePagingExecutive' -Value 1 | Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy' -Name '01' -Value 1
        } catch {
                 Cache-Error -ErrorRecord $_
        }
    }
}


function Fix-OfficeActivation {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$true)]
        [string]$fixOfficeActivation
    )

    Process {
        try {
            Remove-Item HKLM:SOFTWARE\Microsoft\Office\10.0, HKLM:SOFTWARE\Microsoft\Office\12.0, HKLM:SOFTWARE\Microsoft\Office\15.0, HKLM:SOFTWARE\Microsoft\Office\16.0 -Confirm:$false -Force
        } catch {
                 Cache-Error -ErrorRecord $_
        }
    }
}


function Fix-BrokenShortcuts {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$true)]
        [string]$fixBrokenShortcuts
    )

    Process {
        try {
            Get-ChildItem -Path C:\ -Include *.lnk -Recurse -File | ForEach-Object {
            (New-Object -ComObject WScript.Shell).CreateShortcut($_.FullName).Save()}
        } catch {
                 Cache-Error -ErrorRecord $_
        }
    }
}


function Fix-Audio {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$true)]
        [string]$fixAudio
    )

    Process {
        try {
            $audioDevices = Get-WmiObject Win32_SoundDevice | Where-Object { $_.Status -eq 'BAD' }
            Restart-Service -Name 'Audiosrv' -Force
        } catch {
                 Cache-Error -ErrorRecord $_
        }
    }
}


function Restart-NetworkAdapter {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$true)]
        [string]$restartNetworkAdapter
    )

    Process {
        try {
            Restart-NetAdapter -Name $global:NetAdapter
        } catch {
                 Cache-Error -ErrorRecord $_
        }
    }
}


function Test-Domain {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$true)]
        [string]$testDomain
    )

    Process {
        try {
            $TestDomain = Test-ComputerSecureChannel -Server 'domain.net\DC01'
            Test-ComputerSecureChannel -Repair
            $DomainChecker = Get-CimInstance -ClassName Win32_ComputerSystem | Select-Object domain
            Add-Computer -DomainName $domain -Server 'domain.net\DC01'
        } catch {
                 Cache-Error -ErrorRecord $_
        }
    }
}


function Test-MappedDrives {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$true)]
        [string]$testMappedDrives
    )

    Process {
        try {
            Get-PSDrive -PSProvider 'FileSystem' | Where-Object {
            $_.DisplayRoot -like '\\*\\*'} | ForEach-Object {
            Test-Path $_.Root}
        } catch {
                 Cache-Error -ErrorRecord $_
        }
    }
}


function Disable-FastBoot {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$true)]
        [string]$disableFastBoot
    )

    Process {
        try {
            New-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power -Name HiberbootEnabled -Value '0' -PassThru
        } catch {
                 Cache-Error -ErrorRecord $_
        }
    }
}


function Disable-WiFiSense {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$true)]
        [string]$disableWiFiSense
    )

    Process {
        try {
            $WifiSense = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config\AutoConnectAllowedOEM'
            $TestWifiSense = Test-Path $WifiSense
            New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config\ -Name AutoConnectAllowedOEM -Value 0 -Force
        } catch {
                 Cache-Error -ErrorRecord $_
        }
    }
}


function Delete-OldFiles {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$true)]
        [string]$deleteOldFiles
    )

    Process {
        try {
            Get-ChildItem -Path C:\Users\$global:user\Downloads\* -Recurse | Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-30) } | Remove-Item -Force
        } catch {
                 Cache-Error -ErrorRecord $_
        }
    }
}


function Check-MemoryUsage {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$true)]
        [string]$checkMemoryUsage
    )

    Process {
        try {
            Get-Counter '\Memory\Available MBytes' | Select-Object -ExpandProperty CounterSamples | Select-Object -ExpandProperty CookedValue
        } catch {
                 Cache-Error -ErrorRecord $_
        }
    }
}


function Check-CPUUsage {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$true)]
        [string]$checkCPUUsage
    )

    Process {
        try {
            Get-Counter '\Processor(_Total)\% Processor Time' | Select-Object -ExpandProperty CounterSamples | Select-Object -ExpandProperty CookedValue
        } catch {
                 Cache-Error -ErrorRecord $_
        }
    }
}


function Check-DiskSpace {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$true)]
        [string]$checkDiskSpace
    )

    Process {
        try {
            Get-PSDrive | Where-Object { $_.Provider -eq 'FileSystem' } | Select-Object -Property Name, Used, Free, @{ Name='Capacity'; Expression={ $_.Used + $_.Free } } | Format-Table -AutoSize
        } catch {
                 Cache-Error -ErrorRecord $_
        }
    }
}


function Check-DriveHealth {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$true)]
        [string]$checkDriveHealth
    )

    Process {
        try {
            $physicalDisks = Get-PhysicalDisk | Select-Object FriendlyName, HealthStatus
        } catch {
                 Cache-Error -ErrorRecord $_
        }
    }
}


function Check-ServiceCrash {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$true)]
        [string]$checkServiceCrash
    )

    Process {
        try {
            $serviceState = Get-Service -Name $serviceName | Select-Object 'Status'
            Stop-Service -Name $serviceName -Force | Start-Service -Name $serviceName
        } catch {
                 Cache-Error -ErrorRecord $_
        }
    }
}


function Check-DhcpEnabled {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$true)]
        [string]$checkDhcpEnabled
    )

    Process {
        try {
            $LinkStatus = Get-NetAdapter | Where-Object -FilterScript {$_.Status -Eq "Up"} | Select-Object 'Name', 'Status'
            Set-NetIPInterface -dhcp --Enabled $LinkStatus.ifIndex
        } catch {
                 Cache-Error -ErrorRecord $_
        }
    }
}


function Check-AMSI {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$true)]
        [string]$checkAMSI
    )

    Process {
        try {
            Update-MpSignature -UpdateSource MicrosoftUpdateServer | Set-MpPreference -SignatureScheduleDay Everyday | Start-MpScan -ScanType QuickScan | Remove-MpThreat
        } catch {
                 Cache-Error -ErrorRecord $_
        }
    }
}


function Check-TPMEnabled {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$true)]
        [string]$checkTPMEnabled
    )

    Process {
        try {
            $tpm = get-tpm | Select-Object 'TpmEnabled'
            Enable-TpmAutoProvisioning
        } catch {
                 Cache-Error -ErrorRecord $_
        }
    }
}


function Check-Plug {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$true)]
        [string]$checkPlug
    )

    Process {
        try {
            (Get-WmiObject -Class BatteryStatus).PowerOnline
        } catch {
                 Cache-Error -ErrorRecord $_
        }
    }
}


function Check-Issues {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$true)]
        [string]$checkIssues
    )

    Process {
        try {
            Get-EventLog -LogName Application -EntryType Error | Select-Object -Property TimeGenerated, Message
        } catch {
                 Cache-Error -ErrorRecord $_
        }
    }
}


function Check-Incidents {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$true)]
        [string]$checkIncidents
    )

    Process {
        try {
            Get-EventLog -LogName Security -EntryType Error | Select-Object -Property TimeGenerated, Message
        } catch {
                 Cache-Error -ErrorRecord $_
        }
    }
}


function Check-Drivers {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$true)]
        [string]$checkDrivers
    )

    Process {
        try {
            Get-WindowsDriver -Online -All
        } catch {
                 Cache-Error -ErrorRecord $_
        }
    }
}


function Check-DellCommandUpdate {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$true)]
        [string]$checkDellCommandUpdate
    )

    Process {
        try {
            Start-Process 'C:\Program Files (x86)\Dell\CommandUpdate\dcu-cli.exe' -RunSilent
        } catch {
                 Cache-Error -ErrorRecord $_
        }
    }
}


function Check-TimezoneLanguage {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$true)]
        [string]$checkTimezoneLanguage
    )

    Process {
        try {
            $lang = 'en-GB' # Add language
            $country = 'United Kingdom' # Add country
            $WinSysLocale = get-WinSystemLocale | Select-Object Name
            $WinUserLangList = get-WinUserLanguageList | Select-Object LanguageTag
            $HomeLocation = get-WinHomeLocation | Select-Object 'HomeLocation'
            $languageList = New-WinUserLanguageList $lang
            $languageList[0].Handwriting = 1
            $timezone = 'GMT Standard Time' # Add timezone
            $timezoneId = get-timezone | Select-Object Id
            if ($timezoneId -ne $timezone) {
            Set-TimeZone '$timezone' | get-winsystemlocale | get-winhomelocation}
            if ($WinSysLocale -ne $lang) {
            Set-WinSystemLocale $lang}
            if ($WinUserLangList -ne $lang) {
            Set-WinUserLanguageList $languageList -force | Set-WinUILanguageOverride -Language $lang}
            if ($HomeLocation -ne $country) {
                Set-WinHomeLocation 0xf2}
        } catch {
                 Cache-Error -ErrorRecord $_
        }
    }
}


function Check-DNS {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$true)]
        [string]$checkDNS
    )

    Process {
        try {
            Set-DnsClientServerAddress -InterfaceAlias WiFi -ServerAddresses ($global:DNS1,$global:DNS2)
        } catch {
                 Cache-Error -ErrorRecord $_
        }
    }
}


function Check-DefaultPrinter {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$true)]
        [string]$checkDefaultPrinter
    )

    Process {
        try {
            $printers = Get-WmiObject -Query " SELECT * FROM Win32_Printer WHERE Default=$true" | Select-Object 'Name'
            foreach ($printer in $printers) {
            Restart-Service -Name Spooler}
        } catch {
                 Cache-Error -ErrorRecord $_
        }
    }
}


function Check-Fragment {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$true)]
        [string]$checkFragment
    )

    Process {
        try {
            $frag = Optimize-Volume -DriveLetter C -Analyze -Verbose
            Optimize-Volume -DriveLetter C -Defrag -Verbose
        } catch {
                 Cache-Error -ErrorRecord $_
        }
    }
}


function Clear-Caches {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$true)]
        [string]$clearCaches
    )

    Process {
        try {
            $edgeCachePath = "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Cache"
            Remove-Item -Path 'C:\Users\$global:user\AppData\Local\Temp\*' -Force -Recurse | Remove-Item -Path 'C:\Users\$global:user\AppData\Local\Microsoft\Windows\Explorer\*' -Force -Recurse | Remove-Item -Path 'C:\Users\$global:user\AppData\Roaming\Microsoft\Windows\Recent\*' -Force -Recurse | Remove-Item -Path 'C:\Windows\Temp\*' -Force -Recurse | Remove-Item -Path 'C:\Windows\prefetch\*' -Force -Recurse | Remove-Item -Path 'C:\Windows\SoftwareDistribution\*' -Force -Recurse | Clear-DnsClientCache | if (Test-Path $edgeCachePath) {Remove-Item $edgeCachePath\* -Force -Recurse}
        } catch {
                 Cache-Error -ErrorRecord $_
        }
    }
}


function Clear-PageFile {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$true)]
        [string]$clearPageFile
    )

    Process {
        try {
            $PFV = '1'
            $PageFile = Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\SessionManager\MemoryManagement -Name ClearPageFileAtShutdown
            New-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\SessionManager\MemoryManagement -Name ClearPageFileAtShutdown -Value $PFV -PassThru
        } catch {
                 Cache-Error -ErrorRecord $_
        }
    }
}


# Execute
$callFunctions = @("#Create-SnapShot", "#Get-PowerLogs", "#Fix-HardwareFailure", "#Fix-Compatibility", "#Fix-PnP", "Optimise-System", "#Fix-OfficeActivation", "#Fix-BrokenShortcuts", "#Restart-NetworkAdapter", "#Test-MappedDrives", "#Disable-FastBoot", "Delete-OldFiles", "#Check-MemoryUsage", "#Check-CPUUsage", "#Check-DiskSpace", "Check-AMSI", "#Check-Plug", "#Check-Issues", "#Check-Incidents", "Check-Drivers", "#Check-DellCommandUpdate", "#Check-TimezoneLanguage", "Clear-Caches" )
foreach ($function in $callFunctions) {
  & $function
}
if ($LastPoint.CreationTime -le $date){
Create-RestorePoint
}
if (($HoursStart -eq $start) -and ($HoursEnd -eq $finish)) {
continue}
else {
Set-ActiveHours
}
foreach ($audioDevice in $audioDevices) {
if ($audioDevices.Status -eq 'BAD') {
Fix-Audio
}
}
if (!($TestDomain)) {
Test-Domain
}
if (!($TestWifiSense)) {
Disable-WiFiSense
}
if ($serviceState.Status -ne 'Running') {
Check-ServiceCrash
}
foreach ($NetAdapter in $NetAdapter) {
if ($NetAdapter.DHCP -eq 'Disabled') {
Check-DhcpEnabled
}
}
if (!($tpm)) {
Check-TPMEnabled
}
if (!($global:DNS1 -xor $global:DNS2)) {
Check-DNS
}
if ($frag -ge '10') {
Check-Fragment
}
if ($PageFile -ne '1') {
Clear-PageFile
}

GPUpdate /Force

Clear-RecycleBin -Force

# Flags
$conditions = (

    $errorCache.Count -gt 0 -xor
    $frag -ge '10' -xor
    $Score.WinSPRLevel -ge '7' -xor
    $check -eq $false -xor
    $tag -ne 'TAG_NAME' -xor
    $computerName -ne 'COMPUTER_NAME' -xor
    $description -ne 'COMPUTER_DESCRIPTION' -xor
    $SerialNumber -ne $serial -xor
    $acls.Owner -ne '$OwnerAccess.Owner' -xor
    $acls.Access -ne '$OwnerAccess.Access' -xor
    $ports.State -eq 'Established Internet' -xor
    $ports.LocalPort -ne $ActivePorts -xor
    $SysUsers -and $System -ne $SysUserList.User -and $SysUserList.System -xor
    $speed -ge '1' -xor
    $drivers.Date -le $date -xor
    $LastPoint -eq 'The last attempt to restore the computer failed.' -xor
    $battery -eq 'BAD' -xor
    $DomainChecker -eq 'WORKGROUP' -xor
    $Ping.Timeout -ge '40000' -xor
    $secboot -eq $false -xor
    $uptime -ge '24:00:00.0000000' -xor
    $FreeSpace -le '0.100000000000000' -xor
    $pro -ge '99.0' -xor
    $mem -le '1000' -xor
    $temp -ge '60.00' -xor
    $lock.ProtectionStatus -eq 'Off' -xor
    $AV.AntivirusEnabled -eq $false -xor
    $log.LevelDisplayName -eq 'Critical', 'Warning', '$powerEventIDs' -xor
    $lang -ne 'en-GB' -xor
    $country -ne 'United Kingdom' -xor
    $timezone -ne 'GMT Standard Time' -xor
    $DNS -ne $DNS1 -and $DNS -ne $DNS2 -xor
    $compatibilityIssues.Count -gt 0 -xor
    $hardwareFailures -xor
    $deliveryProblems -xor
    $wifiInt.LinkSpeed -le '50' -xor
    $ethInt.LinkSpeed -le '50' -xor
    $audioDevice -eq 'BAD' -xor
    $physicalDisks -eq 'BAD'

    )

# Alert
if ($conditions) {

    $csvPath = "$computerName.$date_error_report.csv"
    $compressedPath = "$computerName.$date_compressed_error_report.csv"

    $errorObjects = $errorCache | ForEach-Object {
        [PSCustomObject]@{
            ErrorTime = $_.ErrorDetails.TimeGenerated
            ErrorMessage = $_.Exception.Message
            ErrorStackTrace = $_.ScriptStackTrace
        }
    }

    $errorObjects | Export-Csv -Path $csvPath -NoTypeInformation | Compress-Archive -Path $csvPath -DestinationPath $compressedPath

    $from = "your.email@domain.com"
    $to = "helpdesk@domain.com"
    $subject = "Alert: Errors found on $computerName"
    $body = "Please check report $computerName.$date."

    # Slack
    $Token = "YOUR_SLACK_API_TOKEN"
    $Channel = "YOUR_SLACK_CHANNEL_ID"
    Send-SlackMessage -Token $Token -Channel $Channel -Message $body

    # Teams
    $ChannelId = "TEAMS_CHANNEL_ID"
    Connect-MicrosoftTeams
    New-TeamChannelMessage -GroupId $ChannelId -Message $body             

    # Email
    $smtpServer = "your.smtp.server"
    Send-MailMessage -SmtpServer $smtpServer -From $from -To $to -Subject $subject -Body $body -Attachment $compressedPath -BodyAsHtml -Priority High -DeliveryNotificationOption OnFailure
    
    }

    }
    }
