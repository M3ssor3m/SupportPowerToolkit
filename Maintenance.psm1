# Version: 0.1.2

# Each function hold its own variables and uses the global variables, it must try to run its commands based on OS query and whether or not its a remote machine. Catch any errors then continue onto the next task.

# Key
# LM = Add Linux & Mac query 

# Global Variables (Used for all functions)
# Source path for report 
$global:sourcePath = "C:\$user_$global:computer_$global:date_ErrorLog.txt"
# System Name
$global:computerName = 
# Current Date
$global:date = Get-Date
# Current User
$global:user = (Get-CimInstance -ClassName Win32_ComputerSystem).PrimaryOwnerName
# System Domain
$global:domain = "domain.net"
# Network Adapter & Interfaces
$global:wifiInt = Get-NetAdapter | Where-Object { $_.Name -like "*WiFi*" }
$global:ethInt = Get-NetAdapter | Where-Object { $_.Name -like "*Ethernet*" }
$global:NetAdapter = Get-NetIPConfiguration -Detailed | Select-Object InterfaceAlias, @{N="DHCP";E={$_.NetIPv4Interface.DHCP}}
# Serial Number
$global:SerialNumber = Get-CimInstance Win32_BIOS | Select-Object -ExpandProperty SerialNumber
# DNS 
$global:DNS = Get-DnsClientServerAddress -AddressFamily IPv4 | Select-Object ServerAddresses
$global:DNS1 = '9.9.9.11' # Add DNS 1 address
$global:DNS2 = '142.112.112.11' # Add DNS 2 address
# System Uptime
$global:uptime = Get-Uptime
# System Drivers
$global:drivers = Get-WindowsDriver -Online -All | Select-Object 'Driver', 'Date', 'Version'
# Restore Point
$global:LastPoint = Get-ComputerRestorePoint -LastStatus
# CPU Status    
$global:pro = Get-CimInstance -ClassName Win32_Processor | Select-Object -ExpandProperty Name
# Memory Status
$global:mem = Get-CimInstance -ClassName Win32_OperatingSystem | Select-Object -ExpandProperty FreePhysicalMemory | ForEach-Object { $_ / 1MB }
# System Description
$global:description = Get-WmiObject -Class Win32_OperatingSystem | Select-Object 'Description'
# System TAG
$global:tag = Get-WmiObject -Class Win32_SystemEnclosure | Select-Object -ExpandProperty SMBIOSAssetTag
# Disc Space
$global:DiskSpace = Get-WmiObject -Class Win32_logicalDisk | Where-Object {$_.DeviceID -eq 'C:'} | Select-Object Size, FreeSpace
$global:FreeSpace = $DiskSpace.FreeSpace / $DiskSpace.Size * 100
# System Name
$global:computer = $env:COMPUTERNAME
# System Temp
$global:temp = Get-WmiObject -Namespace root\wmi -Class MSAcpi_ThermalZoneTemperature -ComputerName $global:computer | Select-Object -ExpandProperty CurrentTemperature
# System BitLocker
$global:lock = Get-BitLockerVolume -MountPoint "C:" |  Select-Object volumetype, protectionstatus -Verbose
# Anti-Malware 
$global:AV = Get-MpComputerStatus | Select-Object 'AMServiceEnabled', 'AntispywareEnabled', 'AntivirusEnabled'
# ACL
$global:acls = Get-Acl -Path C:\ | Select-Object 'AccessToString'
# Secure Boot
$global:secboot = Confirm-SecureBootUefi
# Default Gateway
#$global:DefaultGateway = get-netipconfiguration | Select-Object IPv4DefaultGateway
#$global:Addresses = $global:DefaultGateway.IPv4DefaultGateway | Select-Object NextHop
#$global:Ping = Test-Connection $global:Addresses -Count 1
#$global:battery = Get-CimInstance -ClassName CIM_Battery | Select-Object 'Status'
# NextHop
#$global:GetIP = (Get-NetIPConfiguration) | Select-Object IPv4DefaultGateway
#$global:NextHop = ($GetIP.IPv4DefaultGateway)
#$global:socket = (new-object System.Net.Sockets.TcpClient($NextHop.NextHop, $port))
# System Logs
$global:LogDate = (get-date) - (New-TimeSpan -Day 1)
$global:eventIDs = @(12, 41) # Add event IDs   
$global:logs = get-winevent | Where-Object {$_.LevelDisplayName -eq $global:LogDate, 'Critical, Warning', $global:eventIDs} | Select-Object -ExpandProperty Message
# System Ports
$global:GetPorts = (get-nettcpconnection) | Select-Object LocalPort
$global:Ports = ($global:GetPorts.LocalPort)
# Delivery Problems
$global:emailAddress = ""
$global:deliveryProblems = Get-DeliveryProblems -EmailAddress $global:emailAddress

# Auto Variables 
#$HOME
#$USERPROFILE

# Main function (Nested functions) 
function Run_Maintenance {
# Call all functions
# Create a Snapshot 
#SnapShot
# Check for Power Surges 
#PowerLogs 
# Group Policy Update
RunGPUpdate
# Restart Hardware Failure
#ResolveHardwareFailure
# Resolve Software Compatibility
#ResolveCompatibility
# Refresh PnP Devices
#RefreshPnP
# SFC Scan
RunSFC
# DISM Scan
RunDISM
# Volume Scan
Repair
# LSA Protection
#EnableLSAProtection
# Enable virtual security
#VirtualSec
# Enable VBS
#EnableVBS
# Clear Page File
OptimiseSystem
# Audit logons
#AuditLogon
# Enable VTPM
#EnableVirtualizationBasedSecurity
# Enable Application Guard
#EnableApplicationGuard
# Enable Network Protection 
#EnableNetworkProtection
# Enable LSAP
#EnableLocalSecurityAuthorityProtection
# Enable Windows Defender System Guard
#EnableWindowsDefenderSystemGuard
# Office Activation Fix
#OfficeActivation
# Fix Broken Shortcuts
#FixBrokenShortcuts
# Fix Broken Office Apps
#FixOfficeApps
# Restart Network Adapter
#RestartNetworkAdapter
# Test mapped drive connection
#TestMappedDrives
# Disable SMB v1
#DisableSMB
# Disable Fast Boot
#DisableFastBoot
# Delete files older than 
DeleteOldFiles
# Check Memory Usage
#CheckMemoryUsage
# Check CPU Usage
#CheckCPUUsage
# Check Freespace
#CheckDiskSpace
# Check CCTV 
#CheckCCTV
# Run Anti-Malware Scan
CheckAMSI
# Check power plug
#CheckPlug
# Check for securoty issues in logs
#CheckForIssues
# Check for application issues in logs
#CheckForIncidents
# Windows Assessment
#CheckWinSysAssessment
# Update Drivers
CheckDrivers
# Dell Command Update
#CheckDellCommandUpdate
# Check Dell System Lifecycle
#CheckLifeCycle
# Check Time & Launguage 
#CheckTimezoneLanguage
# Empty Recycle Bin
ClearRecycleBin
# Clear System Caches
ClearCaches
# Check Installed Software 
#CheckSoftware


# Call functions based on query
# Check if PowerShell 7 is installed
if (!(IsPowerShell7Installed)) {
InstallPowerShell7Windows
}
# Compress report if report is present 
if ($global:sourcePath) {
CompressReport
}
# Create system restore point 
if ($global:LastPoint.CreationTime -le $global:date){
CreateRestorePoint
}
# Active Hours 
if (($HoursStart -eq $start) -and ($HoursEnd -eq $finish)) {
continue}
else {
ActiveHours
}
# Fix audio issues
foreach ($audioDevice in $audioDevices) {
if ($audioDevices.Status -eq 'BAD') {
FixAudio
}
# Test connection to DC
if (!($TestDomain)) {
TestDomain
}
# Disable Windows Feeback
If (Test-Path $Advertising) {
DisableWinFeedbackExp
}
# Disable WiFi Sense
if (!($TestWifiSense)) {
DisableWiFiSense
}
# Check Domain 
if ($DomainChecker -eq $global:domain) {
CheckDomain
}
# Check Software Packages
foreach ($package in $packages) {
if ($package.Name -ne $CurrentPackages) {
CheckPackages
}
# Check Crashed Services
if ($serviceState.Status -ne 'Running') {
CheckServiceCrash
}
# Check Adapters DHCP
foreach ($NetAdapter in $global:NetAdapter) {
if ($NetAdapter.DHCP -eq 'Disabled') {
CheckDhcpEnabled
}
}
# Check TPM 
if (!($tpm)) {
CheckTPMEnabled
}
# Check DNS 
if (!($global:DNS1 -xor $global:DNS2)) {
CheckDNS
}
# Check System Uptime
if ($uptime -ge 1) {
CheckUptime
}
# Check Fragmentation 
if ($frag -ge '10') {
CheckFragment
}
# Enable Clear Page File
if ($PageFile -ne '1') {
ClearPageFile
}
#
}

function CreateRestorePoint {
Checkpoint-Computer -Description $date -RestorePointType MODIFY_SETTINGS
}

function RunGPUpdate {
GPUpdate /Force
}

# LM
function PowerLogs {
$powerEvents = Get-WinEvent -ComputerName $global:computerName -LogName 'System' -MaxEvents 100 |
Where-Object { $_.ProviderName -eq 'Microsoft-Windows-Kernel-Power' }
# Check for Power Surges 
$surgeEvents = $powerEvents |
Where-Object { $_.Id -eq 41 -or $_.Id -eq 109 }
}

function IsPowerShell7Installed {
$psVersionTable = $PSVersionTable.PSVersion
$majorVersion = $psVersionTable.Major

if ($majorVersion -eq 7) {
return $true
} else {
return $false
}
}

# LM
function InstallPowerShell7Windows {
$url = "https://aka.ms/powershell7-windows"
$installerPath = "$env:TEMP\PowerShell7.msi"

# Download PowerShell 7 installer
Invoke-WebRequest -Uri $url -OutFile $installerPath

# Quiet Install PowerShell 7
Start-Process -Wait -FilePath msiexec -ArgumentList "/i $installerPath /quiet"

# Clean up installer file
Remove-Item $installerPath -Force
}

# LM
function SnapShot {
$shadowCopy = (Get-WmiObject -List Win32_ShadowCopy).Create("C:\", "ClientAccessible")
}

# LM
function FanStatus {
# Get the Win32_Fan class instances from the server
$fanInstances = Get-WmiObject -Class Win32_Fan -ComputerName $global:computerName

# Check the status of each fan
foreach ($fan in $fanInstances) {
$fanStatus = $fan.Status
$fanName = $fan.Name
}
}

function ResolveHardwareFailure {
$hardwareFailures = Get-CimInstance -ClassName CIM_LogicalDevice -Filter 'Status="Error"'
foreach ($failure in $hardwareFailures) {
$service = Get-Service | Where-Object {$_.Name -eq $failure.DeviceID} 
if ($service) {
Restart-Service -Name $service.Name}
} 
}

function ResolveCompatibility {
$compatibilityIssues = Get-WindowsCompatibility -ScanPath "C:\Path\To\Software" # Add software path
foreach ($issue in $compatibilityIssues) {
Resolve-WindowsCompatibility -Path $issue.Path -Issue $issue.Issue}
}

function RefreshPnP {
$devices = Get-PnpDevice | Where-Object {$_.Class -eq "Human Interface Device" -or $_.Class -eq "Keyboard" -or $_.Class -eq "Mouse"}
$deviceId = $devices.InstanceId
foreach ($device in $devices) {
Disable-PnpDevice -InstanceId $deviceId -Confirm:$false
Wait 5
Enable-PnpDevice -InstanceId $deviceId -Confirm:$false}
}

function RunSFC {
sfc /scannow
}

function RunDISM {
Repair-WindowsImage -Online -RestoreHealth
}

function Repair {
Repair-Volume -DriveLetter C -Scan -OfflineScanAndFix
}

function ActiveHours {
$start = '9' # Set start time for Active Hours
$finish = '9' # Set finish time for Active Hours
$HoursStart = Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings -Name ActiveHoursStart
$HoursEnd = Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings -Name ActiveHoursEnd
New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings -Name ActiveHoursStart -Value $start -PassThru | New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings -Name ActiveHoursEnd -Value $finish -PassThru
}   

function MaximumPerformance {
powercfg /SETDCVALUEINDEX SCHEME_CURRENT 19cbb8fa-5279-450e-9fac-8a3d5fedd0c1 12bbebe6-58d6-4636-95bb-3217ef867c1a 0 | powercfg /SETACVALUEINDEX SCHEME_CURRENT 19cbb8fa-5279-450e-9fac-8a3d5fedd0c1 12bbebe6-58d6-4636-95bb-3217ef867c1a 0 | powercfg /change monitor-timeout-ac 0 | powercfg /change monitor-timeout-dc 0 | powercfg /change disk-timeout-ac 0 | powercfg /change disk-timeout-dc 0 | powercfg /change standby-timeout-ac 0 | powercfg /change standby-timeout-dc 0
} 

function EnableLSAProtection {
REG ADD 'HKLM\SYSTEM\CurrentControlSet\Control\Lsa' /v 'RunAsPPLBoot' /t REG_DWORD /d 2 /f | REG ADD 'HKLM\SYSTEM\CurrentControlSet\Control\Lsa' /v 'RunAsPPL' /t REG_DWORD /d 2 /f
}

function VirtualSec {
REG ADD 'HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard' /v 'EnableVirtualizationBasedSecurity' /t REG_DWORD /d 1 /f
}

function EnableVBS {
REG ADD 'HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard' /v 'RequirePlatformSecurityFeatures' /t REG_DWORD /d 3 /f | REG ADD 'HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard' /v 'Locked' /t REG_DWORD /d 1 /f | reg add 'HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity' /v 'Locked' /t REG_DWORD /d 1 /f
}

function OptimiseSystem {
Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management' -Name 'ClearPageFileAtShutdown' -Value 0 | Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management' -Name 'DisablePagingExecutive' -Value 1 | Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy' -Name '01' -Value 1
}

function AuditLogon {
Auditpol.exe /set /category:"Logon/Logoff" /success:enable /failure:enable
}

function EnableVirtualizationBasedSecurity {
Enable-VTPM
}

function EnableApplicationGuard {
Enable-WindowsOptionalFeature -Online -FeatureName Windows-Defender-ApplicationGuard
}

function EnableNetworkProtection {
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True
}

function EnableLocalSecurityAuthorityProtection {
Set-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\Lsa -Name 'AuditBaseObjects' -Value 1
}

function EnableWindowsDefenderSystemGuard {
Set-MpPreference -EnableControlledFolderAccess Enabled -EnableNetworkProtection Enabled
}

function OfficeActivation {
Remove-Item HKLM:SOFTWARE\Microsoft\Office\10.0, HKLM:SOFTWARE\Microsoft\Office\12.0, HKLM:SOFTWARE\Microsoft\Office\15.0, HKLM:SOFTWARE\Microsoft\Office\16.0 -Confirm:$false -Force
}

function FixBrokenShortcuts {
Get-ChildItem -Path C:\ -Include *.lnk -Recurse -File | ForEach-Object {
(New-Object -ComObject WScript.Shell).CreateShortcut($_.FullName).Save()}
}

function FixOfficeApps {
reg delete 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\winword.exe' /f | reg delete 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\outlook.exe' /f | reg delete 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\powerpnt.exe' /f | reg delete 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\excel.exe' /f | reg delete 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\onenote.exe' /f | reg delete 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\mspub.exe' /f | reg delete 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\msaccess.exe' /f
}

function FixAudio {
$audioDevices = Get-WmiObject Win32_SoundDevice | Where-Object { $_.Status -eq 'BAD' }
Restart-Service -Name 'Audiosrv' -Force
}

function RestartNetworkAdapter {
Restart-NetAdapter -Name $global:NetAdapter
}

function TestDomain {
$TestDomain = Test-ComputerSecureChannel -Server 'domain.net\DC01'
Test-ComputerSecureChannel -Repair
}

function TestMappedDrives {
Get-PSDrive -PSProvider 'FileSystem' | Where-Object {
$_.DisplayRoot -like '\\*\\*'} | ForEach-Object {
Test-Path $_.Root}
}

function DisableSMB {
Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
}

function DisableFastBoot {
New-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power -Name HiberbootEnabled -Value '0' -PassThru
}

function DisableWinFeedbackExp {
$Advertising = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo"
Set-ItemProperty $Advertising Enabled -Value 0
}

function DisableWiFiSense {
$WifiSense = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config\AutoConnectAllowedOEM'
$TestWifiSense = Test-Path $WifiSense
New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config\ -Name AutoConnectAllowedOEM -Value 0 -Force
}

function DeleteOldFiles {
Get-ChildItem -Path C:\Users\$global:user\Downloads\* -Recurse | Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-30) } | Remove-Item -Force
}

function CheckDomain {
$DomainChecker = Get-CimInstance -ClassName Win32_ComputerSystem | Select-Object domain
Add-Computer -DomainName $domain -Server 'domain.net\DC01'
}

function CheckPackages {
$packages = \\fileserver\csv\packages.csv # Add packages CSV
$CurrentPackages = get-packageprovider -name nuget | Get-Package -ProviderName NuGet | Select-Object 'Name', 'Version'
Install-PackageProvider -Name $package.Name -Force
}

function CheckSoftware {
$SoftwarePacks = 'Microsoft Update Health Tools', 'Microsoft Edge' # Add software packages       
foreach ($SoftwarePack in $SoftwarePacks) {
           winget search -q $SoftwarePack
           if (!($SoftwarePack)) {
               winget install -e $_
           }
       } 
}

function CheckMemoryUsage {
Get-Counter '\Memory\Available MBytes' | Select-Object -ExpandProperty CounterSamples | Select-Object -ExpandProperty CookedValue
}

function CheckCPUUsage {
Get-Counter '\Processor(_Total)\% Processor Time' | Select-Object -ExpandProperty CounterSamples | Select-Object -ExpandProperty CookedValue
}

function CheckDiskSpace {
Get-PSDrive | Where-Object { $_.Provider -eq 'FileSystem' } | Select-Object -Property Name, Used, Free, @{ Name='Capacity'; Expression={ $_.Used + $_.Free } } | Format-Table -AutoSize
}

function CheckDriveHealth {
$physicalDisks = Get-PhysicalDisk | Select-Object FriendlyName, HealthStatus
}

function CheckServiceCrash {
$serviceState = Get-Service -Name $serviceName | Select-Object 'Status'
Stop-Service -Name $serviceName -Force | Start-Service -Name $serviceName
}

function CheckCCTV {
Test-NetConnection -ComputerName '192.168.1.100' -Port 80 | Invoke-WebRequest -Uri 'http://192.168.1.100/'
}

function CheckDhcpEnabled {
$LinkStatus = Get-NetAdapter | Where-Object -FilterScript {$_.Status -Eq "Up"} | Select-Object 'Name', 'Status'
Set-NetIPInterface -dhcp --Enabled $LinkStatus.ifIndex
}

function CheckAMSI {
Update-MpSignature -UpdateSource MicrosoftUpdateServer | Set-MpPreference -SignatureScheduleDay Everyday | Start-MpScan -ScanType QuickScan | Remove-MpThreat
}

function CheckTPMEnabled {
$tpm = get-tpm | Select-Object 'TpmEnabled'
Enable-TpmAutoProvisioning
}

function CheckPlug {
(Get-WmiObject -Class BatteryStatus).PowerOnline
}

function CheckForIssues {
Get-EventLog -LogName Application -EntryType Error | Select-Object -Property TimeGenerated, Message
}

function CheckForIncidents {
Get-EventLog -LogName Security -EntryType Error | Select-Object -Property TimeGenerated, Message
}

function CheckWinSysAssessment {
$Score = Get-CimInstance Win32_WinSat | Select-Object CPUScore, D3DScore, DiskScore, GraphicsScore, MemoryScore, WinSPRLevel
}

function CheckDrivers {
Get-WindowsDriver -Online -All
}

function CheckDellCommandUpdate {
Start-Process 'C:\Program Files (x86)\Dell\CommandUpdate\dcu-cli.exe' -RunSilent
}

function CheckLifeCycle {
$DellAPIKey = "your_api_key_here" # Add API key
$URL = "https://api.dell.com/support/v2/assetinfo/warranty/status?apikey=$DellAPIKey&servicetags=$global:SerialNumber"
Invoke-RestMethod -Uri $URL -Method Get
}

function CheckTimezoneLanguage {
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
}

function CheckDNS {
Set-DnsClientServerAddress -InterfaceAlias WiFi -ServerAddresses ($global:DNS1,$global:DNS2)
}

function CheckDefaultPrinter {
$printers = Get-WmiObject -Query " SELECT * FROM Win32_Printer WHERE Default=$true" | Select-Object 'Name'
foreach ($printer in $printers) {
Restart-Service -Name Spooler}
}

function CheckUptime {
powercfg /hibernate off
}

function CheckFragment {
$frag = Optimize-Volume -DriveLetter C -Analyze -Verbose
Optimize-Volume -DriveLetter C -Defrag -Verbose
}

function ClearRecycleBin {
Clear-RecycleBin -Force
}

function ClearCaches {
$edgeCachePath = "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Cache"
Remove-Item -Path 'C:\Users\$global:user\AppData\Local\Temp\*' -Force -Recurse | Remove-Item -Path 'C:\Users\$global:user\AppData\Local\Microsoft\Windows\Explorer\*' -Force -Recurse | Remove-Item -Path 'C:\Users\$global:user\AppData\Roaming\Microsoft\Windows\Recent\*' -Force -Recurse | Remove-Item -Path 'C:\Windows\Temp\*' -Force -Recurse | Remove-Item -Path 'C:\Windows\prefetch\*' -Force -Recurse | Remove-Item -Path 'C:\Windows\SoftwareDistribution\*' -Force -Recurse | Clear-DnsClientCache | if (Test-Path $edgeCachePath) {Remove-Item $edgeCachePath\* -Force -Recurse}
}

function ClearPageFile {
$PFV = '1'
$PageFile = Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\SessionManager\MemoryManagement -Name ClearPageFileAtShutdown
New-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\SessionManager\MemoryManagement -Name ClearPageFileAtShutdown -Value $PFV -PassThru
}

#function CompressReport {
#Function Variables 
# Compressed report destination path
#$destinationPath = "C:\Path\To\Destination\compressed.zip"
#try {
# Check the operating system
#if ($OSType -eq 'Windows_NT') {
# Add your Windows-specific actions here
# Compress report
#Compress-Archive -Path $global:sourcePath -DestinationPath $destinationPath
#}
#elseif ($OSType -eq 'Linux') {
# Add your Linux-specific actions here
#}
#elseif ($OSType -eq 'Darwin') {
# Add your macOS-specific actions here
#}
#else {
#exit
# Add any specific actions for unsupported operating systems here
#}
#} 
#}

# Error handling 
# Catch errors from all functions 
catch {
$ErrorMessage = $_.Exception.Message
$FailedItem = $_.Exception.ItemName
# Alert Condition
    $conditions = (
    #$Error
    $frag -ge '10' -xor
    $Score.WinSPRLevel -ge '7' -xor
    $check -eq $false -xor
    $global:tag -ne 'TAG_NAME' -xor
    $global:computer -ne 'COMPUTER_NAME' -xor
    $global:description -ne 'COMPUTER_DESCRIPTION' -xor
    $global:SerialNumber -ne $serial -xor
    $global:acls.Owner -ne '$OwnerAccess.Owner' -xor
    $global:acls.Access -ne '$OwnerAccess.Access' -xor
    $global:ports.State -eq 'Established Internet' -xor
    $global:ports.LocalPort -ne $ActivePorts -xor
    $SysUsers -and $System -ne $SysUserList.User -and $SysUserList.System -xor
    $speed -ge '1' -xor
    $global:drivers.Date -le $date -xor
    $global:LastPoint -eq 'The last attempt to restore the computer failed.' -xor
    $global:battery -eq 'BAD' -xor
    $DomainChecker -eq 'WORKGROUP' -xor
    $global:Ping.Timeout -ge '40000' -xor
    $global:secboot -eq $false -xor
    $uptime -ge '24:00:00.0000000' -xor
    $global:FreeSpace -le '0.100000000000000' -xor
    $global:pro -ge '99.0' -xor
    $global:mem -le '1000' -xor
    $global:temp -ge '60.00' -xor
    $global:lock.ProtectionStatus -eq 'Off' -xor
    $global:AV.AntivirusEnabled -eq $false -xor
    $global:log.LevelDisplayName -eq 'Critical', 'Warning', '$global:eventIDs' -xor
    $_.HealthStatus -ne "Healthy" -xor
    $lang -ne 'en-GB' -xor
    $country -ne 'United Kingdom' -xor
    $timezone -ne 'GMT Standard Time' -xor
    $global:DNS -ne $global:DNS1 -and $global:DNS -ne $global:DNS2 -xor
    $compatibilityIssues.Count -gt 0 -xor
    $hardwareFailures -xor
    $deliveryProblems -xor
    $global:wifiInt.LinkSpeed -le '50' -xor
    $global:ethInt.LinkSpeed -le '50' -xor
    $audioDevice -eq 'BAD' -xor
    $physicalDisks -eq 'BAD'

    )
}

if ($conditions) 
    {
    $smtpServer = "your.smtp.server" # Add SMTP server
    $from = "your.email@domain.com" # Add from email address
    $to = "helpdesk@domain.com" # Add to email address
    $subject = "Alert: Errors found on $global:computer" # Add email subject
    $body = foreach ($condition in $conditions) { Please check report $global:computer.$global:date. Issues; $condition } # Add email body

    # Alert Helpdesk via Slack
    $Token = "YOUR_SLACK_API_TOKEN" #SecureString
    $Channel = "YOUR_SLACK_CHANNEL_ID"
    Send-SlackMessage -Token $Token -Channel $Channel -Message $body

    # Alert Helpdesk via Teams
    $ChannelId = "TEAMS_CHANNEL_ID"  # Replace with your channel ID
    Connect-MicrosoftTeams
    New-TeamChannelMessage -GroupId $ChannelId -Message $body             

    # Alert Helpdesk via Email
    $ErrorLogPath = "C:\$global:user_$global:computer_$global:date_ErrorLog.txt"
    Send-MailMessage -SmtpServer $smtpServer -From $from -To $to -Subject $subject -Body $body -Attachment $attachment -BodyAsHtml -Priority High -DeliveryNotificationOption OnFailure
    }
}
}

Export-ModuleMember -Function 'Run_Maintenance' -Alias 'runmain' 
