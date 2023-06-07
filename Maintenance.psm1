function Run_Maintenance {

    # Modules # Uncomment to install modules
    #Import-Module Teams
    #Import-Module PSWindowsUpdate
    #Import-Module ActiveDirectory
    #Import-Module BitLocker
    #Import-Module DellBIOSProvider
    #Import-Module DellWarranty
    #Import-Module Defender
    #Import-Module DnsClient
    #Import-Module NetAdapter     
    #Import-Module NetSecurity
    #Import-Module NetTCPIP
    #Import-Module AzureAD
    #Import-Module AzureRM

    # Variables   
    $smtpServer = "your.smtp.server" # Add SMTP server  
    $from = "your.email@domain.com" # Add from email address    
    $to = "helpdesk@domain.com" # Add to email address  
    $subject = "Alert: Errors found on $computer" # Add email subject   
    $body = "Please check report for $computer on $date" # Add email body   
    $attachment = "C:\Temp\MaintenanceLog.txt" # Add attachment path    
    $LogPath = "C:\Temp\MaintenanceLog.txt" # Add log path  
    $credentials = (Get-Credential) # Add credentials for email 
    $os = $PSVersionTable.OS
    $user = (Get-CimInstance -ClassName Win32_ComputerSystem).PrimaryOwnerName
    $modules = Get-Module | Select-Object 'Name'
    $date = Get-Date 
    $drivers = Get-WindowsDriver -Online -All | Select-Object 'Driver', 'Date', 'Version'
    $LastPoint = Get-ComputerRestorePoint -LastStatus 'OK'
    $backupPath = "C:\Backup" # Set backup path for Test-FileIntegrity
    $testResult = Test-FileIntegrity -Path $backupPath -LogPath $LogPath
    $Shortcuts = Get-ChildItem -Recurse "C:\" -Include *.lnk -Force -ErrorAction SilentlyContinue | Where-Object { $_.PSIsContainer -eq $false -and $_.IsDeleted -eq $true }
    $CurrentPackages = get-packageprovider -name nuget | Get-Package -ProviderName NuGet | Select-Object 'Name', 'Version'
    $packages = \\fileserver\csv\packages.csv # Add packages CSV
    $repo = Get-PSRepository | Select-Object 'Name', 'SourceLocation'
    $domain = 'domain.net' # Add domain 
    $DomainChecker = Get-CimInstance -ClassName Win32_ComputerSystem | Select-Object domain
    $TestDomain = Test-ComputerSecureChannel -Server 'domain.net\DC01'
    $RequestStatus = Invoke-WebRequest -uri "https://portal.domain.net/"
    $GoodStatus = '200' # Add good web status
    $BadStatusCodes = '404', '500', '502', '503' # Add bad web status codes
    $start = '9' # Set start time for Active Hours
    $finish = '9' # Set finish time for Active Hours
    $HoursStart = Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings -Name ActiveHoursStart
    $HoursEnd = Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings -Name ActiveHoursEnd
    $PFV = '1' # Set page file value
    $PageFile = Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\SessionManager\MemoryManagement -Name ClearPageFileAtShutdown
    $edgeCachePath = "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Cache" # Add Edge cache path
    $Directory = "C:\DeletedFiles" # Add directory for file recovery
    $Extension = "*.txt" # Add file extension for file recovery
    $DeletedFiles = Get-ChildItem -Path $Directory -Include $Extension -Recurse -Force -ErrorAction SilentlyContinue | Where-Object { $_.PSIsContainer -eq $false -and $_.IsDeleted -eq $true }
    $pro = Get-CimInstance -ClassName Win32_Processor | Select-Object -ExpandProperty Name
    $mem = Get-CimInstance -ClassName Win32_OperatingSystem | Select-Object -ExpandProperty FreePhysicalMemory | ForEach-Object { $_ / 1MB }
    $SerialNo = Get-WmiObject -Class Win32_BIOS | Select-Object -ExpandProperty SerialNumber
    $description = Get-WmiObject -Class Win32_OperatingSystem | Select-Object 'Description'
    $tag = Get-WmiObject -Class Win32_SystemEnclosure | Select-Object -ExpandProperty SMBIOSAssetTag
    $DiskSpace = Get-WmiObject -Class Win32_logicalDisk | Where-Object {$_.DeviceID -eq 'C:'} | Select-Object Size, FreeSpace
    $FreeSpace = $DiskSpace.FreeSpace / $DiskSpace.Size * 100
    $physicalDisks = Get-PhysicalDisk | Select-Object FriendlyName, HealthStatus
    $unhealthyDisks = $physicalDisks | Where-Object {$_.HealthStatus -ne "Healthy"}
    $serviceName = "" # Add service name
    $serviceState = Get-Service -Name $serviceName | Select-Object 'Status'
    $computer = $env:COMPUTERNAME
    $temp = Get-WmiObject -Namespace root\wmi -Class MSAcpi_ThermalZoneTemperature -ComputerName $computer | Select-Object -ExpandProperty CurrentTemperature
    $LinkStatus = Get-NetAdapter | Where-Object -FilterScript {$_.Status -Eq "Up"} | Select-Object 'Name', 'Status'
    $adapters = Get-NetIPConfiguration -Detailed | Select-Object InterfaceAlias, @{N="DHCP";E={$_.NetIPv4Interface.DHCP}}
    $lock = Get-BitLockerVolume -MountPoint "C:" |  Select-Object volumetype, protectionstatus -Verbose
    $AV = Get-MpComputerStatus | Select-Object 'AMServiceEnabled', 'AntispywareEnabled', 'AntivirusEnabled'
    $Score = Get-CimInstance Win32_WinSat | Select-Object CPUScore, D3DScore, DiskScore, GraphicsScore, MemoryScore, WinSPRLevel
    $tpm = get-tpm | Select-Object 'TpmEnabled'
    $OwnerAccess = Get-Acl -Path C:\ | Select-Object 'Owner'
    $acls = Get-Acl -Path C:\ | Select-Object 'AccessToString'
    $secboot = Confirm-SecureBootUefi
    $repair = Repair-Volume -DriveLetter C -Scan -OfflineScanAndFix
    $SerialNumber = Get-CimInstance Win32_BIOS | Select-Object -ExpandProperty SerialNumber
    $APIKey = "your_api_key_here" # Add API key
    $URL = "https://api.dell.com/support/v2/assetinfo/warranty/status?apikey=$APIKey&servicetags=$SerialNumber"
    $lang = 'en-GB' # Add language
    $country = 'United Kingdom' # Add country
    $timezone = 'GMT Standard Time' # Add timezone
    $timezoneId = get-timezone | Select-Object Id
    $WinSysLocale = get-WinSystemLocale | Select-Object Name
    $WinUserLangList = get-WinUserLanguageList | Select-Object LanguageTag
    $HomeLocation = get-WinHomeLocation | Select-Object 'HomeLocation'
    $languageList = New-WinUserLanguageList $lang
    $languageList[0].Handwriting = 1
    $DefaultGateway = get-netipconfiguration | Select-Object IPv4DefaultGateway
    $Addresses = $DefaultGateway.IPv4DefaultGateway | Select-Object NextHop
    $Ping = Test-Connection $Addresses -Count 1
    $DNS1 = '9.9.9.11' # Add DNS 1 address
    $DNS2 = '142.112.112.11' # Add DNS 2 address
    $DNS = Get-DnsClientServerAddress -AddressFamily IPv4 | Select-Object ServerAddresses
    $battery = Get-CimInstance -ClassName CIM_Battery | Select-Object 'Status'
    $LogDate = (get-date) - (New-TimeSpan -Day 1)
    $logs = get-winevent | Where-Object {$_.LevelDisplayName -eq $LogDate, 'Critical'} | Select-Object -ExpandProperty Message
    $printers = Get-WmiObject -Query " SELECT * FROM Win32_Printer WHERE Default=$true" | Select-Object 'Name'
    $uptime = Get-Uptime
    $Advertising = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo"
    $Period = "HKCU:\Software\Microsoft\Siuf\Rules"
    $drives = Get-PSDrive -PSProvider FileSystem | Select-Object 'Name', 'Used', 'Free'
    $MappedDrives = '\\serveraddress\lists\.csv' # Add mapped drives CSV
    $WifiSense = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config\AutoConnectAllowedOEM'
    $TestWifiSense = Test-Path $WifiSense  
    $frag = Optimize-Volume -DriveLetter C -Analyze -Verbose
    $AppX = (Get-AppxPackage) | Select-Object Name
    $SoftwarePacks = 'Microsoft Update Health Tools', 'Microsoft Edge' # Add software packages
    $searches = (winget search -q $SoftwarePacks)
    $install = $SoftwarePacks | ForEach-Object {winget install -e $_}
    $GetPorts = (get-nettcpconnection) | Select-Object LocalPort
    $AllPorts = ($GetPorts.LocalPort)
    $GetIP = (Get-NetIPConfiguration) | Select-Object IPv4DefaultGateway
    $NextHop = ($GetIP.IPv4DefaultGateway)
    $socket = (new-object System.Net.Sockets.TcpClient($NextHop.NextHop, $port))
    $updateSession = New-Object -ComObject Microsoft.Update.Session
    $updateSearcher = $updateSession.CreateUpdateSearcher()
    $updatesToDownload = New-Object -ComObject Microsoft.Update.UpdateColl
    $searchResult = $updateSearcher.Search("IsInstalled=0 and Type='Software' and IsHidden=0")
     
    switch -wildcard ($os) 
    {
        "*Linux*" { continue } 
        "*Darwin*" { continue }  
        "*Windows*" {if ($env:COMPUTERNAME -eq $env:CLIENTNAME) { 
            try {# Add local commands here. Use try | catch for errors and add to log file  
                CreateRestorePoint = "if ($LastPoint.CreationTime -le $date){Checkpoint-Computer -Description $date -RestorePointType MODIFY_SETTINGS}else{continue}" # Add restore point
                #BackupPstFiles = "Copy-Item -Path 'C:\Users\*\AppData\Local\Microsoft\Outlook\*.pst' -Destination '\\server\share\OutlookBackups' -Force" # Add PST backup location
                #BackupSystem = "Compress-Archive -Path C:\Windows\System32, C:\Windows\SysWOW64 -DestinationPath $backupFolder\system_backup.zip" # Add system backup location
                #BackupEventLogs = "Get-EventLog -LogName Application, System, Security | Export-Csv $backupFolder\event_logs.csv}" # Add event log backup location
                #BackupUserProfiles = "Compress-Archive -Path C:\Users -DestinationPath $backupFolder\user_profiles_backup.zip" # Add user profile backup location
                UpdateModules = "foreach ($module in $modules){Update-Module -Name $module}" # Add modules to update
                #UpdatePackages = "winget upgrade --all && choco upgrade all -y" # Add package managers to update
                UpdateDrivers = "Update-Driver -All -Force" # Add drivers to update
                ClearTempFiles = "Remove-Item -Path $Env:TEMP\* -Force -Recurse; Remove-Item -Path $Env:LOCALAPPDATA\Temp\* -Force -Recurse" # Add temp file locations
                ClearPageFile  = "if ($PageFile -eq '1'){continue}else{New-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\SessionManager\MemoryManagement -Name ClearPageFileAtShutdown -Value $PFV -PassThru}" # Add page file location
                ClearCaches = "Remove-Item -Path 'C:\Users\$user\AppData\Local\Temp\*' -Force -Recurse | Remove-Item -Path 'C:\Users\$user\AppData\Local\Microsoft\Windows\Explorer\*' -Force -Recurse | Remove-Item -Path 'C:\Users\$user\AppData\Roaming\Microsoft\Windows\Recent\*' -Force -Recurse | Remove-Item -Path 'C:\Windows\Temp\*' -Force -Recurse | Remove-Item -Path 'C:\Windows\prefetch\*' -Force -Recurse | Remove-Item -Path 'C:\Windows\SoftwareDistribution\*' -Force -Recurse | Clear-DnsClientCache | if (Test-Path $edgeCachePath) {Remove-Item $edgeCachePath\* -Force -Recurse}}" # Add cache locations
                ClearRecycleBin = "Clear-RecycleBin -Force" # Add recycle bin location
                CheckFragment = "if ($frag -ge '10'){Optimize-Volume -DriveLetter C -Defrag -Verbose}elseif ($frag -le '10'){continue}" # Add fragmentation percentage
                #CheckMappedDrives = "foreach ($drive in $drives){if ($drive.Provider -eq 'FileSystem' -and $drive.Root -eq $MappedDrives.Root){continue}elseif ($drive.Provider -eq 'FileSystem' -and $drive.Root -ne $MappedDrives.Root){New-PSDrive -Persist -Name '$MappedDrives.Name' -PSProvider 'FileSystem' -Root '$MappedDrives.Root'}}" # Add mapped drives
                CheckUptime = "if ($uptime -ge 1){powercfg /hibernate off}" # Add uptime in days
                #CheckDefaultPrinter = "foreach ($printer in $printers){ Restart-Service -Name Spooler | {$printers.PrintTestPage()}}" # Add default printer
                CheckDNS = "if ($DNS -eq $DNS1, $DNS2){continue}else{Set-DnsClientServerAddress -InterfaceAlias WiFi -ServerAddresses ($DNS1,$DNS2)}" # Add DNS servers
                CheckTimezoneLanguage = "if ($timezoneId -eq $timezone){continue}else{Set-TimeZone '$timezone' | get-winsystemlocale | get-winhomelocation} | if ($WinSysLocale -eq $lang){continue}else{Set-WinSystemLocale $lang} | if ($WinUserLangList -eq $lang){continue}else{Set-WinUserLanguageList $languageList -force | Set-WinUILanguageOverride -Language $lang} | if ($HomeLocation -eq $country){continue}else{Set-WinHomeLocation 0xf2}" # Add timezone and language
                #CheckLifeCycle = "Invoke-RestMethod -Uri $URL -Method Get" # Add URL to check for lifecycle
                #CheckDellCommandUpdate = "Start-Process 'C:\Program Files (x86)\Dell\CommandUpdate\dcu-cli.exe' -RunSilent" # Add Dell Command Update location
                CheckDrivers = "Get-WindowsDriver -Online -All" # Add drivers to check
                CheckWinSysAssessment = "if ($Score.WinSPRLevel -ge '7'){continue}" # Add Windows System Assessment score
                #CheckForIncidents = "Get-EventLog -LogName Security -EntryType Error | Select-Object -Property TimeGenerated, Message" # Add event log to check
                #CheckForIssues = "Get-EventLog -LogName Application -EntryType Error | Select-Object -Property TimeGenerated, Message" # Add event log to check
                #CheckPlug = "if ((Get-WmiObject -Class BatteryStatus).PowerOnline -eq $true) {Write-Host 'Power supply is plugged in.'}else {    Write-Host 'Power supply is not plugged in.'}" # Add check for power supply
                CheckTPMEnabled = "if ($tpm -eq $true){continue}elseif ($tpm -eq $false){Enable-TpmAutoProvisioning}}" # Add check for TPM
                CheckAMSI = "Update-MpSignature -UpdateSource MicrosoftUpdateServer | Set-MpPreference -SignatureScheduleDay Everyday | Start-MpScan -ScanType QuickScan | Remove-MpThreat" # Add check for AMSI
                CheckControlledFolder = "Set-MpPreference -EnableControlledFolderAccess Enabled" # Add check for Controlled Folder Access
                CheckSmartScreen = "Set-MpPreference -EnableSmartScreen Enabled" # Add check for SmartScreen
                CheckDhcpEnabled = "foreach ($adapter in $adapters){if ($dhcp.DHCP -eq 'Enabled'){continue}elseif ($dhcp.DHCP -eq 'Disabled'){Set-NetIPInterface -dhcp --Enabled $LinkStatus.ifIndex #Might need a ForEach statement for each interface number}}" # Add check for DHCP
                #CheckCCTV = "Test-NetConnection -ComputerName '192.168.1.100' -Port 80 | Invoke-WebRequest -Uri 'http://192.168.1.100/'" # Add check for CCTV
                #CheckServiceCrash = "if ($serviceState.Status -ne 'Running') {Write-Host '$serviceName has crashed. Killing the service...' | Stop-Service -Name $serviceName -Force | Start-Service -Name $serviceName | Write-Host '$serviceName has been restarted.'}else {Write-Host '$serviceName is running smoothly.'}" # Add check for service crash
                #CheckDriveHealth = "if ($unhealthyDisks) {Write-Host 'There are unhealthy disks on the system:' $unhealthyDisks | Select-Object MediaType, OperationalStatus, HealthStatus # You can add code here to send an email or alert to the helpdesk} else {Write-Host 'All disks are healthy.'}}" # Add check for drive health
                CheckDiskSpace = "Get-PSDrive | Where-Object { $_.Provider -eq 'FileSystem' } | Select-Object -Property Name, Used, Free, @{ Name='Capacity'; Expression={ $_.Used + $_.Free } } | Format-Table -AutoSize" # Add check for disk space
                CheckCPUUsage = "Get-Counter '\Processor(_Total)\% Processor Time' | Select-Object -ExpandProperty CounterSamples | Select-Object -ExpandProperty CookedValue" # Add check for CPU usage
                CheckMemoryUsage = "Get-Counter '\Memory\Available MBytes' | Select-Object -ExpandProperty CounterSamples | Select-Object -ExpandProperty CookedValue" # Add check for memory usage
                #CheckBackupIntegrity = "Write-Host 'Number of files that passed the integrity test: $($testResult.FilesPassed)'" # Add check for backup integrity
                #CheckFileINtegrity = "Get-FileHash -Path C:\Windows\notepad.exe" # Add check for file integrity
                #CheckPackages = "foreach ($package in $packages){if ($package.Name -eq $CurrentPackages){continue}else{ Install-PackageProvider -Name $package.Name -Force}}" # Add check for packages
                #CheckModules = "if ($modules.Name -eq 'Microsoft.PowerShell.Management' -or 'Microsoft.PowerShell.Security' -or 'Microsoft.PowerShell.Utility' -or 'Microsoft.WSMan.Management'){continue}else{ Install-Module -Name $modules.Name -Scope CurrentUser -Repository PSGallery | Update-Module -Name $modules.Name}" # Add check for modules
                #CheckDomain = "if ($DomainChecker -eq $domain){continue}else{Add-Computer -DomainName $domain -Server 'domain.net\DC01'}" # Add check for domain
                DeleteOldFiles = "Get-ChildItem -Path C:\Users\$user\Downloads\* -Recurse | Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-30) } | Remove-Item -Force" # Add check for old files
                DisableWiFiSense = "if ($TestWifiSense -eq $false){New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config\ -Name AutoConnectAllowedOEM -Value 0 -Force}else{continue}" # Add check for WiFi Sense
                DisableWinFeedbackExp = "If (Test-Path $Advertising) {Set-ItemProperty $Advertising Enabled -Value 0 }" # Add check for Windows Feedback Experience
                DisableFastBoot = "New-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power -Name HiberbootEnabled -Value '0' -PassThru" # Add check for Fast Boot
                DisableSMB = "Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force" # Add check for SMB
                #TestMappedDrives = "Get-PSDrive -PSProvider 'FileSystem' | Where-Object { $_.DisplayRoot -like '\\*\\*' } | ForEach-Object { Test-Path $_.Root }" # Add check for mapped drives
                #TestDomain = "if ($TestDomain -eq $True){continue}else{Test-ComputerSecureChannel -Repair}" # Add check for domain
                #RestartService = "Restart-Service -Name $serviceName" # Add check for service restart
                #FixOfficeApps = "reg delete 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\winword.exe' /f | reg delete 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\outlook.exe' /f | reg delete 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\powerpnt.exe' /f | reg delete 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\excel.exe' /f | reg delete 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\onenote.exe' /f | reg delete 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\mspub.exe' /f | reg delete 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\msaccess.exe' /f" # Add check for Office apps
                #FixBrokenShortcuts = "Get-ChildItem -Path C:\ -Include *.lnk -Recurse -File | ForEach-Object { (New-Object -ComObject WScript.Shell).CreateShortcut($_.FullName).Save() }" # Add check for broken shortcuts
                #OfficeActivation = "Remove-Item HKLM:SOFTWARE\Microsoft\Office\10.0, HKLM:SOFTWARE\Microsoft\Office\12.0, HKLM:SOFTWARE\Microsoft\Office\15.0, HKLM:SOFTWARE\Microsoft\Office\16.0 -Confirm:$false -Force" # Add check for Office activation
                EnableWindowsDefenderSystemGuard = "Set-MpPreference -EnableControlledFolderAccess Enabled -EnableNetworkProtection Enabled" # Add check for Windows Defender System Guard
                EnableLocalSecurityAuthorityProtection = "Set-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\Lsa -Name 'AuditBaseObjects' -Value 1" # Add check for Local Security Authority Protection
                EnableNetworkProtection = "Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True" # Add check for Network Protection
                EnableApplicationGuard = "Enable-WindowsOptionalFeature -Online -FeatureName Windows-Defender-ApplicationGuard" # Add check for Application Guard
                EnableVirtualizationBasedSecurity = "Enable-VTPM" # Add check for Virtualization Based Security
                AuditLogon = "Auditpol.exe /set /category:"Logon/Logoff" /success:enable /failure:enable" # Add check for Logon
                OptimiseSystem = "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management' -Name 'ClearPageFileAtShutdown' -Value 0 | Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management' -Name 'DisablePagingExecutive' -Value 1 | Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy' -Name '01' -Value 1" # Add check for system optimisation
                EnableVBS = "REG ADD 'HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard' /v 'RequirePlatformSecurityFeatures' /t REG_DWORD /d 3 /f | REG ADD 'HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard' /v 'Locked' /t REG_DWORD /d 1 /f | reg add 'HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity' /v 'Locked' /t REG_DWORD /d 1 /f" # Add check for VBS
                VirtualSec = "REG ADD 'HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard' /v 'EnableVirtualizationBasedSecurity' /t REG_DWORD /d 1 /f" # Add check for Virtualization Based Security
                EnableLSAProtection = "REG ADD 'HKLM\SYSTEM\CurrentControlSet\Control\Lsa' /v 'RunAsPPLBoot' /t REG_DWORD /d 2 /f | REG ADD 'HKLM\SYSTEM\CurrentControlSet\Control\Lsa' /v 'RunAsPPL' /t REG_DWORD /d 2 /f" # Add check for LSA Protection
                MaximumPerformance = "powercfg /SETDCVALUEINDEX SCHEME_CURRENT 19cbb8fa-5279-450e-9fac-8a3d5fedd0c1 12bbebe6-58d6-4636-95bb-3217ef867c1a 0 | powercfg /SETACVALUEINDEX SCHEME_CURRENT 19cbb8fa-5279-450e-9fac-8a3d5fedd0c1 12bbebe6-58d6-4636-95bb-3217ef867c1a 0 | powercfg /change monitor-timeout-ac 0 | powercfg /change monitor-timeout-dc 0 | powercfg /change disk-timeout-ac 0 | powercfg /change disk-timeout-dc 0 | powercfg /change standby-timeout-ac 0 | powercfg /change standby-timeout-dc 0" # Add check for Maximum Performance
                ActiveHours = "if (($HoursStart -eq $start) -and ($HoursEnd -eq $finish)){continue}else{New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings -Name ActiveHoursStart -Value $start -PassThru | New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings -Name ActiveHoursEnd -Value $finish -PassThru}" # Add check for Active Hours
                RunDISM = "Repair-WindowsImage -Online -RestoreHealth" # Add check for DISM
                RunSFC = "sfc /scannow" # Add check for SFC
                #HiddenFile = "Get-ChildItem -Path C:\ -Force -Recurse -ErrorAction SilentlyContinue | ForEach-Object {if ($_.Attributes -match 'Hidden') {}}" # Add check for hidden files
                #RunGPUpdate = "GPUpdate /Force" # Add check for GPUpdate
                #RunSoftwareDebloater = "if ($AppX.Name -eq 'Microsoft.DesktopAppInstaller'){continue}else{Add-AppxPackage -RegisterByFamilyName -MainPackage Microsoft.DesktopAppInstaller_8wekyb3d8bbwe} | winget source update | foreach ($search in $searches){if ($searches -eq $search){continue}else{winget install -q $install}} | winget upgrade --all --include-unknown --verbose-logs" # Add check for Software Debloater
                }
        } 
         catch 
         {
          # Log the errors
          $ErrorMessage = $_.Exception.Message 
          $FailedItem = $_.Exception.ItemName 
          Write-Host "Error: $ErrorMessage" -ForegroundColor Red 
          Write-Host "Failed Item: $FailedItem" -ForegroundColor Red 
          }
        } 
        else 
        {
         # Add remote commands here 
        }
    }

    # Conditions for Alerts
    $condition = (
    $searchResult.Updates.Count -gt 0 -xor # If updates are greater than 0, alert helpdesk.
    $frag -ge '10' -xor # If fragmentation is greater than 10%, alert helpdesk.
    $req.StatusCode -eq $BadStatusCodes -xor # If status code is equal to the bad status codes list, alert helpdesk.
    $Score.WinSPRLevel -ge '7' -xor # If score is less than 7, alert helpdesk.
    $check -eq $false -xor # If check is false, alert helpdesk.
    $tag -ne 'TAG_NAME' -and # If tag is not equal to the tag in the database, alert helpdesk.
    $computer -ne 'COMPUTER_NAME' -and # If computer name is not equal to the computer name in the database, alert helpdesk.
    $description -ne 'COMPUTER_DESCRIPTION' -xor # If description is not equal to the description in the database, alert helpdesk.
    $SerialNo -ne $serial -xor # If serial number is not equal to the serial number in the database, alert helpdesk.
    $acls.Owner -ne '$OwnerAccess.Owner' -xor # If owner is not equal to the owner in the database, alert helpdesk.
    $acls.Access -ne '$OwnerAccess.Access' -xor # If owner access is not equal to the owner access in the database, alert helpdesk.
    $ports.State -eq 'Established Internet' -and # If port is established internet, alert helpdesk.
    $ports.LocalPort -ne $ActivePorts -xor # If local port is not in the active ports list, alert helpdesk.
    $SysUsers -and # If system user is not in the system user list, alert helpdesk.
    $System -ne $SysUserList.User -and # If system user is not in the system user list, alert helpdesk.
    $SysUserList.System -xor # If system user is not in the system user list, alert helpdesk.
    $speed -ge '1' -xor # If speed is less than 1, alert helpdesk.
    $SerialNo -ne '$serial' -xor # If serial number is not equal to the serial number in the database, alert helpdesk.
    $drivers.Date -le $date -xor # If driver is older than 1 year, alert helpdesk.
    $LastPoint -eq 'The last attempt to restore the computer failed.' -xor # If last restore point failed, alert helpdesk.
    $uptime -ge 100 -xor # If uptime is greater than 100 days, alert helpdesk.
    $battery -eq 'BAD' -xor # If battery is bad, alert helpdesk.
    $DomainChecker -eq 'WORKGROUP' -xor # If computer is not on the domain, alert helpdesk.
    $Ping.Timeout -ge '40000' -xor # If ping timeout is greater than 40 seconds, alert helpdesk.
    $secboot -eq $false -xor # If secure boot is disabled, alert helpdesk.
    $uptime -ge '24:00:00.0000000' -xor # If uptime is greater than 24 hours, alert helpdesk.
    $FreeSpace -le '0.100000000000000' -xor # If free space is less than 100MB, alert helpdesk.
    $pro -ge '99.0' -xor # If CPU usage is greater than 99%, alert helpdesk.
    $mem -le '1000' -xor # If memory is less than 1GB, alert helpdesk.
    $temp -ge '60.00' -xor # If CPU temperature is greater than 60 degrees, alert helpdesk.
    $lock.ProtectionStatus -eq 'Off' -xor # If Bitlocker is disabled, alert helpdesk.
    $AV.AntivirusEnabled -eq $false -xor # If antivirus is disabled, alert helpdesk.
    $repair -eq 'ErrorsFound' -xor # If DISM or SFC finds errors, alert helpdesk.
    $log.LevelDisplayName -eq 'Critical' # If critical event is found in event log, alert helpdesk.
    )
    # If condition is true, alert helpdesk.
    if ($condition) {  
    # Create csv output file for detected issues and attach to email alert for technicians. Create a separate csv file for issues users can resolve themselves. 
    Send-MailMessage -SmtpServer $smtpServer -From $from -To $to -Subject $subject -Body $body $attachment -BodyAsHtml -Priority High
}

Export-ModuleMember -Function 'Run_Maintenance' -Alias 'runmain' 
