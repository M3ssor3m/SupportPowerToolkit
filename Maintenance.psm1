function Run_Maintenance {

    # Modules
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
    $smtpServer = "your.smtp.server"
    $from = "your.email@domain.com"
    $to = "helpdesk@domain.com"
    $subject = "Alert: Errors found on $computer"
    $body = "Please check report for $computer on $date"
    $attachment = "C:\Temp\MaintenanceLog.txt"
    $LogPath = "C:\Temp\MaintenanceLog.txt" #Add log path 
    $credentials = (Get-Credential)
    $os = $PSVersionTable.OS
    $user = (Get-CimInstance -ClassName Win32_ComputerSystem).PrimaryOwnerName
    $modules = Get-Module | Select-Object 'Name'
    $date = Get-Date
    $drivers = Get-WindowsDriver -Online -All | Select-Object 'Driver', 'Date', 'Version'
    $LastPoint = Get-ComputerRestorePoint -LastStatus
    $backupPath = "C:\Backup" # Set backup path
    $testResult = Test-FileIntegrity -Path $backupPath
    $Shortcuts = Get-ChildItem -Recurse "C:\" -Include *.lnk -Force
    $CurrentPackages = get-packageprovider
    $packages = \\fileserver\csv\packages.csv # Add packages CSV
    $repo =  # Add repository CSV 
    $domain = 'domain.net' # Set domain address
    $DomainChecker = Get-CimInstance -ClassName Win32_ComputerSystem | Select-Object domain
    $TestDomain = Test-ComputerSecureChannel -Server 'domain.net\DC01' # Add DC address
    $RequestStatus = Invoke-WebRequest -uri "https://portal.domain.net/" # Set URL of webpage to test status
    $GoodStatus = '200' # Add good web status
    $BadStatusCodes = '404', '500', '502', '503' # Add bad web status
    $start = '9' # Set start time for Active Hours
    $finish = '9' # Set finish time for Active Hours
    $HoursStart = Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings -Name ActiveHoursStart
    $HoursEnd = Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings -Name ActiveHoursEnd
    $PFV = '1'
    $PageFile = Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\SessionManager\MemoryManagement -Name ClearPageFileAtShutdown
    $edgeCachePath = "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Cache"
    $Directory = "C:\DeletedFiles" # Add location for file recovery
    $Extension = "*.txt" # Add extension for file recovery
    $DeletedFiles = Get-ChildItem -Path $Directory -Include $Extension -Recurse -Force -ErrorAction SilentlyContinue | Where-Object { $_.PSIsContainer -eq $false -and $_.IsDeleted -eq $true }
    $pro = Get-CimInstance -ClassName Win32_Processor | Select-Object -ExpandProperty Name
    $mem = Get-CimInstance -ClassName Win32_OperatingSystem | Select-Object -ExpandProperty FreePhysicalMemory | ForEach-Object { $_ / 1MB }
    $SerialNo = Get-WmiObject -Class Win32_BIOS | Select-Object -ExpandProperty SerialNumber
    $description = Get-WmiObject -Class Win32_OperatingSystem | Select-Object 'Description'
    $tag = Get-WmiObject -Class Win32_SystemEnclosure | Select-Object -ExpandProperty SMBIOSAssetTag
    $DiskSpace = Get-WmiObject -Class Win32_logicalDisk | Where-Object {$_.DeviceID -eq 'C:'}
    $FreeSpace = $DiskSpace.FreeSpace / $DiskSpace.Size
    $physicalDisks = Get-PhysicalDisk
    $unhealthyDisks = $physicalDisks | Where-Object {$_.HealthStatus -ne "Healthy"}
    $serviceName = "" # Add service CSV
    $serviceState = Get-Service -Name $serviceName
    $computer = $env:COMPUTERNAME # Old var called 'name'
    $temp = Get-WmiObject -Namespace root\wmi -Class MSAcpi_ThermalZoneTemperature -ComputerName $computer
    $LinkStatus = Get-NetAdapter | Where-Object -FilterScript {$_.Status -Eq "Up"}
    $adapters = Get-NetIPConfiguration -Detailed | Select-Object InterfaceAlias, @{N="DHCP";E={$_.NetIPv4Interface.DHCP}}
    $lock = Get-BitLockerVolume -MountPoint "C:" |  Select-Object volumetype, protectionstatus -Verbose # Add foreach loop to check multiple drives
    $AV = Get-MpComputerStatus
    $Score = Get-CimInstance Win32_WinSat
    $tpm = get-tpm | Select-Object 'TpmEnabled'
    $OwnerAccess =  # Add user CSV
    $acls = Get-Acl -Path C:\
    $secboot = Confirm-SecureBootUefi
    $repair = Repair-Volume -DriveLetter C -Scan
    $SerialNumber = Get-CimInstance Win32_BIOS | Select-Object -ExpandProperty SerialNumber
    $APIKey = "your_api_key_here" # Add Dell API 
    $URL = "https://api.dell.com/support/v2/assetinfo/warranty/status?apikey=$APIKey&servicetags=$SerialNumber"
    $lang = 'en-GB'
    $country = 'United Kingdom'
    $timezone = 'GMT Standard Time'
    $timezoneId = get-timezone | Select-Object Id
    $WinSysLocale = get-WinSystemLocale | Select-Object Name
    $WinUserLangList = get-WinUserLanguageList | Select-Object LanguageTag
    $HomeLocation = get-WinHomeLocation | Select-Object 'HomeLocation'
    $languageList = New-WinUserLanguageList $lang
    $languageList[0].Handwriting = 1
    $DefaultGateway = get-netipconfiguration
    $Addresses = $DefaultGateway.IPv4DefaultGateway | Select-Object NextHop
    $Ping = Test-Connection $Addresses -Count 1  # Increase or decrease pings
    $DNS1 = '9.9.9.11' # Add DNS 1 address
    $DNS2 = '142.112.112.11' # Add DNS 2 address
    $DNS = Get-DnsClientServerAddress
    $battery = Get-CimInstance -ClassName CIM_Battery | Select-Object 'Status'
    $LogDate = (get-date) - (New-TimeSpan -Day 1) # Increase or decrease logdate
    $logs = get-winevent | Where-Object {$_.LevelDisplayName -eq $LogDate, 'Critical'} # Add or change status 
    $printers = Get-WmiObject -Query " SELECT * FROM Win32_Printer WHERE Default=$true"
    $uptime = Get-Uptime
    $Advertising = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo"
    $Period = "HKCU:\Software\Microsoft\Siuf\Rules"
    $drives = Get-PSDrive
    $MappedDrives = '\\serveraddress\lists\.csv' # Add active ports CSV
    $WifiSense = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config\AutoConnectAllowedOEM'
    $TestWifiSense = Test-Path $WifiSense
    $frag = Optimize-Volume -DriveLetter C -Analyze
    $AppX = (Get-AppxPackage)
    $SoftwarePacks = 'Microsoft Update Health Tools', 'Microsoft Edge' #Add software CSV
    $searches = (winget search -q $SoftwarePacks)
    $install = $SoftwarePacks
    $GetPorts = (get-nettcpconnection)
    $AllPorts = ($GetPorts.LocalPort)
    $GetIP = (Get-NetIPConfiguration)
    $NextHop = ($GetIP.IPv4DefaultGateway)
    $socket = (new-object System.Net.Sockets.TcpClient($NextHop.NextHop, $port))
    $updateSession = New-Object -ComObject Microsoft.Update.Session
    $updateSearcher = $updateSession.CreateUpdateSearcher()
    $updatesToDownload = New-Object -ComObject Microsoft.Update.UpdateColl
    $searchResult = $updateSearcher.Search("IsInstalled=0 and Type='Software' and IsHidden=0")

     if ($os -like "*Linux*") 
     {continue}
     elseif ($os -like "*Darwin*") 
     {continue}
     elseif ($os -like "*Windows*") 
     {
      if ($env:COMPUTERNAME -eq $env:CLIENTNAME) 
      { # Add local commands here. Use try | catch for errors and add to log file 
        CreateRestorePoint = "if ($LastPoint.CreationTime -le $date){Checkpoint-Computer -Description $date -RestorePointType MODIFY_SETTINGS}else{continue}"
        #BackupPstFiles = "Copy-Item -Path 'C:\Users\*\AppData\Local\Microsoft\Outlook\*.pst' -Destination '\\server\share\OutlookBackups' -Force"
        #BackupSystem = "Compress-Archive -Path C:\Windows\System32, C:\Windows\SysWOW64 -DestinationPath $backupFolder\system_backup.zip"
        #BackupEventLogs = "Get-EventLog -LogName Application, System, Security | Export-Csv $backupFolder\event_logs.csv}"
        #BackupUserProfiles = "Compress-Archive -Path C:\Users -DestinationPath $backupFolder\user_profiles_backup.zip"
        UpdateModules = "foreach ($module in $modules){Update-Module -Name $module}"
        #UpdatePackages = "winget upgrade --all && choco upgrade all -y" #Choco not installed and is thrid party 
        UpdateDrivers = "Update-Driver -All -Force"
        ClearTempFiles = "Remove-Item -Path $Env:TEMP\* -Force -Recurse; Remove-Item -Path $Env:LOCALAPPDATA\Temp\* -Force -Recurse"
        ClearPageFile  = "if ($PageFile -eq '1'){continue}else{New-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\SessionManager\MemoryManagement -Name ClearPageFileAtShutdown -Value $PFV -PassThru}"
        ClearCaches = "Remove-Item -Path 'C:\Users\$user\AppData\Local\Temp\*' -Force -Recurse | Remove-Item -Path 'C:\Users\$user\AppData\Local\Microsoft\Windows\Explorer\*' -Force -Recurse | Remove-Item -Path 'C:\Users\$user\AppData\Roaming\Microsoft\Windows\Recent\*' -Force -Recurse | Remove-Item -Path 'C:\Windows\Temp\*' -Force -Recurse | Remove-Item -Path 'C:\Windows\prefetch\*' -Force -Recurse | Remove-Item -Path 'C:\Windows\SoftwareDistribution\*' -Force -Recurse | Clear-DnsClientCache | if (Test-Path $edgeCachePath) {Remove-Item $edgeCachePath\* -Force -Recurse}}"
        ClearRecycleBin = "Clear-RecycleBin -Force"
        CheckFragment = "if ($frag -ge '10'){Optimize-Volume -DriveLetter C -Defrag -Verbose}elseif ($frag -le '10'){continue}"
        #CheckMappedDrives = "foreach ($drive in $drives){if ($drive.Provider -eq 'FileSystem' -and $drive.Root -eq $MappedDrives.Root){continue}elseif ($drive.Provider -eq 'FileSystem' -and $drive.Root -ne $MappedDrives.Root){New-PSDrive -Persist -Name '$MappedDrives.Name' -PSProvider 'FileSystem' -Root '$MappedDrives.Root'}}"
        CheckUptime = "if ($uptime -ge 1){powercfg /hibernate off}"
        #CheckDefaultPrinter = "foreach ($printer in $printers){ Restart-Service -Name Spooler | {$printers.PrintTestPage()}}"
        CheckDNS = "if ($DNS -eq $DNS1, $DNS2){continue}else{Set-DnsClientServerAddress -InterfaceAlias WiFi -ServerAddresses ($DNS1,$DNS2)}"
        CheckTimezoneLanguage = "if ($timezoneId -eq $timezone){continue}else{Set-TimeZone '$timezone' | get-winsystemlocale | get-winhomelocation} | if ($WinSysLocale -eq $lang){continue}else{Set-WinSystemLocale $lang} | if ($WinUserLangList -eq $lang){continue}else{Set-WinUserLanguageList $languageList -force | Set-WinUILanguageOverride -Language $lang} | if ($HomeLocation -eq $country){continue}else{Set-WinHomeLocation 0xf2}"
        #CheckLifeCycle = "Invoke-RestMethod -Uri $URL -Method Get"
        #CheckDellCommandUpdate = "Start-Process 'C:\Program Files (x86)\Dell\CommandUpdate\dcu-cli.exe' -RunSilent"
        CheckDrivers = "Get-WindowsDriver -Online -All"
        CheckWinSysAssessment = "if ($Score.WinSPRLevel -ge '7'){continue}"
        #CheckForIncidents = "Get-EventLog -LogName Security -EntryType Error | Select-Object -Property TimeGenerated, Message"
        #CheckForIssues = "Get-EventLog -LogName Application -EntryType Error | Select-Object -Property TimeGenerated, Message"
        #CheckPlug = "if ((Get-WmiObject -Class BatteryStatus).PowerOnline -eq $true) {Write-Host 'Power supply is plugged in.'}else {    Write-Host 'Power supply is not plugged in.'}"
        CheckTPMEnabled = "if ($tpm -eq $true){continue}elseif ($tpm -eq $false){Enable-TpmAutoProvisioning}}"
        CheckAMSI = "Update-MpSignature -UpdateSource MicrosoftUpdateServer | Set-MpPreference -SignatureScheduleDay Everyday | Start-MpScan -ScanType QuickScan | Remove-MpThreat"
        CheckControlledFolder = "Set-MpPreference -EnableControlledFolderAccess Enabled"
        CheckSmartScreen = "Set-MpPreference -EnableSmartScreen Enabled"
        CheckDhcpEnabled = "foreach ($adapter in $adapters){if ($dhcp.DHCP -eq 'Enabled'){continue}elseif ($dhcp.DHCP -eq 'Disabled'){Set-NetIPInterface -dhcp --Enabled $LinkStatus.ifIndex #Might need a ForEach statement for each interface number}}"
        #CheckCCTV = "Test-NetConnection -ComputerName '192.168.1.100' -Port 80 | Invoke-WebRequest -Uri 'http://192.168.1.100/'"
        #CheckServiceCrash = "if ($serviceState.Status -ne 'Running') {Write-Host '$serviceName has crashed. Killing the service...' | Stop-Service -Name $serviceName -Force | Start-Service -Name $serviceName | Write-Host '$serviceName has been restarted.'}else {Write-Host '$serviceName is running smoothly.'}"
        #CheckDriveHealth = "if ($unhealthyDisks) {Write-Host 'There are unhealthy disks on the system:' $unhealthyDisks | Select-Object MediaType, OperationalStatus, HealthStatus # You can add code here to send an email or alert to the helpdesk} else {Write-Host 'All disks are healthy.'}}"
        CheckDiskSpace = "Get-PSDrive | Where-Object { $_.Provider -eq 'FileSystem' } | Select-Object -Property Name, Used, Free, @{ Name='Capacity'; Expression={ $_.Used + $_.Free } } | Format-Table -AutoSize"
        CheckCPUUsage = "Get-Counter '\Processor(_Total)\% Processor Time' | Select-Object -ExpandProperty CounterSamples | Select-Object -ExpandProperty CookedValue"
        CheckMemoryUsage = "Get-Counter '\Memory\Available MBytes' | Select-Object -ExpandProperty CounterSamples | Select-Object -ExpandProperty CookedValue"
        #CheckBackupIntegrity = "Write-Host 'Number of files that passed the integrity test: $($testResult.FilesPassed)'"
        #CheckFileINtegrity = "Get-FileHash -Path C:\Windows\notepad.exe"
        #CheckPackages = "foreach ($package in $packages){if ($package.Name -eq $CurrentPackages){continue}else{ Install-PackageProvider -Name $package.Name -Force}}"
        #CheckModules = "if ($modules.Name -eq 'Microsoft.PowerShell.Management' -or 'Microsoft.PowerShell.Security' -or 'Microsoft.PowerShell.Utility' -or 'Microsoft.WSMan.Management'){continue}else{ Install-Module -Name $modules.Name -Scope CurrentUser -Repository PSGallery | Update-Module -Name $modules.Name}"
        #CheckDomain = "if ($DomainChecker -eq $domain){continue}else{Add-Computer -DomainName $domain -Server 'domain.net\DC01'}"
        DeleteOldFiles = "Get-ChildItem -Path C:\Users\$user\Downloads\* -Recurse | Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-30) } | Remove-Item -Force"
        DisableWiFiSense = "if ($TestWifiSense -eq $false){New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config\ -Name AutoConnectAllowedOEM -Value 0 -Force}else{continue}"
        DisableWinFeedbackExp = "If (Test-Path $Advertising) {Set-ItemProperty $Advertising Enabled -Value 0 }"
        DisableFastBoot = "New-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power -Name HiberbootEnabled -Value '0' -PassThru"
        DisableSMB = "Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force"         
        #TestMappedDrives = "Get-PSDrive -PSProvider 'FileSystem' | Where-Object { $_.DisplayRoot -like '\\*\\*' } | ForEach-Object { Test-Path $_.Root }"
        #TestDomain = "if ($TestDomain -eq $True){continue}else{Test-ComputerSecureChannel -Repair}"
        #RestartService = "Restart-Service -Name $serviceName"
        #FixOfficeApps = "reg delete 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\winword.exe' /f | reg delete 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\outlook.exe' /f | reg delete 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\powerpnt.exe' /f | reg delete 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\excel.exe' /f | reg delete 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\onenote.exe' /f | reg delete 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\mspub.exe' /f | reg delete 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\msaccess.exe' /f"
        #FixBrokenShortcuts = "Get-ChildItem -Path C:\ -Include *.lnk -Recurse -File | ForEach-Object { (New-Object -ComObject WScript.Shell).CreateShortcut($_.FullName).Save() }"
        #OfficeActivation = "Remove-Item HKLM:SOFTWARE\Microsoft\Office\10.0, HKLM:SOFTWARE\Microsoft\Office\12.0, HKLM:SOFTWARE\Microsoft\Office\15.0, HKLM:SOFTWARE\Microsoft\Office\16.0 -Confirm:$false -Force"
        EnableWindowsDefenderSystemGuard = "Set-MpPreference -EnableControlledFolderAccess Enabled -EnableNetworkProtection Enabled"
        EnableLocalSecurityAuthorityProtection = "Set-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\Lsa -Name 'AuditBaseObjects' -Value 1"
        EnableNetworkProtection = "Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True"
        EnableApplicationGuard = "Enable-WindowsOptionalFeature -Online -FeatureName Windows-Defender-ApplicationGuard"
        EnableVirtualizationBasedSecurity = "Enable-VTPM"
        AuditLogon = "Auditpol.exe /set /category:"Logon/Logoff" /success:enable /failure:enable"
        OptimiseSystem = "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management' -Name 'ClearPageFileAtShutdown' -Value 0 | Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management' -Name 'DisablePagingExecutive' -Value 1 | Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy' -Name '01' -Value 1"
        EnableVBS = "REG ADD 'HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard' /v 'RequirePlatformSecurityFeatures' /t REG_DWORD /d 3 /f | REG ADD 'HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard' /v 'Locked' /t REG_DWORD /d 1 /f | reg add 'HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity' /v 'Locked' /t REG_DWORD /d 1 /f"
        VirtualSec = "REG ADD 'HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard' /v 'EnableVirtualizationBasedSecurity' /t REG_DWORD /d 1 /f"
        EnableLSAProtection = "REG ADD 'HKLM\SYSTEM\CurrentControlSet\Control\Lsa' /v 'RunAsPPLBoot' /t REG_DWORD /d 2 /f | REG ADD 'HKLM\SYSTEM\CurrentControlSet\Control\Lsa' /v 'RunAsPPL' /t REG_DWORD /d 2 /f"
        MaximumPerformance = "powercfg /SETDCVALUEINDEX SCHEME_CURRENT 19cbb8fa-5279-450e-9fac-8a3d5fedd0c1 12bbebe6-58d6-4636-95bb-3217ef867c1a 0 | powercfg /SETACVALUEINDEX SCHEME_CURRENT 19cbb8fa-5279-450e-9fac-8a3d5fedd0c1 12bbebe6-58d6-4636-95bb-3217ef867c1a 0 | powercfg /change monitor-timeout-ac 0 | powercfg /change monitor-timeout-dc 0 | powercfg /change disk-timeout-ac 0 | powercfg /change disk-timeout-dc 0 | powercfg /change standby-timeout-ac 0 | powercfg /change standby-timeout-dc 0"
        ActiveHours = "if (($HoursStart -eq $start) -and ($HoursEnd -eq $finish)){continue}else{New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings -Name ActiveHoursStart -Value $start -PassThru | New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings -Name ActiveHoursEnd -Value $finish -PassThru}"
        RunDISM = "Repair-WindowsImage -Online -RestoreHealth"
        RunSFC = "sfc /scannow"
        #HiddenFile = "Get-ChildItem -Path C:\ -Force -Recurse -ErrorAction SilentlyContinue | ForEach-Object {if ($_.Attributes -match 'Hidden') {}}"
        #RunGPUpdate = "GPUpdate /Force"
        #RunSoftwareDebloater = "if ($AppX.Name -eq 'Microsoft.DesktopAppInstaller'){continue}else{Add-AppxPackage -RegisterByFamilyName -MainPackage Microsoft.DesktopAppInstaller_8wekyb3d8bbwe} | winget source update | foreach ($search in $searches){if ($searches -eq $search){continue}else{winget install -q $install}} | winget upgrade --all --include-unknown --verbose-logs"
      }
      else # Add remote commands here 
      {continue}
     }
             
 # Alert helpdesk to issues via email
 if ($searchResult.Updates.Count -gt 0 -xor $frag -ge '10' -xor $req.StatusCode -eq $BadStatusCodes -xor $Score.WinSPRLevel -ge '7' -xor $check -eq $false -xor $tag -ne '' -and $computer -ne '' -and $description -ne '' -xor $SerialNo -ne $serial -xor $acls.Owner -ne '$OwnerAccess.Owner' -xor $acls.Access -ne '$OwnerAccess.Access' -xor $ports.State -eq 'Established Internet' -and $ports.LocalPort -ne $ActivePorts -xor $SysUsers -and $System -ne $SysUserList.User -and $SysUserList.System -xor $speed -ge '1' -xor $SerialNo -ne '$serial' -xor $drivers.Date -le $date -xor $LastPoint -eq 'The last attempt to restore the computer failed.' -xor $uptime -ge 100 -xor $battery -eq 'BAD' -xor $DomainChecker -eq 'WORKGROUP'  -xor $Ping.Timeout -ge '40000' -xor $secboot -eq $false -xor $uptime -ge '24:00:00.0000000' -xor $FreeSpace -le '0.100000000000000' -xor $pro -ge '99.0' -xor $mem -le '1000' -xor $temp -ge '60.00' -xor $lock.ProtectionStatus -eq 'Off' -xor $AV.AntivirusEnabled -eq $false -xor $repair -eq 'ErrorsFound' -xor $log.LevelDisplayName -eq 'Critical')  
 {
    # Create csv output file for detected issues and attach to email alert for technicians. Cretae a seperate csv file for issues users can resolve themselves. 
    Send-MailMessage -SmtpServer $smtpServer -From $from -To $to -Subject $subject -Body $body $attachment -BodyAsHtml -Priority High       
 }
 
}

Export-ModuleMember -Function 'Run_Maintenance' -Alias 'runmain'
