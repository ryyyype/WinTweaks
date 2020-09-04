Write-Output "Network Tweaks"

Write-Output "Get Connected Physical Network Adapters (Ethernet/Wifi)"
$NetAdapters = Get-NetAdapterHardwareInfo | Get-NetAdapter | Where-Object {$_.Status -eq "Up"}
foreach ($NetAdapter in $NetAdapters) {
    Write-Output "Found $($NetAdapter.InterfaceDescription) ($($NetAdapter.Name))"
}

Write-Output "Disable TCP Chimney Offload"
Set-NetOffloadGlobalSetting -Chimney Disabled -ErrorAction SilentlyContinue | Out-Null
Write-Output "Disable Packet Coalescing"
Set-NetOffloadGlobalSetting -PacketCoalescingFilter Disabled -ErrorAction SilentlyContinue | Out-Null
Write-Output "Disable Receive Segment Coalescing State (RSC)"
Set-NetOffloadGlobalSetting -ReceiveSegmentCoalescing Disabled -ErrorAction SilentlyContinue | Out-Null
$NetAdapters | Disable-NetAdapterRsc -ErrorAction SilentlyContinue | Out-Null
Write-Output "Disable Large Send Offload (LSO)"
$NetAdapters | Disable-NetAdapterLso -ErrorAction SilentlyContinue | Out-Null
Write-Output "Disable Checksum Offload"
$NetAdapters | Disable-NetAdapterChecksumOffload -ErrorAction SilentlyContinue | Out-Null
Write-Output "Disable Power Management"
$NetAdapters | Disable-NetAdapterPowerManagement -ErrorAction SilentlyContinue | Out-Null

foreach ($NetAdapter in $NetAdapters) {
    if ((Get-NetAdapterRss).Name -contains $NetAdapter.Name) {
        if ((Get-SmbClientNetworkInterface | Where-Object {$_.InterfaceIndex -eq $NetAdapter.InterfaceIndex}).RssCapable -eq $false) {
            Write-Output "Disable Receive-Side Scaling State (RSS)"
            $NetAdapter | Disable-NetAdapterRss -ErrorAction SilentlyContinue | Out-Null
        } else {
            Write-Output "Enable Receive-Side Scaling State (RSS)"
            $NetAdapter | Enable-NetAdapterRss -ErrorAction SilentlyContinue | Out-Null
            $TMPDisplayName = ($NetAdapter | Get-NetAdapterAdvancedProperty -RegistryKeyword "*NumRssQueues").DisplayName
            $MaxNumRssQueues = [int](($NetAdapter | Get-NetAdapterAdvancedProperty -RegistryKeyword "*NumRssQueues").ValidRegistryValues | Measure-Object -Maximum).Maximum
            Write-Output "Set $TMPDisplayName to $MaxNumRssQueues (Max)"
            $NetAdapter | Set-NetAdapterAdvancedProperty -RegistryKeyword "*NumRssQueues" -RegistryValue $MaxNumRssQueues -ErrorAction SilentlyContinue
        }
    }
}

$SettingNames = @(
    "Internet"
    "InternetCustom"
)
foreach ($SettingName in $SettingNames) {
    Write-Output "Set Network TCP Settings For Template: $SettingName"
    Write-Output "Set Add-On Congestion Control Provider To CTCP"
    netsh int tcp set supplemental "$SettingName" congestionprovider=ctcp | Out-Null
    Write-Output "Set InitialCongestionWindow (ICW) To 10"
    Set-NetTCPSetting -SettingName "$SettingName" -InitialCongestionWindow 10 -ErrorAction SilentlyContinue | Out-Null
    Write-Output "Set Receive Window Auto-Tuning Level To Normal"
    Set-NetTCPSetting -SettingName "$SettingName" -AutoTuningLevelLocal Normal -ErrorAction SilentlyContinue | Out-Null
    Write-Output "Enable ECN Capability"
    Set-NetTCPSetting -SettingName "$SettingName" -EcnCapability Enabled -ErrorAction SilentlyContinue | Out-Null
    Write-Output "Disable TCP 1323 Timestamps"
    Set-NetTCPSetting -SettingName "$SettingName" -Timestamps Disabled -ErrorAction SilentlyContinue | Out-Null
    Write-Output "Disable Windows Scaling heuristics"
    Set-NetTCPSetting -SettingName "$SettingName" -ScalingHeuristics Disabled -ErrorAction SilentlyContinue | Out-Null
    Write-Output "Disable Non Sack RTT Resiliency"
    Set-NetTCPSetting -SettingName "$SettingName" -NonSackRttResiliency Disabled -ErrorAction SilentlyContinue | Out-Null
    Write-Output "Set Max SYN Retransmissions to 2"
    Set-NetTCPSetting -SettingName "$SettingName" -MaxSynRetransmissions 2 -ErrorAction SilentlyContinue | Out-Null
}

Write-Output "Set InitialRTO To 2000"
netsh int tcp set global initialRto=2000 | Out-Null

foreach ($NetAdapter in $NetAdapters) {
    Write-Output "Set ECN Marking To UseEct1 On $($NetAdapter.Name)"
    $NetAdapter | Set-NetIPInterface -EcnMarking UseEct1 | Out-Null
}

Write-Output "Test To Find Max MTU Value (This Can Take A While...)"
$MaxMTU = 1500
for ($i = 1472; $i -ge 548; $i--) {
    $ErrorOccured = $false
    try 
    { 
        Test-Connection "www.google.com" -BufferSize $i -Count 1 -ErrorAction Stop | Out-Null
    }
    catch
    {
        $ErrorOccured=$true
    }

    if(!$ErrorOccured) {
        $MaxMTU = $i + 28
        break
    }
}

foreach ($NetAdapter in $NetAdapters) {
    Write-Output "Set MTU to $MaxMTU on $($NetAdapter.Name)"
    $NetAdapter | Set-NetIPInterface -NlMtuBytes $MaxMTU | Out-Null
}

Write-Output "Set Current DHCP IPv4 Address To Static IPv4 Address"
foreach ($NetAdapter in $NetAdapters) {
    $IPType = "IPv4"
    if (($NetAdapter | Get-NetIPInterface | Where-Object {$_.AddressFamily -eq $IPType -and $_.ConnectionState -eq "Connected"}).Dhcp -eq "Enabled") {
        $IPv4Address = ($NetAdapter | Get-NetIPConfiguration).IPv4Address.IPAddress
        $IPv4SubnetMaskBits = [int]($NetAdapter | Get-NetIPConfiguration).IPv4Address.PrefixLength
        $IPv4DefaultGateway = ($NetAdapter | Get-NetIPConfiguration).IPv4DefaultGateway.NextHop
        $IPv4Dns = ($NetAdapter | Get-DnsClientServerAddress -AddressFamily $IPType).ServerAddresses
        Write-Output "Current Address:   $($IPv4Address)/$($IPv4SubnetMaskBits)"
        Write-Output "Default Gateway:   $($IPv4DefaultGateway)"
        Write-Output "DNS Client Server: $($IPv4Dns)"
        
        if (($NetAdapter | Get-NetIPConfiguration).IPv4Address.IPAddress) {
            $NetAdapter | Remove-NetIPAddress -AddressFamily $IPType -Confirm:$false | Out-Null
        }
        if (($NetAdapter | Get-NetIPConfiguration).Ipv4DefaultGateway) {
            $NetAdapter | Remove-NetRoute -AddressFamily $IPType -Confirm:$false | Out-Null
        }
        
        $NetAdapter | New-NetIPAddress `
            -AddressFamily $IPType `
            -IPAddress $IPv4Address `
            -PrefixLength $IPv4SubnetMaskBits `
            -DefaultGateway $IPv4DefaultGateway | Out-Null
        
        $NetAdapter | Set-DnsClientServerAddress -ServerAddresses $IPv4Dns | Out-Null
    } else {
        Write-Output "$($NetAdapter.Name) Has Already A Static IP Address"
    }
}

$componentIDs = @(
    "ms_lldp"
    "ms_lltdio"
    "ms_implat"
    "ms_server"
    "ms_tcpip6"
    "ms_rspndr"
)
foreach ($NetAdapter in $NetAdapters) {
    foreach ($componentID in $componentIDs) {
        if (($NetAdapter | Get-NetAdapterbinding).ComponentID -contains $componentID) {
            $TMPDisplayName = ($NetAdapter | Get-NetAdapterbinding | Where-Object ComponentID -eq "$componentID").DisplayName
            Write-Output "Disable Network Adapter ($($NetAdapter.Name)) Component: $TMPDisplayName"
            $NetAdapter | Disable-NetAdapterBinding -ComponentID $componentID -ErrorAction SilentlyContinue | Out-Null
        }
    }
}

Write-Output "Disable all ISATAP, 6to4 and Teredo Tunneling interfaces"
Set-NetIsatapConfiguration -State Disabled -ErrorAction SilentlyContinue
Set-Net6to4Configuration -State Disabled -ErrorAction SilentlyContinue
Set-NetTeredoConfiguration -Type Disabled -ErrorAction SilentlyContinue
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" -Name "EnableICSIPv6" -Type DWord -Value 0
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" -Name "DisabledComponents" -Type DWord -Value 0xFF

Write-Output "Set Time to Live (TTL) to 64"
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "DefaultTTL" -Type DWord -Value 0x00000040

Write-Output "Set Host Resolution Priority Tweak"
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" -Name "LocalPriority" -Type DWord -Value 0x00000004
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" -Name "HostPriority" -Type DWord -Value 0x00000005
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" -Name "DnsPriority" -Type DWord -Value 0x00000006
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" -Name "NetbtPriority" -Type DWord -Value 0x00000007

Write-Output "Set MaxUserPort to 65534"
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "MaxUserPort" -Type DWord -Value 0x0000FFFE
Write-Output "Set TcpTimedWaitDelay to 30"
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "TcpTimedWaitDelay" -Type DWord -Value 0x0000001E

Write-Output "Disable LargeSystemCache"
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "LargeSystemCache" -Type DWord -Value 0

Write-Output "Enable Multimedia Class Scheduler service (MMCSS) Gaming Tweaks"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" -Name "NetworkThrottlingIndex" -Type DWord -Value 0xFFFFFFFF
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" -Name "SystemResponsiveness" -Type DWord -Value 0

Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" -Name "Affinity" -Type DWord -Value 0
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" -Name "Background Only" -Type String -Value "False"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" -Name "Clock Rate" -Type DWord -Value 0x2710
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" -Name "GPU Priority" -Type DWord -Value 8
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" -Name "Priority" -Type DWord -Value 2
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" -Name "Scheduling Category" -Type String -Value "High"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" -Name "SFIO Priority" -Type String -Value "High"

Write-Output "Disable Nagle's Algorithm"
foreach ($NetAdapter in $NetAdapters) {
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\$($NetAdapter.InterfaceGuid)" -Name "TcpAckFrequency" -Type DWord -Value 1
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\$($NetAdapter.InterfaceGuid)" -Name "TCPNoDelay" -Type DWord -Value 1
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\$($NetAdapter.InterfaceGuid)" -Name "TcpDelAckTicks" -Type DWord -Value 0
}
If (Test-Path "HKLM:\SOFTWARE\Microsoft\MSMQ\Parameters") {
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\MSMQ\Parameters" -Name "TCPNoDelay" -Type DWord -Value 1
}

$disableIntAdvProps = @(
    "*FlowControl"
    "*InterruptModeration"
    "*PMARPOffload"
    "*PMNSOffload"
    "*PriorityVLANTag"
    "*PtpHardwareTimestamp"
    "*SoftwareTimestamp"
    "*WakeOnMagicPacket"
    "*WakeOnPattern"
    "AdaptiveIFS"
    "EEELinkAdvertisement"
    "EnablePME"
    "ITR"
    "ReduceSpeedOnPowerDown"
    "SipsEnabled"
    "ULPMode"
    "WakeOnLink"
)
foreach ($NetAdapter in $NetAdapters) {
    Write-Output "Set Advanced Properties on $($NetAdapter.Name)"
    $NetAdapterProperties = $NetAdapter | Get-NetAdapterAdvancedProperty -AllProperties
    $iReceiveBuffers = [int]($NetAdapter | Get-NetAdapterAdvancedProperty -RegistryKeyword "*ReceiveBuffers").NumericParameterMaxValue
    $iTransmitBuffers = [int]($NetAdapter | Get-NetAdapterAdvancedProperty -RegistryKeyword "*TransmitBuffers").NumericParameterMaxValue

    foreach ($disableIntAdvProp in $disableIntAdvProps) {
        if ($NetAdapterProperties | Where-Object { $_.RegistryKeyword -eq $disableIntAdvProp -and $_.RegistryValue -ne 0 }) {
            $TMPDisplayName = (Get-NetAdapterAdvancedProperty -RegistryKeyword $disableIntAdvProp).DisplayName
            Write-Output "Disable $TMPDisplayName"
            $NetAdapter | Set-NetAdapterAdvancedProperty -RegistryKeyword $disableIntAdvProp -RegistryValue 0 -ErrorAction SilentlyContinue
        }
    }
    if ($NetAdapterProperties | Where-Object { $_.RegistryKeyword -eq "*JumboPacket" -and $_.RegistryValue -ne 1514 }) {
        $TMPDisplayName = (Get-NetAdapterAdvancedProperty -RegistryKeyword "*JumboPacket").DisplayName
        Write-Output "Disable $TMPDisplayName"
        $NetAdapter | Set-NetAdapterAdvancedProperty -RegistryKeyword "*JumboPacket" -RegistryValue 1514 -ErrorAction SilentlyContinue
    }
    if ($NetAdapterProperties | Where-Object { $_.RegistryKeyword -eq "LinkNegotiationProcess" -and $_.RegistryValue -ne 1 }) {
        $TMPDisplayName = (Get-NetAdapterAdvancedProperty -RegistryKeyword "LinkNegotiationProcess").DisplayName
        Write-Output "Disable $TMPDisplayName"
        $NetAdapter | Set-NetAdapterAdvancedProperty -RegistryKeyword "LinkNegotiationProcess" -RegistryValue 1 -ErrorAction SilentlyContinue
    }
    if ($NetAdapterProperties | Where-Object { $_.RegistryKeyword -eq "LogLinkStateEvent" -and $_.RegistryValue -ne 16 }) {
        $TMPDisplayName = (Get-NetAdapterAdvancedProperty -RegistryKeyword "LogLinkStateEvent").DisplayName
        Write-Output "Disable $TMPDisplayName"
        $NetAdapter | Set-NetAdapterAdvancedProperty -RegistryKeyword "LogLinkStateEvent" -RegistryValue 16 -ErrorAction SilentlyContinue
    }
    if ($NetAdapterProperties | Where-Object { $_.RegistryKeyword -eq "*ReceiveBuffers" -and $_.RegistryValue -ne $iReceiveBuffers }) {
        $TMPDisplayName = ($NetAdapter | Get-NetAdapterAdvancedProperty -RegistryKeyword "*ReceiveBuffers").DisplayName
        Write-Output "Set $TMPDisplayName to $iReceiveBuffers"
        $NetAdapter | Set-NetAdapterAdvancedProperty -RegistryKeyword "*ReceiveBuffers" -RegistryValue $iReceiveBuffers -ErrorAction SilentlyContinue
    }
    if ($NetAdapterProperties | Where-Object { $_.RegistryKeyword -eq "*TransmitBuffers" -and $_.RegistryValue -ne $iTransmitBuffers }) {
        $TMPDisplayName = ($NetAdapter | Get-NetAdapterAdvancedProperty -RegistryKeyword "*TransmitBuffers").DisplayName
        Write-Output "Set $TMPDisplayName to $iTransmitBuffers"
        $NetAdapter | Set-NetAdapterAdvancedProperty -RegistryKeyword "*TransmitBuffers" -RegistryValue $iTransmitBuffers -ErrorAction SilentlyContinue
    }
    if ($NetAdapterProperties | Where-Object { $_.RegistryKeyword -eq "PnPCapabilities" -and $_.RegistryValue -ne 280 }) {
        Write-Output "Disable ""Allow the computer to turn off this device to save power"""
        $NetAdapter | Set-NetAdapterAdvancedProperty -AllProperties -RegistryKeyword "PnPCapabilities" -RegistryValue 280 -ErrorAction SilentlyContinue
    }
}

if (Get-PnpDevice -Class Net | Where-Object {$_.InstanceId -like "SWD\*"}) {
    Write-Output "Disable WAN Miniport Adapters"
    Get-PnpDevice -Class Net -InstanceId "SWD\*" | Disable-PnpDevice -Confirm:$false -ErrorAction SilentlyContinue
}

if (Get-PnpDevice -Class Net | Where-Object {$_.InstanceId -like "ROOT\KDNIC\*"}) {
    Write-Output "Disable Microsoft Kernel Debug Network Adapter"
    Get-PnpDevice -Class Net -InstanceId "ROOT\KDNIC\*" | Disable-PnpDevice -Confirm:$false -ErrorAction SilentlyContinue
}

$appNames = @(
    "csgo.exe"
    "valorant-win64-shipping.exe"
    "valorant.exe"
)
Write-Output "Set QoS Policies"
foreach ($appName in $appNames) {
    if ((Get-NetQoSPolicy).AppPathName -contains $appName) {
        Get-NetQosPolicy | Where-Object AppPathName -eq $appName | Remove-NetQosPolicy -Confirm:$false | Out-Null
    }
    Write-Output " - $appName"
    New-NetQosPolicy -Name $appName -DSCPAction 46 -NetworkProfile All -ApplicationName $appName -IPProtocolMatchCondition Both -ErrorAction SilentlyContinue | Out-Null
}