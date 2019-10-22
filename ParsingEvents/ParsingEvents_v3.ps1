<#
	.SYNOPSIS
		Script to parse Sysmon Operational event log into an HTML-based report

	.DESCRIPTION
		Script to parse Sysmon Operational event log from local computer to HTML-based report
	
	.NOTES
		It is assumed that the Microsoft-Windows-Sysmon / Operational log file exists, otherwise, you need to change the parameters of the Get-WinEvent cmdlet.
        The Get-WinEvent cmdlet uses for parameter StartTime value of current date ((Get-Date).Date)
		Sysmon generates GUID's by own algorithm.
		Change the defaults as you wish.
        To parse proxy server log this script run another script ReadProxyLog.ps1 by searching in current folder. Refer to the corresponding description.

	.PARAMETER Source
		The parameter value indicates by which parameter the software chain will be searched: by path or by sysmon GUID (if known)
		Valid values: path, guid
		Default value: path
		
	.PARAMETER Filepath
		Depending on the value of the parameter Source.
		Indicates the path to the file that was running.
		Default value: C:\Program Files\Internet Explorer\iexplore.exe
	
	.PARAMETER ProcessGUID
		Depending on the value of the parameter Source.
		Indicates the sysmon GUID on which the search will be carried out.
		Default value: {2BB90AED-79B3-5D63-0000-0010270DB804}
		
	.PARAMETER ReportPath
		Path to the HTML report file.
		Default value: $env:USERPROFILE + '\Documents\SysmonReport.html'

    .PARAMETER ParseProxyLog
		Tells the script to analyze proxy server access logs.
        Valid values: 0 - do not parse log, 1 - parse log
		Default value: 1

    .PARAMETER ClientIP
		Passes the ip address of the client computer on which the testing took place to the script
		Default value: '172.18.80.15'

    .PARAMETER VirusTotalCheck
		Tells the script to scan executable files using VirusTotal site.
        Sysinternals sigcheck64.exe utility is used (should be in the same folder as the script)
        Valid values: 0 - do not check on VirusTotal, 1 - perform check on VirusTotal
		Default value: 1

	.EXAMPLE
		Example of how to run the script:
		powershell -NoProfile -executionpolicy bypass .\sysmon_report.ps1 -ReportPath 'C:\Reports\SysmonReport.html'
		powershell -NoProfile -executionpolicy bypass .\sysmon_report.ps1 -Filepath 'C:\Users\user01\AppData\Local\Google\Chrome\Application\chrome.exe'
		powershell -NoProfile -executionpolicy bypass .\sysmon_report.ps1 -Source guid -ProcGUID '{2BB90AED-79B3-5D63-0000-0010270DB804}'
        powershell -NoProfile -executionpolicy bypass .\sysmon_report.ps1 -ParseProxyLog 0
#>
[CmdletBinding()]
param
(
    [parameter(mandatory=$false)][ValidateSet('path','guid')][string]$Source='path',
	[parameter(mandatory=$false)][string]$Filepath='C:\Program Files\Internet Explorer\iexplore.exe',
	[parameter(mandatory=$false)][string]$ProcessGUID='{2BB90AED-79B3-5D63-0000-0010270DB804}',
    [parameter(mandatory=$false)][string]$ReportPath='' + $env:USERPROFILE + '\Documents\SysmonReport.html',
    [parameter(mandatory=$false)][ValidateSet(0,1)][int]$ParseProxyLog=1,
    [parameter(mandatory=$false)][string]$ClientIP = '172.18.80.15',
    [parameter(mandatory=$false)][ValidateSet(0,1)][int]$VirusTotalCheck=1
)

# Array for write-progress activity
$SysmonIDs = @('empty', 'Process Creation', 'A process changed a file creation time', 'Network connection', `
    'Sysmon service state changed', 'Process terminated', 'Driver loaded', 'Image loaded', `
    'CreateRemoteThread', 'RawAccessRead', 'ProcessAccess', 'FileCreate', 'RegistryEvent (Object create and delete)', `
    'RegistryEvent (Value Set)', 'RegistryEvent (Key and Value Rename)', 'FileCreateStreamHash', `
    'Sysmon config state changed', 'PipeEvent (Pipe Created)', 'PipeEvent (Pipe Connected)', 'WmiEvent (WmiEventFilter activity detected)', `
    'WmiEvent (WmiEventConsumer activity detected)', 'WmiEvent (WmiEventConsumerToFilter activity detected)', `
    'DNSEvent (DNS query)'
    )
# Array of events
$Events = @()

# HTML code for report
$HTML = ''

# Time of starting app
$UTCTime = ''

# Array for storing GUID's of processes what beeing catch
$ProcGUID = @()

# Order of representing reporting data in HTML: 1. from $SupremeEvents; 2. from EventOrder
# Important sysmon events
$SupremeEvents = @( `
# Sysmon configuration modification + Driver load
4,16,6, `
# WMI monitoring
19,20,21 `
)
$SupremeEventsCount = $SupremeEvents.Count
# Events with this identifier are filtered using the process GUID.
$EventOrder = @( `
#1,22)
# Process activity
1,7,10,8, `
# Monitoring files
11,2, `
# Registry modification
12,13,14, `
# Network interaction
3,22, `
# Alternative data stream access
9,15,17,18 `
)
$EventOrder_count = $EventOrder.Count

# The keys of all events of interest. Also stores the order in which the data appears in the report.
$ID = @(@('empty'),`
# SYSMON EVENT ID 1 : PROCESS CREATION [ProcessCreate]
@('UtcTime','ProcessGuid','ProcessId','Image','CommandLine','ParentCommandLine','User','FileVersion','Description','Product','Company','OriginalFileName','CurrentDirectory','Hashes','ParentProcessGuid','ParentProcessId','ParentImage'),`
# SYSMON EVENT ID 2 : FILE CREATION TIME RETROACTIVELY CHANGED IN THE FILESYSTEM [FileCreateTime]
@('UtcTime','ProcessGuid','TargetFilename','CreationUtcTime','PreviousCreationUtcTime'),`
# SYSMON EVENT ID 3 : NETWORK CONNECTION INITIATED [NetworkConnect]
@('UtcTime','ProcessGuid','ProcessId','Image','User','Protocol','Initiated','SourceIp','SourceHostname','SourcePort','DestinationIp','DestinationHostname','DestinationPort'),`
# SYSMON EVENT ID 4 : RESERVED FOR SYSMON STATUS MESSAGES
@('UtcTime','State','Version','SchemaVersion'),`
# SYSMON EVENT ID 5 : PROCESS ENDED [ProcessTerminate]
@('UtcTime','ProcessId','Image'),`
# SYSMON EVENT ID 6 : DRIVER LOADED INTO KERNEL [DriverLoad]
@('UtcTime','ImageLoaded','Hashes','Signed','Signature','SignatureStatus'),`
# SYSMON EVENT ID 7 : DLL (IMAGE) LOADED BY PROCESS [ImageLoad]
@('UtcTime','ProcessGuid','ProcessId','ImageLoaded','Hashes','Signed','Signature','SignatureStatus'),`
# SYSMON EVENT ID 8 : REMOTE THREAD CREATED [CreateRemoteThread]
@('UtcTime','SourceProcessGuid','TargetProcessId','TargetImage','NewThreadId','StartAddress','StartModule','StartFunction'),`
# SYSMON EVENT ID 9 : RAW DISK ACCESS [RawAccessRead]
@('UtcTime','Device'),`
# SYSMON EVENT ID 10 : INTER-PROCESS ACCESS [ProcessAccess]
@('UtcTime','SourceProcessGuid','SourceProcessId','SourceThreadId','SourceImage','TargetProcessId','TargetImage','GrantedAccess','CallTrace'),`
# SYSMON EVENT ID 11 : FILE CREATED [FileCreate]
@('UtcTime','TargetFilename','CreationUtcTime'),`
# SYSMON EVENT ID 12 & 13 & 14 : REGISTRY MODIFICATION [RegistryEvent]
@('UtcTime','EventType','TargetObject'),`
@('UtcTime','EventType','TargetObject','Details'),`
@('UtcTime','EventType','TargetObject','Details','NewName'),`
# SYSMON EVENT ID 15 : ALTERNATE DATA STREAM CREATED [FileCreateStreamHash]
@('UtcTime','TargetFilename','CreationUtcTime','Hash'),`
# SYSMON EVENT ID 16 : SYSMON CONFIGURATION CHANGE
@('UtcTime','Configuration','ConfigurationFileHash'),`
# SYSMON EVENT ID 17 & 18 : PIPE CREATED / PIPE CONNECTED [PipeEvent]
@('UtcTime','EventType','PipeName'),`
@('UtcTime','EventType','PipeName'),`
# SYSMON EVENT ID 19 & 20 & 21 : WMI EVENT MONITORING [WmiEvent]
@('UtcTime','EventType','Operation','User','Name','Type','Destination','Consumer','Filter'),`
@('UtcTime','EventType','Operation','User','Name','Type','Destination','Consumer','Filter'),`
@('UtcTime','EventType','Operation','User','Name','Type','Destination','Consumer','Filter'),`
# SYSMON EVENT ID 22 : DNS QUERY [DnsQuery]
@('UtcTime','QueryName','QueryStatus','QueryResults')`
)

# Functions for generate HTML code
function Generate-TableHeader($i)
{
    $tmp_html = '<h5>Event ID ' + $i + ' ' + $SysmonIDs[$i] + '</h5>'
    $tmp_html += '<table><tr>'
    foreach ($tmp_head in $ID[$i])
    {
        $tmp_html += '<th>' + $tmp_head + '</th>'
    }
    $tmp_html += '</tr>'
    return $tmp_html
}
function Generate-TableBody($i)
{
	$tmp_html = '<tr>'
	foreach ($tmp_name in $ID[$i])
	{
		$tmp_html += '<td>' + $tmp_hash_table.Item($tmp_name)
	}
	return $tmp_html
}
function Generate-CustTableBody($i)
{
	$tmp_html = '<tr>'
	foreach ($tmp_name in $ID[$i])
	{
		$tmp_html += '<td>' + $CustomEvent[0].Item($tmp_name)
	}
	return $tmp_html
}
# This is fork from function Get-WinHttpProxy from https://p0w3rsh3ll.wordpress.com/2012/10/07/getsetclear-proxy/
Function Get-WinHttpProxy
{
	$binval = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Connections" -Name WinHttpSettings).WinHttPSettings
	$proxylength = $binval[12]
	if ($proxylength -gt 0)
    {
        return $true
    }
    else
    {
        return $false
    }
}

# Searching ProcessGuid for supplied execution file path, all derived processes

Write-Progress -Id 1 -Activity ('Reading events with Get-WinEvent filter')
# Build sysmon event log filter
$Sysmon_events = Get-WinEvent -FilterHash `
	@{LogName='Microsoft-Windows-Sysmon/Operational';ID=1;StartTime=(Get-Date).Date} `
	-ErrorAction SilentlyContinue | Sort-Object -Property TimeCreated
$Sysmon_events_count = $Sysmon_events.count

# Flag for the first appearance of the specified path to the execution file
$First_run = 1

# For write-progress -id 1
$k = 0

Write-output ('Search the specified path to the executable file in the log file (size is ' + $Sysmon_events_count + ')')
foreach ($Event in $Sysmon_events)
{
	Write-Progress -Id 1 -Activity 'Search for supplied execution file path and all derived processes'
	$tmp_hash_table = [ordered]@{}
	# Converting event entry to XML
	$EventXML = [xml]$Event.toXML()
	# Counting number of keys in Message block for event
	$EventData_Col_Count = $EventXML.Event.EventData.Data.Count
	# Parsing to hashtable
	for ($i = 0; $i -lt $EventData_Col_Count; $i++)
	{
		$tmp_name = $EventXML.Event.EventData.Data[$i].Name
		$tmp_data = $eventXML.Event.EventData.Data[$i].'#text'
		$tmp_hash_table.add($tmp_name, $tmp_data)
    }
	# Selecting a subset of fields
	# Searching by launched file path
	if ($First_run -eq 1)
	{
        if (($Source -eq 'path') -and ($tmp_hash_table.Image -eq $Filepath))
		{
			$tmp_hash_table1 = [ordered]@{}
			$tmp_hash_table1.add('ProcessGuid', $tmp_hash_table.ProcessGuid)
			$tmp_hash_table1.add('CommandLine', $tmp_hash_table.CommandLine)
			$tmp_hash_table1.add('ParentProcessGuid', $tmp_hash_table.ParentProcessGuid)
			$tmp_hash_table1.add('ParentCommandLine', $tmp_hash_table.ParentCommandLine)
            $tmp_hash_table1.add('Image', $tmp_hash_table.Image)
			$ProcGUID += ,@($tmp_hash_table1)
            $UTCTime = $tmp_hash_table.UtcTime
			$First_run = 0
		}
		if (($Source -eq 'guid') -and ($tmp_hash_table.ParentProcessGuid -eq $ProcessGUID))
		{
			$tmp_hash_table1 = [ordered]@{}
			$tmp_hash_table1.add('ProcessGuid', $tmp_hash_table.ProcessGuid)
			$tmp_hash_table1.add('CommandLine', $tmp_hash_table.CommandLine)
			$tmp_hash_table1.add('ParentProcessGuid', $tmp_hash_table.ParentProcessGuid)
			$tmp_hash_table1.add('ParentCommandLine', $tmp_hash_table.ParentCommandLine)
            $tmp_hash_table1.add('Image', $tmp_hash_table.Image)
			$ProcGUID += ,@($tmp_hash_table1)
            $UTCTime = $tmp_hash_table.UtcTime
			$First_run = 0
		}
	}
	else
	{
		# Search GUID based on call path
		for ($j = 0; $j -lt $ProcGUID.Count; $j++)
		{
			if ($tmp_hash_table.ParentProcessGuid -eq $ProcGUID[$j].ProcessGuid)
			{
				$tmp_hash_table1 = [ordered]@{}
				$tmp_hash_table1.add('ProcessGuid', $tmp_hash_table.ProcessGuid)
				$tmp_hash_table1.add('CommandLine', $tmp_hash_table.CommandLine)
				$tmp_hash_table1.add('ParentProcessGuid', $tmp_hash_table.ParentProcessGuid)
				$tmp_hash_table1.add('ParentCommandLine', $tmp_hash_table.ParentCommandLine)
                $tmp_hash_table1.add('Image', $tmp_hash_table.Image)
				$ProcGUID += ,@($tmp_hash_table1)
			}
		}
	}
	$k++
	Write-Progress -Id 2 -ParentId 1 -Activity 'Search for supplied execution file path and all derived processes' -Status $k -PercentComplete ($k / $Sysmon_events_count * 100)
}
Write-Progress -id 2 -ParentId 1 -Activity 'Search for supplied execution file path and all derived processes' -Completed
Write-Progress -Id 1 -Activity ('Search for supplied execution file path and all derived processes') -Completed

# Searching and create report for all important events: sysmon configuration modification and driver load

$ProcGUID_count = $ProcGUID.count
Write-Output ('Number of found processes - ' + $ProcGUID_count)

Write-Output ('Parsing sysmon configuration modification and driver load')
for ($i = 0; $i -lt $SupremeEventsCount; $i++)
{
	Write-Progress -Id 1 -Activity ('Reading events with Get-WinEvent filter')
	
	# Build event log filter
    $Sysmon_events = Get-WinEvent -FilterHash `
        @{LogName='Microsoft-Windows-Sysmon/Operational';ID=$SupremeEvents[$i];StartTime=(Get-Date).Date} `
        -ErrorAction SilentlyContinue
    
    $Sysmon_events_count = $Sysmon_events.count
	
	# Mitigate empty log after applying filter
    if ($Sysmon_events_count -eq 0)
    {
        Write-output ('Sysmon event ID ' + $SupremeEvents[$i] + ' ' + $SysmonIDs[$SupremeEvents[$i]] + ' - ' + $Sysmon_events_count + ' qty.')
        continue
    }
	Write-output ('Parsing sysmon event ID ' + $SupremeEvents[$i] + ' ' + $SysmonIDs[$SupremeEvents[$i]] + ' - ' + $Sysmon_events_count + ' qty.')
	Write-Progress -Id 1 -Activity ('Sysmon event ID ' + $SupremeEvents[$i] + ' '+ $SysmonIDs[$SupremeEvents[$i]])

	# For write-progress -id 2
    $k = 0
    
    $tmp_html = ''
	$tmp_html += '<h1>Sysmon configuration modification and driver load</h1><p>Important sysmon events, please refer to description of events.</p>'
    $tmp_html += Generate-TableHeader($SupremeEvents[$i])
	foreach ($Event in $Sysmon_events)
	{
		$tmp_hash_table = [ordered]@{}
        # Convert event entry to XML
        $EventXML = [xml]$Event.toXML()
        # Count number of colomns
        $EventData_Col_Count = $EventXML.Event.EventData.Data.Count
		for ($j = 0; $j -lt $EventData_Col_Count; $j++)
        {
			$tmp_name = $EventXML.Event.EventData.Data[$j].Name
            $tmp_data = $eventXML.Event.EventData.Data[$j].'#text'
            $tmp_hash_table.add($tmp_name, $tmp_data)
        }
		$tmp_html += Generate-TableBody($SupremeEvents[$i])
		
		$k++
        Write-Progress -Id 2 -ParentId 1 -Activity 'Parsing sysmon configuration modification and driver load to HTML' -Status $k -PercentComplete ($k / $Sysmon_events_count * 100)
	}
	$tmp_html += '</table>'
    $HTML += $tmp_html
	Write-Progress -id 2 -ParentId 1 -Activity 'Parsing sysmon configuration modification and driver load to HTML' -Completed
	Write-Progress -Id 1 -Activity ('Sysmon event ID ' + $SupremeEvents[$i] + ' '+ $SysmonIDs[$SupremeEvents[$i]]) -PercentComplete (($i + 1) / $SupremeEventsCount * 100)
}
Write-Progress -id 1 -Activity '...' -Completed

if ($ProcGUID_count -eq 0)
{
    Write-Output 'The script did not find any event records with the provided parameters.'
    if ($Host.Name -eq "ConsoleHost")
    {
        Write-Host "Press any key to continue..."
        $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyUp") > $null
    }
    exit
}

# Searching for required events, copy events data to memory(RAM), read events data from memory(RAM)

# Flag for copy events data to memory(RAM)
$First_run = 1

Write-Output ('Parsing system events for found processes. Total number is ' + $ProcGUID_count)

for ($m = 0; $m -lt $ProcGUID_count; $m++)
{
	$tmp_html = ''
	$tmp_html += '<h3> Process (GUID - ' + $ProcGUID[$m].ParentProcessGuid + ') (parent command line):' + $ProcGUID[$m].ParentCommandLine + '</h3>'
	$tmp_html += '<h3> Run (GUID - ' + $ProcGUID[$m].ProcessGuid + ') with command: ' + $ProcGUID[$m].CommandLine + '</h3>'
    $HTML += $tmp_html

    # check on VirusTotal 
    $SigCh = $PSScriptRoot + '\sigcheck64.exe'
    if (($VirusTotalCheck -eq 1) -and (Test-Path -Path $SigCh))
    {
        if (Get-WinHttpProxy)
        {
            # Run sigcheck64.exe
            & $SigCh -c -vt -vs $ProcGUID[$m].Image > $env:temp\sigcheck_tmp.txt
            $tmp = Get-Content -Path "$env:temp\sigcheck_tmp.txt"
            [system.collections.arraylist]$AL = $tmp
            for ($i = 0; $i -lt 5; $i++)
            {
                $AL.RemoveAt(0)
            }
            $AL > $env:temp\sigcheck_tmp.txt
            $tmp = Import-Csv -LiteralPath "$env:temp\sigcheck_tmp.txt" -Encoding UTF8 -Delimiter ','
            Remove-Item -Path "$env:temp\sigcheck_tmp.txt" -Force
            $tmp_html = '<h4>Information from VirusTotal</h4><table><tr>'
            $tmp_html += '<th>Path</th>'
            $tmp_html += '<th>Verified</th>'
            $tmp_html += '<th>Product</th>'
            $tmp_html += '<th>Product</th>'
            $tmp_html += '<th>File Version</th>'
            $tmp_html += '<th>VT detection</th>'
            $tmp_html += '<th>VT link</th></tr>'
            $tmp_html += '<tr><td>' + $tmp[0].Path + '</td>'
            $tmp_html += '<td>' + $tmp[0].Verified + '</td>'
            $tmp_html += '<td>' + $tmp[0].Product + '</td>'
            $tmp_html += '<td>' + $tmp[0].'Product Version' + '</td>'
            $tmp_html += '<td>' + $tmp[0].'File Version' + '</td>'
            $tmp_html += '<td>' + $tmp[0].'VT detection' + '</td>'
            $tmp_html += '<td><a target=_blank href=' + $tmp[0].'VT link' + '>VT link</a></td>'
            $tmp_html += '</table>'
            $HTML += $tmp_html
        }
        else
        {
            Write-Output "Error: skipping check on VirusTotal. Please review output of netsh winhttp show proxy"
            Write-Output "Missing data will not be included in the report."
        }
    }
    elseif (($VirusTotalCheck -eq 1) -and (!(Test-Path -Path $SigCh)))
    {
        Write-Output "Error: can't find sigcheck64.exe for checking executables on VirusTotal."
        Write-Output "Missing data will not be included in the report."
    }

    ###################

    Write-Output ('Parsing sysmon event for ' + $ProcGUID[$m].ProcessGuid)
	Write-Progress -id 1 -Activity 'Parsing system events for found processes' -Status $ProcGUID[$m].ProcessGuid -PercentComplete ($m / $ProcGUID_count * 100)
	if ($First_run -eq 1)
	{
		# Read all sysmon events to array $Events
		for ($i = 0; $i -lt $EventOrder_count; $i++)
		{
			Write-Progress -Id 2 -ParentId 1 -Activity ('Reading events with Get-WinEvent filter')
			
			# Build event log filter
			$Sysmon_events = Get-WinEvent -FilterHash `
			@{LogName='Microsoft-Windows-Sysmon/Operational';ID=$EventOrder[$i];StartTime=(Get-Date).Date} `
			-ErrorAction SilentlyContinue
			
			$Sysmon_events_count = $Sysmon_events.count
    
			# Mitigate empty log after applying filter
			if ($Sysmon_events_count -eq 0)
			{
				Write-output ('Sysmon event ID ' + $EventOrder[$i] + ' ' + $SysmonIDs[$EventOrder[$i]] + ' - ' + $Sysmon_events_count + ' qty.')
				continue
			}
			Write-output ('Parsing sysmon event ID ' + $EventOrder[$i] + ' ' + $SysmonIDs[$EventOrder[$i]] + ' - ' + $Sysmon_events_count + ' qty.')
			Write-Progress -Id 2 -ParentId 1 -Activity ('Sysmon event ID ' + $EventOrder[$i] + ' '+ $SysmonIDs[$EventOrder[$i]]) -PercentComplete ($i / $EventOrder_count * 100)
			
			# For write-progress -id 3
			$k = 0
			# Temp array for consolidate events
			$tmp_arr = @()

			$tmp_html = ''
			$tmp_html += Generate-TableHeader($EventOrder[$i])
			
			foreach ($Event in $Sysmon_events)
			{
				#Write-Progress -Id 3 -ParentId 2 -Activity 'Parsing to HTML & RAM' -Status $k
				$tmp_hash_table = [ordered]@{}
				# Convert event entry to XML
				$EventXML = [xml]$Event.toXML()
				# Count number of colomns
				$EventData_Col_Count = $EventXML.Event.EventData.Data.Count
				for ($j = 0; $j -le $EventData_Col_Count; $j++)
				{
					if ($j -eq $EventData_Col_Count)
					{
						$tmp_name = 'ID'
						$tmp_data = $EventOrder[$i]
					}
					else
					{
						$tmp_name = $EventXML.Event.EventData.Data[$j].Name
						$tmp_data = $eventXML.Event.EventData.Data[$j].'#text'
					}
					$tmp_hash_table.add($tmp_name, $tmp_data)
				}
				$tmp_arr += ,@($tmp_hash_table)
				
				if (($EventOrder[$i] -eq 1) -and ($tmp_hash_table.Item('ParentProcessGuid') -eq $ProcGUID[$m].ProcessGuid))
				{
					$tmp_html += Generate-TableBody($EventOrder[$i])
				}
				if (($EventOrder[$i] -in (2,3,7,9,11,12,13,14,15,17,18,22)) -and ($tmp_hash_table.Item('ProcessGuid') -eq $ProcGUID[$m].ProcessGuid))
				{
					$tmp_html += Generate-TableBody($EventOrder[$i])
				}
				if (($EventOrder[$i] -in (8,10)) -and ($tmp_hash_table.Item('SourceProcessGuid') -eq $ProcGUID[$m].ProcessGuid))
				{
					$tmp_html += Generate-TableBody($EventOrder[$i])
				}
				
				$k++
				Write-Progress -Id 3 -ParentId 2 -Activity 'Parsing to HTML & RAM' -Status $k -PercentComplete ($k / $Sysmon_events_count * 100)
			}
			$tmp_html += '</table>'
			$HTML += $tmp_html
			$Events += $tmp_arr
			Write-Progress -Id 3 -ParentId 2 -Activity 'Parsing to HTML & RAM' -Completed
			Write-Progress -Id 2 -ParentId 1 -Activity ('Sysmon event ID ' + $EventOrder[$i] + ' '+ $SysmonIDs[$EventOrder[$i]]) -PercentComplete (($i + 1) / $EventOrder_count * 100)
		}
		$First_run = 0
	}
	else
	{
		for ($i = 0; $i -lt $EventOrder_count; $i++)
		{
			Write-Progress -Id 2 -ParentId 1 -Activity ('Reading events from RAM with filter')
			$CustomEvents = $Events | Where-Object {$_.ID -eq $EventOrder[$i]} 
			$CustomEvents_count = $CustomEvents.count
			
			# Mitigate empty log after applying filter
			if ($CustomEvents_count -eq 0)
			{
				Write-Output ('Sysmon event ID ' + $EventOrder[$i] + ' ' + $SysmonIDs[$EventOrder[$i]] + ' - ' + $CustomEvents_count + ' qty.')
				continue
			}
			Write-output ('Parsing sysmon event ID ' + $EventOrder[$i] + ' ' + $SysmonIDs[$EventOrder[$i]] + ' - ' + $CustomEvents_count + ' qty.')
			Write-Progress -Id 2 -ParentId 1 -Activity ('Sysmon event ID ' + $EventOrder[$i] + ' '+ $SysmonIDs[$EventOrder[$i]] + ' for ' + $ProcGUID[$m].ProcessGuid) -PercentComplete ($i / $EventOrder_count * 100)
			
			# For write-progress -id 3
			$k = 0
			
            $tmp_html = ''
			$tmp_html += Generate-TableHeader($EventOrder[$i])
			
			foreach ($CustomEvent in $CustomEvents)
			{
				#Write-Progress -Id 3 -ParentId 2 -Activity 'Parsing to HTML' -Status $k
				if (($EventOrder[$i] -eq 1) -and ($CustomEvent[0].Item('ParentProcessGuid') -eq $ProcGUID[$m].ProcessGuid))
				{
					$tmp_html += Generate-CustTableBody($EventOrder[$i])
				}
				if (($EventOrder[$i] -in (2,3,7,9,11,12,13,14,15,17,18,22)) -and ($CustomEvent[0].Item('ProcessGuid') -eq $ProcGUID[$m].ProcessGuid))
				{
                    $tmp_html += Generate-CustTableBody($EventOrder[$i])
				}
				if (($EventOrder[$i] -in (8,10)) -and ($CustomEvent[0].Item('SourceProcessGuid') -eq $ProcGUID[$m].ProcessGuid))
				{
					$tmp_html += Generate-CustTableBody($EventOrder[$i])
				}
				
				$k++
				Write-Progress -Id 3 -ParentId 2 -Activity 'Parsing to HTML' -Status $k -PercentComplete ($k / $CustomEvents_count * 100)
			}
			$tmp_html += '</table>'
			$HTML += $tmp_html
			Write-Progress -Id 3 -ParentId 2 -Activity 'Parsing to HTML' -Completed
			Write-Progress -Id 2 -Activity ('Sysmon event ID ' + $EventOrder[$i] + ' ' + $SysmonIDs[$EventOrder[$i]] + ' for ' + $ProcGUID[$m].ProcessGuid) -PercentComplete (($i + 1) / $EventOrder_count * 100)
		}
		Write-Progress -Id 2 -Activity ('...') -Completed
	}
	Write-Progress -id 1 -Activity 'Parsing system events for found processes' -Status $ProcGUID[$m].ProcessGuid -PercentComplete (($m + 1) / $ProcGUID_count * 100)
}
Write-Progress -id 1 -Activity 'Parsing system events for found processes' -Completed

if ($HTML -eq '')
{
    $HTML += 'Can`t find data'
}

# Parsing proxy server log
if (($ParseProxyLog -eq 1) -and (Test-Path -Path ($PSScriptRoot + "\ReadProxyLog.ps1")))
{
    Write-Output 'Getting log data from proxy server'
    # perform conversion data
    $UTCTime = $UTCTime.Split()
    $UTCTime = $UTCTime[1].Substring(0,8)
    $result = Invoke-Expression -Command ($PSScriptRoot + "\ReadProxyLog.ps1 -RunFromScript $ParseProxyLog -UTCTime $UTCTime -ClientIP $ClientIP")
    #$result = Invoke-Expression -Command ("$t -RunFromScript $ParseProxyLog -UTCTime $UTCTime -ClientIP $ClientIP")
    ConvertTo-Html -PostContent $HTML,$result | Out-File -FilePath $ReportPath
}
elseif (($ParseProxyLog -eq 1) -and (!(Test-Path -Path ($PSScriptRoot + "\ReadProxyLog.ps1"))))
{
    Write-Output "Error: can't find script for parsing proxy server log."
    Write-Output "Missing data will not be included in the report"
    ConvertTo-Html -PostContent $HTML | Out-File -FilePath $ReportPath
}
else
{
    ConvertTo-Html -PostContent $HTML | Out-File -FilePath $ReportPath
}
# Free memory
$HTML = ''
$CustomEvents = @()
$Events = @()

<#
if ($Host.Name -eq "ConsoleHost")
{
    Write-Host "Press any key to continue..."
    $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyUp") > $null
}
#>