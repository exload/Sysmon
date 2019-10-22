[CmdletBinding()]
param
(
    [parameter(mandatory=$false)][string]$Filepath='C:\Program Files\Internet Explorer\iexplore.exe',
    [parameter(mandatory=$false)][string]$Reportpath='C:\Distr\report.html'
)

# Array for write-progress activity data
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

$HTML = ''
$PreContent = '<h1>' + $Filepath + '</h1>'

# Order of representing data in HTML
$EventOrder = @( `
# Sysmon important events
4,16,6,9, `
# Process activity
1,7,10,8, `
# Monitoring files
11,2, `
# Registry modification
12,13,14, `
# Network interaction
3,22, `
# Alternative data stream access
15,17,18, `
# WMI monitoring
19,20,21 `
)

$EventsToScan = $EventOrder.Count

# All events data keys
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
@('UtcTime','SourceProcessGUID','SourceProcessId','SourceThreadId','SourceImage','TargetProcessId','TargetImage','GrantedAccess','CallTrace'),`
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

function Generate-TableHeader($i)
{
    $tmp_html = '<h2>Event ID ' + $i + ' ' + $SysmonIDs[$i] + '</h2>'
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

# Read all sysmon eventsr to array $Events
for ($i = 0; $i -lt $EventsToScan; $i++)
{
    Write-Progress -Id 1 -Activity ('Reading events with Get-WinEvent filter')

    # Build event log filter
    $Sysmon_events = Get-WinEvent -FilterHash `
        @{LogName='Microsoft-Windows-Sysmon/Operational';ID=$EventOrder[$i];StartTime=(Get-Date).Date} `
        -ErrorAction SilentlyContinue
    
    $Sysmon_events_count = $Sysmon_events.count
    
    # Mitigate empty log after applying filter
    if ($Sysmon_events_count -eq 0)
    {
        write-output ('Sysmon event ID ' + $EventOrder[$i] + ' ' + $SysmonIDs[$EventOrder[$i]] + ' - ' + $Sysmon_events_count + ' qty.')
        continue
    }
    write-output ('Parsing sysmon event ID ' + $EventOrder[$i] + ' ' + $SysmonIDs[$EventOrder[$i]] + ' - ' + $Sysmon_events_count + ' qty.')
    Write-Progress -Id 1 -Activity ('Sysmon event ID ' + $EventOrder[$i] + ' '+ $SysmonIDs[$EventOrder[$i]]) -PercentComplete ((($i + 1) - 1) / $EventsToScan * 100)
    
    # For write-progress -id 2
    $k = 0
    # Temp array for consolidate events
    $tmp_arr = @()
    
    $tmp_html = ''
    
    $tmp_html += Generate-TableHeader($EventOrder[$i])
    
    foreach ($Event in $Sysmon_events)
    {
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
        if (($EventOrder[$i] -eq 1) -and ($tmp_hash_table.Item('ParentImage') -eq $Filepath))
        {
            $tmp_html += Generate-TableBody($EventOrder[$i])
        }
        if (($EventOrder[$i] -eq 2) -and ($tmp_hash_table.Item('Image') -eq $Filepath))
        {
            $tmp_html += Generate-TableBody($EventOrder[$i])
        }
        if (($EventOrder[$i] -eq 3) -and ($tmp_hash_table.Item('Image') -eq $Filepath))
        {
            $tmp_html += Generate-TableBody($EventOrder[$i])
        }
        if (($EventOrder[$i] -eq 4) -or ($EventOrder[$i] -eq 6) -or ($EventOrder[$i] -eq 16) -or ($EventOrder[$i] -eq 19) -or ($EventOrder[$i] -eq 20) -or ($EventOrder[$i] -eq 21))
        {
            $tmp_html += Generate-TableBody($EventOrder[$i])
        }
        if (($EventOrder[$i] -eq 7) -and ($tmp_hash_table.Item('Image') -eq $Filepath))
        {
            $tmp_html += Generate-TableBody($EventOrder[$i])
        }
        if (($EventOrder[$i] -eq 8) -and ($tmp_hash_table.Item('SourceImage') -eq $Filepath))
        {
            $tmp_html += Generate-TableBody($EventOrder[$i])
        }
        if (($EventOrder[$i] -eq 9) -and ($tmp_hash_table.Item('Image') -eq $Filepath))
        {
            $tmp_html += Generate-TableBody($EventOrder[$i])
        }
        if (($EventOrder[$i] -eq 10) -and ($tmp_hash_table.Item('SourceImage') -eq $Filepath))
        {
            $tmp_html += Generate-TableBody($EventOrder[$i])
        }
        if (($EventOrder[$i] -eq 11) -and ($tmp_hash_table.Item('Image') -eq $Filepath))
        {
            $tmp_html += Generate-TableBody($EventOrder[$i])
        }
        if (($EventOrder[$i] -eq 12) -and ($tmp_hash_table.Item('Image') -eq $Filepath))
        {
            $tmp_html += Generate-TableBody($EventOrder[$i])
        }
        if (($EventOrder[$i] -eq 13) -and ($tmp_hash_table.Item('Image') -eq $Filepath))
        {
            $tmp_html += Generate-TableBody($EventOrder[$i])
        }
        if (($EventOrder[$i] -eq 14) -and ($tmp_hash_table.Item('Image') -eq $Filepath))
        {
            $tmp_html += Generate-TableBody($EventOrder[$i])
        }
        if (($EventOrder[$i] -eq 15) -and ($tmp_hash_table.Item('Image') -eq $Filepath))
        {
            $tmp_html += Generate-TableBody($EventOrder[$i])
        }
        if (($EventOrder[$i] -eq 17) -and ($tmp_hash_table.Item('Image') -eq $Filepath))
        {
            $tmp_html += Generate-TableBody($EventOrder[$i])
        }
        if (($EventOrder[$i] -eq 18) -and ($tmp_hash_table.Item('Image') -eq $Filepath))
        {
            $tmp_html += Generate-TableBody($EventOrder[$i])
        }
        if (($EventOrder[$i] -eq 22) -and ($tmp_hash_table.Item('Image') -eq $Filepath))
        {
            $tmp_html += Generate-TableBody($EventOrder[$i])
        }
                
        $tmp_arr += ,@($tmp_hash_table)

        $k++
        Write-Progress -Id 2 -ParentId 1 -Activity 'Parsing to RAM & HTML' -Status $k -PercentComplete (($k - 1) / $Sysmon_events_count * 100)
    }
    $tmp_html += '</table>'
    $HTML += $tmp_html
    Write-Progress -id 2 -ParentId 1 -Activity 'Parsing to array' -Completed
    $Events += $tmp_arr
}
ConvertTo-Html -PostContent $HTML -PreContent $PreContent | Out-File -FilePath $Reportpath