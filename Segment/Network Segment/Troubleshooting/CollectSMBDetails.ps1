$etwSessionName = "ETWWppTestSession"
$etwProviderGuid = "{F818EBB3-FBC4-4191-96D6-4E5C37C8A237}"  
$smbClientGuid = "{988c59c5-0a1c-45b6-a555-0c62276e327d}"
$logPath = "C:\WPPLogs_$($env:COMPUTERNAME)"
$logFileName = "$($env:COMPUTERNAME)_wppTest.etl" -f (Get-Date)
$logFullPath = Join-Path -Path $logPath -ChildPath $logFileName
$backupFullPath = Join-Path -Path $logPath -ChildPath "backup.etl"
$rolloverInterval = 24  # 24 hours

function Start-Session {
    param (
        [string]$mySessionName
    )

    # Check if the ETW session is already running
    $sessionStatus = Get-EtwTraceSession -Name $mySessionName

    if ($sessionStatus -eq $null) {
        Stop-EtwTraceSession -Name $mySessionName
        Remove-EtwTraceSession -Name $mySessionName
        Start-EtwTraceSession -Name $mySessionName -LocalFilePath $logFullPath -LogFileMode 0x8100  -MinimumBuffers 16 -MaximumBuffers 16 -BufferSize 1 -MaximumFileSize 32
        Add-EtwTraceProvider -SessionName $mySessionName -Guid $etwProviderGuid -MatchAnyKeyword 0xFFFFFFFFFFFF -Level 0xFF -Property 0x40
        Add-EtwTraceProvider -SessionName $mySessionName -Guid $smbClientGuid -MatchAnyKeyword 0xFFFFFFFFFFFF -Level 0xFF -Property 0x40

    }
    else
    {
        Send-EtwTraceSession -Name $mySessionName -DestinationFolder $backupFullPath
    }
}
# Create the log directory if it doesn't exist
if (-not (Test-Path -Path $logPath -PathType Container)) {
    New-Item -Path $logPath -ItemType Directory
}

Start-Session($etwSessionName)
