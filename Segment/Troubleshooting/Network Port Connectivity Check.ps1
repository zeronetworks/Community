<#
    .SYNOPSIS
    Does network connectivity Test on Clients and Trust Server on the required ports based on the Deployment guide

    .EXAMPLE
    To do a network connectivity test for protected clients/servers
    Test -machineProfile "Client"

    For Trust Servers
    Test -machineProfile "Trust Server"
#>
param(
    [string]$machineProfile
)
filter Color-Table {
    param(
        [Parameter(ValueFromPipeline=$true)]
        $table,
        [string[]] $word = @("Success","Failed","Allow","Block","TCP","UDP"),
        [string[]] $color = @("Green","Red","Green","Red","Magenta","Yellow"),
        [string[]] $highlight=@(),
        [string[]] $critical=@()
    )
    $all = ($table)
    $lines = ($all -split '\r\n') | % {$_ + "<newline>"}

    ForEach ($line in $lines) {
		$line -split "($($word -join ('|')))" | ForEach-Object {
            $default = @{
                Foreground = [console]::ForegroundColor  
                Background = [console]::BackgroundColor
            }
            $highlight | ForEach-Object { if ($line -match $_) {$default.Foreground = "Yellow"}}
            $critical | ForEach-Object {if ($line -match $_) {$default.Foreground = "Red"}}

			if ($_ -match "<newline>") {
				Write-Host -foreground $default.Foreground -background $default.Background "$($_.replace('<newline>',''))"              
			}
			elseif ($_ -in $word) {
				$index = $word.IndexOf($_)
				Write-Host -ForegroundColor $color[$index] "$_" -NoNewLine 
			} 
			else {
				Write-Host -foreground $default.Foreground -background $default.Background "$_" -NoNewLine
			}   
    	}
	}
}

$portInfo = @{
    "443" = "Secured SSL Connection"
	"80" = "HTTP"
    "30022" = "Health Monitoring - Metrics sent to ZN Cloud"
    "389" = "LDAP - Retrieve AD Information"
    "3268" = "Global Catalog LDAP"
    "88" = "Kerberos - Used for Authentication"
    "135" = "NTLM - Used for Authentication"
    "445" = "NTLM = Used for Authentication"
    "53" = "DNS - Retrieve FQDN and IP from DNS Server"
    "5985" = "WinRM - Retrieve info and manage Windows FW"
    "22" = "SSH - Retrieve info and manage Linux FW"
}
function Test-Port {
	<#
	.SYNOPSIS
		This function tests for open TCP/UDP ports.
	.DESCRIPTION
		This function tests any TCP/UDP port to see if it's open or closed.
	.NOTES
		Known Issue: If this function is called within 10-20 consecutively on the same port
			and computer, the UDP port check will output $false when it can be
			$true.  I haven't figured out why it does this.
	.PARAMETER Computername
		One or more remote, comma-separated computer names
	.PARAMETER Port
		One or more comma-separated port numbers you'd like to test.
	.PARAMETER Protocol
		The protocol (UDP or TCP) that you'll be testing
	.PARAMETER TcpTimeout
		The number of milliseconds that the function will wait until declaring
		the TCP port closed.
	.PARAMETER
		The number of millieconds that the function will wait until declaring
		the UDP port closed.
	.EXAMPLE
		PS> Test-Port -Computername 'LABDC','LABDC2' -Protocol TCP 80,443
		
		This example tests the TCP network ports 80 and 443 on both the LABDC
		and LABDC2 servers.
	#>
	[CmdletBinding(DefaultParameterSetName='TCP')]
	[OutputType([System.Management.Automation.PSCustomObject])]
	param (
		[Parameter(Mandatory)]
		[string[]]$ComputerName,
		[Parameter(Mandatory)]
		[int[]]$Port,
		[Parameter(Mandatory)]
		[ValidateSet('TCP', 'UDP')]
		[string]$Protocol,
		[Parameter(ParameterSetName='TCP')]
		[int]$TcpTimeout = 1000,
		[Parameter(ParameterSetName = 'UDP')]
		[int]$UdpTimeout = 1000
	)
	process {
		foreach ($Computer in $ComputerName) {
			foreach ($Portx in $Port) {
				$Output = @{ 'Computername' = $Computer; 'Port' = $Portx; 'Protocol' = $Protocol; 'Result' = '' }
				Write-Verbose "$($MyInvocation.MyCommand.Name) - Beginning port test on '$Computer' on port '$Protocol<code>:$Portx'"
				if ($Protocol -eq 'TCP') {
					$TcpClient = New-Object System.Net.Sockets.TcpClient
					$Connect = $TcpClient.BeginConnect($Computer, $Portx, $null, $null)
					$Wait = $Connect.AsyncWaitHandle.WaitOne($TcpTimeout, $false)
					if (!$Wait) {
						$TcpClient.Close()
						Write-Verbose "$($MyInvocation.MyCommand.Name) - '$Computer' failed port test on port '$Protocol</code>:$Portx'"
						$Output.Result = $false
					} else {
						$TcpClient.EndConnect($Connect)
						$TcpClient.Close()
						Write-Verbose "$($MyInvocation.MyCommand.Name) - '$Computer' passed port test on port '$Protocol<code>:$Portx'"
						$Output.Result = $true
					}
					$TcpClient.Close()
					$TcpClient.Dispose()
				} elseif ($Protocol -eq 'UDP') {
					$UdpClient = New-Object System.Net.Sockets.UdpClient
					$UdpClient.Client.ReceiveTimeout = $UdpTimeout
					$UdpClient.Connect($Computer, $Portx)
					Write-Verbose "$($MyInvocation.MyCommand.Name) - Sending UDP message to computer '$Computer' on port '$Portx'"
					$a = new-object system.text.asciiencoding
					$byte = $a.GetBytes("$(Get-Date)")
					[void]$UdpClient.Send($byte, $byte.length)
					#IPEndPoint object will allow us to read datagrams sent from any source.
					Write-Verbose "$($MyInvocation.MyCommand.Name) - Creating remote endpoint"
					$remoteendpoint = New-Object system.net.ipendpoint([system.net.ipaddress]::Any, 0)
					try {
						#Blocks until a message returns on this socket from a remote host.
						Write-Verbose "$($MyInvocation.MyCommand.Name) - Waiting for message return"
						$receivebytes = $UdpClient.Receive([ref]$remoteendpoint)
						[string]$returndata = $a.GetString($receivebytes)
						If ($returndata) {
							Write-Verbose "$($MyInvocation.MyCommand.Name) - '$Computer' passed port test on port '$Protocol</code>:$Portx'"
							$Output.Result = $true
						}
					} catch {
						Write-Verbose "$($MyInvocation.MyCommand.Name) - '$Computer' failed port test on port '$Protocol`:$Portx' with error '$($_.Exception.Message)'"
						$Output.Result = $false
					}
					$UdpClient.Close()
					$UdpClient.Dispose()
				}
				[pscustomobject]$Output
			}
		}
	}
}

function Test-ServerRolePortGroup {
	<#
	.SYNOPSIS
		This function tests for open TCP/UDP ports by server role.
	.DESCRIPTION
		This function tests for all the approprite TCP/UDP ports by server role so you don't have
		to memorize or look up all of the ports that need to be tested for every time
		you want to verify remote connectivity on a specific server role.
	.NOTES
		Link port references:
		http://technet.microsoft.com/en-us/library/dd772723(v=ws.10).aspx
		http://en.wikipedia.org/wiki/Server_Message_Block
		http://technet.microsoft.com/en-us/library/cc940063.aspx
	.PARAMETER Computername
		One or more remote, comma-separated computer names
	.PARAMETER ServerRole
		The services on the computer that you'd like to find open ports for. This can be
		common services like WinRm, Smb, Dns, Active Directory and NetBIOS
	.EXAMPLE
		PS> Test-ServerRolePortGroup -Computername 'LABDC','LABDC2' -ServerRole NetBIOS,WinRm,Dns
		
		This example tests the network ports necessary for NetBIOS, WinRm and Dns
		to operate on the servers LABDC and LABDC2.
	#>
	
	[CmdletBinding()]
	[OutputType([System.Management.Automation.PSCustomObject])]
	param (
		[Parameter(Mandatory)]
		#[ValidateScript({ Test-Connection -ComputerName $_ -Count 1 -Quiet})]
		[string[]]$Computername,
		[Parameter(Mandatory)]
		#[ValidateSet('WinRm','Smb','Dns','ActiveDirectoryGeneral','ActiveDirectoryGlobalCatalog','Zero Networks Cloud','NetBIOS','Domain Controllers','Internet','')]
		[string[]]$ServerRole
	)
	begin {
		$PortGroups = @{
			'WinRM' = @{ 'TCP' = 5985}
			'Smb' = @{ 'TCP' = 445; 'UDP' = 445}
			'DNS' = @{ 'TCP' = 53; 'UDP' = 53;}
			'ActiveDirectoryGeneral' = @{ 'TCP' = 25, 88, 389, 464, 636, 5722, 9389; 'UDP' = 88,123,389,464 }
			'ActiveDirectoryGlobalCatalog' = @{ 'TCP' = 3268, 3269 }
			'NetBios' = @{ 'TCP' = 135, 137, 138, 139; 'UDP' = 137,138,139 }
            "Zero Networks Cloud" = @{'TCP' = 443,30022;}
            "Domain Controllers" = @{'TCP' = 389, 3268, 88, 135,445}
            "DC" = @{'TCP' = 389, 3268, 88, 135,445}
            "Internet" = @{'TCP' = 443, 80}
			"Trust Servers" = @{'TCP' = 443; 'UDP' = 443}
		}
	}
	process {
		foreach ($Computer in $Computername) {
			Write-Verbose "Beginning port tests on computer '$Computer'"
			try {
				$TestPortGroups = $PortGroups.GetEnumerator() | where { $ServerRole -contains $_.Key }
				Write-Verbose "Found '$($TestPortGroups.Count)' port group(s) to test"
				foreach ($PortGroup in $TestPortGroups) {
					$PortGroupName = $PortGroup.Key
					$PortGroupValues = $PortGroup.Value
					foreach ($Value in $PortGroupValues.GetEnumerator()) {
						$Protocol = $Value.Key
						$Ports = $Value.Value
						$TestResult = Test-Port -ComputerName $Computer -Protocol $Protocol -Port $Ports
						$TestResult | Add-Member -MemberType 'NoteProperty' -Name 'PortSet' -Value $PortGroupName
						$TestResult
					}
				}
			} catch {
				Write-Verbose "$($MyInvocation.MyCommand.Name) - Computer: $Computer - Error: $($_.Exception.Message) - Line Number: $($_.InvocationInfo.ScriptLineNumber)"
				$false
			}
		}
	}
}

if (-not $machineProfile) {
    if (Get-Service -Include "znwinrm") {$machineProfile = "Trust Server"}
    else {$machineProfile = "Client"}
}

## Initialize and define variables
if  ($($env:LogOnServer.replace('\','')) -ne $env:COMPUTERNAME) { 
    $dc = $($env:LogOnServer.replace('\',''))
} else {
    $dc = "NO_DC_FOUND"
    Write-Host -ForegroundColor "Red" "No associated Domain Controller detected"
}

$groups = @(
    @{  machineProfile=@("Client","Trust Server");  PortSet = "Internet";   Target = @("www.google.com","zeronetworks.com")},
    @{  machineProfile=@("Client","Trust Server");  PortSet = "DNS";        Target = @((Get-DnsClientServerAddress -AddressFamily "IPv4").ServerAddresses)},
    @{  machineProfile=@("Client","Trust Server");  PortSet = "DNS";        Target = @($dc)},
    @{  machineProfile=@("Client","Trust Server");  PortSet = "DC";         Target = @($dc)},
    @{  machineProfile=@("Client");                 PortSet = "Trust Servers";         Target = @("trustsvr.teachjing.com","trustsvr.teachjing.com")}
)

$allResults = @()

ForEach ($group in ($groups | Where-Object {$machineProfile -in $_.machineProfile -and $_.Target})) {
    $Results = Test-ServerRolePortGroup -Computername $group.Target -ServerRole $group.PortSet | Select-Object "PortSet", @{N="Hostname";E={$_.Computername}}, "Port", Protocol, Result
    $groupedObjects = $Results | Group-Object -Property PortSet, Hostname, Port ## Groups by Protocol TCP/UDP
    $Results = $Results | Select-Object PortSet, Hostname, Port, Result, @{N="Protocol";E={
        ## Merges protocols
        $protocols = $groupedObjects.Group.Protocol
        if ($protocols -contains "TCP" -and $protocols -contains "UDP" -and $_.protocol -eq "TCP") {
           "TCP/UDP"
        } else {
            $_.Protocol
        }
    }}
    $Results = $Results | Where-Object {$_.Protocol -ne "UDP"}
    ## Evaulate Result and pass if at least TCP/UDP Passes
    $Results = $Results | Select-Object PortSet, Hostname, Port, Protocol, 
        @{Name="Result"; Expression={
            $item = $_

            #if ($_.Result) {"$($PSStyle.Foreground.BrightGreen)Success"} else {"$($PSStyle.Foreground.BrightRed)Failed"}
            $filteredResult = $results | Where-Object {$_.Hostname -eq $item.Hostname -and $_.Port -eq $item.Port} 
            if ($filteredResult.Result -contains $true){
                return "Success"
            } 
            else {
                return "Failed"
            }
        }
    }
    $Results = $Results | Select-Object PortSet, Hostname, Port, Protocol, Result, @{N="Port Info";E={ $portInfo."$($_.Port)"}}
    $allResults += $Results
}

$highlight = "Trust Server","PortSet","[-]{3,}"
$critical = "NO_DC_FOUND"
$allResults | FT | Out-string | Color-Table -highlight $highlight -critical $critical

read-host