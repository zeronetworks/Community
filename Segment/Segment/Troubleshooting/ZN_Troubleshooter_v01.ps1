<# Zero Networks Troubleshooting script
.NAME Jing Nghik
.LINK https://www.zeronetworks.com
.AUTHOR jing@zeronetworks.com
.VERSION 1.0
.Synopsis
   This scripts purpose is to help quickly troubleshoot common scenarios related to issues on the Trust Server or monitored/protected assets
   
.DESCRIPTION
   This script does the following
   - Checks if WinRM and firewall services are running
   - Checks if WinRM is listening on the proper ports
   - Generates a GPO RSOP report to analyze
   - Validates Zero Network group policies are associated to local asset
   - Identify other group policies that may conflict with Zero Networks
   - Identify if there are other firewall rules on the local asset not managed by Zero Networks
   - Check network connectivity with domain controller
   - Verify firewall events (5156,5157) audit logs are enabled

   - On the trust server
     - Verifies trust services are running
     - Verify connectivity with Zero Network cloud services
     - Verify if on latest version of trust server

   - On endpoints
     - Check network connectivity with trust server

   During all checks remediation will be provided for items that failed and also a recap is generated at the end of the script. 

.EXAMPLE
   Simply just run the file and it will automatically check and provide remediation steps at the end for you to focus troubleshooting on. 

.INPUTS
    - No inputs has been implemented yet

.OUTPUTS
    - No output file has been generated yet

.NOTES
   You typically would run this on a machine that is monitored/protected by Zero Networks or on the trust server for network connectivity checks and testing. 
#>

## Run as admin if not as admin
if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) { Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs; exit }

function Write-Coord {
    param(
        $text,
        $x=([console]::CursorLeft),
        $y=([console]::CursorTop),
        $foreground=([console]::ForegroundColor),
        $background=([console]::BackgroundColor)
    ) 

    # Clear Old content if exist
    [console]::SetCursorPosition($x,$y)
    Write-Host (" " * $text.length) -NoNewline

    # Write new content at coordinates
    [console]::CursorLeft = $x
    Write-Host -ForegroundColor $foreground -BackgroundColor $background -NoNewline $text
}

function TestPort {
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

function TestServerRolePortGroup {
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
			'Smb' = @{ 'TCP' = 445; 'UDP' = 445 }
			'DNS' = @{ 'TCP' = 53; 'UDP' = 53 }
			'ActiveDirectoryGeneral' = @{ 'TCP' = 25, 88, 389, 464, 636, 5722, 9389; 'UDP' = 88,123,389,464 }
			'ActiveDirectoryGlobalCatalog' = @{ 'TCP' = 3268, 3269 }
			'NetBios' = @{ 'TCP' = 135, 137, 138, 139; 'UDP' = 137,138,139 }
            "Zero Networks Cloud" = @{'TCP' = 443}
            "Domain Controllers" = @{'TCP' = 389, 3268, 88, 135,445}
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

class ScriptCheck {
    [string] $Title
    [scriptblock] $Script 
    $output
    [scriptblock] $checkOutput  = {}
    [string] $Result
    [object]$job
    [string] $Remediation = ""
	[string] $sb

    ScriptResult (
        [string] $title, 
        [scriptblock] $script, 
        [scriptblock]$checkOutput) { 
    
        $this.Title = $title 
        $this.Script = $script 
        $this.checkOutput = $checkOutput
    } 
    
    RunScript () {
        $initScript = [scriptblock]::Create(@"
function Test-Port {$function:TestPort}
function Test-ServerRolePortGroup {$function:TestServerRolePortGroup}
"@)
        $this.job = Start-Job -Name $this.Title -InitializationScript $initScript -ScriptBlock ([Scriptblock]::Create(@"
			Try{ $($this.Script.ToString())}
			Catch { $_}
"@))
    } 

    RunAfterScript () {
        # Check if the job is still running
        if ($this.job.State -eq "Running") { Write-Output "Job is still running" }

        # If the job is complete, retrieve the output and store it in the Output property
        elseif ($this.job.State -eq "Completed") {
            $this.output = Receive-Job -Job $this.job -Keep; ## Grab output

            ## Check if Result is boolean and change to pass/fail
            $this.Result = $this.checkOutput.Invoke();
            if ($this.Result -eq "True") {$this.Result = "Pass"} 
            ElseIf ($this.Result -eq "False") {$this.Result = "Fail"}

            ## If no output. Mark as fail by default.
            if (-not $this.output) {$this.output = "Error getting output"; $this.Result = "Fail"}
        }
    }
} 

function Format-String() {
    param (
        [Parameter(ValueFromPipeline=$true)] $object,
        [int]$left,
        [int]$padding = 0
    )
    $screenWidth = ([console]::WindowWidth) - $left - ($padding*2)
    if ($left) {$left = $left + $padding; [console]::CursorLeft = $left} else {$left = ([console]::CursorLeft) + $padding}

    $lines = $object -split "`n";
    
    $all = @()
    ForEach ($s in $lines) {

        if ($s.Length -ge $screenWidth) {
            $words = $s -split '\s+'
            $sublines = @()
            $line = ""
            foreach ($word in $words) {
        
                ## Add word if less than screenwidth
                if (($line.Length + $word.Length + 1) -le $screenWidth) { $line += "$word "}
        
                ## Else, make a new line and add word to new line
                else {
                    $sublines += $line  
                    $line = "$([string]" " * [int]$left)$word "  ## when making a newline, offset to match previous line
                }
            }
            #if ($line) { $sublines += $line.Trim()} # 
            $sublines += $line
            $all += "$($sublines -join "`n")"  # At the end join all the lines back together.
        } 
        else {
            $all += "$([string]" " * [int]$left)$s "
        }
    }
    $all -join "`n"
}

filter Color-Output {
    param(
        [Parameter(ValueFromPipeline=$true)] $object,

        $colorWords = (@{
            Green = "Allowed","Enabled","GPO Found","Online","Pass","Running","Success","True"
            Yellow = "Deny","Warning","No GPO Detected"
            Red = "Block","Disabled","Error getting output","Failed","Fail","Failure","False","Not Allowed","Offline","Stopped"
            Cyan = "ZeroNetworksProtectedAssets","ZeroNetworksMonitor","ZeroNetworksProtect","ZNRemoteAccess"
        }),
        [int]$left = ([console]::CursorLeft),
        $x, $y,
        [string]$foreground
    )

    $default = @{
        foreground = if ($foreground) {$foreground} else {[console]::ForegroundColor}
        background = [console]::BackgroundColor
    }

    $lines = ($object -split "`r`n")

    $words = @()
    ForEach ($color in $colorWords.keys) {
        ForEach ($word in $colorWords[$color]){
            if ($object -match $word) {
                $words += $word
            }
        }
    }

    ForEach ($line in $lines) {
        [console]::CursorLeft = $left
        $line -split "($($words -join ('|')))" | ForEach-Object {

            if ($_ -in $words) {
                $color = @(foreach ($color in $colorWords.keys) { if ($_ -in $colorWords[$color]) {$color}})
                Write-Host -ForegroundColor $color "$_" -NoNewline
            } 
            else {
                Write-Host -foreground $default.foreground "$_" -NoNewline
            }   
        }
        Write-Host ""
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

$colorWords = @{
    Green = "Allowed","Enabled","GPO Found","Online","Pass","Running","Success","True"
    Yellow = "Warning"
    Red = "Block","Disabled","Error","Fail","Failed","Failure","False","No GPO Detected","Not Allowed","Offline"
}

$scripts = @(
    [PSCustomObject]@{
        Field = "Machine Type"
        Title ="Determining if machine is a Trust Server or remote asset"
        Script = {
            $isTrustServer = $using:isTrustServer;
            if (-Not ($isTrustServer)) {
                "Endpoint"} 
            else {
                Write-Output "Trust Server (Version: $( (Get-Content 'C:\Program Files\Zero Networks\VERSION.txt').split(':')[1].Trim() ))"
            } 
        }
        checkOutput = { if(!$this.output.Length -gt 0) {$false} else {$true} }
    },
    [PSCustomObject]@{
        Field = "DC"
        Title ="Determining Domain Controller"
        Script = {
            $dc = $Using:dc;
            $dc
        }
        checkOutput = { ($this.output -match "[\w\d]*") }
        Remediation = "If we couldn't determine your domain controller, Enter in DC when prompted"
        assetType = "Any"
    },  
    [PSCustomObject]@{
        Field = "Machine Domain\Name"
        Title ="Getting Machine hostname"
        Script = {whoami}
        checkOutput = { if(!$this.output.Length -gt 0) {"Fail"} else {"Pass"} }
        assetType = "Any"
    },    
    [PSCustomObject]@{
        Field = "IP Address(s)"
        Title ="Get IPv4 Addresses"
        Script = {
            $IP = (Get-NetIPConfiguration | Select-Object IPv4Address).IPv4Address
            $IPs = $IP | ForEach-Object {
                return "$($_.IPAddress)/$($_.PrefixLength)"
            }
            $IPS -join ", "
        }
        checkOutput = { if(!$this.output.Length -gt 0) {$false} else {$True} }
        Skip = $true
        AssetType = "Any"
    },
    [PSCustomObject]@{
        Field = "DNS Server(s)"
        Title ="Check DNS Servers configures on machine"
        Script = { ([array](Get-DnsClientServerAddress -AddressFamily "IPv4").ServerAddresses) -join "," }
        ExpectedOutput = "[\d]*"
        checkOutput = { if(!$this.output.Length -gt 0) {$false} else {$True} }
        Skip = $true
        AssetType = "Any"
        Remediation = "Verify you have DNS servers properly configured properly."
    },
    [PSCustomObject]@{
        Field = "WinRM Service"
        Title ="Check if WinRM Service is running"
        Script = { [String](Get-Service -Name WinRM).Status }
        checkOutput = { ($this.output -match "Running") }
        AssetType = "Any"
        Remediation = "Download the troubleshooting guide from our portal to determine why WinRM is not working."
    },
    [PSCustomObject]@{
        Title = "Check if Firewall Service 'MPSSVC' is running"
        Script = { [String](Get-Service -Name mpssvc).Status }
        checkOutput = { ($this.output -match "Running") }
        ExpectedOutput = "Running"
        Field = "Firewall Service"
        AssetType = "Any"
        Remediation = "Firewall needs to be enabled. Please check group/local policies to determine why this service is not running."
    },
    [PSCustomObject]@{
        Field = "Trust Server services"
        Title = "Checking if Trust Server services are running"
        Script = { get-service -Name "zn*" | Select DisplayName, Name, Status | FT }
        checkOutput = { if ($this.output -match "Running") {$false} else {$true} }
        AssetType = "Trust Server"
        Remediation = "These services needs to be running. Please review the logs in the directory you installed the trust server."
    },
    [PSCustomObject]@{
        Field = "WinRM Listening Port(s)"
        Title ="Checking WinRM Listening Port(s)"
        Script = {
            "$(($((((winrm enumerate winrm/config/listener) | Select-String -pattern '(Port[\=\s]*)([\d]{1,5})').Matches | % {$_.Groups[2].value}) -join ",")))"
        }
        checkOutput = { ($this.output -match "\d+") } 
        AssetType = "Any"
        Remediation = "Download the troubleshooting guide from our portal to determine why WinRM is not working."
    },
    [PSCustomObject]@{
        Field = "GPO RSOP Report"
        Title ="Generate GPO RSOP Report"
        Script = {
            $path = Join-Path $env:LOCALAPPDATA "ZeroNetworks"
            If(!(test-path -PathType container $path)) { New-Item -ItemType Directory -Path $path }
            if (test-path $path\report.xml) { Remove-Item $path\report.xml} ## Remove old report
            cmd.exe /c "gpresult /X $($path)\report.xml /f"
            (Join-Path $env:LOCALAPPDATA "ZeroNetworks\report.xml")

        }
        checkOutput = { if (Test-Path (Join-Path $env:LOCALAPPDATA "ZeroNetworks\report.xml")) { $true } else {$false}}
        Remediation = "I was not able to locate ZeroNetworks configured group policies assigned to this asset. Please make sure that the asset is part of the `“ZeroNetworksProtectedAssets`” AD group"
    },
    [PSCustomObject]@{
        Field = "Zero Network GPOs"
        Title ="Checking if Zero Network GPOs are on this machine"
        Script = {
            $path = Join-Path $env:LOCALAPPDATA "ZeroNetworks"
            $GPResultXML = [xml](Get-Content -Path "$($path)\report.xml")
            $GPONames = $GPResultXML.Rsop.ComputerResults.GPO | Select-Object *, @{N="Id";E={$_.Path.Identifier."#text"}} | Where-Object {$_.Name -in @("ZeroNetworksMonitor","ZeroNetworksProtect")} | Select Name, Enabled, IsValid, SecurityFilter
            $names = @("ZeroNetworksMonitor","ZeroNetworksProtect") 
            $check = foreach ($name in $names) { 
                [PSCustomObject] @{
                    Name = $name
                    GPO = "$(if($name -in $GPONames.Name) {"GPO Found"} else {"No GPO detected"})"
                }
            }
            $check | Format-Table
        }
        checkOutput = { if ( ( ($this.output | Out-String) -match "No GPO detected")) {"Warning"} else {"Pass"} }
        Remediation = "Zero Networks GPOs not detected for either ZeroNetworksMonitor/ZeroNetworksProtect. You may need to refresh your group policies locally on this machine. `nRun the following command to refresh: `n    klist -li 0x3e4 purge`n    klist -li 0x3e7 purge`n    gpupdate /force"
    },
    [PSCustomObject]@{
        Title ="Parse GPO Report and identifying any GPO conflicts"
        Script = {
            $path = Join-Path $env:LOCALAPPDATA "ZeroNetworks"
            $GPResultXML = [xml](Get-Content -Path "$($path)\report.xml")

            ## Find all GPOS with identifiers
            $GPOs = ($GPResultXML.GetElementsByTagName("GPO") | Where-Object { ($_.Identifier)}) | Select-Object *, @{N="Parent";E={$_.ParentNode.Name}}
            $GPONames = $GPResultXML.Rsop.ComputerResults.GPO | Select-Object *, @{N="Id";E={$_.Path.Identifier."#text"}}

            # Get related GPO name
            ForEach ($GPO in $GPOs) {
                $Name = ($GPONames | Where-Object {$_.Id -eq $GPO.Identifier."#text"})
                $GPO | Add-Member -MemberType NoteProperty -Name "GPOName" -Value $Name.Name -Force
            }

            $filter = @{
                "Names" = @(
                    "Windows Defender Firewall: Prohibit notifications"
                    "Windows Defender Firewall: Prohibit unicast response to multicast or broadcast requests"
                    "Windows Defender Firewall: Protect all network connections"
                    "Configure user Group Policy loopback processing mode"
                    "Specify the maximum log file size (KB)"
                    "Allow Basic authentication"
                    "Allow remote server management through WinRM"
                    "Allow unencrypted traffic"
                )
                "LocalNames" = @(
                    "InboundFirewallRules"
                    "OutboundFirewallRules"
                    "DefaultInboundAction"
                    "DefaultOutboundAction"
                    "AuditSetting"
                    "UserRightsAssignment"
                    "DisableNotifications"
                    "EnableFirewall"
                )
            }

            $filtered = @()
            $maxColumnLength = 30
            ForEach ($GPO in $GPOs) {
                $parentNode = $GPO.ParentNode
                $parentName = "$(if($GPO.ParentNode.KeyPath) {$GPO.ParentNode.KeyPath} else {$GPO.ParentNode.Name})"
                if ( ($GPO.ParentNode.LocalName -in $filter.LocalNames) -or ($GPO.ParentNode.Name -in $filter.Names)) {
                    $p = [PSCustomObject]@{
                        ParentLocalName = "$(([string]$GPO.ParentNode.LocalName)[0..$maxColumnLength] -join '')"
                        ParentName = "$($parentName[0..$maxColumnLength] -join '')"
                        #ParentName = "$(([string]$GPO.ParentNode.Name)[0..$maxColumnLength] -join '')"
                        "Winning GPO" = "$(([string]$GPO.GPOName)[0..$maxColumnLength] -join '')"
                        Value = "$(
                            if ($GPO.ParentNode.Value) {$GPO.ParentNode.Value}
                            elseif ($GPO.ParentNode.KeyPath) {$GPO.ParentNode.AdmSetting}
                            elseif ($GPO.ParentNode.State) {$GPO.ParentNode.State}
                            elseif ($GPO.ParentNode.SettingString) {$GPO.ParentNode.SettingString}
                            elseif ($GPO.ParentNode.SettingBoolean) {$GPO.ParentNode.SettingBoolean}
                            elseif ($GPO.ParentNode.SettingNumber) {$GPO.ParentNode.SettingNumber}
                            elseif ($GPO.ParentNode.SettingValue) {$GPO.ParentNode.SettingValue}
                            elseif ($GPO.ParentNode.Action) {"$($GPO.ParentNode.Dir)-$($GPO.ParentNode.Action)-$(if ($GPO.ParentNode.LPort) {$GPO.ParentNode.LPort} else {$GPO.ParentNode.RPort})"}
                            elseif ($GPO.ParentNode.LocalName -match "UserRightsAssignment") {$GPO.ParentNode.member.name."#text"}
                        )"
                        Result = "$(if( ($GPO.GPOName -like "ZeroNetworks*") ) {"Pass"} else {"Warning"})"
                    }
                    if($p.value) {$filtered += $p}
                }
            }
            $filtered | FT
            
        }
        checkOutput = { if ($this.output.Result -match "Warning") {"Warning"} {"Pass"} }
        Field = "Associated GPOs relevant to Zero Networks"
        Remediation = "If you have any winning GPOs that is taking precedence over Zero Networks, you need to to identify the GPO and ensure you 'deny' this policy to be applied on 'ZeroNetworksProtectedAssets' AD Group"
        AssetType = "Any"
    },
    [PSCustomObject]@{
        Field = "Active Rules Zero Networks is not managing"
        Title ="Getting any firewall rules not configured by Zero Networks"
        Script = {
            $maxColumnLength = 30
            $fwRules = Get-NetFirewallRule -Enabled True -PolicyStore ActiveStore | Where-Object {$_.DisplayName -notlike "ZN*"} | Select-Object *, @{ N="IPs"; Expression={($_ | Get-NetFirewallAddressFilter).RemoteAddress | Where-Object {$_ -notmatch "[A-Za-z]"}}}
            $fwRules | Select-Object @{N="Name"; E={"$(($_.DisplayName)[0..$maxColumnLength] -join '')"}}, Enabled, Profile, Direction, Action, "IPs" | Sort-Object -Property Direction | FT
        }
        checkOutput = { if( ($this.Output | Out-String) -match "True") {"Warning"} else {$true} }
        AssetType = "Any"
        Remediation = "We have identified some firewalls on this asset not managed by ZeroNetworks. Please verify that these rules don't conflict with our rules/MFA policies. It is suggested to migrate these rules and have all rules be managed centrally through our portal."
    },
    [PSCustomObject]@{
        Field = "Firewall Policies"
        Title ="Checking if Firewalls are blocking Inbound/Outbound by default and allowing local firewall rules"
        Script = {
            $fwRules = Get-NetFirewallProfile -PolicyStore ActiveStore | Select-Object Name, Enabled, @{N="Inbound"; E={$_.DefaultInboundAction}}, @{N="Outbound"; E={$_.DefaultOutboundAction}}, @{N="Is Local FW Rules Allowed?"; E={if($_.AllowLocalFirewallRules) {"Allowed"} else {"Not Allowed"}}}
            $fwRules | FT
        }
        ExpectedOutput = "Running"
        checkOutput = { if($this.Output.result) {"Warning"} else {$true} }
        Remediation = "You will need to go into your Group Policies within Active Directory and locate the group policy that is adding additional firewall rules to this asset's firewall configuration"
        AssetType = "Any"
    },
    [PSCustomObject]@{
        Title ="Checking if ZNRemoteAccess Firewall Rule is Configured and enabled."
        Field = "Trust Server Inbound Access FW Rule"
        Script = {
            Get-NetFirewallRule -PolicyStore ActiveStore | Where-Object {$_.DisplayName -eq "ZNRemoteAccess"} | Select DisplayName, Enabled, Profile, Direction, Action, @{ N="Trust Servers"; Expression={($_ | Get-NetFirewallAddressFilter).RemoteAddress}} | FT
        }
        checkOutput = { if(!$this.output.Length -gt 0) {$false} else {$True} }
        Remediation = "This local machine does not seem to have 'ZNRemoteAccess' Rule Configured. Check your Group Policies and ensure this asset is part of the `“ZeroNetworksProtectedAssets`” AD Group."
        AssetType = "Any"
    },
    [PSCustomObject]@{
        Field = "Trust Server Connectivity Check"
        Title ="Testing connectivity with Trust Servers"
        Script = {
            $fwRule = Get-NetFirewallRule -PolicyStore ActiveStore | Where-Object {$_.DisplayName -eq "ZNRemoteAccess"} | Select *, @{ N="Trust Servers"; Expression={($_ | Get-NetFirewallAddressFilter).RemoteAddress}}
            $fwRule = $fwRule | Select-Object DisplayName, Enabled, Profile, Direction, Action, "Trust Servers"
            $trustServers = ForEach ($server in $fwRule."Trust Servers") {
                ## Reverse lookup trust server IP
                Try {
                    $resolvedName = (Resolve-DnsName $server -ErrorAction Ignore).NameHost
                }
                Catch {
                }
                [PSCustomObject]@{
                    IP = $server
                    "Hostname" = $resolvedName
                    "DNS Check" = if ($resolvedName) {"Success"} else {"Failed"}
                }
            }

            $trustServers | ForEach-Object {
                $sslCheck = Test-Port -ComputerName $_.IP -Protocol TCP -Port 443

                $_ | Add-Member -MemberType NoteProperty -Name "Port" -value $sslCheck.Port -Force
                $_ | Add-Member -MemberType NoteProperty -Name "Protocol" -value $sslCheck.Protocol -Force
                $_ | Add-Member -MemberType NoteProperty -Name "Connectivity To Trust Server" -value $(if ($sslCheck.Result) {"Success"} else {"Failed"}) -Force
            }
            $trustServers | FT

        }
        checkOutput = { if(-not $this.Output) {$false} else {$true} }
        AssetType = "Endpoint"
        Remediation = "Outbound network connectivity to Zero Network's Trust Server has failed which will affect the Trust Servers ability to collect this assets network activity."
    },  
    [PSCustomObject]@{
        Title ="Checking Trust Server Version"
        Script = {
            if ($using:isTrustServer) {
                $latestVersion = [System.Version]"5.0.17.0"
                Try {
                    $currentVersion = [System.Version]((Get-Content "C:\Program Files\Zero Networks\VERSION.txt").Split(": ")|?{$_})[-1]
                } Catch {
                    $currentVersion = $null
                }
                $isLatest = ($currentVersion -ge $latestVersion)
                "$($currentVersion) $(if ($isLatest){"(Latest)"} else {"Needs to update to $($latestVersion)"})"
                    
            }
        }
        checkOutput = {if ($this.output -match "Latest") {$true} else {$false} }
        Field = "Trust Server"
        AssetType = "Trust Server"
        Remediation = "You are running a older version of the Trust Server. Please update it by downloading the new installation file from the portal and running the trust-updater."
    },
    [PSCustomObject]@{
        Title ="Testing Domain Controller Connectivity"
        Script = {
            $dc = $using:dc;
            $dcTest = Test-ServerRolePortGroup -Computername $dc -ServerRole "Domain Controllers" | Select-Object "PortSet", @{N="Hostname";E={$_.Computername}}, "Port", @{Name="Result"; Expression={if ($_.Result) {"$($PSStyle.Foreground.BrightGreen)Success"} else {"$($PSStyle.Foreground.BrightRed)Failed"}}}
            $dcTest | FT
        }
        checkOutput = {if ( ($this.output | Out-String) -match "Failed") {$false} else {$true} }
        Field = "Domain Controller Connectivity"
        Remediation = "This asset is having connectivity issues with the Domain Controller. This will affect various authentication and credentials."
        AssetType = "Any"
    },
    [PSCustomObject]@{
        Title ="Testing Zero Networks Cloud Connectivity"
        Script = {
            $test = Test-ServerRolePortGroup -Computername @('cloud-prod-v2.zeronetworks.com','register.zeronetworks.com','monitor.zeronetworks.com') -ServerRole "Zero Networks Cloud" | Select-Object @{N="Hostname";E={$_.Computername}}, @{N="IP(s)";E={([System.Net.Dns]::GetHostAddresses($_.Computername)).IPAddressToString}}, "Port", "PortSet", @{Name="Result"; Expression={if ($_.Result) {"$($PSStyle.Foreground.BrightGreen)Success"} else {"$($PSStyle.Foreground.BrightRed)Failed"}}}
            $test += Test-ServerRolePortGroup -Computername @('cloud-prod-v2.zeronetworks.com') -ServerRole "Zero Networks Healthcheck" | Select-Object @{N="Hostname";E={$_.Computername}}, @{N="IP(s)";E={([System.Net.Dns]::GetHostAddresses($_.Computername)).IPAddressToString}}, "Port", "PortSet", @{Name="Result"; Expression={if ($_.Result) {"$($PSStyle.Foreground.BrightGreen)Success"} else {"$($PSStyle.Foreground.BrightRed)Failed"}}}
            $test | FT
        }
        checkOutput = { if ("Failed" -in $this.output.Result) {$false} else {$true} }
        Field = "Zero Networks Cloud Connectivity"
        Remediation = "If this asset is cloud connected, this asset would need access to the Zero Networks Cloud Service. Please ensure the network segment this asset sits on is allowed outbound access to hostname and IPs indicated below."
        AssetType = "Any"
    },
    [PSCustomObject]@{
        Title ="Validating if asset is logging firewall events (5156, 5157)"
        Field = "Windows Event Logs"
        Script = {           
                #Get-WinEvent -LogName Security -FilterXPath "*[System[EventID=$($_)]]" -MaxEvents 1 | Select-Object Id, @{ N="Last Event Time"; E={$_.TimeCreated}}, Message
                (auditpol /get /category:* | Select-String "(Filtering Platform Connection|Process Creation|Process Termination)") | Out-String
        }
        checkOutput = { if ($this.output -match "No Auditing") {$false} else {$true} }
        Remediation = "Zero Networks' group policy settings should have enabled Windows Defender Firewall events. Verify if there are any conflicting group policies obstructing the logging of asset to local firewall events 5156 and 5157."
        AssetType = "Any"
    }
)

# Build script objects from the script array above
$scriptArray = @(); 
$remediation = @(); 
$step = 0
ForEach ($item in $scripts) {
    $p = @{
        Title=$item.Title
        Script=$item.Script 
        checkOutput = {}
    }
    if ($item | Get-Member -MemberType Properties -Name "checkOutput") { $p.checkOutput = $item.checkOutput }

    $script = New-Object -TypeName ScriptCheck -Property $p
    $scriptArray += $script
    $msg = "[Added] "
}

#### Initialize console variables and GUI ########
[Console]::Clear();
[console]::CursorVisible = $False
$left = 3
$top = [console]::CursorTop

########################### Initialize dependencies used by scripts ######################
#

## Determine DC automatically or from user input.
$dc = $env:LOGONSERVER
if ($dc) { $dc = $dc.replace('\','') }
else {
    $match = [array]((gpresult /r |  find /i "Group Policy was applied from:").split() | Where {$_})[-1]
    if ($match -match "^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9])$") { $dc = $match }
    if (-not $dc) { $dc = Read-Host "Could not determine DC, Please Enter DC Hostname" } ## If couldn't determine DC... prompt user for input
}

## Determine if trust server
if (-Not (Test-Path "C:\Program Files\Zero Networks\VERSION.txt")) {$isTrustServer = $false} else { 
    $isTrustServer = $true
    $currentVersion = [System.Version]((Get-Content "C:\Program Files\Zero Networks\VERSION.txt").Split(": ")|?{$_})[-1]
} 

###########################################################################################
## Write header
Write-Host -BackgroundColor Cyan -ForegroundColor Black " Zero Networks - Health Check Troubleshooting Tool " -NoNewLine;
Write-Host -ForegroundColor Cyan " $(if ($isTrustServer) {"Trust Server"} else {"Endpoint"})" -NoNewline;
if ($isTrustServer) {Write-Host " ($($currentVersion))`n" -NoNewline} Write-Host "`n";
###########################################################################################

#### Loop through scripts ###############
while ($step -lt $scriptArray.count){
    
    ####################################################################################
    ## Skip Check - Forced or skip scripts for asset types that doesn't match.

    $skip = $false
    $assetType = $scripts[$step].assetType

    if ( ([boolean]$isTrustServer) -and ($assetType -eq "Endpoint") ) {$skip = $true}  ## if Turst server and asset type is endpoint skip
    if ( (-not [boolean]$isTrustServer) -and ($assetType -eq "Trust Server") ) {$skip = $true} ## 
    #Write-Host "Is Trust Server? $($isTrustServer), Asset Type: $assetTYpe, Skip: $($skip)"
    ####################################################################################

    if (-not $skip) { ## run if not skipped
        $goRight = $true; 
        $i = 0
        $howManyDots = 10;
        $titleWhitespace = $(" " * $($scriptArray[$step].Title.length + $howManyDots + 2)) ## Whitespace

        $scriptArray[$step].RunScript() ## Run Script

        Write-Coord "$($scripts[$step].Field): " -foreground "Cyan" -x $left
        $leftAfterField = [console]::CursorLeft
        Write-Coord "$($scriptArray[$step].Title) " -foreground "Yellow"

        while ($scriptArray[$step].job.State -eq "Running") {
           
            ## Animation
            if ($goRight) {
                if ($i -eq $howManyDots) { $goRight = ($false) }
                Write-Host -NoNewline ".";
                $i++  # dots grow
            } 
            else {
                if ($i -eq 1) { $goRight = ($true) }
                if ([Console]::CursorLeft -gt 0) { 
                    [Console]::CursorLeft -= 1; Write-Host -NoNewline " "; [Console]::CursorLeft -= 1
                };
                $i--  # dots shrink
            }
        
            Start-Sleep -Milliseconds 50   # Wait 100 milliseconds before looping
        }
        $scriptArray[$step].RunAfterScript() ## Check if script completed 

        ## If task complete process below
        if (($scriptArray[$step].job.State -eq "Completed")){

            ######### clear current line when job completed.#########
            Write-Coord -x $leftAfterField $titleWhitespace; [Console]::CursorLeft = $leftAfterField;

            ######### Set color of result status and add to remediation array when required ########
            $result = $scriptArray[$step].Result     ## If no results... Just print output 
            $addToRemediation = $false; 

            if ($result -eq "Warning") { $foreground = "Yellow"; $addToRemediation = $true}
            elseif ($result -eq "Pass") { $foreground = "Green"; $addToRemediation = $false}
            elseif ($result -eq "Fail") { $foreground = "Red"; $addToRemediation = $true}
            
            Write-Coord -foreground $foreground -text "[$($scriptArray[$step].Result)] "
            #########################################################################################

            ## Output any output provided by script and colorize based on special keywords
            $output = $scriptArray[$step].Output
            if ($output) {
                if ($output.gettype().name -eq "String") {
                    #$output = "$($output.gettype().name)($( ($output | Measure-Object -line).Lines )) - $output"
                    $output = $output | Where-Object {$_ -ne ""}
                    #$output | Color-Output -word $colorWords.words -color $colorWords.colors
                    $output | Color-Output
                }
                elseif ($output.GetType().Name -eq "Object[]") {
                        Write-Host
                        [Console]::CursorLeft = $left + 6;
                        $output = (($output | Out-String).Split("`n") | Where-Object {$_.Length -gt 0}) | Out-String
                        #$output | Color-Output -word $colorWords.words -color $colorWords.colors
                        $output | Color-Output
                } 
            } else {
			    #$output | Color-Output -word $colorWords.words -color $colorWords.colors
                $output | Color-Output
            }

           ## If output and add item requires remediation, add this to remediation array
            if ($addToRemediation) {

                ## If remediation provided output it
                if ($scripts[$step].remediation) {
                    $remediationText = Format-String "$($scripts[$step].Remediation)`n" -padding 3 -left ($left)
                    $remediationText | Color-Output -foreground "Yellow"
                    Write-Host "`n";
                }

                ## remediation to array
                $remediation += [PSCustomObject]@{
                    field = $scripts[$step].field
                    title = $scripts[$step].Title
                    remediation = $scripts[$step].remediation
                    result = $result
                    output = $output
                    foreground = $foreground
                    background = $background
                }
            }
        }
    }
    $step ++
}

###################### Recap and Output remediation items #############################

ForEach ($item in $remediation) {
    Write-Host -ForegroundColor Black -BackgroundColor Yellow "  $($item.field)" -NoNewline   ## Field
    Write-Host -ForegroundColor Yellow -NoNewline " - $($item.title) ";                     ## Title
    Write-Host -ForegroundColor $item.foreground "[$($item.result)]"                 ## Pass/Warning/Fail
    if ($item.Remediation) {
        #Write-Host -ForegroundColor "Yellow" "[Remediation] "
        $formatted = Format-String "$($item.remediation)`n" -padding 4
        $formatted | Color-Output -left $left
    }
}

## End of script and recap remediation.
if ($remediation.count -gt 0) {
    Write-Coord -foreground Cyan "Checks are done! " -nonewline; Write-Host -ForegroundColor Yellow " $($remediation.Count) item(s) " -NoNewline; Write-Host -ForegroundColor Cyan "that need to be reviewed."
} else {
    Write-Coord -foreground Cyan "Things seem to look okay. Please reach out to us at support@zeronetworks.zendesk.com to troubleshoot further."
}
