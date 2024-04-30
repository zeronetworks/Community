<#PSScriptInfo

SEE .EXAMPLES SECTION FOR USAGE

.VERSION 1.0

.AUTHOR Thomas Obarowski (https://www.linkedin.com/in/tjobarow/)

.COPYRIGHT (c) 2024 Thomas Obarowski

.TAGS Automation Scripts

.SYNOPSIS
    This module copies the C:\Program Files\Zero Networks\BreakGlass\ directory to a destination server

.DESCRIPTION
    This module will use a PSSession to connect to the provided Segment Server. It attempts
    to compress C:\Program Files\Zero Networks\BreakGlass\ to BreakGlass.zip, and then copy
    it to the local filesystem (host running module). It then closes the previous pssession
    and enters a new one on the destination server. It copies the breakglass.zip file to 
    a remote directory provided at run time. It then closes the pssession and removes the 
    local copy of BreakGlass.zip

.PARAMETER Credential
    PSCredential object needed to create PSSession to Segment Server
.PARAMETER Username
    Account username to use to create PSSession
.PARAMETER Password
    Password for the associated username provided
.PARAMETER SegmentServer
    SHORT hostname for Segment Server (such as znserver)
.PARAMETER RemoteDirectory
    Remote directory to copy the archive into
.PARAMETER BreakGlassServer
    SHORT hostname for the BreakGlass (destination) server

.NOTES
    DEPENDENCIES:
    * Inbound allow rule allowing the device running this script to WinRM to both
        the BreakGlass and Segment server without MFA (if applicable)
    * PSRemoting must be enabled on both servers (Enable-PSRemoting -Force)
    * Account used must:
        - Be have PSRemoting permission on the segment and breakglass (destination) server
            - Run the below command while in a GRAPHICAL session on the server (GUI pop up)
            - Can set the account to have permissions to PSRemote
            - Set-PSSessionConfiguration -Name Microsoft.PowerShell -ShowSecurityDescriptorUI -Force 
        - Be local admin on the segment and breakglass server
        - Have permission to copy a file to the remote directory you specify
            - AKA - You should make sure the domain account you are using have permissions
            to access and write to the remote directory you specify on the destination server

.EXAMPLE
    To use the script
        Sync-BreakGlassDirectory -Username "adminUsername" -Password "adminPwd"-BreakGlassServer "destinationServerHostName" -SegmentServer "znSegmentServerHostName" -RemoteDirectory "C:\Users\Public\ZNBreakGlassFiles"

    OR
        Sync-BreakGlassDirectory -Credential (Get-Credential) -BreakGlassServer "destinationServerHostName" -SegmentServer "znSegmentServerHostName" -RemoteDirectory "C:\Users\Public\ZNBreakGlassFiles"

    OR WITH ENV VARIABLES SET
        $ENV:segmentServer = "ZnSegmentServer1"
        $ENV:breakglass_server = "ZnBreakGlassServer1"
        $ENV:remote_directory = "C:\Users\Public\ZNBreakGlassFiles"
        $ENV:username = "ad-account-with-admin-username"
        $ENV:password = "somesecurepassword"
        Sync-BreakGlassDirectory -Username $ENV:username -Password $ENV:password -BreakGlassServer $ENV:BreakGlassServer -SegmentServer $ENV:SegmentServer -RemoteDirectory $ENV:RemoteDirectory
#>


function Log-Message {
    <#
    .SYNOPSIS
        Log-Message function writes a string to stdout and appends to a pre-named log file.
    .DESCRIPTION
        Accepts a string, adds a timestamp infront of said string, writes to stdout, and then
        appends to a log file. less verbose than Start-Transcript, but still includes timestamps
    .PARAMETER Message
        String message to log to stdout and file
    .OUTPUTS
        None
    .NOTES
        N/A
    .FUNCTIONALITY
    Logging Mechanism
    #>
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [string]$Message = ""
    )
    Write-Host "$((Get-Date -Format 'yyyy-MM-dd HH:mm:ss').ToString()) - $Message"
    "$((Get-Date -Format 'yyyy-MM-dd HH:mm:ss').ToString()) - $Message" | Out-File -FilePath "$((Get-Date -Format 'yyyy-MM-dd').ToString())_sync-BreakGlass-Directory.log" -Append
}


function Get-Credentials {
    <#
    .SYNOPSIS
        Get-Credentials - Creates a PSCredential Object based on provided username/password
    .DESCRIPTION
        Accepts username and password, converts the password to a securestring, and then
        creates a PSCredentialObject based on the securestring and username
    .PARAMETER Username
        Admin account username
    .PARAMETER Password
        Admin account password
    .OUTPUTS
        Return PSCredentials object
    .NOTES
        Information or caveats about the function e.g. 'This function is not supported in Linux'
    .FUNCTIONALITY
    Create PSCredential object used in other Cmdlets
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$Username,
        [Parameter(Mandatory = $true)]
        [string]$Password
    )
    try {
        # Convert password to secure string
        $svc_pwd = ConvertTo-SecureString "$Password" -AsPlainText -Force
        # Create new PSCredential based on username and SecureString password
        $credentials = New-Object System.Management.Automation.PSCredential ($Username, $svc_pwd)
        Log-Message "Loaded credentials for use with AD. Username: $($credentials.UserName)"
        #Return credentials object
        return $credentials
    }
    catch {
        Log-Message "An error occurred when creating the credentials object."
        Log-Message $Error[0]
        exit 1
    }
}


function Get-BreakGlassZip {
    <#
    .SYNOPSIS
        Get-BreakGlassZip - Compresses and copies the contents of 
        C:\Program Files\Zero Networks\BreakGlass\ on the Segment Server
        to your local filesystem
    .DESCRIPTION
        This function requires a valid credential object that has local administrator
        privileges on the ZN Segment Server, as well as the ComputerName of the Segment
        Server. It then creates a new PSSession with the Segment Server. It uses
        Invoke-Command to compress the C:\Program Files\Zero Networks\BreakGlass\ directory
        to a file named BreakGlass.zip. It then uses Copy-Item -FromSession to copy
        the BreakGlass.zip from the Segment Server PSSession into the local filesystem
        where the script is ran from. It then terminates the PSSession to the Segment
        Server.
    .PARAMETER Credential
        PSCredential object needed to create PSSession to Segment Server
    .PARAMETER SegmentServer
        SHORT hostname for Segment Server (such as znserver)
    .OUTPUTS
        N/A - None
    .NOTES
        The credentials object used must be enabled for PSRemoting on the segment server
        and have local admin.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [System.Management.Automation.PSCredential]$Credential,
        [Parameter(Mandatory = $true)]
        [string]$SegmentServer
    )
    try {
        # Create new PSSession to Segment Server using the provided credentials
        Log-Message "Attemping to connect to $SegmentServer via New-PSSession."
        $RemoteSession = New-PSSession -ComputerName $SegmentServer -Credential $Credential
        Log-Message "Successfully connected to $SegmentServer via PSSession using $($Credential.UserName)"

        # Define scriptblock that will compress the BreakGlass directory.
        Log-Message "Attempting to compress the ZN BreakGlass directory to breakGlass.zip file"
        $CompressScript = {
            #The args[0] is because we pass the username of the account in use so we can store the zip in it's home folder
            Compress-Archive -Path "C:\Program Files\Zero Networks\BreakGlass\" -DestinationPath "C:\Users\$($args[0])\BreakGlass.zip" -Update
        }
        # Use Invoke-Command to run the Compress-Archive command on the Segment Server
        Invoke-Command -Session $RemoteSession -ArgumentList $Credential.UserName -ScriptBlock $CompressScript
        Log-Message "Successfully compressed ZN BreakGlass directory to zip file breakGlass.zip"

        # Copy the BreakGlass.zip archive from the Segment Server (via PSSession) to local directory
        Log-Message "Attempting to copy BreakGlass.zip file from $SegmentServer to $ENV:COMPUTERNAME"
        Copy-Item -FromSession $RemoteSession -Path "C:\Users\$($Credential.UserName)\BreakGlass.zip" -Destination .
        Log-Message "Successfully copied the BreakGlass.zip file from $SegmentServer to $ENV:COMPUTERNAME"

        #Tear down the PSSession
        Log-Message "Tearing down PSSession to $SegmentServer"
        Remove-PsSession -Session $RemoteSession
        Log-Message "Exited PSSession on $SegmentServer"
    }
    catch {
        $Error
        Log-Message $Error[0]
        exit 1
    }
}


function Push-BreakGlassZip {
    <#
    .SYNOPSIS
        Push-BreakGlassZip - Copies the BreakGlass.zip archive from local folder into the
        the RemoteDirectory specified on the breakglass (destination) server
    .DESCRIPTION
        This function requires a valid credential object that has local administrator
        privileges on the BreakGlass Server, as well as the ComputerName of the Segment
        Server, ComputerName of the BreakGlass Server, and Remote Directory where the file
        will be copied to. It then creates a new PSSession with the BreakGlass Server. It uses
        Invoke-Command to verify the remote directory specified exists, and tries to create
        it if it does not exist. It then uses Copy-Item -ToSession to copy
        the BreakGlass.zip from the local filesystem into the BreakGlass server, at the
        provided remote directory. It renames BreakGlass.zip to include the Segment Server
        name the archive was retrieved from. It then terminates the PSSession to the Segment
        Server.
    .PARAMETER Credential
        PSCredential object needed to create PSSession to Segment Server
    .PARAMETER SegmentServer
        SHORT hostname for Segment Server (such as znserver)
    .PARAMETER RemoteDirectory
        Remote directory to copy the archive into
    .PARAMETER BreakGlassServer
        SHORT hostname for the BreakGlass (destination) server
    .OUTPUTS
        N/A - None
    .NOTES
        The credentials object used must be enabled for PSRemoting on the breakglass
        server and have local admin.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [System.Management.Automation.PSCredential]$Credential,
        [Parameter(Mandatory = $true)]
        [string]$RemoteDirectory,
        [Parameter(Mandatory = $true)]
        [string]$BreakGlassServer,
        [Parameter(Mandatory = $true)]
        [string]$SegmentServer
    )
    try {

        # Create new PSSession to BreakGlass server using provided credentials
        Log-Message "Attemping to connect to $BreakGlassServer via New-PSSession."
        $RemoteSession = New-PSSession -ComputerName $BreakGlassServer -Credential $Credential
        Log-Message "Successfully connected to $BreakGlassServer via PSSession using $($Credential.UserName)"

        # Create script block that will verify that the remote directory specified exists
        Log-Message "Verifying directory $RemoteDirectory exists on $BreakGlassServer and creating it if non-existent."
        $VerifyDirectoryScript = {
            #args[0] will be the $RemoteDirectory value
            if (-not (Test-Path -Path $args[0])) {
                New-Item -Path $args[0] -ItemType Directory
            }
            else {
                Write-Output "$($args[0]) already exists"
            }
        }
        #Use Invoke-Command to run the script block on the breakglass server
        Invoke-Command -Session $RemoteSession -ArgumentList $RemoteDirectory -ScriptBlock $VerifyDirectoryScript
        Log-Message "Verfied directory $RemoteDirectory exists on $BreakGlassServer"

        # Copy the BreakGlass.zip archive to the breakglass server, updating the name to include reference to 
        # the segment server it was fetched from
        Log-Message "Attempting to copy BreakGlass.zip file from $ENV:COMPUTERNAME to $BreakGlassServer ($RemoteDirectory\BreakGlass-From-$($SegmentServer).zip)"
        Copy-Item -ToSession $RemoteSession -Path ".\BreakGlass.zip" -Destination "$($RemoteDirectory)\BreakGlass-From-$($SegmentServer).zip"
        Log-Message "Successfully copied the BreakGlass.zip file from $ENV:COMPUTERNAME to $BreakGlassServer ($RemoteDirectory\BreakGlass-From-$($SegmentServer).zip)"

        # Tear down the PSSession to the BreakGlass server
        Log-Message "Tearing down PSSession to $BreakGlassServer"
        Remove-PsSession -Session $RemoteSession
        Log-Message "Exited PSSession on $BreakGlassServer"

        # Remove the local copy of BreakGlass.zip
        Log-Message "Attempting to remove BreakGlass.zip file from $ENV:COMPUTERNAME"
        Remove-Item -Path ".\BreakGlass.zip"
        Log-Message "Successfully removed BreakGlass.zip file from $ENV:COMPUTERNAME"
    }
    catch {
        Log-Message $Error[0]
        exit 1
    }
}


function Sync-BreakGlassDirectory {
    <#
    .SYNOPSIS
        Sync-BreakGlassDirectory - Main function that executes scripts - calls required
        functions to copy archive from segment server to breakglass server
    .DESCRIPTION
        This function accepts either a PSCredential object directly, or a username/password,
        and then determines which was provided. If user/pass, it calls Get-Credential to 
        convert that to a PSCredential object. It then executes:
        1. Get-BreakGlassZip
        2. Push-BreakGlassZip
        Which copies the BreakGlass directory from the Segement Server to the BreakGlass server
    .PARAMETER Credential
        PSCredential object needed to create PSSession to Segment Server
    .PARAMETER Username
        Account username to use to create PSSession
    .PARAMETER Password
        Password for the associated username provided
    .PARAMETER SegmentServer
        SHORT hostname for Segment Server (such as znserver)
    .PARAMETER RemoteDirectory
        Remote directory to copy the archive into
    .PARAMETER BreakGlassServer
        SHORT hostname for the BreakGlass (destination) server
    .OUTPUTS
        N/A - None
    .NOTES
        You can provide either a PSCredential object such as using (Get-Credential)
        in the function call. OR you can provide it a username/password
    .FUNCTIONALITY
    Basically the __init__ function of this script
    #>
    param(
        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]$Credential = $null,
        [Parameter(Mandatory = $true)]
        [string]$RemoteDirectory,
        [Parameter(Mandatory = $true)]
        [string]$BreakGlassServer,
        [Parameter(Mandatory = $true)]
        [string]$SegmentServer,
        [Parameter(Mandatory = $false)]
        [string]$Username,
        [Parameter(Mandatory = $false)]
        [string]$Password
    )

    # If no credential object was provided
    if ($null -eq $Credential) {
        # If the username and password fields are ALSO null
        if (("" -eq $Username) -or ( "" -eq $Password)) {
            Log-Message "You must either provide a valid credential object, or a valid -Username and -Password"
            exit 1
        }
        else {
            # Else if a valid user/pass is provided, create PSCredential object by calling Get-Credentials function
            $Credential = Get-Credentials -Username $Username -Password $Password
        }
    } # If the value of $Credential object is not of type PSCredential
    elseif (-not ($Credential -is [System.Management.Automation.PSCredential])) {
        # log and exit
        Log-Message "The value provided for -Credential is not a valid PSCredential object."
        exit 1
    }

    # Else execute the functions to copy the breakglass directory
    Get-BreakGlassZip -Credential $Credential -SegmentServer $SegmentServer
    Push-BreakGlassZip -Credential $Credential -RemoteDirectory $RemoteDirectory -BreakGlassServer $BreakGlassServer -SegmentServer $SegmentServer
    Log-Message "Completed copying BreakGlass directory from $SegmentServer to $BreakGlassServer at $RemoteDirectory\BreakGlass-From-$($SegmentServer)"
}

