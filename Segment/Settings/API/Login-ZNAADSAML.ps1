function Test-IsAdmin
{
   <#
         .SYNOPSIS
         Check if PowerShell run elevated (e.g. as admin or not)

         .DESCRIPTION
         This is a complete new approach to check if the Shell runs elevated or not.
         It runs on PowerShell and PowerShell Core, and it supports macOS or Linux as well.

         .EXAMPLE
         PS C:\> Test-IsAdmin

         .NOTES
         Rewritten function to support PowerShell Desktop and Core on Windows, macOS, and Linux
         Mostly used within other functions and in the personal PowerShell profiles.

         Version: 1.0.1

         GUID: a59bfa91-7206-4892-bc2a-acf666b35364

         Author: Joerg Hochwald

         Companyname: Alright IT GmbH

         Copyright: Copyright (c) 2019, Alright IT GmbH - All rights reserved.

         License: https://opensource.org/licenses/BSD-3-Clause

         Releasenotes:
         1.0.1 2019-05-09: Add some comments to the code
         1.0.0 2019-05-09: Initial Release of the rewritten function

         THIS CODE IS MADE AVAILABLE AS IS, WITHOUT WARRANTY OF ANY KIND. THE ENTIRE RISK OF THE USE OR THE RESULTS FROM THE USE OF THIS CODE REMAINS WITH THE USER.
   #>

   [CmdletBinding(ConfirmImpact = 'None')]
   [OutputType([bool])]
   param ()

   process
   {
      if ($PSVersionTable.PSEdition -eq 'Desktop')
      {
         # Fastest way on Windows
         ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] 'Administrator')
      }
      elseif (($PSVersionTable.PSEdition -eq 'Core') -and ($PSVersionTable.Platform -eq 'Unix'))
      {
         # Ok, on macOS and Linux we use ID to figure out if we run elevated (0 means superuser rights)
         if ((id -u) -eq 0)
         {
            return $true
         }
         else
         {
            return $false
         }
      }
      elseif (($PSVersionTable.PSEdition -eq 'Core') -and ($PSVersionTable.Platform -eq 'Win32NT'))
      {
         # For PowerShell Core on Windows the same approach as with the Desktop work just fine
         # This is for future improvements :-)
         ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] 'Administrator')
      }
      else
      {
         # Unable to figure it out!
         Write-Warning -Message 'Unknown'

         return
      }
   }
}
#only works on windows
if($PSVersionTable.PSEdition -eq 'Core'){
    if($isWindows -eq $false){
        throw "This script only works on Windows"
        exit
    }
}

#Check for module
if (Get-Module -ListAvailable -Name "MSIdentityTools") {
    Import-Module MSIdentityTools
} else {
    if((Test-IsAdmin) -eq $true){
        Install-Module -Name "MSIdentityTools" -Force
        Import-Module MSIdentityTools
    } else {
        Install-Module -Name "MSIdentityTools" -Force -Scope CurrentUser
        Import-Module MSIdentityTools
    }
}

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Web

$BASE_URI = "https://portal.zeronetworks.com/api/v1"

function Get-ZeroTokenUsingAAD {

    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$false)]
        [string]
        $Issuer = "$($BASE_URI)/sso/azure/metadata",

        [Parameter(Mandatory=$false)]
        [string]
        $Tenant = "common",

        [Parameter(Mandatory=$false)]
        [string]
        $ACS = "$($BASE_URI)/sso/azure/acs",

        [Parameter(Mandatory=$false)]
        [switch]
        $ForceAuth
    )


    $samlreq = New-MsIdSamlRequest -Issuer $Issuer -AssertionConsumerServiceURL $ACS -ForceAuthn:$ForceAuth -DeflateAndEncode:$true
    $samlreq = [System.Web.HTTPUtility]::UrlEncode($samlreq)
    $url = "https://login.microsoftonline.com/$($tenant)/saml2?SAMLRequest=$($samlreq)`&sso_reload=true"

    $Form = New-Object -TypeName System.Windows.Forms.Form -Property @{Width=440;Height=640}
    $WebBrowser = New-Object -TypeName System.Windows.Forms.WebBrowser -Property @{Width=420;Height=600;Url=($Url) }

    $DocComp  = {
        $Global:uri = $WebBrowser.Url.AbsoluteUri
        if ($Global:uri -match "error=[^&]*|code=[^&]*") {$Form.Close() }
    }
    $DocNav = {
        if($WebBrowser.DocumentText -match "Zero Networks - SSO")
        {
            $Script:Document = [System.Windows.Forms.HtmlDocument]$WebBrowser.Document
            $Form.Close()
        }
    }

    $WebBrowser.ScriptErrorsSuppressed = $true
    $WebBrowser.Add_DocumentCompleted($DocComp)
    $WebBrowser.Add_Navigated($DocNav)
    $Form.AutoScaleMode = 'Dpi'
    $Form.text = "Azure AD Authentication"
    $Form.ShowIcon = $False
    $Form.AutoSizeMode = 'GrowAndShrink'
    $Form.StartPosition = 'CenterScreen'
    $Form.Controls.Add($WebBrowser)
    $Form.Add_Shown({$Form.Activate()})
    [Void]$Form.ShowDialog()
    return $Script:Document.All["token"].GetAttribute("Value")
}

$token = Get-ZeroTokenUsingAAD -ForceAuth
$znHeaders = @{
    Authorization = $token
    "Content-Type" = "application/json"
}

return $znHeaders