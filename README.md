<br>
    
<p align="center"><img src="https://avatars.githubusercontent.com/u/46243031?s=200&v=4" alt="name" width="15%"></p>
<h2><p align="center">Community Repo</p></h2>

<p align="center">
<a href="https://github.com/zeronetworks/Community/fork" target="blank">
<img src="https://img.shields.io/github/forks/zeronetworks/Community?style=flat-square" alt="zeronetworks community forks"/>
</a>
<a href="https://github.com/zeronetworks/Community/stargazers" target="blank">
<img src="https://img.shields.io/github/stars/zeronetworks/Community?style=flat-square" alt="zeronetworks community scripts"/>
</a>
<img src="https://img.shields.io/badge/scripts-14-blueviolet?style=flat-square" alt="zeronetworks community stars"/>
<a href="https://github.com/zeronetworks/Community/issues" target="blank">
<img src="https://img.shields.io/github/issues/zeronetworks/Community?style=flat-square" alt="zeronetworks issues"/>
</a>
<a href="https://github.com/zeronetworks/Community/pulls" target="blank">
<img src="https://img.shields.io/github/issues-pr/zeronetworks/Community?style=flat-square" alt="zeronetworks pull-requests"/>
</a>
<h4 align="center">A collaborative collection of valuable scripts for configuring, managing, and troubleshooting issues with Zero Networks, actively contributed by the community and Zero Networks </h4>


<p align="center">
    <a href="https://zeronetworks.com/zero-network-segment/" target="blank">Segment</a>
    ·
    <a href="https://zeronetworks.com/zero-networks-connect/">Connect</a>
    ·
    <a href="https://zeronetworks.com/trustmeter/">Trust Meter</a>
    ·
    <a href="https://github.com/zeronetworks/">Red & Blue Team Tools</a>
</p>

------

<br>

## Segment

<details>
<summary>Active Directory (2)</summary>

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;**[Get-ADGPOsWithFWRules.ps1](/home/runner/work/Community/Community/Segment/Active%20Directory/Get-ADGPOsWithFWRules.ps1)** - Gets any firewall rules associated with other AD group policies (GPOs)

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;**[purgeKerberosOnHosts.ps1](/home/runner/work/Community/Community/Segment/Active%20Directory/purgeKerberosOnHosts.ps1)** - This script accepts a CSV of remote Windows servers, and runs several command useful for forcing GPO processing


</details>



<details>
<summary>Asset Management (5)</summary>

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;**[CreateOTAssets.ps1](/home/runner/work/Community/Community/Segment/Asset%20Management/CreateOTAssets.ps1)** - Simple API Call to add an OT/IoT asset entry to Zero Networks

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;**[Move-ProtectToLearning.ps1](/home/runner/work/Community/Community/Segment/Asset%20Management/Move-ProtectToLearning.ps1)** - Move-ProtectToLearning.ps1 


&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;**[Unprotect-ZNLearningButNotConnected.ps1](/home/runner/work/Community/Community/Segment/Asset%20Management/Unprotect-ZNLearningButNotConnected.ps1)** - Unprotect-ZNLearningButNotConnected.ps1 


&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;**[enrollLinuxAsset.ps1](/home/runner/work/Community/Community/Segment/Asset%20Management/enrollLinuxAsset.ps1)** - This script accepts a CSV of Linux servers, and adds them to the Zero Networks dashboard as a manual Linux asset.

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;**[auditMonitoredAssets.ps1](/home/runner/work/Community/Community/Segment/Asset%20Management/auditMonitoredAssets.ps1)** - This script accepts a CSV of assets which SHOULD be monitored, and queries the ZN API to see if they are showing as monitored..


</details>



<details>
<summary>Rules (2)</summary>

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;**[Update-ZNBlockRulewithRiskyIps.ps1](/home/runner/work/Community/Community/Segment/Rules/Update-ZNBlockRulewithRiskyIps.ps1)** - Update-ZNBlockRulewithRiskyIps.ps1 


&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;**[Update-ZNOutboundBlockfromURLFile.ps1](/home/runner/work/Community/Community/Segment/Rules/Update-ZNOutboundBlockfromURLFile.ps1)** - Update-ZNOutboundBlockfromURLFile.ps1 



</details>



<details>
<summary>Troubleshooting (3)</summary>

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;**[Network Port Connectivity Check.ps1](/home/runner/work/Community/Community/Segment/Troubleshooting/Network%20Port%20Connectivity%20Check.ps1)** - Does network connectivity Test on Clients and Trust Server on the required ports based on the Deployment guide

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;**[ZN_Troubleshooter_v01.ps1](/home/runner/work/Community/Community/Segment/Troubleshooting/ZN_Troubleshooter_v01.ps1)** - ZN_Troubleshooter_v01.ps1 


&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;**[ZNConnectivityTest.ps1](/home/runner/work/Community/Community/Segment/Troubleshooting/ZNConnectivityTest.ps1)** - ZNConnectivityTest.ps1 



</details>


<br>API - **[Login-ZNAADSAML.ps1](Segment/API/Login-ZNAADSAML.ps1)** - Login-ZNAADSAML.ps1 


<br>MFA Push - **[getSecretMicrosoftAuth.ps1](Segment/MFA%20Push/getSecretMicrosoftAuth.ps1)** - getSecretMicrosoftAuth.ps1 


<br>Settings - **[Add-ZNTrustedInternetAddresses.ps1](Segment/Settings/Add-ZNTrustedInternetAddresses.ps1)** - Simple API Call to Trusted Internet IPs

<br>Trust Server - **[Logs - Parse WinRM from Trust Server logs and Summarize.ps1](Segment/Trust%20Server/Logs%20-%20Parse%20WinRM%20from%20Trust%20Server%20logs%20and%20Summarize.ps1)** - Sample Script to parse through the trust server logs and summarize the last 1000 entries for quick troubleshooting


<br>

## TrustMeter

<details>
<summary>Examples (4)</summary>

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;**[Ex1 - Simple scan for open ports on all AD assets.ps1](/home/runner/work/Community/Community/TrustMeter/Examples/Ex1%20-%20Simple%20scan%20for%20open%20ports%20on%20all%20AD%20assets.ps1)** - Example 1 - Scans for open ports on any AD asset within the Domain

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;**[Ex2 - Simple scan for open ports on all AD Assets in Forest.ps1](/home/runner/work/Community/Community/TrustMeter/Examples/Ex2%20-%20Simple%20scan%20for%20open%20ports%20on%20all%20AD%20Assets%20in%20Forest.ps1)** - Example 2 - Scans for open ports on any AD asset within the AD Forest

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;**[Ex3 - Scan an list of IP Ranges.ps1](/home/runner/work/Community/Community/TrustMeter/Examples/Ex3%20-%20Scan%20an%20list%20of%20IP%20Ranges.ps1)** - Example 3 - Scans for open ports on an AD asset and any IP residing in the provided input IP ranges

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;**[Ex4 - Scan for open ports and parse JSON output.ps1](/home/runner/work/Community/Community/TrustMeter/Examples/Ex4%20-%20Scan%20for%20open%20ports%20and%20parse%20JSON%20output.ps1)** - Example 4 - Scans for open ports on any asset and IP range. After scan, parse JSON results from report


</details>


<br>POC - **[POC_TrustMeter_ScanManagedAssets.ps1](TrustMeter/POC/POC_TrustMeter_ScanManagedAssets.ps1)** - The purpose of this script is to perform a network port scan on assets managed by Zero Networks.

<br>

---

## Contributing

If you have a script you would like to share to the community or improvements on an existing script, your help is welcome!

### How to make a clean pull request

- Create a [personal fork](https://github.com/zeronetworks/Community/fork) of the project on Github.
- Clone the fork on your local machine. Your remote repo on Github is called `origin`.
- Add the original repository as a remote called `upstream`.
- If you created your fork a while ago be sure to pull upstream changes into your local repository.
- Add your script to an existing folder/subfolder or update an existing script with your improvements.
- Comment the script so others can understand how the code works.
- Commit and push your changes to your remote repo `origin`.
- Submit a pull request so your changes can be reviewed and added to `Zero Networks Community Repo`.
- Once the pull request is approved and merged you can pull the changes from `upstream` to your local repo.

<br><br>
![generated_image](https://img.shields.io/badge/generated%20date-09/07/2023%2013:03:22-blue)
