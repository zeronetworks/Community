
## Zero Networks Troubleshooting script
```ZN_Troubleshooter_v01.ps1```

![Demo](images/ZN_Troubleshooter_endpoint.gif)

This script is a powerful tool used to quickly diagnose a range of issues and help identify common problems related to your deployment. It is designed to run on endpoints experiencing connectivity issues with the Trust Server or when the Trust Server is encountering connectivity problems with Zero Networks Cloud Service.
It is required to run this script as an administrator to check group policies on the computer as well as local firewall rules configured. 
This script will perform the following:
- Checks if WinRM and firewall services are running
- What ports WinRM is listening to
- Generates the assets Group Policy RSoP report to analyze
- Validates Zero Network group policies are associated to the local asset
- Identify other group policies that may conflict with Zero Networks
- Identify if there are other firewall rules on the local asset not managed by Zero Networks
- Check network connectivity with the domain controller, trust server, and cloud services.
- Verify firewall events (5156,5157) audit logs are enabled
- Checks if the required services are running on the trust server. 

You have two options for running the troubleshooting tool. 
You can either [download the script directly here ](https://raw.githubusercontent.com/zeronetworks/Community/master/Segment/Troubleshooting/ZN_Troubleshooter_v01.ps1) and run it manually.

Or you can simply execute the following command, which will automatically download and run the script for you in one line:

```
IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/zeronetworks/Community/master/Segment/Troubleshooting/ZN_Troubleshooter_v01.ps1')
```

If the script is unable to promptly identify the issue at hand, we recommend referring to the following guide and refer to the relevant section that corresponds to the problem you are facing to troubleshoot the issue further.
rust server