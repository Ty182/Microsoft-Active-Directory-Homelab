# Lab_Automation

These two scripts allow for an easy and automated way to setup a home lab quick!

--- DC_Script_Setup.ps1 ---
- Description:
    - Configures a Windows domain controller via PowerShell script
        1. Updates the IP address and Hostname, creates a Scheduled Task and Restarts the OS
        2. Installs Active Directory and DNS, creates a Scheduled Task and Restarts the OS
        3. Installs DHCP and Restarts the OS
    
- How-to Run:
    - Place DC_Script_Setup.ps1 on the root of the C:\ drive
    - Open PowerShell.exe or Cmd.exe and run this code >  powershell.exe -ExecutionPolicy Bypass .\DC_Script_Setup.ps1 -one
    
- Tested on Windows Server 2016


--- Client_Script_Setup.ps1 ---
- Description:
    - Configures a Windows domain controller via PowerShell script
        1. Configures IP address and Hostname, Joins host to the domain and Restarts the OS
    
- How-to Run:
    - Open PowerShell.exe or Cmd.exe and run this code >  powershell.exe -ExecutionPolicy Bypass .\Client_Setup_Script.exe
    
- Tested on Windows 10 Enterprise
