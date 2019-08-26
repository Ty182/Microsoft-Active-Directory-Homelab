# Lab_Automation

These two scripts allow for an easy and automated way to setup a home lab quick!

DC_Script_Setup.ps1
- Description:
    - Configures a Windows domain controller via PowerShell script
      - Configures IP Address
      - Sets up Windows Active Directory, DNS, and DHCP
    - Tested on Windows Server 2016
    
- How-to Run:
    - Place DC_Script_Setup.ps1 on the root of the C:\ drive
    - Open PowerShell.exe or Cmd.exe and run this code >  powershell.exe -ExecutionPolicy Bypass .\DC_Script_Setup.ps1 -one

Client_Script_Setup.ps1

