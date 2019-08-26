<#
    .DESCRIPTION 
    Place this script at the root of the C directory >  C:\
    Open PowerShell.exe or Cmd.exe and type >  cd C:\
                                            >  powershell.exe -ExecutionPolicy Bypass .\Client_Setup_Script.exe

    Once the script executes it does the following:
        1. Configures IP address and Hostname, Joins host to the domain and Restarts the OS

    .NOTES
    Author:     Tyler Petty
    Date:       24 Aug 2019
    Version:    1.0
#>

# Each parameter below has a default value. 
# If no parameters are specified on script execution then the default value is used instead
[cmdletbinding()]
Param
    (
        # Declare IP Address for this host
        [string]$ipAddress = '10.10.10.20',

        # Declare DNS Address of the Domain Controller - if DNS is setup on the Domain Controller then this must be the IP address of the Domain Controller
        [string]$dnsAddress = '10.10.10.15',

        # Declare Hostname for this host
        [string]$hostname = 'VM-Win10-01',

        # Declare domain name for this host to join to
        [string]$domainName = 'coffee.com',

        # Declare account username with permissions to add host to domain
        [string]$username = "DomainJoinAccount",

        # Declare password of above account
        [string]$password = "P@ssword123456"
        
    )

# Get the name of this script - this command only works if you run the script file i.e. not from powershell_ise.exe
$scriptName = 'Client_Setup_Script'

# Location to run the script from
$location = 'C:\'

# Path to log file
$logPath = "$location$scriptName.log"


Function Get-TimeStamp
    {
        return "[{0:MM/dd/yy} {0:HH:mm:ss}]" -f (Get-Date)  
    } # Get-TimeStamp


Function Update-Log
    {
        [cmdletbinding()]
        Param
        (
            $logMessage
        )

        Add-Content -Value "$(Get-TimeStamp) $logMessage." -Path $logPath -Force
    } # Update-Log


Function Configure-IPandDNS
    {
        [cmdletbinding()]
        Param
        (
            [string]$new_IPv4,
            [string]$new_DNS
        )

        Update-Log -logMessage "Configuring IPv4 interface"

        # get old IPv4 address
        $old_IPv4 = (Get-NetIPConfiguration).IPv4Address.IPAddress

        Update-Log -logMessage "Old IP address found: $old_IPv4"

        # remove old IPv4 address
        Remove-NetIPAddress -InterfaceAlias Ethernet -IPAddress $old_IPv4 -Confirm:$false

        Update-Log -logMessage "Replacing with new IP address: $new_IPv4"

        # set new IPv4 address
        New-NetIPAddress -InterfaceAlias Ethernet -IPAddress $new_IPv4 -PrefixLength 24

        # Get IPv4 address
        $current_IPv4 = (Get-NetIPConfiguration).IPv4Address.IPAddress

        # Verify IPv4 address is set correctly
        If ($current_IPv4 -ne $new_IPv4)
            {
                Update-Log -logMessage "Error: IPv4 address not set correctly. Script will now exit"
                Exit
            }
        Else
            {
                Update-Log -logMessage "IPv4 address set correctly"
                
                Update-Log -logMessage "Configuring DNS to use IP address: $new_DNS"

                # Configure DNS address
                Set-DnsClientServerAddress -InterfaceAlias Ethernet -ServerAddresses $new_DNS

                # Get DNS address
                $current_DNS = (Get-DnsClientServerAddress -AddressFamily IPv4 -InterfaceAlias Ethernet).ServerAddresses

                # Verify DNS address is set correctly
                If ($current_DNS -ne $new_DNS)
                    {
                        Update-Log -logMessage "Error: DNS address not set correctly. Script will now exit"
                        Exit
                    }
                Else
                    {
                        Update-Log -logMessage "DNS address set correctly"
                    }
            }
    } # Configure-IPandDNS


Function Add-ToDomain
    {
        [cmdletbinding()]
        Param
        (
            [string]$username,
            [string]$password,
            [string]$hostname,
            [string]$domainName
        )
        
        $secPass = ConvertTo-SecureString -String $password -AsPlainText -Force
	    
        $credential = New-Object System.Management.Automation.PSCredential($username,$secPass)

        Rename-Computer -NewName $hostname -Force
        Sleep -Seconds 5

        Add-Computer -DomainName $domainName -Options JoinWithNewName,accountcreate -Credential $credential -Force -Restart
    } # Add-ToDomain


####  Begin Script Logic ####

Update-Log -logMessage "First script run"

Update-Log -logMessage "Configuring this host with a new IP and DNS address"

# Configure this host's IP and DNS addresses
Configure-IPandDNS -new_IPv4 $ipAddress -new_DNS $dnsAddress

Update-Log -logMessage "Configuring this host with a new Hostname and joining to the domain"

Update-Log -logMessage "A restart is needed to make these changes. Run this script again after logon"

# Configure hostname, join to the domain, and restart the OS
Add-ToDomain -username $username -password $password -hostname $hostname -domainName $domainName