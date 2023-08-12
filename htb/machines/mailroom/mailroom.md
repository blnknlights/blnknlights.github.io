## Enum
```bash
nmap -Pn -sC -sV 10.10.11.209 -oN scans/nmap.initial
Starting Nmap 7.94 ( https://nmap.org ) at 2023-07-22 16:17 IST
Nmap scan report for 10.10.11.209
Host is up (0.032s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 94:bb:2f:fc:ae:b9:b1:82:af:d7:89:81:1a:a7:6c:e5 (RSA)
|   256 82:1b:eb:75:8b:96:30:cf:94:6e:79:57:d9:dd:ec:a7 (ECDSA)
|_  256 19:fb:45:fe:b9:e4:27:5d:e5:bb:f3:54:97:dd:68:cf (ED25519)
80/tcp open  http    Apache httpd 2.4.54 ((Debian))
|_http-title: The Mail Room
|_http-server-header: Apache/2.4.54 (Debian)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 8.15 seconds
```
