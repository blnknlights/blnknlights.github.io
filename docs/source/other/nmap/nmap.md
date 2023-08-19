# Nmap

## cheat sheet 
```
-sL          : Scan List    - simply list targets to scan
-sV          : Scan Version - OS & services version detection
-sC          : Scan Script  - Running NSE script scanning - Advanced version detection 

-sU          : Scan UDP     - longer but will potentially circumvent firewall (much longer)

-sS          : Scan SYN     - half TCP handshake - Is the default/popular and relatively stealthy because some IDSes only log fully established connections 
-sT          : Scan TCP     - full TCP handshake
-sA          : Scan ACK
-sW          : Scan Window
-sM          : Scan Maimon

-sN          : Scan TCP Null
-sF          : Scan TCP FIN 
-sX          : Scan TCP Xmas
```
```
-A            : All - Enable OS detection, version detection, script scanning, and traceroute
-O            : OS - Enable OS detection
-n            : Never do DNS resolution  [default: sometimes]
-R            : Always do DNS resolution [default: sometimes]
-PR           : Just sends out ARP packets 
-sn           : Ping Scan - disable port scan (just do host discovery)
-Pn           : Skip host discovery - (No ping) - (ie Treat all hosts as online — Used to circumvent firewalls)
-T            : paranoid(0)|sneaky(1)|polite(2)|normal(3)|aggressive(4)|insane(5)
-p-           : scan all ports from 1 to 65535
-p            : Scan a specific port or port range
-p 1-65535    : one way to scan all ports from 1 to 65535
-p -65535     : one way to scan all ports from 1 to 65535
-p 1-         : one way to scan all ports from 1 to 65535
-PS           : Send SYN to a specific port (will receive SYN-ACK)
-PA           : Send ACK to a specific port (will receive RST)
-PU           : Send UDP to a specific port 
-F            : Fast mode (only scan some of the ports) 
-vvv          : Degrees of verbosity
--traceroute  : Trace hop path to each host
--exclude     : Exclude a specific ip(s)
--open        : Only show open (or possibly open) ports
--reason      : Display the reason a port is in a particular state

--script      : Run a lua script such as: 
	       --script=smb-os-discovery
	       --script=banner
	       --script=http-enum
	       See build-in nmap scripts in /usr/share/nmap/scripts/
```
```
-oA           : Output scan in all formats at the same time
-oN           : Output scan in normal
-oS           : Output scan in s|<rIpt kIddi3
-oG           : Output scan in Grepable format
-oX           : Output scan in XML
--stylesheet  : Specify an XSL stylesheet <path/URL> to transform XML output to HTML
```
```
-D            : Decoy appear to be scanning from different IP 
-D            : 10.0.0.1,10.0.0.2,10.0.0.3 
--spoof-mac   : Feed a MAC address, prefix, or vendor name to spoof the MAC address you're scanning from 
-sI           : Idle scan - Feed <zombie host[:probeport]> and probes will be routed through a zombie before going back to the scanner
```

Examples of targeted host discovery: 
```bash
nmap -PR $hosts 
nmap -sn -n -v 192.168.100.0/24 
nmap -sn -n -v —exclude 192.168.100.7 192.168.100.1-32
```

Examples of targeted service discovery: 
```bash
nmap -F -sS -n -v —reason —open 192.168.100.11 
nmap -F -sU -n -v —reason —open 192.168.100.11 
nmap -p- -sS -n -v —reason —open -oX output.xml —stylesheet=nmap.xml 192.168.100.11 
nmap -sS -sV -sC -n -v -p 21,22,80,445,631,3000,3306,3500,6697,8181 -oX output.xml 192.168.100.11
```

## other scanners 

### amap 
```
Amap is a scanning tool that allows you to identify the applications that are running on a specific port or ports. 
This is achieved by connecting to the port(s) and sending trigger packets. 
These trigger packets will typically be an application protocol handshake.
```
### unicornscan
### speed
### Hping3: 
### Galishmero
### rustscan
### masscan
