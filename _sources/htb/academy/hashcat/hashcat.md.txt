# Hashcat

## Useful documentation & stuff

[https://hashcat.net/wiki/doku.php?id=maskprocessor](https://hashcat.net/wiki/doku.php?id=maskprocessor)  
[https://hashcat.net/wiki/doku.php?id=rule_based_attack](https://hashcat.net/wiki/doku.php?id=rule_based_attack)  
[https://hashcat.net/wiki/doku.php?id=rule_based_attack#implemented_compatible_functions](https://hashcat.net/wiki/doku.php?id=rule_based_attack#implemented_compatible_functions)  
[https://hashcat.net/wiki/doku.php?id=rule_based_attack#rules_used_to_reject_plains](https://hashcat.net/wiki/doku.php?id=rule_based_attack#rules_used_to_reject_plains)  
[https://hashcat.net/wiki/doku.php?id=mask_attack](https://hashcat.net/wiki/doku.php?id=mask_attack)  
[https://hashcat.net/wiki/doku.php?id=example_hashes    ](https://hashcat.net/wiki/doku.php?id=example_hashes    )  
[https://hashcat.net/wiki/doku.php?id=frequently_asked_questions](https://hashcat.net/wiki/doku.php?id=frequently_asked_questions)  
[https://hashcat.net/wiki/doku.php?id=frequently_asked_questions#i_may_have_the_wrong_driver_installed_what_should_i_do](https://hashcat.net/wiki/doku.php?id=frequently_asked_questions#i_may_have_the_wrong_driver_installed_what_should_i_do)  
[https://hashcat.net/wiki/doku.php?id=frequently_asked_questions#how_to_create_more_work_for_full_speed](https://hashcat.net/wiki/doku.php?id=frequently_asked_questions#how_to_create_more_work_for_full_speed)  
[https://www.hacklikeapornstar.com/new-release-hack-like-legend/](https://www.hacklikeapornstar.com/new-release-hack-like-legend/)  


## More Wordlists & Rules
[https://github.com/d4rkduck1/OneRuleToRuleThemAll](https://github.com/d4rkduck1/OneRuleToRuleThemAll)  
[https://github.com/praetorian-inc/Hob0Rules.git](https://github.com/praetorian-inc/Hob0Rules.git)  
[https://github.com/danielmiessler/SecLists.git](https://github.com/danielmiessler/SecLists.git)  
[https://crackstation.net/crackstation-wordlist-password-cracking-dictionary.html](https://crackstation.net/crackstation-wordlist-password-cracking-dictionary.html)  

## Options
```
-b               benchmark
-a               attack mode
-m               module - hash type
-r               ruleset 
-o               output
--username       also output the associated username in the outfile
-w               workload profile
-O               --optimized-kernel-enable TLDR - always start with that 
--force          disables warnings and should be descouraged
--stdout         send tries to stdout for debugging
-1               options 1 to 4 to define custom charset in a mask attack
--increment      increment the mask length automatically
--increment-max  max increment length limit
--show           show cracked hashes
--left           show uncracked hashes
--example-hashes show examples of hashes
-j --rule-left
-k --rule-right
-g  generate random rules on the fly and apply them to the input wordlist.
```



## Examples

helpful commands
```bash
hashcat --example-hashes
hashcat --show
hashcat --left
hashcat -b -m 0    # benchmark test (performances) for hash type 0
```

dictionary attacks
```bash
hashcat -a 0 -m <hash type> <hash file> <wordlist>
hashcat -a 0 -m 1400 hash /usr/share/wordlists/rockyou.txt                               # sha256
hashcat -a 0 -m 3200 hash wordlist -r Hob0Rules/d3adhob0.rule -o cracked.txt -w 3 -O     # Bcrypt with toggle rules
hashcat -a 0 -m 100 hash /usr/share/wordlists/rockyou.txt -r rule.txt                    # sha1 with custom ruleset
hashcat -a 0 -m 100 -g 1000 hash /usr/share/wordlists/rockyou.txt
```

combination attacks 
```bash
hashcat -a 1 --stdout file1 file2    # just print to stdout
hashcat -a 1 -m 0 hash file1 file2   # md5
```

Brute-force mask attacks & Hybrid
```bash
hashcat -a 3 -m 0 hash -1 01 'ILFREIGHT?l?l?l?l?l20?1?d'
hashcat -a 3 -m 0 hash -1 02 'HASHCAT?l?l?l?l?l20?1?d' -O
hashcat -a 6 -m 0 hash /usr/share/wordlists/rockyou.txt '?d?s'          # Hybrid - Wordlist + Mask -> rockyou + 1 int + 1 special char
hashcat -a 6 -m 100 hash /usr/share/wordlists/rockyou.txt '?d?s'        # Hybrid - Wordlist + Mask -> rockyou + 1 int + 1 special char on a SHA1
hashcat -a 7 -m 0 hash -1 01 '20?1?d' /usr/share/wordlists/rockyou.txt  # Hybrid - Mask + Wordlist -> 20[0..19] + rockyou
```
    
## Attack Modes 
```
0 | Straight
1 | Combination
3 | Brute-force (Mask) 
6 | Hybrid Wordlist + Mask
7 | Hybrid Mask + Wordlist
9 | Association
```


## Mask attacks 

```
?l    lower-case ASCII letters (a-z)
?u    upper-case ASCII letters (A-Z)
?d    digits (0-9)
?h    0123456789abcdef hex lower
?H    0123456789ABCDEF hex upper
?s    special characters («space»!"#$%&'()*+,-./:;<=>?@[]^_`{
?a    ?l?u?d?s
?b    0x00 - 0xff  

?1    custom charset 1
?2    custom charset 2
?3    custom charset 3
?4    custom charset 4
```
        
example
```
ILFREIGHT<userid>  <year>
ILFREIGHT?l?l?l?l?l20[0-1]?d
```

## Rule based attacks 
```
l   Convert all letters to lowercase
u   Convert all letters to uppercase
c   capitalize  first letter lowercase the rest
C   lowercase first letter and invert the rest 
t   Toggle case : whole word
T   Toggle case : at position N
d   Duplicate word
s   Substitute character
q   Duplicate all characters
z   Duplicate first character
Z   Duplicate last character
{   Rotate word left
}   Rotate word right
^X  Prepend character X
$X  Append character X
r   Reverse
```

Reject rules - only when using -j or -k with Hashcat 
```
>N  reject words with length greater than N 
<N  reject words with length smaller than N 
```

Default rules
```
ls -l /usr/share/hashcat/rules/
-g  # generate random rules on the fly and apply them to the input wordlist.
```

Custom rules
[https://github.com/NSAKEY/nsa-rules](https://github.com/NSAKEY/nsa-rules)   
[https://github.com/praetorian-code/Hob0Rules](https://github.com/praetorian-code/Hob0Rules)  
[https://github.com/HackLikeAPornstar/StratJumbo/blob/master/chap3/corporate.rule](https://github.com/HackLikeAPornstar/StratJumbo/blob/master/chap3/corporate.rule)  
 
Self made rules
```bash
echo 'password_ilfreight' > test.txt
echo 'so0 si1 se3 ss5 sa@ c $2 $0 $1 $9' > rule.txt
../hashcat -r rule.txt test.txt --stdout
P@55w0rd_1lfr31ght2019

hashcat -a 0 -m 100 hash /usr/share/wordlists/rockyou.txt -r rule.txt
```


## DB Dumps
        
SHA1, MD5, BCRYPT are often seen in database dumps
```bash
cat words
winter!
baseball1
waterslide
summertime
baconandeggs
beach1234
sunshine1
welcome1
password123
```
```bash
for i in $(cat words); do echo -n $i | sha1sum | tr -d ' -';done > hashes
cat hashes
fa3c9ecfc251824df74026b4f40e4b373fd4fc46
e6852777c0260493de41fb43918ab07bbb3a659c
0c3feaa16f73493f998970e22b2a02cb9b546768
b863c49eada14e3a8816220a7ab7054c28693664
b0feedd70a346f7f75086026169825996d7196f9
f47f832cba913ec305b07958b41babe2e0ad0437
08b314f0e1e2c41ec92c3735910658e5a82c6ba7
e35bece6c5e6e0e86ca51d0440e92282a9d6ac8a
cbfdac6008f9cab4083784cbd1874f76618d2a97
```
```bash
../hashcat -a 0 -m 100 hashes /opt/wordlists/rockyou.txt # sha1
```


## Linux shadow
SHA512CRYPT are commonly found in Linx /etc/shadow
        
```
root:$6$tOA0cyybhb/Hr7DN$htr2vffCWiPGnyFOicJiXJVMbk1muPORR.eRGYfBYUnNPUjWABGPFiphjIjJC5xPfFUASIbVKDAHS3vTW1qU.1:18285:0:99999:7:::
$6 -> type 6 = SHA512
$tOA0cyybhb/Hr7DN -> 16chr Salt
$htr2vffCWiPGnyFOicJiXJVMbk1muPORR.eRGYfBYUnNPUjWABGPFiphjIjJC5xPfFUASIbVKDAHS3vTW1qU.1 -> Actual hash
```

```bash
hashcat -m 1800 nix_hash /opt/worldlists/rockyou.txt  # sha512crypt
```
            

## Active directory 

NTLM
```python
>>> import hashlib,binascii
>>> hash = hashlib.new('md4', "Password01".encode('utf-16le')).digest()
>>> print(binascii.hexlify(hash))
b'7100a909c7ff05b266af3c42ec058c33'
```
```bash
printf '7100a909c7ff05b266af3c42ec058c33' > ntlm_example
../hashcat -a 0 -m 1000 ntlm_example /opt/wordlists/rockyou.txt -r ../rules/hybrid/append_ds.rule  # NTLM
../hashcat -a 6 -m 1000 ntlm_example /opt/wordlists/rockyou.txt '?d?s'                             # NTLM
```

NetNTLMv1 
NetNTLMv2
```
sqladmin::INLANEFREIGHT:f54d6f198a7a47d4:7FECABAE13101DAAA20F1B09F7F7A4EA:0101000000000000C0653150DE09D20126F3F71DF13C1FD8000000000200080053004D004200330001001E00570049004E002D00500052004800340039003200520051004100460056000400140053004D00420033002E006C006F00630061006C0003003400570049004E002D00500052004800340039003200520051004100460056002E0053004D00420033002E006C006F00630061006C000500140053004D00420033002E006C006F00630061006C0007000800C0653150DE09D201060004000200000008003000300000000000000000000000003000001A67637962F2B7BF297745E6074934196D5F4371B6BA3E796F2997306FD4C1C00A001000000000000000000000000000000000000900280063006900660073002F003100390032002E003100360038002E003100390035002E00310037003000000000000000000000000000
```
```bash
../hashcat -a 0 -m 5600 inlanefreight_ntlmv2 /opt/wordlists/rockyou.txt   # NetNTLMv2
```

Kerberos 5 TGS-REP


## John the ripper extract tools 

Install the tools
```bash
sudo git clone https://github.com/magnumripper/JohnTheRipper.git
cd JohnTheRipper/src
sudo ./configure && make
```

MS office 
```bash
python3 office2john.py hashcat_Word_example.docx 
hashcat_Word_example.docx:$office$*2013*100000*256*16*6e059661c3ed733f5730eaabb41da13a*aa38e007ee01c07e4fe95495934cf68f*2f1e2e9bf1f0b320172cd667e02ad6be1718585b6594691907b58191a6
```
```bash
../hashcat -m 9600 office_hash /opt/wordlists/rockyou.txt  # office
```

Zip files
```bash
zip --password zippyzippy blueprints.zip dummy.pdf
python3 zip2john.py ./blueprints.zip
ver 1.0 efh 5455 efh 7875 blueprints.zip/dummy.pdf PKZIP Encr: 2b chk, TS_chk, cmplen=26, decmplen=14, crc=54961861 ts=A03A cs=a03a type=0
blueprints.zip/dummy.pdf:$pkzip$1*2*2*0*1a*e*54961861*0*43*0*1a*a03a*ceba04fce27f62009718d425edf297457615d4117e4cdd3d3cea*$/pkzip$:dummy.pdf:blueprints.zip::./blueprints.zip
```
```bash
../hashcat -a 0 -m 17200 zip /opt/wordlists/rockyou.txt  # zip
```

Keepass 
```bash
python3 keepass2john.py Master.kbdx
```
```bash
../hashcat -a 0 -m 13400 keepass_hash /opt/wordlists/rockyou.txt  # Keepass
```

Protected pdf files
```bash
~arthur/JohnTheRipper/run/pdf2john.pl inventory.pdf
$pdf$4*4*128*-1028*1*16*f7d77b3d22b9f92829d49ff5d78b8f28*32*d33f35f776215527d65155f79d9ed79800000000000000000000000000000000*32*6cfb859c107acaae8c0ca9ceec56fd91ff75fe7b1cddb03f629ca3583f59e52f
```
```bash
../hashcat -a 0 -m 10500 pdf_hash /opt/wordlists/rockyou.txt # pdf
```

## MIC (WPA 4-way handshake) 

Lexicon
```
- MSK - Master Session Key
- PMK - Pairwise Master Key
- GMK - Group Master Key
- PTK - Pairwise Transit Key
- GTK - Group Temporal Key
- ANonce
- SNonce
- MIC - Message Integrity Check
```

The handshake
```
        ╔══════════════╗                 ╔══════════════╗
        ║ Supplicant   ║                 ║Authenticator ║
        ║ Auth/Assoc   ║                 ║   Auth/Assoc ║
        ║ 802.1X       ║                 ║       802.1X ║
        ║ Blocked      ║                 ║      Blocked ║
        ║ PMK          ║                 ║          PMK ║
        ╠══════════════╝                 ╚══════════════╣
        ║                                               ║
        ║                                               ║
        ║     <═══════════════M1:AA,ANonce,sn═══════════╣
        ║                                               ║
        ╠══════════════╗                                ║
        ║ Derive PTK   ║                                ║
        ╠══════════════╝                                ║
        ║                                               ║
        ╠══════════════M2:SPA,SNonce,sn,MIC═══════>     ║
        ║                                               ║
        ║                                ╔══════════════╣
        ║                                ║   Derive PTK ║
        ║                                ║ Generate GTK ║
        ║                                ╚══════════════╣
        ║                                               ║
        ║     <═════M3:AA,ANonce,GTK,sn+1,MIC═══════════╣
        ║                                               ║
        ║                                               ║
        ║                                               ║
        ║                                               ║
        ║                                               ║
        ╠═════════════M4:SPA,no+1,MIC═════════════>     ║
        ║                                               ║
        ║                                               ║
        ╠══════════════╗                 ╔══════════════╣
        ║ PTK & GTK    ║                 ║    PTK & GTK ║
        ║ 802.1X       ║                 ║       802.1X ║
        ║ Unblocked    ║                 ║    Unblocked ║
        ╚══════════════╝                 ╚══════════════╝
```

The attack flow
```
- Attacker Sends deauth to client to force disconnection from the AP
- Client attempts to re-authenticate
- Attacker snifs and captures the handshake with airodump-ng
- The handshake is a collection of keys used to generate a common key called MIC
- Format required by hashcat is hccapx, conversion tools: 
- online - https://hashcat.net/cap2hccapx
- offline - https://github.com/hashcat/hashcat-utils.git
```
```bash
git clone https://github.com/hashcat/hashcat-utils.git
cd hashcat-utils/src
make
./cap2hccapx.bin input.pcap mic_to_crack.hccapx
```
```bash
../hashcat -a 0 -m 2500 mic_to_crack.hccapx /opt/wordlists/rockyou.txt  # wpa mic
```


## PMKID (WPA/WPA2-PSK - 1st packet/handshake)
Lexicon
```
- PMKID - Pairwise Master Key Identifier
	- Unique ID to keep track of the PMK used by a given client
	- It's essentially an HMAC-SHA1 of:
	    - The PMK
	    - The str "PMK Name"
	    - The MAC addr of the AP
	    - The MAC addr of the station
```

Diagram of PMKID
```
        ╔══════════════╗        ╔═════════════╗         ╔══════════════╗
        ║   PMK Name   ║        ║   MAC_AP    ║         ║    MAC_STA   ║
        ╚══════════════╣        ╚══════╦══════╝         ╠══════════════╝
                       ║               ║                ║               
                       ╚═══════════════╬════════════════╝ 
                                       ║
                 ╔═════════════════════╩═══════════════════════╗
        PMK ---> ║ HMAC-SHA1-128(PMK,"PMK Name",MAC_AP,MAC_STA)║ ---> PMKID
                 ╚═════════════════════════════════════════════╝
```
 
The attack flow
```
- To attack PSK we need to attack the AP directly
- No deauth is needed 
- Take a capture
```
```bash
git clone https://github.com/ZerBea/hcxtools.git
cd hcxtools 
sudo yum install -y libcurl-devel
git checkout 7cc478632870744ca3c4ca13c7b129e2163c132a
make && make install
./hcxpcaptool -z pmkidhash_corp cracking_pmkid.cap
```
```bash
../hashcat -a 0 -m 16800 pmkidhash_corp /opt/wordlists/rockyou.txt  # wpa pmkid
```
 

## More tools
```
Responder
SMB Relay attach
Kerberoasting
NtdsAudit 
DPAT
```
