# Kerberos
[https://www.tarlogic.com/blog/how-kerberos-works/](https://www.tarlogic.com/blog/how-kerberos-works/)

## KDC - (Kerberos Key Distribution Center)
```
The Kerberos service that issues the tickets,
It's typically hosted on the domain controller on port 88
```

## AS - (Authentication server)
```
Part of the KDC
Delivers TGT - (Ticket Granting Ticket)
TGT is typically requested at machine logon and stays valid for a while
It is used to request TGS tickets
```

## TGS - (Ticket Granting Server)
```
Part of the KDC
Delivers TGS - (Ticket Granting Service)
TGS is requested by the client to authenticate to a specific service
also has an expiry date and can be reused within that timeframe
```

## Kerberos Authentication Flow
1. Client ->  `AS_REQ` - "auhentication ticket" encrypted with user NT hash
2. KDC    ->  `AS_REP` - TGT encrypted with the krbtgt NT hash
3. Client -> `TGS_REQ` - TGT with a TGS request to a specific svc encrypted with user NT hash
4. TGS    -> `TGS_REP` - TGS encrypted with the NT hash of the account running the requested service
5. Client ->  `AP_REQ` - TGS to the service, access is granted if valid

```
1 - client ->  AS_REQ -> KDC
2 - client <-  AS_REP <- KDC
3 - client -> TGS_REQ -> KDC
4 - client <- TGS_REP <- KDC
5 - client ->  AS_REQ -> SVC
```

## SPNs - (Service Principal Names)
```
An SPN is the id of a service instance
SPNs are used by Kerberos to associate a service instance with a service logon account
This allows a client to request that the service authenticate an account
even if the client does not have the account name
```

## PAC - (Privileged Attribute Certificate)
```
The PAC is an extension to Kerberos tickets that contains useful information about a user’s privileges.  
This information is added to Kerberos tickets by a DC when a user authenticates within an ADdomain.  
The PAC can be read and used to determine their level of privileges without reaching out to the DC.
PACs contain sensitive information and therefore have been the target of several AD attack techniques.
```

## Golden Ticket Attack
See BlackHat talk [Abusing Microsof Kerberos: Sorry You Guys Don't Get It](https://youtu.be/lJQn06QLwEw)
```
Access to the whole Domain by stealing the krbtgt NT-Hash allowing to forge a TGT
```

## Silver Ticket Attack
See BlackHat talk [Abusing Microsof Kerberos: Sorry You Guys Don't Get It](https://youtu.be/lJQn06QLwEw)
```
Access to a single service by stealing the svc NT-Hash allowing to forge a TGS
Necessary information to perform a silver ticket attack:

NTHash      - NT hash of the targeted service, can be derived from its password
Domain SID  - The security identifier of the domain - can be obtained from a PAC
Domain Name - scrm.local
SPN         - The Service Principal Name - can be obtained with GetUserSPN.py
User Id     - uid 500
```


## Kerbrute

Using kerbrute for user enumeration
```bash
kerbrute userenum \
    -d scrm.local \
    --dc scrambled.htb \
    /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt
```

Using kerbrute for password spraying, meaning try 1 same password on a bunch of known users
```bash
kerbrute passwordspray \
    -d scrm.local \
    --dc scrambled.htb \
    ./users.txt \
    ksimpson
```

Using kerbrute to bruteforce a specific user
```bash
kerbrute bruteuser \
    -d authority.htb \
    --dc authority.htb \
    /usr/share/wordlists/rockyou.txt authority
```

