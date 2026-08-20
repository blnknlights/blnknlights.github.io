# Active Directory

## Lexicon & Acronyms
```
CIM  - Common Information Model              - Object-oriented data model that contains information about different parts of an enterprise
WMI  - Windows Management Instrumentation    - Windows implementation of CIM, now deprecated in favor of CIMv2 in Powershell Core
ADSI - Active Directory Service Interfaces   - 
UAC  - User Account Controls                 - 
MMC  - Microsof Management Console           -
OID  - Object Identifier                     -
SPN  - Service Principal Name                - 
```
> https://social.technet.microsoft.com/wiki/contents/articles/5392.active-directory-ldap-syntax-filters.aspx

## AD Users
> https://ldapwiki.com/wiki/Active%20Directory%20User%20Related%20Searches
```
# select name` | List disabled users
Get-ADUser -LDAPFilter '(userAccountControl:1.2.840.113556.1.4.803:=2)'

# Find admin users that don't require Kerberos Pre-Auth (for Kerberoasting Or ASREPRoasted)
# The adminCount attribute. The group with this attribute set to 1 are protected by AdminSDHolder and known as protected groups
Get-ADUser -Filter {adminCount -eq '1' -and DoesNotRequirePreAuth -eq 'True'}
Get-ADUser -Filter {adminCount -eq '1'} -Properties * | where servicePrincipalName -ne $null | select SamAccountName,MemberOf,ServicePrincipalName | fl
Get-ADUser -Filter {DoesNotRequirePreAuth -eq 'True'}
Get-ADUser -Filter {DoesNotRequirePreAuth -eq 'True'} -Properties *|select name,memberOf
Get-ADUser -Filter 'useraccountcontrol -band 4194304' -Properties useraccountcontrol | Format-Table name

# Count all users in an OU
(Get-ADUser -SearchBase "OU=Employees,DC=INLANEFREIGHT,DC=LOCAL" -Filter *).count

# Get all users
Get-ADObject -LDAPFilter '(&(objectCategory=person)(objectClass=user))'

# Get all administratively disabled accounts in the domain
Get-ADObject -LDAPFilter '(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=2))' | select samaccountname,useraccountcontrol

# Will return all administratively disabled user accounts (bitwise and)
Get-ADUser -LDAPFilter '(userAccountControl:1.2.840.113556.1.4.803:=2)' | select name

# All accounts that do not have a blank description
Get-ADUser -Properties * -LDAPFilter '(&(objectCategory=user)(description=*))' | select samaccountname,description

# Find all users or computers marked as trusted for delegation
Get-ADUser -Properties * -LDAPFilter '(userAccountControl:1.2.840.113556.1.4.803:=524288)' | select Name,memberof, servicePrincipalName,TrustedForDelegation | fl

# Users with the "adminCount" attribute set to 1 whose "useraccountcontrol" attribute is set with the flag "PASSWD_NOTREQD," 
# meaning that the account can have a blank password set. 
Get-AdUser -LDAPFilter '(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=32))(adminCount=1)' -Properties * | select name,memberof | fl

# Enumerate UAC values for admin users
Get-ADUser -Filter {adminCount -gt 0} -Properties admincount,useraccountcontrol

# Enumerate User-Account-Control Attributes
Get-ADUser -Filter {adminCount -gt 0} -Properties admincount,useraccountcontrol | select Name,useraccountcontrol
```

## AD Groups
> https://ldapwiki.com/wiki/Active%20Directory%20Group%20Related%20Searches
```
# Get information about an AD group
Get-ADGroup -Identity "<GROUP NAME" -Properties *

# select Name` | Get all administrative groups
Get-ADGroup -Filter "adminCount -eq 1"
Get-ADGroup -Filter "adminCount -eq 1" | select Name

# LDAP query to return all AD groups
Get-ADObject -LDAPFilter '(objectClass=group)'

# This matching rule will find all groups that the user Harry Jones is a member of using the Matching rule in chain OID operand
Get-ADGroup -LDAPFilter '(member:1.2.840.113556.1.4.1941:=CN=Harry Jones,OU=Network Ops,OU=IT,OU=Employees,DC=INLANEFREIGHT,DC=LOCAL)' | select Name

# Get all members of the Security Operations group
Get-ADGroupMember -Identity "Security Operations"

# Check what groups user harry.jones is a member of 
Get-ADUser -Identity harry.jones -Properties * | select memberof | ft -Wrap

# Enumerating nested group membership 
Get-ADGroup -Filter 'member -RecursiveMatch "CN=Harry Jones,OU=Network Ops,OU=IT,OU=Employees,DC=INLANEFREIGHT,DC=LOCAL"' | select name

# Enumerating nested group membership with ldap OID matching rule
Get-ADGroup -LDAPFilter '(member:1.2.840.113556.1.4.1941:=CN=Harry Jones,OU=Network Ops,OU=IT,OU=Employees,DC=INLANEFREIGHT,DC=LOCAL)' |select Name
```

## AD Computers
> https://ldapwiki.com/wiki/Active%20Directory%20Computer%20Related%20LDAP%20Query
```
# Get hostnames with the word "SQL" in their hostname
Get-ADComputer -Filter "DNSHostName -like 'SQL*'"

# Get all computers
Get-ADObject -LDAPFilter '(objectCategory=Computer)'

# Get domain controllers
Get-ADObject -LDAPFilter '(&(objectCategory=Computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))'

# Find trusted computers
Get-ADComputer -Properties * -LDAPFilter '(userAccountControl:1.2.840.113556.1.4.803:=524288)' | select DistinguishedName,servicePrincipalName,TrustedForDelegation | fl

```

## SearchBase & SearchScope
```
# SearchScope Base or 0 will only return the exact search base 
Get-ADUser -SearchBase "OU=Employees,DC=INLANEFREIGHT,DC=LOCAL" -SearchScope Base -Filter *     # returns nothing as expected
Get-ADObject -SearchBase "OU=Employees,DC=INLANEFREIGHT,DC=LOCAL" -SearchScope Base -Filter *   # returns the employee OU

# SearchScope OneLevel or 1
Get-ADUser -SearchBase "OU=Employees,DC=INLANEFREIGHT,DC=LOCAL" -SearchScope OneLevel -Filter *

# SearchScope Subtree or 2
(Get-ADUser -SearchBase "OU=Employees,DC=INLANEFREIGHT,DC=LOCAL" -SearchScope Subtree -Filter *).count

```

## RSAT
```
# Check if RSAT tools are installed
Get-WindowsCapability -Name RSAT* -Online | Select-Object -Property Name, State

# Install all RSAT tools
Add-WindowsCapability -Name RSAT* -Online | Add-WindowsCapability –Online

# Install a specific RSAT tool
Add-WindowsCapability -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0  –Online
```

## Query CIM / WMI Objects
```
# Query for installed software
Get-CimInstance win32_product | fl
Get-CimInstance win32_product -Filter "NOT Vendor like '%Microsoft%'" | fl

# Get AD groups using WMI
Get-WmiObject -Class win32_group -Filter "Domain='INLANEFREIGHT'"
```

## Use ADSI
```
# Use ADSI to search for all computers
([adsisearcher]"(&(objectClass=Computer))").FindAll()
```

## Other
```
# xfreeRDP to target
xfreerdp /v:<target IP address> /u:htb-student /p:<password>

# View a user's current rights 
whoami /priv

# Run a utility as another user
runas /netonly /user:htb.local\jackie.may powershell | select cn 

# Run mmc as a domain user
runas /netonly /user:Domain_Name\Domain_USER mmc
```



### Powershell Filter Operators
```
-eq        Equal to
-le        Less than or equal to
-ge        Greater than or equal to
-ne        Not equal to
-lt        Less than
-gt        Greater than
-approx    Approximately equal to
-bor       Bitwise OR
-band      Bitwise AND
-like      Like
-notlike   Not like
-and       Boolean AND
-or        Boolean OR
-not       Boolean NOT
-recursivematch    Recursive match
```

### LDAP Filter Operators
```
&    and
|    or
!    not
```

### LDAP Search Criterias
```
Equal to             (attribute=123)     (&(objectclass=user)(displayName=Smith)
Not equal to         (!(attribute=123))  (!objectClass=group)
Present              (attribute=*)       (department=*)
Not present          (!(attribute=*))    (!homeDirectory=*)
Greater than         (attribute>=123)    (maxStorage=100000)
Less than            (attribute<=123)    (maxStorage<=100000)
Wildcards            (attribute=*A)      (givenName=*Sam)
Approximate match    (attribute~=123)    (sAMAccountName~=Jason)
```

### OID Matches
```
1.2.840.113556.1.4.803     LDAP_MATCHING_RULE_BIT_AND    A match is found only if all bits from the attribute match the value. This rule is equivalent to a bitwise AND operator.
1.2.840.113556.1.4.804     LDAP_MATCHING_RULE_BIT_OR     A match is found if any bits from the attribute match the value. This rule is equivalent to a bitwise OR operator.
1.2.840.113556.1.4.1941    LDAP_MATCHING_RULE_IN_CHAIN   This rule is limited to filters that apply to the DN. This is a special "extended" match operator that walks the chain of ancestry in objects all the way to the root until it finds a match.
```

## Filter types:
```
=     Equal to
~=    Approximately equal to
>=    Greater than or equal to
<=    Less than or equal to
```

## Item types:
```
=              Simple
=*             Present
=something*    Substring
Extensible     varies depending on type
```

## Characters that need to be escaped
```
*      \2a
(      \28
)      \29
\      \5c
NUL    \00
```

# User Account Control Values
> https://academy.hackthebox.com/storage/resources/Convert-UserAccountControlValues.zip
```
1         "SCRIPT"
2         "ACCOUNTDISABLE"
8         "HOMEDIR_REQUIRED"
16        "LOCKOUT"
32        "PASSWD_NOTREQD"
128       "ENCRYPTED_TEXT_PWD_ALLOWED"
256       "TEMP_DUPLICATE_ACCOUNT"
512       "NORMAL_ACCOUNT"
2048      "INTERDOMAIN_TRUST_ACCOUNT"
4096      "WORKSTATION_TRUST_ACCOUNT"
8192      "SERVER_TRUST_ACCOUNT"
65536     "DONT_EXPIRE_PASSWORD"
131072    "MNS_LOGON_ACCOUNT"
262144    "SMARTCARD_REQUIRED"
524288    "TRUSTED_FOR_DELEGATION"
1048576   "NOT_DELEGATED"
2097152   "USE_DES_KEY_ONLY"
4194304   "DONT_REQ_PREAUTH"
8388608   "PASSWORD_EXPIRED"
16777     "TRUSTED_TO_AUTH_FOR_DELEGATION"
67108864  "PARTIAL_SECRETS_ACCOUNT"
```

## PowerView
```
Import-Module .\PowerView.ps1
Get-DomainUser * -AdminCount | select samaccountname,useraccountcontrol
```

## PowerShell AD Module
```
dsquery user "OU=Employees,DC=inlanefreight,DC=local" -name * -scope subtree -limit 0
dsquery user "OU=Employees,DC=inlanefreight,DC=local" -name * -scope subtree -limit 0 | dsget user -samid -pwdneverexpires | findstr /V no
```

## AD DS Tools
```
Get-ADUser -Filter * -SearchBase 'OU=Admin,DC=inlanefreight,dc=local'
```

## The Sysinternals Suite (WMI)
```
Get-WmiObject -Class win32_group -Filter "Domain='INLANEFREIGHT'" | Select Caption,Name
```

## The Sysinternals Suite (ADSI)
```
([adsisearcher]"(&(objectClass=Computer))").FindAll() | select Path
```

## Python ldap3
```
from ldap3 import *
s = Server('10.129.1.207',get_info = ALL)
c =  Connection(s, '', '')
c.bind()
s.info
```

## Ldapsearch
```
ldapsearch -h 10.129.1.207 -p 389 -x -b "dc=inlanefreight,dc=local"
```

## Windapsearch
```
./windapsearch.py --dc-ip 10.129.1.207 -u "" --functionality
./windapsearch.py --dc-ip 10.129.1.207 -u "" -C
./windapsearch.py --dc-ip 10.129.1.207 -u "" -U
./windapsearch.py --dc-ip 10.129.1.207 -u inlanefreight\\james.cross --da
./windapsearch.py --dc-ip 10.129.1.207 -d inlanefreight.local -u inlanefreight\\james.cross --unconstrained-users
```

## Ldapsearch-ad
```
./ldapsearch-ad.py -l 192.168.56.20 -t info
./ldapsearch-ad.py -l 192.168.56.20 -d evilcorp -u jjohnny -p 'P@$$word' -t all
./ldapsearch-ad.py -l 192.168.56.20 -d evilcorp -u jjohnny -hashes :32ed87bdb5fdc5e9cba88547376818d4 -t show-admins
./ldapsearch-ad.py -l 10.129.1.207 -d inlanefreight -u james.cross -p Summer2020 -t pass-pols
./ldapsearch-ad.py -l 10.129.1.207 -d inlanefreight -u james.cross -p Summer2020 -t kerberoast | grep servicePrincipalName:
./ldapsearch-ad.py -l 10.129.1.207 -d inlanefreight -u james.cross -p Summer2020 -t asreproast
```

