# Windows OS Fundamentals

## version numbers
```
Windows NT 4                             4.0
Windows 2000                             5.0
Windows XP                               5.1
Windows Server 2003, 2003 R2             5.2
Windows Vista, Server 2008               6.0
Windows 7, Server 2008 R2                6.1
Windows 8, Server 2012                   6.2
Windows 8.1, Server 2012 R2              6.3
Windows 10, Server 2016, Server 2019    10.0
```

## Powershell cmdlets
```
Get-WmiObject -List
Get-WmiObject -Class Win32_Service
Get-WmiObject -Class Win32_Bios
Get-WmiObject -Class Win32_Process
Get-WmiObject -Class Win32_Bios
Get-WmiObject -Class win32_OperatingSystem 
Get-WmiObject -Class win32_OperatingSystem | select Version,BuildNumber
Get-WmiObject -Class Win32_OperatingSystem -ComputerName DC
Get-WmiObject -Class CIM_DataFile -Filter "Compressed = 'True'"
Get-WmiObject -Query "SELECT * FROM CIM_DataFile WHERE Compressed = 'True'"
```

## Windows file structure 
```
Perflogs                     Can hold Windows performance logs but is empty by default.
Program Files                On 32-bit systems, all 16-bit and 32-bit programs are installed here. On 64-bit systems, only 64-bit programs are installed here.
Program Files (x86)          32-bit and 16-bit programs are installed here on 64-bit editions of Windows.
ProgramData                  This is a hidden folder that contains data that is essential for certain installed programs to run.                                                                               This data is accessible by the program no matter what user is running it.
Users                        This folder contains user profiles for each user that logs onto the system and contains the two folders Public and Default.
Default                      This is the default user profile template for all created users. 
                             Whenever a new user is added to the system, their profile is based on the Default profile.
Public                       This folder is intended for computer users to share files and is accessible to all users by default.                                                                              This folder is shared over the network by default but requires a valid network account to access.
AppData                      Per user application data and settings are stored in a hidden user subfolder (i.e., cliff.moore\AppData). 
                             Each of these folders contains three subfolders. The Roaming folder contains machine-independent data that should follow the user's profile, 
                             such as custom dictionaries. The Local folder is specific to the computer itself and is never synchronized across the network. 
                             LocalLow is similar to the Local folder, but it has a lower data integrity level. Therefore it can be used, for example, 
                             by a web browser set to protected or safe mode.
Windows                      The majority of the files required for the Windows operating system are contained here.
System, System32, SysWOW64   Contains all DLLs required for the core features of Windows and the Windows API. 
WinSxS                       The Windows Component Store contains a copy of all Windows components, updates, and service packs.
```

## NTFS Basic permissions
```
Full Control            Users are permitted to add, edit, move, delete files & folders as well as change NTFS permissions that apply to all allowed folders
Modify                  Users are permitted or denied permissions to view and modify files and folders. This includes adding or deleting files
Read & Execute          Users are permitted or denied permissions to read the contents of files and execute programs
List folder contents    Users are permitted or denied permissions to view a listing of files and subfolders
Read                    Users are permitted or denied permissions to read the contents of files
Write                   Users are permitted or denied permissions to write changes to a file and add new files to a folder
```

## Special Permissions
```
Full control                    Users are permitted or denied permissions to add, edit, move, delete files & folders as well as change 
                                NTFS permissions that apply to all permitted folders
Traverse folder / execute file  Users are permitted or denied permissions to access a subfolder within a directory structure even if the user 
                                is denied access to contents at the parent folder level. Users may also permitted or denied permissions to execute programs
List folder/read data           Users are permitted or denied permissions to view files and folders contained in the parent folder. 
                                Users can also be permitted to open and view files
Read attributes                 Users are permitted or denied permissions to view basic attributes of a file or folder. 
                                Examples of basic attributes: system, archive, read-only, and hidden
Read extended attributes        Users are permitted or denied permissions to view extended attributes of a file or folder. Attributes differ depending on the program
Create files/write data         Users are permitted or denied permissions to create files within a folder and make changes to a file
Create folders/append data      Users are permitted or denied permissions to create subfolders within a folder. Data can be added to files but 
                                pre-existing content cannot be overwritten
Write attributes                Users are permitted or denied to change file attributes. This permission does not grant access to creating files or folders
Write extended attributes       Users are permitted or denied permissions to change extended attributes on a file or folder. Attributes differ depending on the program
Delete subfolders and files     Users are permitted or denied permissions to delete subfolders and files. Parent folders will not be deleted
Delete                          Users are permitted or denied permissions to delete parent folders, subfolders and files.
Read permissions                Users are permitted or denied permissions to read permissions of a folder
Change permissions              Users are permitted or denied permissions to change permissions of a file or folder
Take ownership                  Users are permitted or denied permission to take ownership of a file or folder. 
                                The owner of a file has full permissions to change any permissions
```

## Integrity Control Access Control List (icacls)

> inheritance levels
```
(CI): container inherit
(OI): object inherit
(IO): inherit only
(NP): do not propagate inherit
(I): permission inherited from parent container
```

> Basic access permissions
```
F : full access
D :  delete access
N :  no access
M :  modify access
RX :  read and execute access
R :  read-only access
W :  write-only access
```

> examples of icacls commands
```
icacls c:\Users
icacls c:\users /grant joe:f
icacls c:\users /remove joe
```


## SMB Shares permissions (not the same as NTFS Perms)
```
Full Control    Users are permitted to perform all actions given by Change and Read permissions as well as change permissions for NTFS files and subfolders
Change          Users are permitted to read, edit, delete and add files and subfolders
Read            Users are allowed to view file & subfolder contents
```

## connect ot a net share 
```
smbclient -L 10.129.90.10 -U htb-student
sudo mount -t cifs -o username=htb-student,password=Academy_WinFun! //10.129.90.10/"Company Data" /home/blnkn/Desktop/
```

## tools to check net shares from the server side
```
net share
Computer Management
Event Viewer
```

## SCM - Service Control Manager
```
SCM - Service Control Manager - Manages Windows services accessible via the services.msc MMC add-in.
```

## Services
```
Get-Service | ? {$_.Status -eq "Running"} | select -First 2 |fl
```

## Critical System Services
```
smss.exe                   Session Manager SubSystem. Responsible for handling sessions on the system.
csrss.exe                  Client Server Runtime Process. The user-mode portion of the Windows subsystem.
wininit.exe                Starts the Wininit file .ini file that lists all of the changes to be made to Windows when the computer is restarted after installing a program.
logonui.exe                Used for facilitating user login into a PC
lsass.exe                  The Local Security Authentication Server verifies the validity of user logons to a PC or server. 
                           It generates the process responsible for authenticating users for the Winlogon service.
services.exe               Manages the operation of starting and stopping services.
winlogon.exe               Responsible for handling the secure attention sequence, loading a user profile on logon, and locking the computer when a screensaver is running.
System                     A background system process that runs the Windows kernel.
svchost.exe with RPCSS     Manages system services that run from dynamic-link libraries (files with the extension .dll) such as "Automatic Updates," 
                           "Windows Firewall," and "Plug and Play." Uses the Remote Procedure Call (RPC) Service (RPCSS).
svchost.exe with Dcom/PnP  Manages system services that run from dynamic-link libraries (files with the extension .dll) such as "Automatic Updates," 
                           "Windows Firewall," and "Plug and Play." Uses the Distributed Component Object Model (DCOM) and Plug and Play (PnP) services.
```

## LSASS - Local Security Authority Subsystem Service
```
- lsass.exe
- verifies logon attempts
- issue tokens based on access level
- resets passwords
- high value as we can get the hashes from memory dumps
```

## SysInternals Tools suite
```
\\live.sysinternals.com\tools
\\live.sysinternals.com\tools\PSExec
\\live.sysinternals.com\tools\TCPView
\\live.sysinternals.com\tools\Process Monitor
\\live.sysinternals.com\tools\Process Explorer  (taskmgr on steroids)
\\live.sysinternals.com\tools\procdump.exe -accepteula
```
