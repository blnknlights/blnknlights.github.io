# Server Hardening 

## Updates packages 
```bash
yum install yum-plugin-security
yum updateinfo
yum updateinfo list
yum updateinfo list --sec-severity=Critical
yum updateinfo list --sec-severity=Moderate
yum updateinfo list --sec-severity=Low
yum update --bugfix
yum update --security
yum update --advisory
yum update --sec-serverity=SEVS
```
## Verifying Packages
```bash
rpm --import /tmp/rpm-gpg-keynew
    # install a gpg key
rpm -qa gpg-pubkey*
    # look at the install keys
rpm -qi gpg-pubkey-8483c65d-5ccc5b19
    # get detailed information of a specific key
rpm -K *.rpm
    # verify the key that was used to sign a given package corresponds with known gpg keys
/etc/yum.conf
    # make sure gpgcheck=1 
rpm -Uvh *.rpm
    # install packages from rpm
yum localinstall *.rpm
    # install from yum (will also install the dependencies indeed)
```

## Install Packages 
```bash
  -e, --erase=<package>+             erase (uninstall) package
  -F, --freshen=<packagefile>+       upgrade package(s) if already installed
  -h, --hash                         print hash marks as package installs (good with -v)
  -i, --install                      install package(s)
  -U, --upgrade=<packagefile>+       upgrade package(s)
  -v, --verbose                      provide more detailed output

Query options (with -q or --query):
  -c, --configfiles                  list all configuration files
  -d, --docfiles                     list all documentation files
  -L, --licensefiles                 list all license files
  -A, --artifactfiles                list all artifact files
      --dump                         dump basic file information
  -l, --list                         list files in package
      --queryformat=QUERYFORMAT      use the following query format
  -s, --state                        display the states of the listed files

rpm -e screen
    # erase scren
rpm -q screen
    # query for elinks to check if installed 
yum install --downloadonly --downloaddir=. screen
    # download the package localy without installing 
rpm -ivh screen
    # install 
rpm -Uvh screen
    # -U stands for upgrades and replaces the current version (ie overwrites) it will also install if no version exists 
rpm -Fvh screen
    # -F stands for freshen will update only if a new version exists, will not install if no version already exists

    # 
    # 
    # 
```

## AIDE - Advanced Intrusion Detection Environment
* IDS
* Creates a database from Regex rules
* Checks file integrity from digest algorithms
* Also check file attributes for inconsistencies

```bash
vim /etc/aide.conf
    # AIDE conf file
/usr/sbin/aide --init
    # generates the db
file /var/lib/aide/aide.db.new.gz
    # db location
cp /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz
    # copy here once generated  
/usr/sbin/aide --check
    # runs checks on the filesystem
0 1 * * * /usr/sbin/aide --check
    # set a cronjob to run everyday 1am 
```
* build the baseline database
* put the check in crontab 
* MAILTO

